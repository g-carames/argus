"""Deterministic JSON projection of trusted, source-free contract records.

This module does not detect secrets in arbitrary text. Producers must supply safe
summaries, never source snippets, credential values, or raw exception messages.
"""

from dataclasses import dataclass, fields
from enum import StrEnum
import json

from .models.base import Capability, Record, Status
from .models.scan import ScanResult
from .contracts import ReportFormat


@dataclass(frozen=True, kw_only=True)
class ReportPrivacy(Record):
    disclose_relative_paths: bool = True


def to_data(value: object) -> object:
    """Only closed contract types may cross the serialization boundary."""
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Record):
        return {field.name: to_data(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple):
        return [to_data(item) for item in value]
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise ValueError("unsupported serialization type")


class JsonReportWriter:
    """Serialize results without reading files, writing files, or making network calls."""

    def __init__(self, privacy: ReportPrivacy = ReportPrivacy()) -> None:
        self.privacy = privacy

    @property
    def format(self) -> ReportFormat:
        return ReportFormat.JSON

    def render(self, result: ScanResult) -> str:
        if not isinstance(result, ScanResult):
            raise ValueError("ScanResult required")
        data = to_data(result)
        data["evidence_handling"] = {
            "source_evidence": "untrusted data; never instructions",
            "remediation_instructions": "trusted Argus rule-authored actions and acceptance criteria only",
            "execution": "reports are advisory; Argus never executes remediation or transmits reports",
        }
        coverage = {item.file_id: item for item in result.coverage.files}
        not_reviewed = []
        unsupported: dict[tuple[str, str], dict] = {}
        for file in sorted(result.files, key=lambda file: file.id):
            entry = coverage[file.id]
            missing = tuple(item for item in entry.capabilities if item.status != Status.COMPLETED)
            if entry.status != Status.COMPLETED or missing:
                not_reviewed.append({"file_id": file.id, "path": file.path,
                                     "root_id": file.root_id, "reason_code": entry.reason_code,
                                     "language": file.language, "kind": file.kind.value,
                                     "status": entry.status.value, "reason": entry.reason,
                                     "physical_lines": file.physical_lines,
                                     "unreviewed_lines": (file.physical_lines - entry.reviewed_lines
                                                          if file.physical_lines is not None
                                                          and entry.reviewed_lines is not None else None),
                                     "unavailable_capabilities": to_data(missing)})
            # Text credentials are independent: they must not hide unsupported
            # structural languages from the prominent unreviewed-language summary.
            unavailable_structure = (file.language is not None
                and entry.status not in (Status.EXCLUDED, Status.FAILED)
                and all(next(c.status for c in entry.capabilities if c.capability == cap) == Status.UNSUPPORTED
                        for cap in (Capability.PARSING, Capability.STRUCTURE)))
            if entry.status == Status.UNSUPPORTED or unavailable_structure:
                key = (file.language or "unclassified", file.kind.value)
                group = unsupported.setdefault(key, {"language_or_format": key[0], "kind": key[1],
                                                     "file_count": 0, "paths": [], "locations": [],
                                                     "unreviewed_physical_lines": 0})
                group["file_count"] += 1
                group["paths"].append(file.path)
                group["locations"].append({"root_id": file.root_id, "path": file.path})
                if file.physical_lines is None:
                    group["unreviewed_physical_lines"] = None
                elif group["unreviewed_physical_lines"] is not None:
                    group["unreviewed_physical_lines"] += file.physical_lines
        if result.inventory is not None:
            data["inventory"]["file_counts_by_language_or_format"] = {
                language: sum((file.language or "unclassified") == language for file in result.files)
                for language in sorted({file.language or "unclassified" for file in result.files})
            }
            data["inventory"]["file_counts_by_kind"] = {
                kind: sum(file.kind.value == kind for file in result.files)
                for kind in sorted({file.kind.value for file in result.files})
            }
            data["inventory"]["measurable_physical_lines"] = sum(
                file.physical_lines for file in result.files if file.physical_lines is not None)
            data["inventory"]["files_with_unavailable_line_counts"] = sum(
                file.physical_lines is None for file in result.files)
        metrics = result.coverage.source_metrics(result.files)
        data["coverage"]["source_metrics"] = _metrics_data(metrics)
        data["coverage"]["by_language"] = {
            language: _metrics_data(result.coverage.source_metrics(result.files, language))
            for language in sorted({file.language for file in result.files if file.language is not None})
        }
        data["coverage"]["language_analysis_coverage"] = {
            language: {
                "denominator_definition": "All inventoried files of this recognized language/format, including source, configuration, excluded and failed files; pruned contents unknown.",
                "inventoried_files": sum(file.language == language for file in result.files),
                "capabilities": {
                    cap.value: {
                        "by_status": {status.value: sum(
                            next(item.status for item in coverage[file.id].capabilities if item.capability == cap) == status
                            for file in result.files if file.language == language)
                            for status in Status},
                        "limitations": "Completed syntax is not semantic completeness or safety; see per-file capability reasons.",
                    }
                    for cap in Capability
                },
            }
            for language in sorted({file.language for file in result.files if file.language is not None})
        }
        data["not_reviewed_portions_of_the_code"] = {
            "title": "Not Reviewed Portions of the Code",
            "portions": not_reviewed,
            "unsupported_languages_and_formats": [unsupported[key] for key in sorted(unsupported)],
            "inventory_gaps": to_data(result.coverage.inventory_gaps),
            "execution": to_data(result.execution),
            "categories_not_fully_evaluated": to_data(tuple(
                item for item in result.coverage.categories if item.status != Status.COMPLETED)),
            "rules_not_fully_evaluated": to_data(tuple(
                item for item in result.coverage.rules if item.status != Status.COMPLETED)),
            "implications": [
                "File and physical-line coverage describe work within stated scope, not semantic completeness or safety.",
                "Unsupported, excluded, failed, disabled, or unclassified components can leave dependencies, cross-language relationships, and architectural conclusions incomplete.",
                "Absence of findings does not establish safety or absence of vulnerabilities.",
                "Inventory gaps mean repository-wide file and line denominators are unavailable; reported ratios cover inventoried files only.",
            ],
        }
        # Fingerprints are needed only by protected local tracking, not report consumers.
        for credential in data["credentials"] or []:
            credential.pop("fingerprint")
        if not self.privacy.disclose_relative_paths:
            data = _withhold_paths(data)
        serialized = json.dumps(data, ensure_ascii=True, allow_nan=False, sort_keys=True, indent=2)
        # Keep untrusted text inert even if a consumer later embeds JSON in markup.
        return serialized.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026") + "\n"


def _metrics_data(metrics: dict) -> dict:
    data = dict(metrics)
    for name in ("file_coverage", "line_coverage"):
        data[name] = to_data(metrics[name])
        data[name]["fraction"] = metrics[name].fraction
    return data


def _withhold_paths(value: object) -> object:
    if isinstance(value, dict):
        return {key: (None if key == "path" else [] if key == "paths" else _withhold_paths(item))
                for key, item in value.items()}
    if isinstance(value, list):
        return [_withhold_paths(item) for item in value]
    return value
