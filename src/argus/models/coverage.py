"""Coverage is evidence of work performed, never a safety score."""

from dataclasses import dataclass

from .base import Capability, Category, Record, Status, nonempty, require, unique
from .source import FileKind, SourceFile


@dataclass(frozen=True, kw_only=True)
class CapabilityCoverage(Record):
    capability: Capability
    status: Status
    reason: str
    rule_id: str | None = None
    eligible_units: int | None = None
    evaluated_units: int | None = None
    unit: str = "files"

    def validate(self) -> None:
        nonempty(self.reason)
        nonempty(self.unit)
        require(self.status != Status.UNCLASSIFIED, "capability cannot be unclassified")
        for count in (self.eligible_units, self.evaluated_units):
            require(count is None or count >= 0, "negative coverage count")
        require(self.eligible_units is None or self.evaluated_units is None
                or self.evaluated_units <= self.eligible_units, "invalid coverage denominator")
        require(self.status not in (Status.UNSUPPORTED, Status.DISABLED, Status.EXCLUDED, Status.FAILED)
                or self.evaluated_units in (None, 0), "unavailable capability cannot claim evaluations")
        require(self.status != Status.COMPLETED or self.eligible_units is None
                or self.evaluated_units is None or self.eligible_units == self.evaluated_units,
                "completed capability cannot claim incomplete unit coverage")


@dataclass(frozen=True, kw_only=True)
class FileCoverage(Record):
    file_id: str
    status: Status
    reason: str
    capabilities: tuple[CapabilityCoverage, ...]
    reviewed_lines: int | None = None
    reason_code: str = "unspecified"

    def validate(self) -> None:
        nonempty(self.file_id)
        nonempty(self.reason)
        nonempty(self.reason_code)
        unique(tuple(item.capability.value for item in self.capabilities))
        require({item.capability for item in self.capabilities} == set(Capability),
                "file coverage must explicitly account for every capability")
        require(self.reviewed_lines is None or self.reviewed_lines >= 0, "negative reviewed lines")
        require(self.status not in (Status.UNSUPPORTED, Status.EXCLUDED, Status.FAILED,
                                   Status.DISABLED, Status.UNCLASSIFIED)
                or self.reviewed_lines in (None, 0), "unreviewed file cannot claim reviewed lines")
        require(self.status != Status.COMPLETED
                or any(item.status == Status.COMPLETED for item in self.capabilities),
                "completed file requires completed capability")
        require(self.status != Status.UNSUPPORTED
                or all(item.status in (Status.UNSUPPORTED, Status.DISABLED)
                       for item in self.capabilities), "unsupported file claims analysis")


@dataclass(frozen=True, kw_only=True)
class CategoryCoverage(Record):
    category: Category
    status: Status
    reason: str
    rule_ids: tuple[str, ...] = ()

    def validate(self) -> None:
        nonempty(self.reason)
        require(self.status != Status.UNCLASSIFIED, "category cannot be unclassified")
        unique(self.rule_ids)
        require(self.status not in (Status.COMPLETED, Status.PARTIAL) or bool(self.rule_ids),
                "evaluated category requires rules")


@dataclass(frozen=True, kw_only=True)
class InventoryGap(Record):
    """Pruned/unreadable scope whose contents could not safely be enumerated."""

    reason: str
    status: Status
    path: str | None = None
    file_count: int | None = None
    root_id: str = "root"
    reason_code: str = "unspecified"

    def validate(self) -> None:
        from .base import relative_path

        nonempty(self.reason)
        nonempty(self.root_id)
        nonempty(self.reason_code)
        require(self.status in (Status.EXCLUDED, Status.FAILED), "invalid inventory gap status")
        if self.path is not None:
            relative_path(self.path)
        require(self.file_count is None or self.file_count >= 0, "negative gap count")


@dataclass(frozen=True, kw_only=True)
class Ratio(Record):
    numerator: int | None
    denominator: int | None
    definition: str
    unavailable_reason: str | None = None

    def validate(self) -> None:
        nonempty(self.definition)
        require(self.numerator is None or self.numerator >= 0, "negative numerator")
        require(self.denominator is None or self.denominator >= 0, "negative denominator")
        require(self.numerator is None or self.denominator is None
                or self.numerator <= self.denominator, "numerator exceeds denominator")
        require((self.numerator is None or self.denominator in (None, 0))
                == bool(self.unavailable_reason), "unavailable ratio requires reason")

    @property
    def fraction(self) -> float | None:
        if self.numerator is None or self.denominator in (None, 0):
            return None
        return self.numerator / self.denominator


@dataclass(frozen=True, kw_only=True)
class Coverage(Record):
    files: tuple[FileCoverage, ...]
    categories: tuple[CategoryCoverage, ...]
    rules: tuple[CapabilityCoverage, ...] = ()
    inventory_gaps: tuple[InventoryGap, ...] = ()
    limitations: tuple[str, ...] = ()

    def validate(self) -> None:
        unique(tuple(item.file_id for item in self.files))
        unique(tuple(item.category.value for item in self.categories))
        require({item.category for item in self.categories} == set(Category),
                "every analysis category requires coverage")
        require(all(item.rule_id for item in self.rules), "rule coverage requires rule ID")
        unique(tuple(item.rule_id for item in self.rules))

    def source_metrics(self, files: tuple[SourceFile, ...], language: str | None = None) -> dict:
        """Aggregate supplied records only; performs no repository inspection."""
        selected = tuple(file for file in files if file.kind == FileKind.SOURCE
                         and (language is None or file.language == language))
        entries = {item.file_id: item for item in self.files}
        require(all(file.id in entries for file in selected), "missing file coverage")
        counts = {status.value: sum(entries[file.id].status == status for file in selected)
                  for status in Status}
        denominator = len(selected)
        file_ratio = Ratio(numerator=counts[Status.COMPLETED.value], denominator=denominator,
                           definition="completed source files / all inventoried source files, including excluded files",
                           unavailable_reason="no inventoried source files" if denominator == 0 else None)
        measurable = all(file.physical_lines is not None
                         and entries[file.id].reviewed_lines is not None for file in selected)
        line_denominator = sum(file.physical_lines for file in selected) if measurable else None
        line_numerator = sum(entries[file.id].reviewed_lines for file in selected) if measurable else None
        line_ratio = Ratio(numerator=line_numerator, denominator=line_denominator,
                           definition="reviewed physical source lines / all physical lines in inventoried source files; not semantic LOC",
                           unavailable_reason=("line counts unavailable" if not measurable else
                                               "no physical source lines" if not line_denominator else None))
        return {"total_discovered_source_files": denominator, "by_status": counts,
                "file_coverage": file_ratio, "line_coverage": line_ratio,
                "inventory_complete": not self.inventory_gaps}
