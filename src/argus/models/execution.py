"""Future scalable input/execution/export contracts, without execution machinery."""

from dataclasses import dataclass
from enum import StrEnum

from .base import Category, Record, Severity, nonempty, relative_path, require, unique


class InputKind(StrEnum):
    LOCAL_DIRECTORY = "local_directory"
    PREPARED_ARCHIVE = "prepared_archive"
    AUTHORIZED_GIT_CHECKOUT = "authorized_git_checkout"


@dataclass(frozen=True, kw_only=True)
class RootScope(Record):
    """Opaque authorized root identity, never an absolute host path or Git URL."""

    id: str = "root"
    kind: InputKind = InputKind.LOCAL_DIRECTORY
    preparation_reference: str | None = None

    def validate(self) -> None:
        nonempty(self.id)
        require(self.kind == InputKind.LOCAL_DIRECTORY or bool(self.preparation_reference),
                "prepared archive/checkout requires authorization and preparation reference")


@dataclass(frozen=True, kw_only=True)
class ResourceBudget(Record):
    """Declared limits, not a claim that runtime enforcement is implemented."""

    max_file_bytes: int
    max_memory_bytes: int
    max_workers: int
    max_files: int | None = None
    max_graph_nodes: int | None = None
    max_graph_edges: int | None = None
    max_archive_bytes: int | None = None
    max_extracted_bytes: int | None = None
    max_archive_members: int | None = None

    def validate(self) -> None:
        for value in (self.max_file_bytes, self.max_memory_bytes, self.max_workers,
                      self.max_files, self.max_graph_nodes, self.max_graph_edges,
                      self.max_archive_bytes, self.max_extracted_bytes, self.max_archive_members):
            require(value is None or value > 0, "resource limits must be positive")


class Freshness(StrEnum):
    FRESH = "fresh"
    CACHED = "cached"
    MIXED = "mixed"


@dataclass(frozen=True, kw_only=True)
class CacheProvenance(Record):
    origin_scan_id: str
    entity_ids: tuple[str, ...]
    analysis_signature: str
    invalidation_basis: str

    def validate(self) -> None:
        for value in (self.origin_scan_id, self.analysis_signature, self.invalidation_basis):
            nonempty(value)
        require(bool(self.entity_ids), "cached entities must be explicit")


@dataclass(frozen=True, kw_only=True)
class ExecutionMetadata(Record):
    freshness: Freshness = Freshness.FRESH
    incremental: bool = False
    previous_scan_id: str | None = None
    cache_provenance: tuple[CacheProvenance, ...] = ()
    cancelled: bool = False
    limitations: tuple[str, ...] = ()

    def validate(self) -> None:
        require(not self.incremental or bool(self.previous_scan_id), "incremental scan requires baseline")
        require((self.freshness != Freshness.FRESH) == bool(self.cache_provenance),
                "cache reuse requires explicit non-fresh provenance")


@dataclass(frozen=True, kw_only=True)
class ProgressEvent(Record):
    phase: str
    completed_units: int
    total_units: int | None = None
    unit: str = "files"

    def validate(self) -> None:
        nonempty(self.phase)
        nonempty(self.unit)
        require(self.completed_units >= 0 and (self.total_units is None
                or self.total_units >= self.completed_units), "invalid progress counts")


@dataclass(frozen=True, kw_only=True)
class RemediationExportFilter(Record):
    """Future filtering/pagination; no report selection implementation yet."""

    severities: tuple[Severity, ...] = ()
    categories: tuple[Category, ...] = ()
    finding_ids: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    directories: tuple[str, ...] = ()
    service_ids: tuple[str, ...] = ()
    component_ids: tuple[str, ...] = ()
    root_ids: tuple[str, ...] = ()
    max_findings: int | None = None
    max_output_bytes: int | None = None

    def validate(self) -> None:
        for path in self.directories:
            relative_path(path)
        for values in (self.finding_ids, self.languages, self.service_ids, self.component_ids, self.root_ids):
            unique(values)
            for value in values:
                nonempty(value)
        for limit in (self.max_findings, self.max_output_bytes):
            require(limit is None or limit > 0, "export limits must be positive")
