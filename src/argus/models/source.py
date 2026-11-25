"""Language-neutral source identities and evidence; no source text is retained."""

from dataclasses import dataclass
from enum import StrEnum

from .base import Confidence, Provenance, Record, nonempty, relative_path, require


class FileKind(StrEnum):
    SOURCE = "source"
    CONFIGURATION = "configuration"
    OTHER = "other"
    UNKNOWN = "unknown"


@dataclass(frozen=True, kw_only=True)
class SourceLocation(Record):
    path: str
    start_line: int
    start_column: int
    end_line: int | None = None
    end_column: int | None = None
    root_id: str = "root"

    def validate(self) -> None:
        relative_path(self.path)
        nonempty(self.root_id)
        require(self.start_line > 0 and self.start_column > 0, "location must be positive")
        require((self.end_line is None) == (self.end_column is None), "end requires both coordinates")
        if self.end_line is not None:
            require(self.end_line > 0 and self.end_column > 0
                    and (self.end_line, self.end_column) >= (self.start_line, self.start_column),
                    "invalid end location")


@dataclass(frozen=True, kw_only=True)
class SourceFile(Record):
    id: str
    path: str
    kind: FileKind
    language: str | None = None
    physical_lines: int | None = None
    root_id: str = "root"

    def validate(self) -> None:
        nonempty(self.id)
        nonempty(self.root_id)
        relative_path(self.path)
        if self.language is not None:
            nonempty(self.language)
        require(self.physical_lines is None or self.physical_lines >= 0, "negative line count")


@dataclass(frozen=True, kw_only=True)
class Module(Record):
    id: str
    file_id: str
    qualified_name: str
    language: str

    def validate(self) -> None:
        for value in (self.id, self.file_id, self.qualified_name, self.language):
            nonempty(value)


@dataclass(frozen=True, kw_only=True)
class Symbol(Record):
    id: str
    module_id: str
    name: str
    kind: str
    location: SourceLocation
    parent_id: str | None = None

    def validate(self) -> None:
        for value in (self.id, self.module_id, self.name, self.kind):
            nonempty(value)


@dataclass(frozen=True, kw_only=True)
class Evidence(Record):
    id: str
    observation: str
    producer: str
    producer_version: str
    provenance: Provenance
    confidence: Confidence
    locations: tuple[SourceLocation, ...] = ()
    limitations: tuple[str, ...] = ()

    def validate(self) -> None:
        for value in (self.id, self.observation, self.producer, self.producer_version):
            nonempty(value)
