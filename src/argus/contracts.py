"""Argus-owned boundaries. These protocols implement no analysis capabilities.

Only trusted installed components may implement these interfaces. Parser objects
stay adapter-local; supplied content must never be executed or imported.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from .models.analysis import Cycle, Finding, Graph, Metric, Relationship
from .models.base import Capability, Category, Record, nonempty, require, unique
from .models.coverage import CapabilityCoverage
from .models.credentials import CredentialExposure, ProtectedFingerprint, RemediationEvent
from .models.scan import Diagnostic, ScanResult
from .models.source import Evidence, Module, SourceFile, Symbol
from .models.execution import ProgressEvent


@dataclass(frozen=True, kw_only=True)
class CapabilityDeclaration(Record):
    capability: Capability
    available: bool
    limitations: tuple[str, ...]
    reason: str

    def validate(self) -> None:
        nonempty(self.reason)


@dataclass(frozen=True, kw_only=True)
class AdapterDescriptor(Record):
    id: str
    version: str
    language: str
    capabilities: tuple[CapabilityDeclaration, ...]
    parser_id: str
    parser_version: str
    grammar_version: str | None = None

    def validate(self) -> None:
        for value in (self.id, self.version, self.language, self.parser_id, self.parser_version):
            nonempty(value)
        unique(tuple(item.capability.value for item in self.capabilities))
        require({item.capability for item in self.capabilities} == set(Capability),
                "declare every capability independently")


class ParsedUnit(Protocol):
    """Opaque parser-owned document: AST/CST never enters shared results."""

    @property
    def file_id(self) -> str: ...

    @property
    def diagnostics(self) -> tuple[Diagnostic, ...]: ...


@dataclass(frozen=True, kw_only=True)
class Extraction(Record):
    modules: tuple[Module, ...]
    symbols: tuple[Symbol, ...]
    relationships: tuple[Relationship, ...]
    evidence: tuple[Evidence, ...]
    coverage: tuple[CapabilityCoverage, ...]
    diagnostics: tuple[Diagnostic, ...] = ()


@dataclass(frozen=True, kw_only=True)
class ResolutionResult(Record):
    relationships: tuple[Relationship, ...]
    evidence: tuple[Evidence, ...]
    coverage: tuple[CapabilityCoverage, ...]
    diagnostics: tuple[Diagnostic, ...] = ()


@runtime_checkable
class SyntaxParser(Protocol):
    """Reusable parser provider; locally prepared grammars only, no lazy downloads."""
    def parse(self, file: SourceFile, content: bytes) -> ParsedUnit: ...


@runtime_checkable
class SemanticExtractor(Protocol):
    def extract(self, file: SourceFile, parsed: ParsedUnit) -> Extraction: ...


@runtime_checkable
class DependencyResolver(Protocol):
    def resolve(self, extraction: Extraction, modules: tuple[Module, ...]) -> ResolutionResult: ...


@runtime_checkable
class LanguageAdapter(SyntaxParser, SemanticExtractor, DependencyResolver, Protocol):
    @property
    def descriptor(self) -> AdapterDescriptor: ...


@dataclass(frozen=True, kw_only=True)
class RuleDescriptor(Record):
    id: str
    version: str
    category: Category
    required_capabilities: tuple[Capability, ...]
    limitations: tuple[str, ...]

    def validate(self) -> None:
        nonempty(self.id)
        nonempty(self.version)
        unique(tuple(item.value for item in self.required_capabilities))


@dataclass(frozen=True, kw_only=True)
class RuleSettings(Record):
    """Small typed scalar settings; no executable configuration or arbitrary objects."""

    name: str
    value: str | int | float | bool

    def validate(self) -> None:
        nonempty(self.name)


@dataclass(frozen=True, kw_only=True)
class RuleResult(Record):
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]
    coverage: CapabilityCoverage
    diagnostics: tuple[Diagnostic, ...] = ()


@runtime_checkable
class AnalysisRule(Protocol):
    @property
    def descriptor(self) -> RuleDescriptor: ...

    def evaluate(self, context: ScanResult, settings: tuple[RuleSettings, ...]) -> RuleResult: ...


@runtime_checkable
class GraphBackend(Protocol):
    """Future NetworkX-backed implementation; no NetworkX types cross this boundary."""

    def strongly_connected_components(self, graph: Graph, projection: str) -> tuple[tuple[str, ...], ...]: ...

    def circular_dependencies(self, graph: Graph, projection: str) -> tuple[Cycle, ...]: ...

    def metrics(self, graph: Graph, names: tuple[str, ...], projection: str) -> tuple[Metric, ...]: ...

    def reachable(self, graph: Graph, node_id: str, direction: str, projection: str) -> tuple[str, ...]: ...


@runtime_checkable
class ReportWriter(Protocol):
    @property
    def format(self) -> "ReportFormat": ...

    def render(self, result: ScanResult) -> str: ...


class ReportFormat(StrEnum):
    JSON = "json"
    AGENT_MARKDOWN = "agent_markdown"
    INTERACTIVE_HTML = "interactive_html"


@runtime_checkable
class RemediationStore(Protocol):
    """Future local persistence must preserve unresolved exposures across scans."""

    def find(self, fingerprint: ProtectedFingerprint) -> tuple[CredentialExposure, ...]: ...

    def record_exposure(self, exposure: CredentialExposure) -> None: ...

    def append_event(self, exposure_id: str, event: RemediationEvent) -> None: ...


class ProgressSink(Protocol):
    def emit(self, event: ProgressEvent) -> None: ...


class CancellationToken(Protocol):
    @property
    def is_cancelled(self) -> bool: ...
