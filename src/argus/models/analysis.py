"""Architectural entities, relationships, findings, and metrics."""

from dataclasses import dataclass
from enum import StrEnum

from .base import Category, Confidence, Provenance, Record, Severity, Status, nonempty, require, unique
from .source import SourceLocation
from .semantic import Assessment


class RelationshipKind(StrEnum):
    IMPORT = "module_import"
    CALL = "invocation"
    HTTP = "http_request"
    DATABASE = "database_interaction"
    SERVICE = "external_service"
    LLM = "llm_provider"
    AGENT_TOOL = "agent_tool"
    CONFIGURATION = "configuration"
    INFRASTRUCTURE = "infrastructure"
    CONTAINS = "contains"
    EXTENSION = "extension"


class Resolution(StrEnum):
    RESOLVED = "resolved"
    EXTERNAL = "external"
    UNRESOLVED = "unresolved"
    AMBIGUOUS = "ambiguous"


class RemediationStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    USER_ATTESTED = "user_attested"
    VERIFIED = "verified"
    UNVERIFIABLE = "unverifiable"


class ComparisonStatus(StrEnum):
    NEW = "new"
    PERSISTENT = "persistent"
    RESOLVED = "resolved"
    UNVERIFIABLE = "unverifiable"


@dataclass(frozen=True, kw_only=True)
class FindingComparison(Record):
    """Comparison assertion, not a comparison engine. Coverage loss is never resolution."""

    stable_finding_id: str
    previous_scan_id: str
    current_scan_id: str
    status: ComparisonStatus
    reason: str
    current_file_status: Status
    current_rule_status: Status
    evidence_ids: tuple[str, ...] = ()

    def validate(self) -> None:
        for value in (self.stable_finding_id, self.previous_scan_id, self.current_scan_id, self.reason):
            nonempty(value)
        require(self.status != ComparisonStatus.RESOLVED
                or (self.current_file_status == Status.COMPLETED
                    and self.current_rule_status == Status.COMPLETED and bool(self.evidence_ids)),
                "resolution requires reviewed file, completed rule, and evidence")


@dataclass(frozen=True, kw_only=True)
class GraphNode(Record):
    id: str
    kind: str
    label: str
    language: str | None = None
    file_id: str | None = None
    layer: str | None = None
    evidence_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    parent_id: str | None = None
    grouping_provenance: Provenance | None = None

    def validate(self) -> None:
        for value in (self.id, self.kind, self.label):
            nonempty(value)
        require(self.layer is None or bool(self.evidence_ids), "layer requires evidence")
        require(self.parent_id is None or (self.parent_id != self.id and self.grouping_provenance is not None
                                           and bool(self.evidence_ids)),
                "parent grouping requires provenance and evidence")


@dataclass(frozen=True, kw_only=True)
class Relationship(Record):
    id: str
    source_id: str
    kind: RelationshipKind
    language: str
    provenance: Provenance
    confidence: Confidence
    resolution: Resolution
    evidence_ids: tuple[str, ...]
    target_id: str | None = None
    target_reference: str | None = None
    limitations: tuple[str, ...] = ()
    dependency_phase: str | None = None
    extension_kind: str | None = None
    callsite_id: str | None = None
    context_ids: tuple[str, ...] = ()
    candidate_target_ids: tuple[str, ...] = ()

    def validate(self) -> None:
        for value in (self.id, self.source_id, self.language):
            nonempty(value)
        require(bool(self.evidence_ids), "relationship requires evidence")
        require(self.target_id is not None or bool(self.target_reference), "target reference required")
        require(self.resolution != Resolution.RESOLVED or self.target_id is not None,
                "resolved relationship requires target")
        require(self.resolution not in (Resolution.UNRESOLVED, Resolution.AMBIGUOUS)
                or self.target_id is None, "unresolved relationship cannot invent target")
        unique(self.candidate_target_ids)
        require(not self.candidate_target_ids or self.resolution!=Resolution.RESOLVED or self.target_id in self.candidate_target_ids, 'resolved target missing from candidates')
        require((self.kind == RelationshipKind.EXTENSION) == bool(self.extension_kind),
                "extension relationships require a namespaced kind")


@dataclass(frozen=True, kw_only=True)
class ResourceImpact(Record):
    """Potential static cost exposure only; no measured expenses or guaranteed savings."""

    consumption_mechanism: str
    potential_financial_consequences: str
    assumptions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    basis: str = "potential_static_exposure"

    def validate(self) -> None:
        nonempty(self.consumption_mechanism)
        nonempty(self.potential_financial_consequences)
        require(self.basis == "potential_static_exposure", "static risk is not measured operating expense")


@dataclass(frozen=True, kw_only=True)
class Finding(Record):
    id: str
    rule_id: str
    rule_version: str
    category: Category
    severity: Severity
    confidence: Confidence
    provenance: Provenance
    title: str
    explanation: str
    remediation: str
    evidence_ids: tuple[str, ...]
    corrective_actions: tuple[str, ...]
    acceptance_criteria: tuple[str, ...]
    affected_ids: tuple[str, ...] = ()
    locations: tuple[SourceLocation, ...] = ()
    limitations: tuple[str, ...] = ()
    relationship_ids: tuple[str, ...] = ()
    remediation_status: RemediationStatus = RemediationStatus.OPEN
    remediation_evidence_ids: tuple[str, ...] = ()
    additional_categories: tuple[Category, ...] = ()
    resource_impact: ResourceImpact | None = None
    assessment: Assessment | None = None

    def validate(self) -> None:
        for value in (self.id, self.rule_id, self.rule_version, self.title,
                      self.explanation, self.remediation):
            nonempty(value)
        require(bool(self.evidence_ids), "finding requires evidence")
        require(bool(self.corrective_actions) and bool(self.acceptance_criteria),
                "corrective actions and acceptance criteria required")
        for value in self.corrective_actions + self.acceptance_criteria:
            nonempty(value)
        require(self.remediation_status not in (RemediationStatus.USER_ATTESTED, RemediationStatus.VERIFIED)
                or bool(self.remediation_evidence_ids), "remediation assertion requires evidence")
        unique((self.category.value,) + tuple(item.value for item in self.additional_categories))
        require(Category.COST not in (self.category,) + self.additional_categories
                or self.resource_impact is not None, "cost findings require resource mechanism and consequences")


@dataclass(frozen=True, kw_only=True)
class Metric(Record):
    name: str
    definition: str
    scope_id: str
    projection: str
    algorithm_version: str
    value: float | None = None
    unavailable_reason: str | None = None
    limitations: tuple[str, ...] = ()

    def validate(self) -> None:
        for value in (self.name, self.definition, self.scope_id, self.projection, self.algorithm_version):
            nonempty(value)
        require((self.value is None) == bool(self.unavailable_reason),
                "unknown metric requires reason; available metric cannot have unavailable reason")


@dataclass(frozen=True, kw_only=True)
class Cycle(Record):
    node_ids: tuple[str, ...]
    relationship_ids: tuple[str, ...]
    projection: str

    def validate(self) -> None:
        require(bool(self.node_ids) and bool(self.relationship_ids), "cycle members required")
        nonempty(self.projection)


@dataclass(frozen=True, kw_only=True)
class RiskSummary(Record):
    """Future hierarchical rollup references, never an aggregate safety score."""

    node_id: str
    finding_ids: tuple[str, ...]
    coverage_status: Status
    includes_descendants: bool = False
    limitations: tuple[str, ...] = ()

    def validate(self) -> None:
        nonempty(self.node_id)
        unique(self.finding_ids)


@dataclass(frozen=True, kw_only=True)
class Graph(Record):
    nodes: tuple[GraphNode, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    cycles: tuple[Cycle, ...] = ()
    metrics: tuple[Metric, ...] = ()
    risk_summaries: tuple[RiskSummary, ...] = ()
    limitations: tuple[str, ...] = ()

    def validate(self) -> None:
        node_ids = tuple(node.id for node in self.nodes)
        unique(node_ids)
        ids = set(node_ids)
        edge_ids = tuple(edge.id for edge in self.relationships)
        unique(edge_ids)
        for node in self.nodes:
            require(node.parent_id is None or node.parent_id in ids, "dangling parent node")
        require(all(summary.node_id in ids for summary in self.risk_summaries), "dangling risk summary node")
        for edge in self.relationships:
            require(set(edge.candidate_target_ids)<=set(ids), 'dangling candidate target')
            require(edge.source_id in ids and (edge.target_id is None or edge.target_id in ids),
                    "dangling graph endpoint")
        for cycle in self.cycles:
            require(set(cycle.node_ids) <= set(ids) and set(cycle.relationship_ids) <= set(edge_ids),
                    "dangling cycle reference")
