"""Source-free contextual assessment contracts; no literal source values."""
from dataclasses import dataclass
from enum import StrEnum
from .base import Record, require


class MitigationState(StrEnum):
    ESTABLISHED = 'mitigation_established_within_analyzed_scope'
    PARTIAL = 'partially_mitigated'
    UNVERIFIED = 'safeguard_observed_applicability_unverified'
    NONE = 'no_applicable_safeguard_detected'
    UNSUPPORTED = 'safeguard_analysis_unsupported'
    INCOMPLETE = 'safeguard_analysis_incomplete'
    UNDETERMINED = 'undetermined'


@dataclass(frozen=True, kw_only=True)
class Safeguard(Record):
    kind: str
    evidence_ids: tuple[str, ...]
    applicability: MitigationState
    reason: str

    def validate(self):
        require(bool(self.evidence_ids), 'safeguard requires evidence')


@dataclass(frozen=True, kw_only=True)
class Assessment(Record):
    initial_pattern: str
    mitigation_state: MitigationState
    supporting_evidence_ids: tuple[str, ...] = ()
    contradictory_evidence_ids: tuple[str, ...] = ()
    safeguards: tuple[Safeguard, ...] = ()
    call_path_relationship_ids: tuple[str, ...] = ()
    unresolved_relationship_ids: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    remaining_risk: str = 'Static observation does not establish exploitability or operational impact.'
    limitations: tuple[str, ...] = ()
    severity_adjustment: str | None = None

    def validate(self):
        require(bool(self.initial_pattern.strip()), 'initial pattern required')
        require(self.severity_adjustment is None or
                (self.mitigation_state == MitigationState.ESTABLISHED and bool(self.contradictory_evidence_ids)),
                'severity adjustment requires established mitigation and evidence')


class SemanticCertainty(StrEnum):
    OBSERVED = 'directly_observed'
    ESTABLISHED = 'statically_established'
    POSSIBLE = 'possible_inference'
    UNKNOWN = 'unknown_or_unresolved'


class TimeoutSettingState(StrEnum):
    EXPLICIT = 'explicit'
    DEFAULT = 'sdk_default'
    DISABLED = 'disabled'
    PARTIAL = 'partial'
    INVALID = 'invalid'
    NO_DEFAULT = 'library_no_default'
    UNKNOWN = 'unknown'


class ObservationKind(StrEnum):
    OPERATION = 'operation_binding'
    BOUND = 'collection_bound'
    ARGUMENT = 'argument_constraint'
    RETURN = 'return_bound'
    TIMEOUT = 'timeout_setting'
    SQL = 'sql_construction'
    AUTHENTICATION = 'authentication_registration'
    INVALIDATION = 'safeguard_invalidation'
    CALL = 'call_path'


@dataclass(frozen=True, kw_only=True)
class SemanticObservation(Record):
    id: str
    kind: ObservationKind
    certainty: SemanticCertainty
    file_id: str
    scope_id: str
    evidence_ids: tuple[str, ...]
    conclusion: str
    operation_id: str | None = None
    timeout_state: TimeoutSettingState | None = None
    context_lines: tuple[int, ...] = ()
    upper_bound: int | None = None
    assumptions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    relationship_ids: tuple[str, ...] = ()
    contract_version: str = '1.0.0'

    def validate(self):
        require(bool(self.id and self.file_id and self.scope_id and self.conclusion), 'observation identity and conclusion required')
        require(bool(self.evidence_ids), 'observation requires evidence')
        require(self.upper_bound is None or self.upper_bound>=0, 'negative bound')
        require(self.contract_version == '1.0.0', 'unsupported observation version')
