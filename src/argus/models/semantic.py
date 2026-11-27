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
    ASSIGNMENT = 'assignment_fact'
    RECEIVER = 'receiver_resolution'
    DOMAIN = 'loop_domain'
    INCOMPLETE = 'incomplete_analysis'


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
    context_id: str | None = None
    callsite_id: str | None = None
    call_path_ids: tuple[str, ...] = ()
    formal_id: str | None = None
    actual_id: str | None = None
    origin_value_id: str | None = None
    result_id: str | None = None
    value_id: str | None = None
    argument_position: int | None = None
    binding_kind: str | None = None
    candidate_target_ids: tuple[str, ...] = ()
    fact_state: str = 'known'
    exit_channels: tuple[str, ...] = ()
    contract_version: str = '1.1.0'

    def validate(self):
        require(bool(self.id and self.file_id and self.scope_id and self.conclusion), 'observation identity and conclusion required')
        require(bool(self.evidence_ids), 'observation requires evidence')
        require(self.upper_bound is None or self.upper_bound>=0, 'negative bound')
        require(self.fact_state in ('known','possible','unknown','incomplete'), 'invalid fact state')
        require(set(self.exit_channels)<= {'normal_fallthrough','returned','raised','unreachable','unsupported_control'}, 'invalid exit channel')
        require(self.argument_position is None or self.argument_position>=0, 'invalid argument position')
        require(self.contract_version == '1.1.0', 'unsupported observation version')
