"""Source-free contextual assessment contracts; no literal source values."""
from dataclasses import dataclass
from enum import StrEnum
from .base import Record, require
from .source import SourceLocation


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
    bound_supported: bool = True
    lower_bound: int | None = None
    finite: bool = False
    operation_upper_bound: int | None = None
    iteration_upper_bound: int | None = None
    conditional_execution: bool = False
    observation_scope: str = 'effective_invocation'
    reachability: str = 'potential'
    constrained_value_id: str | None = None
    constraint_applicability: str = 'unverified'
    constraint_locations: tuple[SourceLocation, ...] = ()
    contract_version: str = '1.2.0'

    def validate(self):
        require(bool(self.id and self.file_id and self.scope_id and self.conclusion), 'observation identity and conclusion required')
        require(bool(self.evidence_ids), 'observation requires evidence')
        require(self.upper_bound is None or self.upper_bound>=0, 'negative bound')
        require(self.constraint_applicability in ('all_reaching_states','some_reaching_states','unverified'), 'invalid predicate applicability')
        require(self.observation_scope in ('function_body','effective_invocation','scope_gap','projection_summary'), 'invalid observation scope')
        require(self.reachability in ('potential','abstract_reachable','unreachable'), 'invalid reachability')
        require(self.operation_upper_bound is None or self.operation_upper_bound>=0, 'invalid operation bound')
        require(self.lower_bound is None or self.lower_bound>=0, 'invalid lower bound')
        require(self.fact_state in ('known','possible','unknown','incomplete'), 'invalid fact state')
        require(set(self.exit_channels)<= {'normal_fallthrough','returned','raised','unreachable','unsupported_control'}, 'invalid exit channel')
        require(self.argument_position is None or self.argument_position>=0, 'invalid argument position')
        require(self.contract_version == '1.2.0', 'unsupported observation version')


@dataclass(frozen=True, kw_only=True)
class SemanticFileAnalysis(Record):
    file_id: str
    worklist_steps: int = 0
    widenings: int = 0
    reachable_blocks: int = 0
    cfg_blocks: int = 0
    prepared_cfg_nodes: int = 0
    contexts: int = 0
    transfer_steps: int = 0
    requested_observations: int = 0
    emitted_observations: int = 0
    omitted_observations: int = 0
    consolidated_gap_occurrences: int = 0
    omitted_kinds: tuple[str, ...] = ()
    omitted_scope_ids: tuple[str, ...] = ()
    omitted_context_ids: tuple[str, ...] = ()
    omitted_locations: tuple[SourceLocation, ...] = ()

    def validate(self):
        require(all(v>=0 for v in (self.worklist_steps,self.widenings,self.reachable_blocks,self.cfg_blocks,self.prepared_cfg_nodes,self.contexts,
            self.transfer_steps,self.requested_observations,self.emitted_observations,self.omitted_observations,self.consolidated_gap_occurrences)), 'invalid semantic accounting')
