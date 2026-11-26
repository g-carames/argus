"""Source-free contextual assessment contracts; no literal source values."""
from dataclasses import dataclass
from enum import StrEnum
from .base import Record, require


class MitigationState(StrEnum):
    ESTABLISHED = 'mitigation_established_within_analyzed_scope'
    PARTIAL = 'partially_mitigated'
    UNVERIFIED = 'safeguard_observed_applicability_unverified'
    NONE = 'no_applicable_safeguard_detected'
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
