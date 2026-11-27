"""Future credential contracts; no detection, authentication, or storage implementation."""

from dataclasses import dataclass
from enum import StrEnum
import re

from .base import Record, nonempty, require, unique


class RemediationAction(StrEnum):
    REMOVAL = "removal"
    REPLACEMENT = "replacement"
    ROTATION = "rotation"
    REVOCATION = "revocation"


class Assurance(StrEnum):
    USER_ATTESTED = "user_attested"
    INDEPENDENTLY_VERIFIED = "independently_verified"


class Presence(StrEnum):
    PRESENT = "present"
    ABSENT_IN_SCOPE = "absent_in_scope"
    UNKNOWN = "unknown"


class ExposureState(StrEnum):
    UNRESOLVED = "unresolved"
    RESOLVED = "resolved"


class ExposureContext(StrEnum):
    LOCAL_STORAGE = "local_storage"
    POTENTIAL_EXPOSURE = "potential_exposure"
    OBSERVED_EXPOSURE = "observed_exposure"


@dataclass(frozen=True, kw_only=True)
class CredentialPolicy(Record):
    """Separate authorization/exclusions from general architectural discovery."""

    inspect_tracked_files: bool = True
    authorized_ignored_paths: tuple[str, ...] = ()
    inspect_accessible_history: bool = False
    exclusions: tuple[str, ...] = ()

    def validate(self) -> None:
        from .base import relative_path

        for path in self.authorized_ignored_paths:
            relative_path(path)


@dataclass(frozen=True, kw_only=True)
class ProtectedFingerprint(Record):
    key_id: str
    digest: str
    algorithm: str = "hmac-sha256"

    def validate(self) -> None:
        nonempty(self.key_id)
        require(self.algorithm == "hmac-sha256", "unsupported protected fingerprint algorithm")
        require(re.fullmatch(r"[0-9a-f]{64}", self.digest) is not None, "invalid protected fingerprint")


@dataclass(frozen=True, kw_only=True)
class RemediationEvent(Record):
    id: str
    action: RemediationAction
    assurance: Assurance
    recorded_at: str
    scope: str
    evidence_ids: tuple[str, ...]

    def validate(self) -> None:
        from datetime import datetime

        for value in (self.id, self.scope):
            nonempty(value)
        try:
            timestamp = datetime.fromisoformat(self.recorded_at)
        except ValueError:
            raise ValueError("invalid remediation timestamp") from None
        require(timestamp.tzinfo is not None, "timestamp requires timezone")
        require(bool(self.evidence_ids), "remediation requires evidence")


@dataclass(frozen=True, kw_only=True)
class CredentialExposure(Record):
    id: str
    credential_type: str
    fingerprint: ProtectedFingerprint
    context: ExposureContext
    presence: Presence
    presence_scope: str
    evidence_ids: tuple[str, ...]
    events: tuple[RemediationEvent, ...] = ()
    state: ExposureState = ExposureState.UNRESOLVED
    resolution_evidence_ids: tuple[str, ...] = ()
    masked_identifier: str = "[REDACTED]"

    def validate(self) -> None:
        for value in (self.id, self.credential_type, self.presence_scope):
            nonempty(value)
        require(self.masked_identifier == "[REDACTED]", "credential identifiers must be fully masked")
        require(bool(self.evidence_ids), "credential exposure requires evidence")
        unique(tuple(event.id for event in self.events))
        require(self.state != ExposureState.RESOLVED or bool(self.resolution_evidence_ids),
                "resolution requires explicit remediation evidence")
        require(self.state != ExposureState.RESOLVED
                or any(event.action == RemediationAction.REVOCATION for event in self.events),
                "removal or replacement alone cannot resolve prior exposure")


class CandidateClassification(StrEnum):
    RECOGNIZED = 'recognized_pattern'
    PLAUSIBLE = 'plausible_assignment'
    PLACEHOLDER = 'obvious_placeholder'
    UNCERTAIN = 'uncertain_candidate'


@dataclass(frozen=True, kw_only=True)
class CredentialCandidate(Record):
    """Classification only; no raw values, hashes or validity claims."""
    id: str
    file_id: str
    evidence_ids: tuple[str, ...]
    classification: CandidateClassification
    documentation_context: bool = False
    validity: str = 'unverified'

    def validate(self):
        require(bool(self.id and self.file_id and self.evidence_ids), 'candidate identity/evidence required')
        require(self.validity=='unverified','credential validity verification unavailable')
