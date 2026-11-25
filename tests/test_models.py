from dataclasses import FrozenInstanceError, replace
from math import inf, nan

import pytest

from argus.models.analysis import (
    ComparisonStatus, Finding, FindingComparison, Graph, GraphNode, Metric,
    Relationship, RelationshipKind, RemediationStatus, Resolution,
    ResourceImpact,
)
from argus.models.base import Capability, Category, Confidence, Provenance, Severity, Status
from argus.models.coverage import CapabilityCoverage
from argus.models.credentials import (
    Assurance, CredentialExposure, CredentialPolicy, ExposureContext, ExposureState,
    Presence, ProtectedFingerprint, RemediationAction, RemediationEvent,
)
from argus.models.scan import DISCLAIMER
from argus.models.source import Evidence, FileKind, Module, SourceFile, SourceLocation, Symbol


@pytest.mark.parametrize("path", ["/tmp/a.py", "../a.py", "a/../b.py", "C:/a.py", "a\\b.py",
                                  "", ".", "a//b.py", "./a.py", "a\nb.py"])
def test_invalid_relative_paths(path):
    with pytest.raises(ValueError):
        SourceFile(id="f", path=path, kind=FileKind.SOURCE)


@pytest.mark.parametrize("updates", [{"start_line": 0}, {"start_column": -1},
                                      {"start_line": True}, {"end_line": 1},
                                      {"end_line": 1, "end_column": 1},
                                      {"end_line": 2, "end_column": 0}])
def test_location_validation(updates):
    with pytest.raises(ValueError):
        SourceLocation(**({"path": "a.py", "start_line": 1, "start_column": 2} | updates))


def test_unicode_location_and_immutable_source():
    location = SourceLocation(path="src/é.py", start_line=1, start_column=1, end_line=1, end_column=2)
    assert location.end_column == 2
    with pytest.raises(FrozenInstanceError):
        location.path = "changed.py"


@pytest.mark.parametrize("updates", [{"physical_lines": -1}, {"physical_lines": True},
                                      {"kind": "source"}, {"id": " "}])
def test_source_types(updates):
    with pytest.raises(ValueError):
        SourceFile(**({"id": "f", "path": "a.py", "kind": FileKind.SOURCE} | updates))


def relationship(**updates):
    return Relationship(**(dict(id="r", source_id="n1", kind=RelationshipKind.IMPORT, language="python",
                                provenance=Provenance.OBSERVED, confidence=Confidence.HIGH,
                                resolution=Resolution.UNRESOLVED, target_reference="package",
                                evidence_ids=("e",)) | updates))


def test_unresolved_relationship_does_not_invent_node():
    edge = relationship()
    graph = Graph(nodes=(GraphNode(id="n1", kind="module", label="module"),), relationships=(edge,))
    assert graph.relationships[0].target_id is None
    with pytest.raises(ValueError):
        relationship(target_id="n2")
    with pytest.raises(ValueError):
        relationship(resolution=Resolution.RESOLVED)


@pytest.mark.parametrize("kind", list(RelationshipKind))
def test_future_relationship_kinds(kind):
    assert relationship(kind=kind, extension_kind="argus.custom" if kind == RelationshipKind.EXTENSION else None).kind == kind


def test_cost_risk_has_multiple_categories_without_duplicating_finding():
    with pytest.raises(ValueError):
        replace(finding(), additional_categories=(Category.COST,))
    impact = ResourceImpact(consumption_mechanism="Repeated model calls in a loop",
                            potential_financial_consequences="Usage charges could increase with iteration count",
                            limitations=("Static analysis does not measure operating expenses",))
    updated = replace(finding(), additional_categories=(Category.AI, Category.COST), resource_impact=impact)
    assert updated.id == finding().id
    assert updated.resource_impact.basis == "potential_static_exposure"
    with pytest.raises(ValueError):
        replace(updated, additional_categories=(Category.ARCHITECTURE,))
    with pytest.raises(ValueError):
        replace(impact, basis="measured_loss")


def test_graph_rejects_missing_endpoints_and_duplicates():
    with pytest.raises(ValueError):
        Graph(relationships=(relationship(),))
    node = GraphNode(id="n", kind="module", label="module")
    with pytest.raises(ValueError):
        Graph(nodes=(node, node))
    with pytest.raises(ValueError):
        replace(node, layer="application")


@pytest.mark.parametrize("value", [nan, inf, -inf, True])
def test_metric_rejects_nonfinite_or_boolean(value):
    with pytest.raises(ValueError):
        Metric(name="centrality", definition="defined metric", scope_id="n", projection="imports",
               algorithm_version="future", value=value)


def test_unknown_metric_is_not_zero():
    metric = Metric(name="centrality", definition="defined metric", scope_id="n", projection="imports",
                    algorithm_version="future", unavailable_reason="Not computed")
    assert metric.value is None
    with pytest.raises(ValueError):
        replace(metric, unavailable_reason=None)
    assert replace(metric, value=0.0, unavailable_reason=None).value == 0


def finding():
    return Finding(id="stable-finding", rule_id="ARGUS.ARCH.001", rule_version="1", category=Category.ARCHITECTURE,
                   severity=Severity.MEDIUM, confidence=Confidence.HIGH, provenance=Provenance.OBSERVED,
                   title="Synthetic finding", explanation="Synthetic structural observation",
                   remediation="Review dependencies", evidence_ids=("e",),
                   corrective_actions=("Review dependency direction",),
                   acceptance_criteria=("Relevant dependency relationship is reviewed",))


def test_remediation_requires_actions_criteria_and_evidence():
    assert finding().remediation_status == RemediationStatus.OPEN
    for updates in ({"corrective_actions": ()}, {"acceptance_criteria": ()}, {"evidence_ids": ()},
                    {"remediation_status": RemediationStatus.VERIFIED}):
        with pytest.raises(ValueError):
            replace(finding(), **updates)


@pytest.mark.parametrize("status", [Status.DISABLED, Status.UNSUPPORTED, Status.EXCLUDED,
                                    Status.PARTIAL, Status.FAILED, Status.UNCLASSIFIED])
def test_coverage_loss_never_means_resolved(status):
    base = dict(stable_finding_id="f", previous_scan_id="old", current_scan_id="new", reason="Synthetic comparison",
                current_file_status=Status.COMPLETED, current_rule_status=Status.COMPLETED, evidence_ids=("e",))
    for field in ("current_file_status", "current_rule_status"):
        with pytest.raises(ValueError):
            FindingComparison(**(base | {field: status}), status=ComparisonStatus.RESOLVED)
        assert FindingComparison(**(base | {field: status}), status=ComparisonStatus.UNVERIFIABLE)
    assert FindingComparison(**base, status=ComparisonStatus.RESOLVED)


def credential():
    return CredentialExposure(id="c", credential_type="synthetic", fingerprint=ProtectedFingerprint(
        key_id="local-key", digest="a" * 64), context=ExposureContext.POTENTIAL_EXPOSURE,
        presence=Presence.ABSENT_IN_SCOPE, presence_scope="current tree only", evidence_ids=("e",))


@pytest.mark.parametrize("action", [RemediationAction.REMOVAL, RemediationAction.REPLACEMENT, RemediationAction.ROTATION])
def test_credential_removal_is_not_revocation(action):
    event = RemediationEvent(id="event", action=action, assurance=Assurance.USER_ATTESTED,
                             recorded_at="2026-11-25T12:00:00+00:00", scope="synthetic", evidence_ids=("e",))
    exposure = replace(credential(), events=(event,))
    assert exposure.state == ExposureState.UNRESOLVED
    with pytest.raises(ValueError):
        replace(exposure, state=ExposureState.RESOLVED, resolution_evidence_ids=("e",))


def test_fingerprint_masking_and_safe_errors():
    synthetic_secret = "SYNTHETIC-DO-NOT-AUTHENTICATE-123456"
    with pytest.raises(ValueError) as error:
        replace(credential(), masked_identifier=synthetic_secret)
    assert synthetic_secret not in str(error.value)
    with pytest.raises(ValueError) as error:
        ProtectedFingerprint(key_id="local", digest=synthetic_secret)
    assert synthetic_secret not in str(error.value)
    with pytest.raises(ValueError):
        CredentialPolicy(authorized_ignored_paths=("../secrets.env",))


def test_scan_reference_validation(result):
    with pytest.raises(ValueError):
        replace(result, modules=(Module(id="m", file_id="missing", qualified_name="sample", language="python"),))
    with pytest.raises(ValueError):
        replace(result, findings=(finding(),))
    with pytest.raises(ValueError):
        replace(result, disclaimer="Safe software")
    assert result.disclaimer == DISCLAIMER


def test_valid_connected_source_models(result):
    location = SourceLocation(path=result.files[0].path, start_line=1, start_column=1)
    module = Module(id="m", file_id="f1", qualified_name="sample", language="python")
    symbol = Symbol(id="s", module_id="m", name="function", kind="function", location=location)
    evidence = Evidence(id="e", observation="Static relationship", producer="synthetic", producer_version="1",
                        provenance=Provenance.OBSERVED, confidence=Confidence.HIGH, locations=(location,))
    rule_coverage = CapabilityCoverage(capability=Capability.ARCHITECTURE, rule_id=finding().rule_id,
        status=Status.COMPLETED, reason="Synthetic rule evaluated", eligible_units=1, evaluated_units=1)
    categories = tuple(replace(item, status=Status.PARTIAL, rule_ids=(finding().rule_id,))
                       if item.category == Category.ARCHITECTURE else item for item in result.coverage.categories)
    coverage = replace(result.coverage, rules=(rule_coverage,), categories=categories)
    updated = replace(result, coverage=coverage, modules=(module,), symbols=(symbol,),
                      evidence=(evidence,), findings=(finding(),))
    assert updated.findings[0].id == "stable-finding"
