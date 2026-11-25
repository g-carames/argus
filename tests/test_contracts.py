from dataclasses import replace
import inspect

import pytest

from argus.contracts import (
    AdapterDescriptor, AnalysisRule, CapabilityDeclaration, Extraction, GraphBackend,
    LanguageAdapter, RemediationStore, ReportFormat, ReportWriter, RuleDescriptor,
    RuleResult, RuleSettings,
)
from argus.models.base import Capability, Category, Status
from argus.models.coverage import CapabilityCoverage
from argus.reporting import JsonReportWriter


def descriptor():
    return AdapterDescriptor(id="synthetic-parser", version="1", language="typescript", parser_id="synthetic",
                             parser_version="1", grammar_version="1", capabilities=tuple(
                                 CapabilityDeclaration(capability=cap, available=cap == Capability.PARSING,
                                                       reason="Synthetic declaration", limitations=())
                                 for cap in Capability))


def test_adapter_capabilities_are_independent_and_complete():
    declaration = descriptor()
    assert next(item for item in declaration.capabilities if item.capability == Capability.PARSING).available
    assert not next(item for item in declaration.capabilities if item.capability == Capability.SECURITY).available
    with pytest.raises(ValueError):
        replace(declaration, capabilities=declaration.capabilities[:1])


def test_protocol_can_be_implemented_without_parser_dependency(result):
    class SyntheticAdapter:
        descriptor = descriptor()

        def parse(self, file, content):
            # A contract test double, not a language parser.
            return type("Parsed", (), {"file_id": file.id, "diagnostics": ()})()

        def extract(self, file, parsed):
            return Extraction(modules=(), symbols=(), relationships=(), evidence=(), coverage=())

        def resolve(self, extraction, modules):
            from argus.contracts import ResolutionResult
            return ResolutionResult(relationships=(), evidence=(), coverage=())

    adapter = SyntheticAdapter()
    assert isinstance(adapter, LanguageAdapter)
    parsed = adapter.parse(result.files[0], b"synthetic")
    extraction = adapter.extract(result.files[0], parsed)
    assert adapter.resolve(extraction, ()).relationships == ()


def test_rule_settings_and_unavailable_rule_result(result):
    class SyntheticRule:
        descriptor = RuleDescriptor(id="synthetic", version="1", category=Category.SECURITY,
                                    required_capabilities=(Capability.SYMBOLS,), limitations=())

        def evaluate(self, context, settings):
            return RuleResult(findings=(), evidence=(), coverage=CapabilityCoverage(
                capability=Capability.SECURITY, rule_id="synthetic", status=Status.UNSUPPORTED,
                reason="Required symbols unavailable", eligible_units=None, evaluated_units=0))

    rule = SyntheticRule()
    assert isinstance(rule, AnalysisRule)
    assert rule.evaluate(result, (RuleSettings(name="threshold", value=2),)).coverage.status == Status.UNSUPPORTED
    with pytest.raises(ValueError):
        RuleSettings(name="threshold", value={"execute": "anything"})


def test_reporting_and_future_protocol_boundaries():
    assert isinstance(JsonReportWriter(), ReportWriter)
    assert JsonReportWriter().format == ReportFormat.JSON
    assert {item.value for item in ReportFormat} == {"json", "agent_markdown", "interactive_html"}
    # No runtime implementations or third-party graph objects are exposed.
    for protocol in (GraphBackend, RemediationStore):
        assert not isinstance(object(), protocol)
        assert "networkx" not in str(inspect.get_annotations(protocol))
