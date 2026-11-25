from dataclasses import replace
import json

import pytest

from argus.models.analysis import Graph, GraphNode, RiskSummary
from argus.models.base import Category, Provenance, Severity, Status
from argus.models.coverage import InventoryGap
from argus.models.execution import (
    CacheProvenance, ExecutionMetadata, Freshness, InputKind, ProgressEvent,
    RemediationExportFilter, ResourceBudget, RootScope,
)
from argus.reporting import JsonReportWriter


def test_multiroot_identity_and_scope(result):
    roots = (RootScope(), RootScope(id="service-b"))
    second = replace(result.files[1], path=result.files[0].path, root_id="service-b")
    updated = replace(result, scope=replace(result.scope, roots=roots),
                      files=(result.files[0], second, result.files[2]))
    assert updated.files[0].path == updated.files[1].path
    with pytest.raises(ValueError):
        replace(updated, scope=result.scope)
    with pytest.raises(ValueError):
        RootScope(kind=InputKind.PREPARED_ARCHIVE)


def test_budgets_and_progress_are_only_validated_contracts():
    assert ResourceBudget(max_file_bytes=1024, max_memory_bytes=1024 * 1024, max_workers=1)
    with pytest.raises(ValueError):
        ResourceBudget(max_file_bytes=0, max_memory_bytes=1024, max_workers=1)
    assert ProgressEvent(phase="inventory", completed_units=10).total_units is None
    with pytest.raises(ValueError):
        ProgressEvent(phase="inventory", completed_units=11, total_units=10)


def test_cache_cannot_masquerade_as_fresh():
    cache = CacheProvenance(origin_scan_id="old", entity_ids=("f1",), analysis_signature="signature",
                            invalidation_basis="Configuration, content, dependency and producer versions")
    with pytest.raises(ValueError):
        ExecutionMetadata(cache_provenance=(cache,))
    with pytest.raises(ValueError):
        ExecutionMetadata(freshness=Freshness.CACHED)
    with pytest.raises(ValueError):
        ExecutionMetadata(incremental=True)
    assert ExecutionMetadata(freshness=Freshness.MIXED, cache_provenance=(cache,),
                             incremental=True, previous_scan_id="old")


def test_cancellation_and_resource_gaps_are_reported(result):
    gap = InventoryGap(path="large-service", status=Status.EXCLUDED,
                       reason="Configured file limit reached", reason_code="resource_limit.max_files")
    updated = replace(result, execution=ExecutionMetadata(cancelled=True),
                      coverage=replace(result.coverage, inventory_gaps=(gap,)))
    data = json.loads(JsonReportWriter().render(updated))
    section = data["not_reviewed_portions_of_the_code"]
    assert section["execution"]["cancelled"] is True
    assert section["inventory_gaps"][0]["reason_code"] == "resource_limit.max_files"
    with pytest.raises(ValueError):
        replace(updated, status=Status.COMPLETED)


def test_hierarchy_and_rollup_provenance():
    system = GraphNode(id="system", kind="system", label="System")
    service = GraphNode(id="service", kind="service", label="Service", parent_id="system",
                        grouping_provenance=Provenance.INFERRED, evidence_ids=("e",))
    graph = Graph(nodes=(system, service), risk_summaries=(RiskSummary(node_id="system", finding_ids=(),
                  coverage_status=Status.PARTIAL, includes_descendants=True, limitations=("Unsupported children",)),))
    assert graph.nodes[1].grouping_provenance == Provenance.INFERRED
    with pytest.raises(ValueError):
        replace(service, grouping_provenance=None)
    with pytest.raises(ValueError):
        Graph(nodes=(service,))


def test_targeted_exports_have_no_selector_implementation():
    selected = RemediationExportFilter(severities=(Severity.HIGH,), categories=(Category.COST,),
        finding_ids=("finding",), languages=("typescript",), directories=("services/api",),
        service_ids=("service",), component_ids=("module",), max_findings=20, max_output_bytes=16000)
    assert selected.languages == ("typescript",)
    with pytest.raises(ValueError):
        replace(selected, directories=("../outside",))
    with pytest.raises(ValueError):
        replace(selected, max_output_bytes=0)
