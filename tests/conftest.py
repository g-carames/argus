"""Synthetic contracts only: fixtures never contain real source or credentials."""

from dataclasses import replace

import pytest

from argus.models.base import Capability, Category, Status
from argus.models.coverage import CapabilityCoverage, CategoryCoverage, Coverage, FileCoverage
from argus.models.scan import ScanResult, ScanScope
from argus.models.source import FileKind, SourceFile


def capability_records(completed=()):
    return tuple(CapabilityCoverage(capability=cap, status=(Status.COMPLETED if cap in completed
                                                           else Status.UNSUPPORTED),
                                    reason="Synthetic capability observation") for cap in Capability)


@pytest.fixture
def result():
    files = (
        SourceFile(id="f1", path="src/example.py", kind=FileKind.SOURCE, language="python", physical_lines=10),
        SourceFile(id="f2", path="src/example.rs", kind=FileKind.SOURCE, language="rust", physical_lines=20),
        SourceFile(id="f3", path="settings.yaml", kind=FileKind.CONFIGURATION, language="yaml"),
    )
    coverage = Coverage(files=(
        FileCoverage(file_id="f1", status=Status.COMPLETED, reason="Parsing only within requested scope",
                     capabilities=capability_records((Capability.PARSING,)), reviewed_lines=10),
        FileCoverage(file_id="f2", status=Status.UNSUPPORTED, reason="No Rust adapter installed",
                     capabilities=capability_records(), reviewed_lines=0),
        FileCoverage(file_id="f3", status=Status.UNSUPPORTED, reason="No YAML adapter installed",
                     capabilities=capability_records(), reviewed_lines=None),
    ), categories=tuple(CategoryCoverage(category=category, status=Status.UNSUPPORTED,
                                        reason="No analysis rules implemented") for category in Category))
    return ScanResult(scan_id="synthetic-scan", tool_version="0.1.0", scope=ScanScope(repository_id="synthetic",
                      requested_capabilities=(Capability.PARSING,)), status=Status.PARTIAL,
                      files=files, coverage=coverage, limitations=("Synthetic result; no scanner exists",))


@pytest.fixture
def mutate():
    return replace
