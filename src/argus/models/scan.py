"""Versioned scan result contract, deliberately independent of parsers and graphs libraries."""

from dataclasses import dataclass
from enum import StrEnum

from .analysis import Finding, Graph
from .base import Capability, Category, Record, Status, nonempty, require, unique
from .coverage import Coverage
from .credentials import CredentialExposure, CredentialCandidate
from .execution import ExecutionMetadata, ResourceBudget, RootScope
from .semantic import SemanticObservation, SemanticFileAnalysis
from .source import Evidence, Module, SourceFile, SourceLocation, Symbol

SCHEMA_VERSION = "1.6.0"
DISCLAIMER = (
    "Argus is a software architecture analysis and decision-support tool. It does not certify or "
    "guarantee software safety, security, correctness, reliability, regulatory compliance, or AI "
    "alignment. Findings are derived from static analysis, observable source-code relationships, "
    "configurable rules, and heuristic indicators. Analysis may produce false positives, false "
    "negatives, incomplete results, or inaccurate architectural inferences. The absence of findings "
    "does not establish the absence of vulnerabilities, particularly where portions of the codebase "
    "have not been reviewed. Argus is intended to complement, not replace, professional security "
    "assessments, runtime analysis, comprehensive software testing, code review, and qualified human "
    "engineering judgment."
)


@dataclass(frozen=True, kw_only=True)
class ScanScope(Record):
    repository_id: str
    requested_capabilities: tuple[Capability, ...]
    exclusions: tuple[str, ...] = ()
    respect_repository_gitignore: bool = True
    follow_symlinks: bool = False
    roots: tuple[RootScope, ...] = (RootScope(),)
    resource_budget: ResourceBudget | None = None

    def validate(self) -> None:
        nonempty(self.repository_id)
        require(bool(self.requested_capabilities), "explicit requested scope required")
        unique(tuple(item.value for item in self.requested_capabilities))
        require(not self.follow_symlinks, "symlink traversal is not authorized")
        require(bool(self.roots), "authorized roots required")
        unique(tuple(root.id for root in self.roots))


class DiagnosticClass(StrEnum):
    UNSUPPORTED = 'expected_unsupported'
    UNRESOLVED = 'unresolved_runtime_behavior'
    PARTIAL = 'partial_semantic_coverage'
    RESOURCE = 'resource_budget_exhaustion'
    FAILURE = 'parser_or_analysis_failure'


@dataclass(frozen=True, kw_only=True)
class Diagnostic(Record):
    code: str
    stage: str
    message: str
    location: SourceLocation | None = None
    classification: DiagnosticClass = DiagnosticClass.FAILURE
    affected_locations: tuple[SourceLocation, ...] = ()
    occurrences: int = 1

    def validate(self) -> None:
        for value in (self.code, self.stage, self.message):
            nonempty(value)


@dataclass(frozen=True, kw_only=True)
class InventorySummary(Record):
    status: Status
    inventoried_files: int
    visited_entries: int
    inspected_bytes: int
    max_entries: int | None = None
    max_depth: int | None = None
    max_total_bytes: int | None = None
    max_ignore_bytes: int | None = None
    repository_file_count: int | None = None
    limitations: tuple[str, ...] = ()

    def validate(self) -> None:
        require(self.status in (Status.COMPLETED, Status.PARTIAL, Status.FAILED), "invalid inventory status")
        require(all(x >= 0 for x in (self.inventoried_files, self.visited_entries, self.inspected_bytes)),
                "negative inventory count")
        require(all(x is None or x > 0 for x in (self.max_entries, self.max_depth, self.max_total_bytes, self.max_ignore_bytes)),
                "invalid inventory resource limits")
        require(self.repository_file_count is None or self.repository_file_count >= self.inventoried_files,
                "invalid repository denominator")


@dataclass(frozen=True, kw_only=True)
class ScanResult(Record):
    scan_id: str
    tool_version: str
    scope: ScanScope
    status: Status
    files: tuple[SourceFile, ...]
    coverage: Coverage
    evidence: tuple[Evidence, ...] = ()
    modules: tuple[Module, ...] = ()
    symbols: tuple[Symbol, ...] = ()
    findings: tuple[Finding, ...] = ()
    semantic_observations: tuple[SemanticObservation, ...] = ()
    semantic_analysis: tuple[SemanticFileAnalysis, ...] = ()
    graph: Graph = Graph()
    credentials: tuple[CredentialExposure, ...] | None = None
    credential_candidates: tuple[CredentialCandidate, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    limitations: tuple[str, ...] = ()
    schema_version: str = SCHEMA_VERSION
    disclaimer: str = DISCLAIMER
    execution: ExecutionMetadata = ExecutionMetadata()
    inventory: InventorySummary | None = None

    def validate(self) -> None:
        if self.inventory is not None:
            require(self.inventory.inventoried_files == len(self.files), "inventory file count mismatch")
            require(not self.execution.cancelled or self.inventory.status != Status.COMPLETED,
                    "cancelled inventory cannot claim completion")
            require(self.inventory.status != Status.COMPLETED or
                    (not self.coverage.inventory_gaps and all(item.status != Status.FAILED for item in self.coverage.files)),
                    "incomplete inventory cannot claim completion")
        nonempty(self.tool_version)
        nonempty(self.scan_id)
        require(not self.execution.cancelled or self.status != Status.COMPLETED,
                "cancelled scan cannot claim completion")
        require(self.schema_version == SCHEMA_VERSION, "unsupported schema version")
        require(self.disclaimer == DISCLAIMER, "mandatory disclaimer cannot be changed")
        require(self.status in (Status.COMPLETED, Status.PARTIAL, Status.FAILED), "invalid scan status")
        for collection in (self.files, self.modules, self.symbols, self.evidence, self.findings,
                           self.credentials or ()):
            unique(tuple(item.id for item in collection))
        require(len({(file.root_id, file.path) for file in self.files}) == len(self.files),
                "duplicate file paths within root")
        root_ids = {root.id for root in self.scope.roots}
        require(all(file.root_id in root_ids for file in self.files), "file outside authorized root scope")
        require(all(gap.root_id in root_ids for gap in self.coverage.inventory_gaps), "gap outside root scope")
        files = {file.id: file for file in self.files}
        modules = {module.id: module for module in self.modules}
        symbols = {symbol.id: symbol for symbol in self.symbols}
        evidence_ids = {item.id for item in self.evidence}
        require(set(files) == {item.file_id for item in self.coverage.files}, "file coverage mismatch")
        unique(tuple(o.id for o in self.semantic_observations))
        graph_ids={n.id for n in self.graph.nodes}
        scope_ids=set(files)|set(modules)|set(symbols)
        relationship_ids={r.id for r in self.graph.relationships}
        observation_counts={}
        for observation in self.semantic_observations:observation_counts[observation.file_id]=observation_counts.get(observation.file_id,0)+1
        unique(tuple(s.file_id for s in self.semantic_analysis))
        for summary in self.semantic_analysis:
            require(summary.file_id in files, 'dangling semantic accounting file')
            require(summary.emitted_observations==observation_counts.get(summary.file_id,0), 'semantic accounting mismatch')
        for observation in self.semantic_observations:
            require(set(observation.candidate_target_ids)<=graph_ids, 'dangling semantic target candidate')
            require(observation.file_id in files, 'observation references missing file')
            require(observation.scope_id in scope_ids, 'observation references missing scope')
            require(set(observation.evidence_ids) <= evidence_ids, 'dangling semantic evidence')
            require(set(observation.relationship_ids) <= relationship_ids, 'dangling semantic relationship')
        unique(tuple(c.id for c in self.credential_candidates))
        for candidate in self.credential_candidates:
            require(candidate.file_id in files and set(candidate.evidence_ids)<=evidence_ids, 'dangling credential candidate')
        rules = {item.rule_id: item for item in self.coverage.rules}
        for category in self.coverage.categories:
            require(set(category.rule_ids) <= set(rules), "category references missing rule coverage")
            require(category.status != Status.COMPLETED
                    or all(rules[rule_id].status == Status.COMPLETED for rule_id in category.rule_ids),
                    "completed category requires completed rules")
        if self.credentials is not None:
            credential_category = next(item for item in self.coverage.categories
                                       if item.category == Category.CREDENTIALS)
            require(credential_category.status in (Status.COMPLETED, Status.PARTIAL)
                    and any(cap.capability == Capability.CREDENTIALS
                            and cap.status in (Status.COMPLETED, Status.PARTIAL)
                            for item in self.coverage.files for cap in item.capabilities),
                    "credential results require evaluated credential coverage")
        for item in self.coverage.files:
            file = files[item.file_id]
            require(item.reviewed_lines is None or file.physical_lines is None
                    or item.reviewed_lines <= file.physical_lines, "reviewed lines exceed file lines")
            require(item.status != Status.UNCLASSIFIED or file.language is None,
                    "recognized language cannot be unclassified")
            require(item.status not in (Status.COMPLETED, Status.PARTIAL) or file.language is not None,
                    "analyzed file requires recognized language")
            completed_scope = all(any(cap.capability == requested and cap.status == Status.COMPLETED
                                      for cap in item.capabilities)
                                  for requested in self.scope.requested_capabilities)
            require(item.status != Status.COMPLETED or completed_scope,
                    "completed file must satisfy requested capabilities")
            require(item.status != Status.PARTIAL
                    or any(cap.status in (Status.COMPLETED, Status.PARTIAL) for cap in item.capabilities),
                    "partial file requires performed analysis")
        if self.status == Status.COMPLETED:
            require(not self.coverage.inventory_gaps and
                    all(item.status == Status.COMPLETED for item in self.coverage.files),
                    "incomplete file inventory cannot claim completed scan")
        require(all(module.file_id in files for module in self.modules), "dangling module file")
        require(all(symbol.module_id in modules and (symbol.parent_id is None or symbol.parent_id in symbols)
                    for symbol in self.symbols), "dangling symbol reference")
        for node in self.graph.nodes:
            require(node.file_id is None or node.file_id in files, "dangling graph file")
            require(set(node.evidence_ids) <= evidence_ids, "dangling node evidence")
        entity_ids = set(files) | set(modules) | set(symbols) | {node.id for node in self.graph.nodes}
        for edge in self.graph.relationships:
            require(set(edge.evidence_ids) <= evidence_ids, "dangling relationship evidence")
        for finding in self.findings:
            require(finding.rule_id in rules
                    and rules[finding.rule_id].status in (Status.COMPLETED, Status.PARTIAL),
                    "finding requires evaluated rule coverage")
            for category in (finding.category,) + finding.additional_categories:
                category_coverage = next(item for item in self.coverage.categories if item.category == category)
                require(category_coverage.status in (Status.COMPLETED, Status.PARTIAL)
                        and finding.rule_id in category_coverage.rule_ids,
                        "finding requires corresponding category coverage")
            require((set(finding.evidence_ids) | set(finding.remediation_evidence_ids)) <= evidence_ids
                    and set(finding.affected_ids) <= entity_ids, "dangling finding reference")
            require(set(finding.relationship_ids) <= {edge.id for edge in self.graph.relationships},
                    "dangling finding relationship")
            if finding.assessment is not None:
                assessment=finding.assessment
                refs=set(assessment.supporting_evidence_ids+assessment.contradictory_evidence_ids)
                refs.update(e for guard in assessment.safeguards for e in guard.evidence_ids)
                require(refs <= evidence_ids, "dangling assessment evidence")
                require(set(assessment.call_path_relationship_ids+assessment.unresolved_relationship_ids)
                        <= {edge.id for edge in self.graph.relationships}, "dangling assessment relationship")
        for credential in self.credentials or ():
            refs = set(credential.evidence_ids) | set(credential.resolution_evidence_ids)
            refs.update(ref for event in credential.events for ref in event.evidence_ids)
            require(refs <= evidence_ids, "dangling credential evidence")
        require(all(set(summary.finding_ids) <= {finding.id for finding in self.findings}
                    for summary in self.graph.risk_summaries), "dangling risk summary finding")
        locations = [loc for item in self.evidence for loc in item.locations]
        locations += [symbol.location for symbol in self.symbols]
        locations += [loc for finding in self.findings for loc in finding.locations]
        locations += [item.location for item in self.diagnostics if item.location is not None]
        inventoried_paths = {(file.root_id, file.path) for file in self.files}
        require(all((loc.root_id, loc.path) in inventoried_paths for loc in locations),
                "location outside file inventory")
