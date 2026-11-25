"""Inventory composition root; no analysis adapters or risk rules run here."""
from importlib.metadata import version
from pathlib import PurePosixPath
import re

from .config import DiscoverySettings
from .discovery import DEFAULT_EXCLUSIONS, Discovery
from .models.analysis import Graph, GraphNode
from .models.base import Capability, Category, Confidence, Provenance, Status
from .models.coverage import CapabilityCoverage, CategoryCoverage, Coverage, FileCoverage
from .models.execution import ExecutionMetadata, ResourceBudget
from .models.scan import Diagnostic, InventorySummary, ScanResult, ScanScope
from .models.source import Evidence, SourceFile, SourceLocation
from .privacy import identity, safe_path
from .recognition import RecognitionRegistry
from .technologies import inspect_manifest, is_argus_report, suggests_application

LIMITATIONS = (
    'Inventory and technology recognition are not architectural or security analysis; no analysis adapters or risk rules are implemented.',
    'Credential, reliability, AI-risk and cost analysis are unavailable. Zero findings provide no safety assurance.',
    'Exclusions use architecture policy only; future credential inspection requires separate authorization and policy.',
    'Pruned directories have unknown contents. Unknown file types may contain source; repository-wide denominators are unavailable when discovery has gaps.',
    'Only UTF-8 text without NUL bytes receives physical line counts; counts include comments and blank lines.',
    'Bounded file reads and entry/file/depth/total-byte limits are enforced; process memory and wall-clock limits are not enforced. Structured reports remain in memory.',
    'Defensive path masking recognizes common credential forms but cannot guarantee arbitrary filenames contain no secrets. Report structure and relative names may remain sensitive.',
    'Live filesystem mutation can invalidate inventory consistency; scans are not filesystem snapshots.',
)
NO_ANALYSIS = tuple(CapabilityCoverage(capability=cap, status=Status.UNSUPPORTED,
                                      reason='No analysis adapter is implemented.', evaluated_units=0)
                    for cap in Capability)


def scan(root, settings: DiscoverySettings = DiscoverySettings(), progress=None, cancellation=None):
    discovery = Discovery(root, settings, progress, cancellation)
    registry = RecognitionRegistry()
    files, coverage, evidence, diagnostics = [], [], [], []
    nodes = {'root': GraphNode(id='root', kind='repository', label='Authorized repository root')}
    has_failures = False

    def observation(key, message, location=None, provenance=Provenance.OBSERVED):
        eid = identity('evidence', key)
        evidence.append(Evidence(id=eid, observation=message, producer='argus.inventory',
                                 producer_version='1', provenance=provenance,
                                 confidence=Confidence.HIGH if provenance == Provenance.OBSERVED else Confidence.MEDIUM,
                                 locations=(location,) if location else ()))
        return eid

    def directory(path):
        parent = 'root'
        parts = PurePosixPath(path).parts
        for index in range(1, len(parts) + 1):
            subpath = '/'.join(parts[:index])
            node_id = identity('directory', subpath)
            if node_id not in nodes:
                eid = observation(node_id, 'Observed filesystem directory containment.')
                nodes[node_id] = GraphNode(id=node_id, kind='directory', label=safe_path(subpath),
                                           parent_id=parent, evidence_ids=(eid,), grouping_provenance=Provenance.OBSERVED)
            parent = node_id
        return parent

    for item in discovery.files():
        path = safe_path(item.path)
        file_id = identity('file', item.path)
        rec = registry.recognize(item.path, (item.content or b'')[:4096])
        text = None
        lines = None
        if item.content is not None and b'\0' not in item.content:
            try:
                text = item.content.decode('utf-8-sig')
                lines = len(re.findall(r'\r\n|\r|\n', text)) + (bool(text) and not text.endswith(('\n', '\r')))
            except UnicodeError:
                pass
        if text is not None and is_argus_report(item.path, text):
            item.excluded = True
            text = None
            lines = None
        file = SourceFile(id=file_id, path=path, language=rec.language, kind=rec.kind,
                          physical_lines=lines, size_bytes=item.size,
                          recognition_basis=rec.basis, language_candidates=rec.candidates)
        files.append(file)
        status = (Status.EXCLUDED if item.excluded else Status.FAILED if item.failure else
                  Status.UNSUPPORTED if rec.language else Status.UNCLASSIFIED)
        has_failures |= bool(item.failure)
        coverage.append(FileCoverage(file_id=file_id, status=status, capabilities=NO_ANALYSIS,
                                     reviewed_lines=0 if lines is not None else None,
                                     reason_code='excluded' if item.excluded else item.failure or ('ambiguous_language' if rec.candidates else
                                                                 'no_adapter' if rec.language else 'unknown_format'),
                                     reason='Excluded by architecture inventory policy; no analysis performed.' if item.excluded else
                                     'File could not be read within safe resource limits.' if item.failure else
                                     'Recognized inventory only; no analysis performed.' if rec.language else
                                     'Language ambiguous or unknown; no analysis performed.'))
        parent_path = str(PurePosixPath(item.path).parent)
        parent = directory(parent_path) if parent_path != '.' else 'root'
        location = SourceLocation(path=path, start_line=1, start_column=1)
        eid = observation(file_id, 'Observed filesystem file containment.', location)
        nodes[file_id] = GraphNode(id=file_id, kind=file.kind.value + '_file', label=path,
                                   file_id=file_id, language=rec.language, parent_id=parent,
                                   evidence_ids=(eid,), grouping_provenance=Provenance.OBSERVED)
        if item.failure:
            diagnostics.append(Diagnostic(code=item.failure, stage='discovery',
                                           message='File inspection unavailable; see file coverage.', location=location))
        if text is not None:
            technologies, malformed = inspect_manifest(item.path, text)
            if malformed:
                diagnostics.append(Diagnostic(code='malformed_manifest', stage='technology_recognition',
                                               message='Manifest could not be safely interpreted; no dependency observations retained.',
                                               location=location))
            for tech, basis in technologies:
                tech_id = identity('technology', item.path + ':' + tech + ':' + basis)
                eid = observation(tech_id, f'{tech}: {basis}; source usage and framework security not evaluated.', location)
                nodes[tech_id] = GraphNode(id=tech_id, kind='technology', label=tech, parent_id=file_id,
                                           grouping_provenance=Provenance.OBSERVED, evidence_ids=(eid,),
                                           limitations=('Declaration/configuration evidence does not establish installed versions, source usage, runtime reachability or security review.',))
            name = PurePosixPath(item.path).name
            if name in {'package.json', 'pyproject.toml', 'Cargo.toml', 'go.mod', 'Gemfile'} and not malformed:
                group_id = identity('package', item.path)
                eid = observation(group_id, 'Manifest suggests a package boundary; application/service boundary is unconfirmed.', location,
                                  Provenance.INFERRED)
                nodes[group_id] = GraphNode(id=group_id, kind='package', label='Manifest-inferred package',
                                            parent_id=parent, grouping_provenance=Provenance.INFERRED,
                                            evidence_ids=(eid,), limitations=('No application or service boundary is asserted.',))
            if not malformed and suggests_application(item.path, text):
                app_id = identity('application', item.path)
                eid = observation(app_id, 'Manifest entry-point declaration suggests an application boundary.',
                                  location, Provenance.INFERRED)
                nodes[app_id] = GraphNode(id=app_id, kind='application', label='Manifest-inferred application',
                                          parent_id=parent, grouping_provenance=Provenance.INFERRED,
                                          evidence_ids=(eid,), limitations=('Declared scripts are not executed; service boundaries and runtime behavior are unconfirmed.',))
    for path in discovery.directories:
        if path:
            directory(path)
    files.sort(key=lambda f: f.path)
    # Privacy masking uses stable component hashes; collisions are cryptographically unlikely.
    gaps = tuple(sorted(discovery.gaps, key=lambda g: (g.path or '', g.reason_code)))
    inventory_status = Status.PARTIAL if gaps or has_failures else Status.COMPLETED
    summary = InventorySummary(status=inventory_status, inventoried_files=len(files), visited_entries=discovery.visited,
                               inspected_bytes=discovery.inspected_bytes, max_entries=settings.max_entries,
                               max_depth=settings.max_depth, max_total_bytes=settings.max_total_bytes,
                               max_ignore_bytes=settings.max_ignore_bytes,
                               repository_file_count=None if gaps else len(files), limitations=LIMITATIONS[3:])
    scope = ScanScope(repository_id='local-repository', requested_capabilities=tuple(Capability),
                      exclusions=DEFAULT_EXCLUSIONS + tuple('user-pattern-' + str(i + 1) for i in range(len(settings.excludes))),
                      resource_budget=ResourceBudget(max_file_bytes=settings.max_file_bytes,
                                                     max_memory_bytes=512 * 1024 * 1024,
                                                     max_workers=1, max_files=settings.max_files))
    return ScanResult(scan_id=identity('scan', repr((files, gaps, settings.max_files, settings.max_entries,
                                                    settings.max_depth, settings.max_total_bytes))),
                      tool_version=version('argus'), scope=scope, status=Status.PARTIAL,
                      files=tuple(files), coverage=Coverage(files=tuple(sorted(coverage, key=lambda f: f.file_id)),
                          categories=tuple(CategoryCoverage(category=cat, status=Status.UNSUPPORTED,
                                           reason='No analysis rules implemented.') for cat in Category),
                          inventory_gaps=gaps, limitations=LIMITATIONS),
                      graph=Graph(nodes=tuple(nodes[key] for key in sorted(nodes)), limitations=('Containment only; no dependency relationships or graph algorithms evaluated.',)),
                      evidence=tuple(sorted(evidence, key=lambda e: e.id)), diagnostics=tuple(diagnostics),
                      limitations=LIMITATIONS, inventory=summary,
                      execution=ExecutionMetadata(cancelled=discovery.cancelled, limitations=(LIMITATIONS[5],)))
