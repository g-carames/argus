"""Incremental analysis collector; retains facts, never raw source buffers."""
from dataclasses import replace

from .parsing import parse, PRIMARY, SUPPORTED, ParseFailure, ParseUnavailable
from .extraction import extract
from .resolution import Resolver
from .graphs import NetworkXBackend
from .rules import REGISTRY, evaluate
from .adapters import supported_caps, descriptor
from ..models.analysis import Graph, GraphNode, Relationship, RelationshipKind, Resolution, Metric
from ..models.base import Capability, Category, Status, Confidence, Provenance
from ..models.coverage import CapabilityCoverage, FileCoverage, CategoryCoverage
from ..models.scan import Diagnostic
from ..models.source import SourceLocation, Evidence
from ..privacy import identity

LIMITATIONS = ('Structural static analysis only; no security, credential, dependency-health, reliability, performance, AI, cost or framework rules.',
               'Function/class containment is extracted; no call graph or inheritance resolution, cross-language contracts, embedded-language analysis, runtime loading, conditional package exports or executable configuration resolution. Identifier labels are opaque for privacy.',
               'SQL is tokenized, not syntax validated. Dockerfile instruction recognition does not validate argument or embedded shell semantics.',
               'Extraction retains at most 50000 entities and 100000 imports, rejecting further files with explicit failures. Parsing uses file-size, 200000-node and 256-depth traversal budgets; Tree-sitter parsing timeout is one second. Python AST/JSON/TOML and SQL tokenization have no hard time or memory isolation.',)




class Analysis:
    def __init__(self, settings):
        self.settings = settings
        self.facts = {}
        self.files = {}
        self.failures = {}
        self.manifests, self.tsconfigs = {}, {}
        self.entity_count = 0
        self.import_count = 0

    def inspect(self, original_path, file, content, eligible):
        self.files[original_path] = file
        if not eligible or file.language not in SUPPORTED:
            return
        if content is None:
            self.failures[file.id] = 'analysis_encoding_unavailable'
            return
        try:
            parsed = parse(file.language, content)
            facts = extract(file, parsed)
            entities = 1 + len(facts.symbols)
            if self.entity_count + entities > 50000 or self.import_count + len(facts.imports) > 100000:
                self.failures[file.id] = 'analysis_resource_limit'
                return
            self.entity_count += entities
            self.import_count += len(facts.imports)
            self.facts[file.id] = facts
            if file.language == 'json' and isinstance(parsed.tree, dict):
                # Retain only resolution-related fields, never arbitrary config values.
                if original_path.endswith('package.json'):
                    self.manifests[original_path] = {k: parsed.tree[k] for k in ('name', 'main', 'module', 'types') if k in parsed.tree}
                if original_path.endswith('tsconfig.json'):
                    self.tsconfigs[original_path] = {k: parsed.tree[k] for k in ('compilerOptions', 'extends') if k in parsed.tree}
        except ParseUnavailable:
            self.failures[file.id] = 'grammar_unavailable'
        except (ParseFailure, RecursionError, MemoryError):
            self.failures[file.id] = 'parse_or_extraction_failed'

    def finish(self, result):
        evidence, nodes = list(result.evidence), list(result.graph.nodes)
        diagnostics = list(result.diagnostics)
        metrics, relationships = [], []
        modules, symbols = [], []
        file_by_id = {f.id: f for f in result.files}
        module_by_file = {fid: facts.module.id for fid, facts in self.facts.items()}
        resolver = Resolver(self.files, self.manifests, self.tsconfigs)
        locations = {}
        measured = {}
        for path, file in sorted(self.files.items()):
            facts = self.facts.get(file.id)
            if facts is None:
                continue
            module = facts.module
            modules.append(module)
            symbols.extend(facts.symbols)
            location = SourceLocation(path=file.path, start_line=1, start_column=1)
            locations[module.id] = location
            eid = identity('evidence', module.id)
            adapter = descriptor(file.language)
            evidence.append(Evidence(id=eid, observation='Static module extraction; identifiers withheld.', producer='argus.extractor',
                producer_version='1', confidence=Confidence.HIGH, provenance=Provenance.OBSERVED, locations=(location,), limitations=facts.limitations + (f'Parser {adapter.parser_id} {adapter.parser_version}; grammar {adapter.grammar_version or "not applicable"}; extractor 1.',)))
            nodes.append(GraphNode(id=module.id, kind='module', label=module.qualified_name, file_id=file.id, language=file.language,
                parent_id=file.id, evidence_ids=(eid,), grouping_provenance=Provenance.OBSERVED, limitations=facts.limitations))
            for symbol in facts.symbols:
                locations[symbol.id] = symbol.location
                nodes.append(GraphNode(id=symbol.id, kind=symbol.kind, label=symbol.name, file_id=file.id, language=file.language,
                    parent_id=symbol.parent_id or module.id, evidence_ids=(eid,), grouping_provenance=Provenance.OBSERVED))
            measures = list(facts.measurements)
            if file.language in PRIMARY:
                measures.append((module.id, location, {'module_length': file.physical_lines}))
            if facts.declarations:
                measures.append((module.id, location, facts.declarations))
            for scope, loc, values in measures:
                locations[scope] = loc
                for name, value in values.items():
                    measured[scope, name] = value
                    metrics.append(Metric(name=name, scope_id=scope, value=value,
                        definition='Physical structural count; see rule catalog and language support for exact semantics.',
                        projection='file-structure-v1', algorithm_version='argus-extraction-1'))
            for index, fact in enumerate(facts.imports):
                target = resolver.resolve(path, file.language, fact)
                target_file = self.files.get(target.path)
                target_id = module_by_file.get(target_file.id, target_file.id) if target_file else None
                rid = identity('relationship', module.id + ':' + str(index))
                eid = identity('evidence', rid)
                loc = SourceLocation(path=file.path, start_line=fact.line, start_column=1)
                evidence.append(Evidence(id=eid, observation='Observed static import syntax; ' + target.reason,
                    producer='argus.resolver', producer_version='1', confidence=Confidence.HIGH,
                    provenance=Provenance.OBSERVED, locations=(loc,)))
                relationships.append(Relationship(id=rid, source_id=module.id, target_id=target_id,
                    target_reference=identity('reference', fact.reference or 'computed'), language=file.language,
                    kind=RelationshipKind.IMPORT, resolution=target.status,
                    provenance=Provenance.OBSERVED, confidence=Confidence.HIGH if target_id else Confidence.MEDIUM,
                    dependency_phase=fact.phase + ('_conditional' if fact.conditional else ''), evidence_ids=(eid,),
                    limitations=(target.reason, 'Static reference only; alias shadowing, runtime search paths and loading are unverified.')))
        graph = NetworkXBackend().analyze(Graph(nodes=tuple(sorted(nodes, key=lambda n: n.id)), relationships=tuple(sorted(relationships, key=lambda r: r.id))))
        for metric in graph.metrics:
            measured[metric.scope_id, metric.name] = metric.value
        findings = []
        rule_coverages = []
        primary_ids = {facts.module.id for fid, facts in self.facts.items() if file_by_id[fid].language in PRIMARY}
        symbol_owners = {s.id: s.module_id for s in symbols}
        for rule in REGISTRY:
            threshold = self.settings.thresholds.get(rule.parameter, rule.default)
            disabled = rule.id in self.settings.disabled_rules
            eligible = sum(f.language in PRIMARY for f in result.files)
            if not disabled:
                if rule.id == 'ARGUS-ARCH-001':
                    for cycle in graph.cycles:
                        if len(cycle.node_ids) <= threshold:
                            continue
                        scope = cycle.node_ids[0]
                        findings.append(evaluate(rule, len(cycle.node_ids), scope, locations[scope], evidence, threshold, cycle.relationship_ids, affected=cycle.node_ids))
                else:
                    for (scope, parameter), value in sorted(measured.items()):
                        if parameter != rule.parameter or value is None:
                            continue
                        owner = symbol_owners.get(scope, scope)
                        if owner not in primary_ids:
                            continue
                        if value > threshold:
                            related = tuple(r.id for r in graph.relationships if r.source_id == scope or r.target_id == scope)
                            findings.append(evaluate(rule, value, scope, locations[scope], evidence, threshold, related))
                    if rule.id == 'ARGUS-ARCH-005':
                        existing = {f.affected_ids[0] for f in findings if f.rule_id == rule.id}
                        for scope in sorted(primary_ids - existing):
                            length = measured.get((scope, 'module_length'))
                            limit = self.settings.thresholds.get('module_length', 500)
                            if length is not None and length > limit:
                                findings.append(evaluate(rule, length, scope, locations[scope], evidence, limit, parameter='module_length'))
            rule_coverages.append(CapabilityCoverage(capability=Capability.ARCHITECTURE if rule.category == Category.ARCHITECTURE else Capability.STRUCTURE,
                rule_id=rule.id, status=Status.DISABLED if disabled else Status.PARTIAL if eligible else Status.UNSUPPORTED,
                eligible_units=eligible, evaluated_units=0 if disabled else len(primary_ids),
                reason='Disabled by local configuration.' if disabled else 'Evaluated eligible successfully extracted primary-language modules only; unsupported, failed and excluded scope remains unreviewed.'))
        coverage = []
        for entry in result.coverage.files:
            file = file_by_id[entry.file_id]
            if entry.file_id in self.failures:
                code = self.failures[entry.file_id]
                caps = tuple(CapabilityCoverage(capability=c, status=Status.UNSUPPORTED if code == 'grammar_unavailable' or c not in supported_caps(file.language) else Status.FAILED,
                           reason='Prepared grammar unavailable.' if code == 'grammar_unavailable' else 'Input malformed, undecodable or parser/extractor budget exceeded; no source diagnostics retained.') for c in Capability)
                coverage.append(replace(entry, status=Status.UNSUPPORTED if code == 'grammar_unavailable' else Status.FAILED,
                                        capabilities=caps, reason_code=code, reason='Static extraction unavailable.'))
                diagnostics.append(Diagnostic(code=code, stage='analysis', message='Static extraction unavailable; source and exception text withheld.',
                                              location=SourceLocation(path=file.path, start_line=1, start_column=1)))
            elif entry.file_id in self.facts:
                caps = supported_caps(file.language)
                architecture_disabled = (file.language in PRIMARY and
                    all(r.id in self.settings.disabled_rules for r in REGISTRY if r.category == Category.ARCHITECTURE))
                coverage.append(FileCoverage(file_id=file.id, status=Status.PARTIAL, reason_code='partial_static_analysis',
                    reason='Listed static capabilities evaluated; other capabilities and embedded languages unavailable.', reviewed_lines=file.physical_lines,
                    capabilities=tuple(CapabilityCoverage(capability=c, status=(Status.DISABLED if c == Capability.ARCHITECTURE and architecture_disabled else Status.COMPLETED if c == Capability.PARSING and c in caps else Status.PARTIAL if c in caps else Status.UNSUPPORTED),
                        eligible_units=1, evaluated_units=1 if c in caps and not (c == Capability.ARCHITECTURE and architecture_disabled) else 0,
                        reason='All architecture rules disabled.' if c == Capability.ARCHITECTURE and architecture_disabled else 'Conservative static extraction; see language limitations.' if c in caps else 'No implemented analyzer for this capability.') for c in Capability)))
            else:
                coverage.append(entry)
        categories = tuple(CategoryCoverage(category=cat, status=Status.PARTIAL if any(r.category == cat and c.evaluated_units for r,c in zip(REGISTRY, rule_coverages)) else Status.UNSUPPORTED,
                    reason='Initial structural heuristics only.' if cat in (Category.ARCHITECTURE, Category.MAINTAINABILITY) else 'No implemented rules.',
                    rule_ids=tuple(r.id for r in REGISTRY if r.category == cat)) for cat in Category)
        return replace(result, modules=tuple(modules), symbols=tuple(sorted(symbols, key=lambda s:s.id)), findings=tuple(sorted(findings,key=lambda f:f.id)),
            evidence=tuple(sorted(evidence,key=lambda e:e.id)), diagnostics=tuple(diagnostics),
            graph=replace(graph, metrics=tuple(metrics) + graph.metrics), limitations=LIMITATIONS + result.limitations[1:],
            coverage=replace(result.coverage, files=tuple(coverage), rules=tuple(rule_coverages), categories=categories, limitations=LIMITATIONS),
            inventory=replace(result.inventory, status=Status.PARTIAL if self.failures else result.inventory.status))
