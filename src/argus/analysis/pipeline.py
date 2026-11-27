"""Incremental analysis collector; retains facts, never raw source buffers."""
from dataclasses import replace

from .parsing import parse, PRIMARY, SUPPORTED, ParseFailure, ParseUnavailable, ParseResourceLimit
from .extraction import extract
from .resolution import Resolver
from .graphs import NetworkXBackend
from .rules import REGISTRY, evaluate
from .risks import detect, credentials
from .isolation import isolated_extract
from .parsing import GRAMMARS
from .adapters import supported_caps, descriptor
from ..models.analysis import Graph, GraphNode, Relationship, RelationshipKind, Resolution, Metric, Finding, ResourceImpact
from ..models.base import Capability, Category, Status, Confidence, Provenance, Severity
from ..models.coverage import CapabilityCoverage, FileCoverage, CategoryCoverage
from ..models.scan import Diagnostic
from ..models.source import SourceLocation, Evidence
from ..privacy import identity

LIMITATIONS = ('Contextual analysis is bounded and partial: Python and separately lowered JS-family flow, statically resolved cross-file functions/constants, simple Python classes and specific client timeouts. No general sanitizer, authorization, Express middleware-order verification, retry/backoff policy, shared execution budget or database-limit enforcement. Semantic budget/unsupported-control diagnostics identify incomplete work; findings retain observations.','Limited syntactic security, credential, reliability, AI and cost rules; no authentication, authorization, general taint analysis or framework security, dependency-health or safety certification. Credential history, ignored/tracked overrides, reuse, persistence and remediation tracking are unavailable.',
               'Function/class containment is extracted; partial direct/imported call bindings and inferred frontend HTTP matches only; no general method, inheritance or cross-language type resolution, embedded-language analysis, runtime loading, runtime selection of conditional package exports or executable configuration resolution. Identifier labels are opaque for privacy.',
               'HTTP matching is bounded to 1000000 endpoint/request comparisons; exhausted matching remains unresolved with diagnostics. Routes, SDK calls and bindings are syntactic candidates, not runtime relationships. SQL is tokenized, not syntax validated. Dockerfile instruction recognition does not validate argument or embedded shell semantics.',
               'Extraction retains at most 50000 entities and 100000 import/call/request declarations, rejecting further files with explicit failures. Parsing uses file-size, 200000-node and 256-depth traversal budgets; Tree-sitter parsing timeout is one second; native parsing/extraction isolated per file with five-second parent deadline, three CPU seconds and core dumps disabled. Memory hard limits are not enforced. Python AST/JSON/TOML and SQL tokenization have no hard time or memory isolation.',)




class Analysis:
    def __init__(self, settings):
        self.settings = settings
        self.facts = {}
        self.files = {}
        self.failures = {}
        self.manifests, self.tsconfigs = {}, {}
        self.entity_count = 0
        self.import_count = 0
        self.risk_hits = {}
        self.credential_files = set()
        self.credential_candidates = {}
        self.workspace_patterns = []

    def inspect(self, original_path, file, content, eligible):
        self.files[original_path] = file
        if not eligible:
            return
        if content is not None:
            try:
                text = content.decode('utf-8-sig')
                if '\x00' not in text:
                    self.credential_files.add(file.id)
                    from .risks import credential_candidates
                    if 'ARGUS-CRED-001' not in self.settings.disabled_rules:
                        records=credential_candidates(content, original_path)
                        self.credential_candidates[file.id]=records
                        self.risk_hits[file.id]=sorted({('ARGUS-CRED-001',line) for line,kind,_ in records if kind!='obvious_placeholder'})
                    else: self.risk_hits[file.id]=[]
            except UnicodeError:
                pass
        if original_path.endswith('pnpm-workspace.yaml') and content is not None:
            # Only simple literal package glob list entries, not general YAML evaluation.
            import re
            text = content.decode('utf-8', errors='replace')
            if re.search(r'^packages:\s*$', text, re.M):
                base = original_path.rsplit('/',1)[0] + '/' if '/' in original_path else ''
                self.workspace_patterns.extend(base + m[1] for m in re.finditer(r'^\s+-\s+[\"\']?([A-Za-z0-9_./*@-]+)[\"\']?\s*$', text, re.M))
        if file.language not in SUPPORTED:
            return
        if content is None:
            self.failures[file.id] = 'analysis_encoding_unavailable'
            return
        try:
            parsed = None
            if file.language in GRAMMARS:
                facts, hits = isolated_extract(file, content)
            else:
                if file.language == 'json' and original_path.endswith(('tsconfig.json','jsconfig.json','.jsonc')):
                    from .jsonc import loads
                    from .parsing import Parsed
                    parsed = Parsed('json', loads(content), content)
                else:
                    try:
                        parsed = parse(file.language, content)
                    except ParseFailure:
                        # Extended project configs may have arbitrary JSON basenames.
                        if file.language != 'json': raise
                        from .jsonc import loads
                        from .parsing import Parsed
                        value=loads(content)
                        if not isinstance(value,dict) or not {'compilerOptions','extends'} & value.keys(): raise ParseFailure()
                        parsed=Parsed('json',value,content)
                facts = extract(file, parsed)
                hits = detect(parsed)
            self.risk_hits.setdefault(file.id, []).extend(hits)
            entities = 1 + len(facts.symbols) + len(facts.links.endpoints)
            if self.entity_count + entities > 50000 or self.import_count + len(facts.imports) + len(facts.links.calls) + len(facts.links.requests) > 100000:
                self.failures[file.id] = 'analysis_resource_limit'
                return
            self.entity_count += entities
            self.import_count += len(facts.imports) + len(facts.links.calls) + len(facts.links.requests)
            self.facts[file.id] = facts
            if file.language == 'json' and isinstance(parsed.tree, dict):
                # Retain only resolution-related fields, never arbitrary config values.
                if original_path.endswith('package.json'):
                    self.manifests[original_path] = {k: parsed.tree[k] for k in ('name', 'main', 'module', 'types', 'exports', 'workspaces') if k in parsed.tree}
                if 'compilerOptions' in parsed.tree or 'extends' in parsed.tree or original_path.endswith(('tsconfig.json','jsconfig.json')):
                    self.tsconfigs[original_path] = {k: parsed.tree[k] for k in ('compilerOptions', 'extends') if k in parsed.tree}
        except ParseResourceLimit:
            self.failures[file.id] = 'analysis_resource_limit'
        except ParseUnavailable:
            self.failures[file.id] = 'grammar_unavailable'
        except (ParseFailure, RecursionError, MemoryError, ValueError):
            self.failures[file.id] = 'parse_or_extraction_failed'

    def finish(self, result):
        evidence, nodes = list(result.evidence), list(result.graph.nodes)
        diagnostics = list(result.diagnostics)
        file_by_id = {f.id: f for f in result.files}
        from ..models.credentials import CredentialCandidate, CandidateClassification
        candidates=[]
        for fid,records in sorted(self.credential_candidates.items()):
            file=file_by_id[fid]
            for line,kind,documentation in records:
                cid=identity('candidate',fid+':'+str(line)+':'+kind)
                eid=identity('evidence',cid)
                evidence.append(Evidence(id=eid,observation='Credential candidate classification: '+kind+'; validity unverified; literal withheld.',
                    producer='ARGUS-CRED-001',producer_version='1.3.0',confidence=Confidence.MEDIUM,provenance=Provenance.HEURISTIC,
                    locations=(SourceLocation(path=file.path,start_line=line,start_column=1),)))
                candidates.append(CredentialCandidate(id=cid,file_id=fid,evidence_ids=(eid,),classification=CandidateClassification(kind),documentation_context=documentation))
        metrics, relationships = [], []
        modules, symbols = [], []
        module_by_file = {fid: facts.module.id for fid, facts in self.facts.items()}
        resolver = Resolver(self.files, self.manifests, self.tsconfigs, self.workspace_patterns)
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
        from .relationships import assemble
        link_nodes, link_edges, link_diagnostics = assemble(self.facts, file_by_id, resolver, evidence)
        diagnostics.extend(link_diagnostics)
        nodes.extend(link_nodes)
        relationships.extend(link_edges)
        graph = NetworkXBackend().analyze(Graph(nodes=tuple(sorted(nodes, key=lambda n: n.id)), relationships=tuple(sorted(relationships, key=lambda r: r.id))))
        for metric in graph.metrics:
            measured[metric.scope_id, metric.name] = metric.value
        from .workspace import WorkspaceFlow
        WorkspaceFlow(self.facts, self.files, resolver).run()
        from .observations import project
        semantic_observations=project(self.facts,file_by_id,graph,evidence)
        from .contextual import investigate, attach, relationship_index
        additions, assessments, semantic_gaps = investigate(self.facts, graph, evidence, file_by_id)
        controlled={'ARGUS-SEC-004','ARGUS-REL-003','ARGUS-AI-001','ARGUS-AI-002'}
        for fid, hits in additions.items():
            if not semantic_gaps.get(fid):
                self.risk_hits[fid]=[hit for hit in self.risk_hits.get(fid,()) if hit[0] not in controlled]
            else:
                # Explicitly classified operations still override broad syntax candidates.
                classified={(s.line,k) for s in self.facts[fid].semantic.sites for k in
                    (('ARGUS-SEC-004',) if s.operation=='database' else ('ARGUS-REL-003',) if s.operation=='http' else ('ARGUS-AI-001','ARGUS-AI-002') if s.operation in ('model','embedding') else ())}
                self.risk_hits[fid]=[h for h in self.risk_hits.get(fid,()) if (h[1],h[0]) not in classified]
            self.risk_hits.setdefault(fid, []).extend(hits)
        for fid, gaps in sorted(semantic_gaps.items()):
            for gap in sorted(gaps):
                diagnostics.append(Diagnostic(code='semantic_analysis_incomplete', stage='analysis',
                    message=gap, location=SourceLocation(path=file_by_id[fid].path, start_line=1, start_column=1)))
        findings = []
        rule_coverages = []
        primary_ids = {facts.module.id for fid, facts in self.facts.items() if file_by_id[fid].language in PRIMARY}
        symbol_owners = {s.id: s.module_id for s in symbols}
        for rule in (r for r in REGISTRY if r.evaluator == 'structural'):
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
        for rule in (r for r in REGISTRY if r.evaluator == 'pattern'):
            credential = rule.category == Category.CREDENTIALS
            applicable = {f.id for f in result.files if credential or f.language in rule.languages}
            evaluated = applicable & (self.credential_files if credential else self.facts.keys())
            disabled = rule.id in self.settings.disabled_rules
            cap = Capability.CREDENTIALS if credential else Capability.AI if rule.category == Category.AI else Capability.SECURITY if rule.category == Category.SECURITY else Capability.STRUCTURE
            rule_coverages.append(CapabilityCoverage(capability=cap, rule_id=rule.id,
                status=Status.DISABLED if disabled else Status.PARTIAL if evaluated else Status.UNSUPPORTED,
                eligible_units=len(applicable), evaluated_units=0 if disabled else len(evaluated),
                reason='Disabled by configuration.' if disabled else 'Only enumerated syntactic patterns evaluated on eligible text or successfully parsed files; no semantic completeness.'))
            if disabled or self.settings.thresholds.get(rule.parameter, rule.default) >= 1:
                continue
            for fid in sorted(evaluated):
                file = file_by_id[fid]
                for ordinal, (rule_id, line) in enumerate(sorted(hit for hit in set(self.risk_hits.get(fid, ())) if hit[0] == rule.id)):
                    loc = SourceLocation(path=file.path, start_line=line, start_column=1)
                    scope = fid + ':' + str(ordinal)
                    eid = identity('evidence', rule.id + ':' + scope)
                    evidence.append(Evidence(id=eid, observation=rule.name + ': registered syntax pattern observed; source and literal values withheld. See versioned rule catalog for detection parameters.',
                        producer=rule.id, producer_version=rule.version, provenance=Provenance.OBSERVED,
                        confidence=Confidence.HIGH, locations=(loc,)))
                    secondary = tuple(Category(c) for c in rule.secondary_categories)
                    cost = Category.COST in (rule.category,) + secondary
                    findings.append(Finding(id=identity('finding',rule.id + ':' + scope), rule_id=rule.id, rule_version=rule.version,
                        category=rule.category, additional_categories=secondary, severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM, provenance=Provenance.HEURISTIC, title=rule.name,
                        explanation=rule.name + '. ' + rule.rationale, remediation=rule.remediation, evidence_ids=(eid,), affected_ids=(fid,),
                        locations=(loc,), corrective_actions=(rule.remediation,), acceptance_criteria=(rule.validation,),
                        limitations=(rule.limitations,), resource_impact=ResourceImpact(
                            consumption_mechanism=rule.methodology,
                            potential_financial_consequences='Repeated or unconstrained operations may increase provider or infrastructure consumption; no prices, usage or losses measured.',
                            limitations=('Static indicator only; runtime limits, batching and caching may exist elsewhere.',)) if cost else None))
        related_index = relationship_index(graph, evidence)
        findings = [attach(f, f.affected_ids[0], assessments, related_index, semantic_gaps)
                    if f.rule_id.startswith(('ARGUS-SEC-', 'ARGUS-REL-', 'ARGUS-AI-', 'ARGUS-COST-', 'ARGUS-CRED-')) else f
                    for f in findings]
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
                if file.id in self.credential_files: caps.add(Capability.CREDENTIALS)
                architecture_disabled = (file.language in PRIMARY and
                    all(r.id in self.settings.disabled_rules for r in REGISTRY if r.category == Category.ARCHITECTURE))
                coverage.append(FileCoverage(file_id=file.id, status=Status.PARTIAL, reason_code='partial_static_analysis',
                    reason='Listed static capabilities evaluated; other capabilities and embedded languages unavailable.', reviewed_lines=file.physical_lines,
                    capabilities=tuple(CapabilityCoverage(capability=c, status=(Status.DISABLED if c == Capability.ARCHITECTURE and architecture_disabled else Status.COMPLETED if c == Capability.PARSING and c in caps else Status.PARTIAL if c in caps else Status.UNSUPPORTED),
                        eligible_units=1, evaluated_units=1 if c in caps and not (c == Capability.ARCHITECTURE and architecture_disabled) else 0,
                        reason='All architecture rules disabled.' if c == Capability.ARCHITECTURE and architecture_disabled else 'Conservative static extraction; see language limitations.' if c in caps else 'No implemented analyzer for this capability.') for c in Capability)))
            else:
                coverage.append(entry)
            if file.id in self.facts:
                current=coverage[-1]
                def rule_capability(item):
                    groups={Capability.SECURITY:Category.SECURITY, Capability.AI:Category.AI}
                    category=groups.get(item.capability)
                    if category is None: return item
                    applicable=[r for r in REGISTRY if r.category==category and file.language in r.languages]
                    if applicable and all(r.id in self.settings.disabled_rules for r in applicable):
                        return replace(item,status=Status.DISABLED,evaluated_units=0,reason='All applicable rules disabled.')
                    return item
                coverage[-1]=replace(current,capabilities=tuple(rule_capability(c) for c in current.capabilities))
            # Credential review is independent of parser availability/failure.
            if file.id in self.credential_files:
                current = coverage[-1]
                disabled = 'ARGUS-CRED-001' in self.settings.disabled_rules
                coverage[-1] = replace(current, status=Status.PARTIAL if current.status == Status.UNSUPPORTED and not disabled else current.status, reason='Text credential patterns evaluated; structural and other capabilities remain unavailable.' if current.status == Status.UNSUPPORTED and not disabled else current.reason, capabilities=tuple(
                    CapabilityCoverage(capability=c.capability, status=Status.DISABLED if disabled else Status.PARTIAL,
                        eligible_units=1, evaluated_units=0 if disabled else 1,
                        reason='Text patterns only; no history, ignored override, tracking or revocation verification.')
                    if c.capability == Capability.CREDENTIALS else c for c in current.capabilities))
        def category_coverage(cat):
            rules=[r for r in REGISTRY if r.category == cat or cat.value in r.secondary_categories]
            counts={c.rule_id:c for c in rule_coverages}
            evaluated=any(counts[r.id].evaluated_units for r in rules)
            disabled=bool(rules) and all(r.id in self.settings.disabled_rules for r in rules)
            return CategoryCoverage(category=cat,
                status=Status.PARTIAL if evaluated else Status.DISABLED if disabled else Status.UNSUPPORTED,
                reason='Limited static patterns only; unavailable sub-capabilities remain unreviewed.' if evaluated else 'All registered rules disabled.' if disabled else 'No applicable rule evaluations; unsupported/excluded/failed scope remains unreviewed.',
                rule_ids=tuple(r.id for r in rules))
        categories=tuple(category_coverage(cat) for cat in Category)
        from ..diagnostics import consolidate
        return replace(result, modules=tuple(modules), symbols=tuple(sorted(symbols, key=lambda s:s.id)), findings=tuple(sorted(findings,key=lambda f:f.id)),
            credential_candidates=tuple(candidates), semantic_observations=semantic_observations, evidence=tuple(sorted(evidence,key=lambda e:e.id)), diagnostics=consolidate(diagnostics),
            graph=replace(graph, metrics=tuple(metrics) + graph.metrics), limitations=LIMITATIONS + result.limitations[3:],
            coverage=replace(result.coverage, files=tuple(coverage), rules=tuple(rule_coverages), categories=categories, limitations=LIMITATIONS),
            inventory=replace(result.inventory, status=Status.PARTIAL if self.failures else result.inventory.status))
