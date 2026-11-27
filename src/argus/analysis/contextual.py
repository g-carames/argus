"""Assess retained observations using source-free semantic facts and resolved calls."""
from dataclasses import replace
from .semantic import Site
from .semantic_contracts import FactState
from ..models.analysis import Resolution, RelationshipKind
from ..models.base import Confidence, Provenance, Severity
from ..models.semantic import Assessment, Safeguard, MitigationState as M
from ..models.source import Evidence, SourceLocation
from ..privacy import identity

LIMITATIONS = (
    'Bounded static analysis only; no runtime enforcement, authentication/authorization, validation effectiveness, isolation, caching, throttling, retries or shared agent budgets verified.',
    'Bounded Python and JS-family flow supports statically resolved module functions, arguments/returns and finite collection domains. Dynamic dispatch, exceptions, mutable global invariants, arbitrary aliases and scheduling remain incomplete.',
    'JavaScript uses a separate restricted Tree-sitter lowering; coercion, closures, prototypes, getters, destructuring, promise scheduling and general counter-loop bounds remain unavailable. Provider import plus suffix without a resolved receiver remains heuristic evidence.',
)


def investigate(facts_by_file, graph, evidence, files):
    """Return additional pattern candidates and assessments keyed by file/rule/line.

    No summary removes or resolves an original risk observation.
    """
    module_files={f.module.id:files[fid] for fid,f in facts_by_file.items()}
    sites={fid:f.semantic.sites for fid,f in facts_by_file.items() if f.semantic}
    summaries={owner:set(ops) for f in facts_by_file.values() if f.semantic for owner,ops in f.semantic.summaries.items()}
    locations={e.id:e.locations for e in evidence}
    calls=[r for r in graph.relationships if r.kind==RelationshipKind.CALL]
    paths={f.path:fid for fid,f in files.items()}
    site_index={}
    for fid,entries in sites.items():
        for s in entries:
            if s.operation=='call': site_index.setdefault((fid,s.owner,s.line),[]).append(s)
    calls_at={}
    for edge in calls:
        for eid in edge.evidence_ids:
            for loc in locations.get(eid,()):
                calls_at.setdefault((paths.get(loc.path),loc.start_line),[]).append(edge)
    additions={fid:set() for fid in sites}
    assessments={}
    gaps={fid:set(f.semantic.incomplete) for fid,f in facts_by_file.items() if f.semantic}
    # Bounded monotone operation summaries. Values/safeguards never propagate
    # through graph-only resolution, whose binding precision is more limited.
    expanded=0
    for depth in range(4):
        changed=False
        for edge in calls:
            if edge.resolution!=Resolution.RESOLVED: continue
            ops=summaries.get(edge.target_id,set())
            if not ops: continue
            before=summaries.setdefault(edge.source_id,set())
            if not ops<=before:
                if expanded>=256:
                    for fid in gaps: gaps[fid].add('semantic_graph_summary_limit')
                    break
                expanded+=1; before.update(ops); changed=True
        if not changed: break
    else:
        for fid in gaps: gaps[fid].add('semantic_graph_depth_limit')
    propagated=0
    for edge in calls:
        if edge.resolution!=Resolution.RESOLVED: continue
        ops=summaries.get(edge.target_id,set())
        for loc in locations.get(edge.evidence_ids[0],()):
            fid=paths.get(loc.path)
            if fid not in sites: continue
            originals=site_index.get((fid,edge.source_id,loc.start_line),())
            for site in originals:
                for op in ops:
                    if op in ('model','embedding','database') and site.loops:
                        # Graph summary does not carry a local safeguard.
                        if propagated>=4096:
                            gaps[fid].add('semantic_propagated_sites_limit')
                            continue
                        propagated+=1
                        sites[fid].append(replace(site,operation=op,limit=False,receiver_resolved=False,fact_state=FactState.POSSIBLE))
    for fid,entries in sites.items():
        grouped={}
        for site in entries:
            keys=[]
            if site.operation in ('model','embedding') and site.loops: keys.append('ARGUS-AI-002')
            if site.operation=='database' and site.loops: keys.append('ARGUS-COST-001')
            if site.operation=='execution' and site.tainted: keys.append('ARGUS-SEC-001')
            if site.operation=='database' and site.dynamic_sql and site.sql_value not in ('constant','integer'): keys.append('ARGUS-SEC-004')
            if not site.expanded:
                if site.operation=='http': keys.append('ARGUS-REL-003')
                if site.operation=='model': keys.append('ARGUS-AI-001')
            for key in keys:
                if key not in ('ARGUS-REL-003','ARGUS-AI-001') or not site.limit:
                    additions[fid].add((key,site.line))
                grouped.setdefault((key,site.line),[]).append(site)
        for (key,line),contexts in grouped.items():
            bounded=[s for s in contexts if s.upper_bound is not None] if key in ('ARGUS-AI-002','ARGUS-COST-001') else []
            limited=[s for s in contexts if s.limit] if key in ('ARGUS-REL-003','ARGUS-AI-001') else []
            framework=tuple(sorted({g for s in contexts for g in s.safeguards}))
            scope_gaps=facts_by_file[fid].semantic.scope_gaps
            affected=set().union(*(set(scope_gaps.get(s.owner,())) | set(s.incomplete) for s in contexts))
            # Module-wide resource/import/lowering gaps still apply everywhere.
            localized=set().union(*(set(v) for v in scope_gaps.values())) if scope_gaps else set()
            affected.update(gaps[fid]-localized)
            affected.update(scope_gaps.get(facts_by_file[fid].module.id,()))
            affected.update(g for g in gaps[fid] if 'limit' in g)
            # De-duplicate graph and interpreter contexts conservatively.
            applicable=bool(bounded) and len(bounded)==len(contexts) and not affected
            configured=any(s.configuration_observed for s in contexts)
            state=M.ESTABLISHED if applicable or limited and len(limited)==len(contexts) and not affected else M.PARTIAL if bounded or limited else M.UNVERIFIED if configured else M.INCOMPLETE if affected else M.NONE
            if not bounded and not limited and not configured and any(s.operation in ('model','embedding') and not s.receiver_resolved for s in contexts): state=M.UNDETERMINED
            if key in ('ARGUS-SEC-001','ARGUS-SEC-004'): state=M.UNSUPPORTED
            loc=SourceLocation(path=files[fid].path,start_line=line,start_column=1)
            eid=identity('evidence',fid+':context:'+key+':'+str(line))
            observation='Contextual investigation: '+str(len(contexts))+' statically analyzed operation contexts; '
            if bounded:
                observation+='iteration-domain upper bound at most '+str(max(s.upper_bound for s in bounded))+' in '+str(len(bounded))+' contexts. '
            if any(s.tainted for s in contexts): observation+='Possible input-source influence reaches this operation. '
            if limited: observation+=str(len(limited))+' contexts have an applicable positive numerical operation limit; other contexts remain independently assessed. '
            if any(s.sensitive for s in contexts): observation+='Possible environment-derived sensitive information reaches this operation; disclosure and redaction effectiveness are unverified. '
            if framework: observation+='Framework safeguard registration observed; identity validation, authorization and deployment enforcement remain unverified. '
            if any(s.receiver_resolved for s in contexts): observation+='A statically identified receiver contributes operation evidence. '
            origins=tuple(sorted({origin for s in contexts for origin in s.origins}))
            if origins: observation+='Value-flow provenance includes '+str(len(origins))+' source-free module/line origins. '
            if configured and not limited: observation+='Explicit limit configuration observed; a positive numerical value was not established. '
            observation+='Unknown or other callers are not protected by these bounds. No measured cost or runtime enforcement assertion.'
            evidence.append(Evidence(id=eid,observation=observation,producer='argus.semantic',producer_version='1',
                confidence=Confidence.MEDIUM,provenance=Provenance.INFERRED,locations=(loc,)+tuple(SourceLocation(path=module_files[mid].path,start_line=point,start_column=1) for mid,point in origins if mid in module_files and (module_files[mid].path,point)!=(loc.path,loc.start_line))))
            relevant={e.id:e for s in contexts for point in s.context+(s.line,) for e in calls_at.get((fid,point),())}
            related=tuple(sorted(relevant))
            unresolved=tuple(eid for eid in related if relevant[eid].resolution in (Resolution.UNRESOLVED,Resolution.AMBIGUOUS))
            guards=(Safeguard(kind='iteration_domain_bound',evidence_ids=(eid,),applicability=state,
                reason='Literal collection/range/slice bound in listed contexts; mutation and unknown calls invalidate known collection bounds.'),) if bounded else (Safeguard(kind='explicit_limit_configuration',evidence_ids=(eid,),applicability=M.UNVERIFIED,reason='Configuration supplied but a positive numerical limit could not be established.'),) if configured else ()
            if limited:
                guards+=(Safeguard(kind='positive_operation_limit',evidence_ids=(eid,),applicability=state,
                    reason='A positive numerical token/timeout limit applies in the listed contexts; unknown/external callers and runtime changes remain unverified.'),)
            for guard in framework:
                guards+=(Safeguard(kind=guard,evidence_ids=(eid,),applicability=M.UNVERIFIED,
                    reason='Known framework dependency/decorator observed; credential presence differs from identity verification and authorization. No finding is suppressed.'),)
            assessments[fid,key,line]=Assessment(initial_pattern=key,mitigation_state=state,
                supporting_evidence_ids=(eid,),contradictory_evidence_ids=(eid,) if bounded or limited else (),safeguards=guards,
                call_path_relationship_ids=related,unresolved_relationship_ids=unresolved,
                assumptions=('Static call bindings and standard Python builtins retain their ordinary meanings; no external monkey patching.',
                    'Recognized external operation candidates do not mutate the iteration domain; receiver identity and runtime behavior remain unverified.'),
                remaining_risk='Bounded iteration can still incur significant cost or latency; unconstrained callers and provider behavior remain unverified.',
                limitations=LIMITATIONS+tuple(sorted(affected)),
                severity_adjustment=None)
    return additions,assessments,gaps


def relationship_index(graph, evidence):
    locations={e.id:e.locations for e in evidence}
    result={}
    for r in graph.relationships:
        if r.kind!=RelationshipKind.CALL: continue
        for eid in r.evidence_ids:
            for loc in locations.get(eid,()):
                result.setdefault((loc.path,loc.start_line),[]).append(r)
    return result


def attach(finding, fid, assessments, related_index, gaps):
    key=(fid,finding.rule_id,finding.locations[0].start_line)
    assessment=assessments.get(key)
    if assessment is None:
        related=related_index.get((finding.locations[0].path,finding.locations[0].start_line),())
        assessment=Assessment(initial_pattern=finding.title,mitigation_state=M.INCOMPLETE if gaps.get(fid) else M.UNSUPPORTED,
            supporting_evidence_ids=finding.evidence_ids,
            call_path_relationship_ids=tuple(r.id for r in related),
            unresolved_relationship_ids=tuple(r.id for r in related if r.resolution in (Resolution.UNRESOLVED,Resolution.AMBIGUOUS)),
            limitations=LIMITATIONS+tuple(sorted(gaps.get(fid,()))))
    return replace(finding,assessment=assessment,
        severity=Severity.LOW if assessment.severity_adjustment else finding.severity)
