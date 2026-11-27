"""Bounded projection of useful semantic facts, independent of risk evaluation."""
from ..models.semantic import SemanticObservation, ObservationKind as K, SemanticCertainty as C, TimeoutSettingState
from ..models.source import Evidence, SourceLocation
from ..models.base import Confidence, Provenance
from ..privacy import identity
from ..models.analysis import RelationshipKind, Resolution
from .semantic_contracts import FactState
from .semantic import Site
from dataclasses import replace

LIMIT = 4096
ASSUMPTIONS = ('Static bindings retain standard SDK/builtin meanings; external monkey patching is not modeled.',)
LIMITATIONS = ('Context-specific static facts; no runtime enforcement or comprehensive safeguard review.',)


def project(facts, files, graph, evidence):
    observations=[]
    drafts={}
    gap_locations={}
    gap_repeats={}
    broad_by_file={}
    evidence_by_id={e.id:e for e in evidence}
    scope_files={scope:fid for fid,f in facts.items() for scope in (f.module.id,)+tuple(s.id for s in f.symbols)}
    module_files={f.module.id:files[fid] for fid,f in facts.items()}
    for fid, fact in sorted(facts.items()):
        if not fact.semantic: continue
        seen=set()
        localized={g for values in fact.semantic.scope_gaps.values() for g in values}
        broad_gaps=(set(fact.semantic.incomplete)-localized | set(fact.semantic.scope_gaps.get(fact.module.id,())) |
            {g for g in fact.semantic.incomplete if 'limit' in g})
        broad_by_file[fid]=broad_gaps
        for site in fact.semantic.sites:
            candidates=[]
            if site.operation=='mock_operation':
                candidates.append((K.OPERATION,C.OBSERVED,'Known unittest.mock receiver; no genuine SDK operation established.',None))
            if site.operation in ('model','embedding'):
                candidates.append((K.OPERATION,C.ESTABLISHED if site.receiver_resolved else C.POSSIBLE,
                    'SDK operation binding established.' if site.receiver_resolved else 'Operation suffix/import candidate; receiver identity unresolved.',None))
            if site.operation in ('http','database','execution'):
                candidates.append((K.OPERATION,C.POSSIBLE if site.fact_state==FactState.POSSIBLE or site.operation=='database' and not site.receiver_resolved else C.OBSERVED,
                    'Static operation observation: '+site.operation+'; applicability and runtime behavior remain scoped.',None))
            if site.operation=='http':
                state=site.timeout_state
                candidates.append((K.TIMEOUT,C.ESTABLISHED if site.limit or state=='disabled' else C.UNKNOWN,
                    'Timeout applicability: '+state+'. Network inactivity limits do not bound total request duration.',None))
            if site.operation=='database' and site.parameter_binding:
                candidates.append((K.SQL,C.OBSERVED,'Known DB-API parameter-binding argument supplied; SQL text assessed independently.',None))
            if site.operation=='database' and site.dynamic_sql:
                candidates.append((K.SQL,C.ESTABLISHED if site.sql_value in ('constant','integer') else C.POSSIBLE,
                    'Dynamic SQL construction; value classification: '+site.sql_value+('; possible identifier interpolation' if site.sql_identifier else '')+'. Parameter binding and identifier context require driver-specific review.',None))
            if site.loops and site.upper_bound is not None and site.operation!='loop_domain':
                candidates.append((K.BOUND,C.ESTABLISHED if site.bound_supported else C.POSSIBLE,'Iteration domain bound in this context; other callers remain independent.',site.upper_bound))
            certainty=C.ESTABLISHED if site.fact_state==FactState.KNOWN else C.POSSIBLE if site.fact_state==FactState.POSSIBLE else C.UNKNOWN
            if site.upper_bound is not None and not site.bound_supported:certainty=C.POSSIBLE
            if site.operation in ('argument_bound','return_bound'):
                candidates.append((K.ARGUMENT if site.operation=='argument_bound' else K.RETURN,certainty,
                    ('Function-body collection size: ' if site.observation_scope=='function_body' else 'Effective invocation collection size: ')+('verified upper bound.' if site.upper_bound is not None and site.bound_supported else 'unverified slice-parameter hint; result cardinality and receiver protocol are unresolved.' if site.upper_bound is not None else 'unknown; no infinite-execution claim.'),site.upper_bound))
            if site.operation=='loop_domain':
                candidates.append((K.DOMAIN,certainty,'Iteration domain: '+('known upper bound in this supported context.' if site.upper_bound is not None else 'unknown; no infinite-execution claim.'),site.upper_bound))
            if site.operation=='assignment':
                candidates.append((K.ASSIGNMENT,certainty,'Assignment value fact; '+('collection upper bound established.' if site.upper_bound is not None and site.bound_supported else 'unverified slice-parameter hint; collection cardinality unresolved.' if site.upper_bound is not None else 'collection bound unknown.'),site.upper_bound))
            if site.operation=='receiver_resolution':
                candidates.append((K.RECEIVER,certainty,'Static receiver/call target evidence; alternatives do not establish a definite invocation.',None))
            if site.operation=='call' and site.loops and site.upper_bound is None:
                candidates.append((K.DOMAIN,C.UNKNOWN,'Iteration domain bound unknown; this does not establish infinite execution.',None))
            for gap in tuple(sorted(broad_gaps | set(site.incomplete) | set(fact.semantic.scope_gaps.get(site.owner,())))):
                candidates.append((K.INCOMPLETE,C.UNKNOWN,'Incomplete semantic analysis in this scope: '+gap+'.',None))
            if site.operation=='invalidation':
                candidates.append((K.INVALIDATION,C.OBSERVED,'Known abstract safeguards invalidated by an operation with unmodeled effects.',None))
            for guard in site.safeguards:
                candidates.append((K.AUTHENTICATION,C.OBSERVED,'Framework registration observed: '+guard+'; identity validation and authorization unverified.',None))
            for kind,certainty,conclusion,bound in candidates:
                key=(site.line,site.column,site.owner,site.context_id,site.callsite_id,site.value_id,site.formal_id,site.actual_id,site.result_id,site.candidate_target_ids,site.fact_state,site.origins,site.exit_channels,site.observation_scope,kind,conclusion,bound)
                if kind==K.INCOMPLETE:
                    key=(site.owner,site.context_id,kind,conclusion)
                    group=(fid,key)
                    gap_locations.setdefault(group,set()).add((site.line,site.column))
                    gap_repeats[fid]=gap_repeats.get(fid,0)+1
                if key in seen:continue
                seen.add(key)
                drafts.setdefault(fid,[]).append((site,kind,certainty,conclusion,bound,key,None))
    # Existing evidence-backed call relationships already carry resolution and provenance.
    # Invocation syntax remains useful even when no risk or resolved target exists.
    for rel in graph.relationships:
        if rel.kind!=RelationshipKind.CALL: continue
        fid=scope_files.get(rel.source_id)
        if fid is None: continue
        locations=[loc for eid in rel.evidence_ids for loc in evidence_by_id[eid].locations]
        loc=locations[0]
        site=Site(loc.start_line,rel.source_id,'call',column=loc.start_column,callsite_id=rel.callsite_id,candidate_target_ids=rel.candidate_target_ids)
        drafts.setdefault(fid,[]).append((site,K.CALL,C.ESTABLISHED if rel.resolution==Resolution.RESOLVED else C.POSSIBLE if rel.resolution==Resolution.AMBIGUOUS else C.UNKNOWN,
            'Static call relationship: '+rel.resolution.value+'.',None,('relationship',rel.id),rel))
    priority={K.CALL:0,K.RETURN:1,K.ARGUMENT:2,K.BOUND:2,K.DOMAIN:3,K.OPERATION:3,K.TIMEOUT:3,K.SQL:3,K.RECEIVER:3,K.AUTHENTICATION:3,K.INVALIDATION:3,K.INCOMPLETE:4,K.ASSIGNMENT:5}
    for fid,fact in sorted(facts.items()):
        if not fact.semantic:continue
        entries=sorted(drafts.get(fid,()),key=lambda d:(priority[d[1]],repr(d[5])))
        requested=len(entries);selected=entries[:LIMIT-1] if requested>LIMIT else entries
        omitted=entries[len(selected):]
        accounting=dict(requested_observations=requested,emitted_observations=len(selected)+(1 if omitted else 0),omitted_observations=len(omitted),
            consolidated_gap_occurrences=max(0,gap_repeats.get(fid,0)-sum(d[1]==K.INCOMPLETE for d in entries)),
            omitted_kinds=tuple(sorted({d[1].value for d in omitted})),
            omitted_scope_ids=tuple(sorted({d[0].owner for d in omitted})),
            omitted_context_ids=tuple(sorted({d[0].context_id for d in omitted if d[0].context_id}|{ctx for d in omitted if d[6] for ctx in d[6].context_ids})),
            omitted_locations=tuple(SourceLocation(path=files[fid].path,start_line=line,start_column=col) for line,col in sorted({(d[0].line,d[0].column) for d in omitted})))
        fact.semantic.projection_accounting=accounting
        if omitted:
            fact.semantic.incomplete=tuple(sorted(set(fact.semantic.incomplete+('semantic_observation_limit',))))
            summary=Site(1,fact.module.id,'projection_summary',fact_state=FactState.INCOMPLETE,observation_scope='projection_summary')
            selected.append((summary,K.INCOMPLETE,C.UNKNOWN,'Projection truncated: '+str(len(omitted))+' distinct records omitted; kinds/scopes/contexts/locations are in semantic_analysis accounting.',None,('projection_limit',fid),None))
        for site,kind,certainty,conclusion,bound,key,rel in selected:
            if kind==K.INCOMPLETE:
                owner_location=next((symbol.location for symbol in fact.symbols if symbol.id==site.owner),None)
                site=replace(site,line=owner_location.start_line if owner_location else 1,column=owner_location.start_column if owner_location else 1,formal_id=None,actual_id=None,result_id=None,value_id=None,origin_value_id=None,upper_bound=None,lower_bound=None,finite=False,operation_upper_bound=None,exit_channels=())
            oid=identity('semantic',rel.id) if rel else identity('semantic',fid+':'+repr(key))
            if rel:
                evidence_ids=rel.evidence_ids;limitations=rel.limitations;relationship_ids=(rel.id,)
            else:
                eid=identity('evidence',oid)
                locations={(files[fid].path,site.line,site.column)}
                if kind==K.INCOMPLETE:
                    locations.update((files[fid].path,line,col) for line,col in gap_locations.get((fid,key),()))
                locations.update((module_files[mid].path,line,1) for mid,line in site.origins if mid in module_files)
                primary=(files[fid].path,site.line,site.column)
                ordered=[primary]+sorted(locations-{primary})
                evidence.append(Evidence(id=eid,observation=conclusion,producer='argus.semantic',producer_version='3',
                    confidence=Confidence.MEDIUM,provenance=Provenance.OBSERVED if certainty==C.OBSERVED else Provenance.INFERRED,
                    locations=tuple(SourceLocation(path=path,start_line=line,start_column=col) for path,line,col in ordered)))
                evidence_ids=(eid,);relationship_ids=()
                scope_gaps=set(fact.semantic.scope_gaps.get(site.owner,()))|set(site.incomplete)
                limitations=LIMITATIONS+tuple(sorted(scope_gaps|broad_by_file.get(fid,set())))
            observations.append(SemanticObservation(id=oid,kind=kind,certainty=certainty,file_id=fid,scope_id=site.owner,
                evidence_ids=evidence_ids,relationship_ids=relationship_ids,conclusion=conclusion,operation_id=site.operation_id,
                timeout_state=TimeoutSettingState(site.timeout_state) if site.operation=='http' else None,
                context_lines=site.context,upper_bound=bound,assumptions=ASSUMPTIONS,limitations=limitations,
                context_id=site.context_id,callsite_id=site.callsite_id,call_path_ids=site.call_path_ids,
                formal_id=site.formal_id,actual_id=site.actual_id,origin_value_id=site.origin_value_id,result_id=site.result_id,value_id=site.value_id,
                argument_position=site.argument_position,binding_kind=site.binding_kind,candidate_target_ids=site.candidate_target_ids,
                fact_state='incomplete' if kind==K.INCOMPLETE else 'known' if rel and rel.resolution==Resolution.RESOLVED else 'possible' if rel and rel.resolution==Resolution.AMBIGUOUS else 'unknown' if rel or certainty==C.UNKNOWN else 'possible' if certainty==C.POSSIBLE else site.fact_state.value,
                exit_channels=tuple(k.value for k in site.exit_channels),bound_supported=site.bound_supported,lower_bound=site.lower_bound,finite=site.finite,
                operation_upper_bound=site.operation_upper_bound,iteration_upper_bound=site.upper_bound if site.loops else None,conditional_execution=site.conditional,
                observation_scope='scope_gap' if kind==K.INCOMPLETE and site.observation_scope!='projection_summary' else site.observation_scope,
                reachability=site.reachability,constrained_value_id=site.constrained_value_id,constraint_applicability=site.constraint_applicability,
                constraint_locations=tuple(SourceLocation(path=module_files[mid].path,start_line=line,start_column=1) for mid,line in site.constraint_origins if mid in module_files)))
    return tuple(sorted(observations,key=lambda o:o.id))
