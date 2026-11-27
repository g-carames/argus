"""Bounded projection of useful semantic facts, independent of risk evaluation."""
from ..models.semantic import SemanticObservation, ObservationKind as K, SemanticCertainty as C, TimeoutSettingState
from ..models.source import Evidence, SourceLocation
from ..models.base import Confidence, Provenance
from ..privacy import identity
from ..models.analysis import RelationshipKind, Resolution
from .semantic_contracts import FactState

LIMIT = 4096
ASSUMPTIONS = ('Static bindings retain standard SDK/builtin meanings; external monkey patching is not modeled.',)
LIMITATIONS = ('Context-specific static facts; no runtime enforcement or comprehensive safeguard review.',)


def project(facts, files, graph, evidence):
    observations=[]
    counts={}
    scope_files={scope:fid for fid,f in facts.items() for scope in (f.module.id,)+tuple(s.id for s in f.symbols)}
    module_files={f.module.id:files[fid] for fid,f in facts.items()}
    for fid, fact in sorted(facts.items()):
        if not fact.semantic: continue
        seen=set()
        localized={g for values in fact.semantic.scope_gaps.values() for g in values}
        broad_gaps=(set(fact.semantic.incomplete)-localized | set(fact.semantic.scope_gaps.get(fact.module.id,())) |
            {g for g in fact.semantic.incomplete if 'limit' in g})
        for site in fact.semantic.sites:
            if len(seen)>=LIMIT:
                fact.semantic.incomplete=tuple(sorted(set(fact.semantic.incomplete+('semantic_observation_limit',))))
                break
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
                candidates.append((K.BOUND,C.ESTABLISHED,'Iteration domain bound in this context; other callers remain independent.',site.upper_bound))
            certainty=C.ESTABLISHED if site.fact_state==FactState.KNOWN else C.POSSIBLE if site.fact_state==FactState.POSSIBLE else C.UNKNOWN
            if site.operation in ('argument_bound','return_bound'):
                candidates.append((K.ARGUMENT if site.operation=='argument_bound' else K.RETURN,certainty,
                    'Collection size in this invocation context: '+('known upper bound.' if site.upper_bound is not None else 'unknown; no infinite-execution claim.'),site.upper_bound))
            if site.operation=='loop_domain':
                candidates.append((K.DOMAIN,certainty,'Iteration domain: '+('known upper bound in this supported context.' if site.upper_bound is not None else 'unknown; no infinite-execution claim.'),site.upper_bound))
            if site.operation=='assignment':
                candidates.append((K.ASSIGNMENT,certainty,'Assignment value fact; '+('collection upper bound established.' if site.upper_bound is not None else 'collection bound unknown.'),site.upper_bound))
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
                key=(site.line,site.column,site.owner,site.context_id,site.callsite_id,site.value_id,site.formal_id,site.actual_id,site.result_id,site.candidate_target_ids,site.fact_state,site.origins,site.exit_channels,kind,conclusion,bound)
                if key in seen: continue
                if len(seen)>=LIMIT:
                    fact.semantic.incomplete=tuple(sorted(set(fact.semantic.incomplete+('semantic_observation_limit',))))
                    break
                seen.add(key)
                oid=identity('semantic',fid+':'+repr(key))
                eid=identity('evidence',oid)
                evidence.append(Evidence(id=eid,observation=conclusion,producer='argus.semantic',producer_version='2',
                    confidence=Confidence.MEDIUM,provenance=Provenance.OBSERVED if certainty==C.OBSERVED else Provenance.INFERRED,
                    locations=(SourceLocation(path=files[fid].path,start_line=site.line,start_column=site.column),)+tuple(SourceLocation(path=module_files[mid].path,start_line=line,start_column=1) for mid,line in site.origins if mid in module_files and (module_files[mid].path,line)!=(files[fid].path,site.line))))
                observations.append(SemanticObservation(id=oid,kind=kind,certainty=certainty,file_id=fid,scope_id=site.owner,
                    evidence_ids=(eid,),conclusion=conclusion,operation_id=site.operation_id,
                    timeout_state=TimeoutSettingState(site.timeout_state) if site.operation=='http' else None,context_lines=site.context,upper_bound=bound,
                    assumptions=ASSUMPTIONS,limitations=LIMITATIONS+tuple(sorted(broad_gaps|set(site.incomplete)|set(fact.semantic.scope_gaps.get(site.owner,())))),
                    context_id=site.context_id,callsite_id=site.callsite_id,call_path_ids=site.call_path_ids,
                    formal_id=site.formal_id,actual_id=site.actual_id,origin_value_id=site.origin_value_id,result_id=site.result_id,value_id=site.value_id,
                    argument_position=site.argument_position,binding_kind=site.binding_kind,
                    candidate_target_ids=site.candidate_target_ids,fact_state='incomplete' if kind==K.INCOMPLETE else site.fact_state.value,
                    exit_channels=tuple(k.value for k in site.exit_channels)))
        counts[fid]=len(seen)
    # Existing evidence-backed call relationships already carry resolution and provenance.
    # Invocation syntax remains useful even when no risk or resolved target exists.
    for rel in graph.relationships:
        if rel.kind!=RelationshipKind.CALL: continue
        fid=scope_files.get(rel.source_id)
        if fid is None: continue
        if counts.get(fid,0)>=LIMIT:
            fact=facts[fid]
            fact.semantic.incomplete=tuple(sorted(set(fact.semantic.incomplete+('semantic_observation_limit',))))
            continue
        counts[fid]=counts.get(fid,0)+1
        observations.append(SemanticObservation(id=identity('semantic',rel.id),kind=K.CALL,
            certainty=C.ESTABLISHED if rel.resolution==Resolution.RESOLVED else C.POSSIBLE if rel.resolution==Resolution.AMBIGUOUS else C.UNKNOWN,file_id=fid,scope_id=rel.source_id,
            evidence_ids=rel.evidence_ids,conclusion='Static call relationship: '+rel.resolution.value+'.',
            relationship_ids=(rel.id,),assumptions=ASSUMPTIONS,limitations=rel.limitations,
            callsite_id=rel.callsite_id,candidate_target_ids=rel.candidate_target_ids,
            fact_state='known' if rel.resolution==Resolution.RESOLVED else 'possible' if rel.resolution==Resolution.AMBIGUOUS else 'unknown'))
    return tuple(sorted(observations,key=lambda o:o.id))
