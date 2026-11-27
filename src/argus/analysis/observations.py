"""Bounded projection of useful semantic facts, independent of risk evaluation."""
from ..models.semantic import SemanticObservation, ObservationKind as K, SemanticCertainty as C, TimeoutSettingState
from ..models.source import Evidence, SourceLocation
from ..models.base import Confidence, Provenance
from ..privacy import identity

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
            if site.operation=='http':
                state=site.timeout_state
                candidates.append((K.TIMEOUT,C.ESTABLISHED if site.limit or state=='disabled' else C.UNKNOWN,
                    'Timeout applicability: '+state+'. Network inactivity limits do not bound total request duration.',None))
            if site.operation=='database' and site.parameter_binding:
                candidates.append((K.SQL,C.OBSERVED,'Known DB-API parameter-binding argument supplied; SQL text assessed independently.',None))
            if site.operation=='database' and site.dynamic_sql:
                candidates.append((K.SQL,C.ESTABLISHED if site.sql_value in ('constant','integer') else C.POSSIBLE,
                    'Dynamic SQL construction; value classification: '+site.sql_value+('; possible identifier interpolation' if site.sql_identifier else '')+'. Parameter binding and identifier context require driver-specific review.',None))
            if site.loops and site.operation!='call' and site.upper_bound is not None:
                candidates.append((K.BOUND,C.ESTABLISHED,'Iteration domain bound in this context; other callers remain independent.',site.upper_bound))
            if site.operation in ('argument_bound','return_bound'):
                candidates.append((K.ARGUMENT if site.operation=='argument_bound' else K.RETURN,C.ESTABLISHED,'Collection size bound in this invocation context.',site.upper_bound))
            if site.operation=='invalidation':
                candidates.append((K.INVALIDATION,C.OBSERVED,'Known abstract safeguards invalidated by an operation with unmodeled effects.',None))
            for guard in site.safeguards:
                candidates.append((K.AUTHENTICATION,C.OBSERVED,'Framework registration observed: '+guard+'; identity validation and authorization unverified.',None))
            for kind,certainty,conclusion,bound in candidates:
                key=(site.line,site.owner,site.context,kind,conclusion,bound)
                if key in seen: continue
                if len(seen)>=LIMIT:
                    fact.semantic.incomplete=tuple(sorted(set(fact.semantic.incomplete+('semantic_observation_limit',))))
                    break
                seen.add(key)
                oid=identity('semantic',fid+':'+repr(key))
                eid=identity('evidence',oid)
                evidence.append(Evidence(id=eid,observation=conclusion,producer='argus.semantic',producer_version='2',
                    confidence=Confidence.MEDIUM,provenance=Provenance.OBSERVED if certainty==C.OBSERVED else Provenance.INFERRED,
                    locations=(SourceLocation(path=files[fid].path,start_line=site.line,start_column=1),)+tuple(SourceLocation(path=module_files[mid].path,start_line=line,start_column=1) for mid,line in site.origins if mid in module_files and (module_files[mid].path,line)!=(files[fid].path,site.line))))
                observations.append(SemanticObservation(id=oid,kind=kind,certainty=certainty,file_id=fid,scope_id=site.owner,
                    evidence_ids=(eid,),conclusion=conclusion,operation_id=site.operation_id,
                    timeout_state=TimeoutSettingState(site.timeout_state) if site.operation=='http' else None,context_lines=site.context,upper_bound=bound,
                    assumptions=ASSUMPTIONS,limitations=LIMITATIONS+fact.semantic.incomplete))
        counts[fid]=len(seen)
    # Existing evidence-backed call relationships already carry resolution and provenance.
    # Export only resolved local paths or paths connected to semantic operation scopes.
    scopes={o.scope_id for o in observations}
    for rel in graph.relationships:
        if rel.kind.value!='call' or not ({rel.source_id,rel.target_id}&scopes): continue
        fid=scope_files.get(rel.source_id)
        if fid is None: continue
        if counts.get(fid,0)>=LIMIT:
            fact=facts[fid]
            fact.semantic.incomplete=tuple(sorted(set(fact.semantic.incomplete+('semantic_observation_limit',))))
            continue
        counts[fid]=counts.get(fid,0)+1
        observations.append(SemanticObservation(id=identity('semantic',rel.id),kind=K.CALL,
            certainty=C.ESTABLISHED if rel.resolution.value=='resolved' else C.UNKNOWN,file_id=fid,scope_id=rel.source_id,
            evidence_ids=rel.evidence_ids,conclusion='Static call relationship: '+rel.resolution.value+'.',
            relationship_ids=(rel.id,),assumptions=ASSUMPTIONS,limitations=rel.limitations))
    return tuple(sorted(observations,key=lambda o:o.id))
