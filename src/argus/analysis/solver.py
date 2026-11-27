"""Deterministic bounded fixed-point execution of the shared control graph.

The existing expression interpreter performs transfers. No target code executes.
Incoming states join at blocks; expanding loop heads widen after three updates.
Facts from repeated visits are joined before they become public guarantees.
"""
import ast
from collections import deque
from dataclasses import replace
from .abstract import State, Effect, EffectKind, Interval
from .control_flow import build, EdgeKind as E, exception_names, matches
from .predicates import refine
from .semantic_contracts import Outcomes, Point, FactState, join_returns


def solve(flow,body,env):
    from .semantic import UNKNOWN, Value, Site, column
    graph=flow.cfg_cache.get(id(body))
    if graph is None:
        remaining=flow.b.cfg_nodes-flow.cfg_nodes_used
        if remaining<=0:
            flow.gap('semantic_cfg_nodes_limit');flow.last_normal=True;flow.last_exceptions=('?',)
            return Outcomes(True,None,False,True)
        graph=build(body,remaining,flow.language=='python');flow.cfg_nodes_used+=graph.budget_used;flow.cfg_cache[id(body)]=graph
        graph.module_id=flow.facts.module.id;graph.owner_id=flow.owner
        from ..privacy import identity
        for block in graph.blocks:
            block.id=identity('block',repr((graph.module_id,graph.owner_id,block.kind,block.index,block.source.lineno if block.source is not None else None,column(block.source) if block.source is not None else None)))
    if graph.truncated:flow.gap('semantic_cfg_nodes_limit')
    incoming={graph.entry:State(env.copy(),graph.truncated)};queue=deque([graph.entry]);queued={graph.entry};visits={}
    exits={};base_loops=flow.loop_bounds;base_origins=flow.loop_origins;base_conditional=flow.conditional
    start=len(flow.result.sites);steps=0;widenings=0;exhausted=False
    def send(target,state):
        nonlocal widenings
        previous=incoming.get(target)
        loophead=graph.blocks[target].kind=='loop_test'
        widening=loophead and visits.get(target,0)>=3
        merged=state if previous is None else previous.join(state,UNKNOWN,widening)
        if previous is None or merged!=previous:
            if widening:widenings+=1
            incoming[target]=merged
            if target not in queued:queue.append(target);queued.add(target)
    def evaluate(expr,state):
        flow.expression_exceptions=();flow.expression_normal=True
        value=flow.evaluate(expr,state.env)
        if value.incomplete_result:
            state.incomplete=True;flow.gap('semantic_callee_or_expression_incomplete')
        return value,flow.expression_normal,flow.expression_exceptions
    try:
        while queue:
            index=queue.popleft();queued.remove(index);block=graph.blocks[index];state=incoming[index].copy()
            steps+=1;visits[index]=visits.get(index,0)+1
            if not flow.spend('iterations'):
                flow.gap('semantic_worklist_limit');exhausted=True;break
            flow.loop_bounds=base_loops+tuple(state.env.get('@loop:'+str(k),UNKNOWN).size for k in block.loops)
            flow.loop_origins=tuple(sorted(set(base_origins)|{o for k in block.loops for o in state.env.get('@loop:'+str(k),UNKNOWN).origins+state.env.get('@loop:'+str(k),UNKNOWN).constraint_origins}))
            flow.conditional=base_conditional or state.conditional
            flow.current_loop_ids=block.loops;flow.current_base_loops=base_loops
            flow.current_constraints=tuple(sorted({o for k in block.loops for o in state.env.get('@loop:'+str(k),UNKNOWN).constraint_origins}))
            guarded=[state.env.get('@loop:'+str(k),UNKNOWN) for k in block.loops if state.env.get('@loop:'+str(k),UNKNOWN).constraint_origins]
            ids={v.constraint_value_id for v in guarded}
            flow.current_constraint_value_id=next(iter(ids)) if len(ids)==1 else None
            flow.current_constraint_applicability='all_reaching_states' if guarded and all(v.constraint_must and v.size is not None for v in guarded) and flow.current_constraint_value_id else 'some_reaching_states' if guarded else 'unverified'
            flow.current_incomplete=state.incomplete
            n=block.source;kind=block.kind
            if flow.owner==flow.facts.module.id:
                flow.globals={k:v for k,v in state.env.items() if not k.startswith('@') and v.size is None}
            normal=True;exceptions=()
            if kind.endswith('_exit'):
                old=exits.get(kind);exits[kind]=state if old is None else old.join(state,UNKNOWN)
                continue
            if kind=='branch':
                if visits[index]==1 and not flow.spend('paths'):
                    flow.gap('semantic_worklist_limit');exhausted=True;break
                predicate,normal,exceptions=evaluate(n.test,state)
                exceptions=tuple(sorted(set(exceptions+flow.truth_effect(predicate,state.env,n.lineno))))
                for edge in block.edges:
                    if edge.kind in (E.TRUE,E.FALSE) and normal:
                        branch=refine(n.test,state.env,edge.kind==E.TRUE,flow)
                        if branch is not None:
                            candidate=state.copy();candidate.env=branch;candidate.conditional=True;send(edge.target,candidate)
                    elif edge.kind==E.EXCEPTION and exceptions:
                        candidate=state.copy();candidate.exception=exceptions;candidate.pending=None;send(edge.target,candidate)
                continue
            if kind=='loop_entry':
                if isinstance(n,ast.While):
                    maximum=flow.counter_bound(n,state.env)
                    domain=Value('possible',size=maximum,size_verified=maximum is not None,collection_kind='counter',finite=maximum is not None)
                else:domain,normal,exceptions=evaluate(n.iter,state)
                source_domain=domain
                if not domain.size_verified:domain=replace(domain,size=None)
                # Known domains are invalidated if any body effect may mutate an
                # alias. No purity inference from repository-local function names.
                if domain.collection_kind not in ('range','tuple') and any(isinstance(x,ast.Call) and flow.call_may_mutate(x,state.env) for statement in n.body for x in ast.walk(statement)) or isinstance(n,ast.AsyncFor):
                    domain=replace(domain,size=None,finite=False,constraint_origins=())
                header=block.edges[0].target
                state.env['@loop:'+str(header)]=domain
                state.env['@iteration:'+str(header)]=Value('definite',number=0,minimum=0,maximum=0,numeric=True,integer=True)
                if isinstance(n,ast.AsyncFor):
                    state.incomplete=True;flow.gap('semantic_async_iteration_incomplete')
                flow.result.sites.append(Site(n.lineno,flow.owner,'loop_domain',column=column(n),upper_bound=domain.size,
                    lower_bound=domain.size_lower,finite=domain.finite,origins=domain.origins+domain.constraint_origins,
                    constraint_origins=domain.constraint_origins,constrained_value_id=domain.constraint_value_id,
                    constraint_applicability='all_reaching_states' if domain.constraint_must and domain.constraint_value_id and domain.size is not None else 'some_reaching_states' if domain.constraint_origins else 'unverified',fact_state=FactState.KNOWN if domain.size is not None else FactState.UNKNOWN))
            elif kind=='loop_test':
                domain=state.env.get('@loop:'+str(index),UNKNOWN)
                for edge in block.edges:
                    if edge.kind==E.EXCEPTION:continue
                    candidate=state.copy();candidate.conditional=True
                    if isinstance(n,ast.While):
                        predicate,normal,exceptions=evaluate(n.test,candidate)
                        exceptions=tuple(sorted(set(exceptions+flow.truth_effect(predicate,candidate.env,n.lineno))))
                        if not normal:continue
                        branch=refine(n.test,candidate.env,edge.kind==E.TRUE,flow)
                        if branch is None:continue
                        candidate.env=branch
                    else:
                        count=state.env.get('@iteration:'+str(index),UNKNOWN)
                        interval=Interval(count.minimum,count.maximum).meet(Interval(None,domain.size-1) if edge.kind==E.TRUE and domain.size is not None else Interval(domain.size_lower or 0,None) if edge.kind==E.FALSE else Interval())
                        if interval is None:continue
                        candidate.env['@iteration:'+str(index)]=replace(count,minimum=interval.lower,maximum=interval.upper,
                            number=interval.lower if interval.lower==interval.upper else None)
                        if edge.kind==E.TRUE and isinstance(n.target,ast.Name):candidate.env[n.target.id]=Value(taint=domain.taint)
                    send(edge.target,candidate)
                if exceptions:
                    candidate=state.copy();candidate.exception=exceptions
                    send(next(e.target for e in block.edges if e.kind==E.EXCEPTION),candidate)
                continue
            elif kind=='back' and not isinstance(n,ast.While):
                key='@iteration:'+str(block.loops[-1]);count=state.env.get(key,UNKNOWN)
                state.env[key]=replace(count,number=count.number+1 if count.number is not None else None,minimum=count.minimum+1 if count.minimum is not None else None,maximum=count.maximum+1 if count.maximum is not None else None)
            elif kind=='return':
                value,normal,exceptions=evaluate(n.value,state);state.pending=value
            elif kind=='raise':
                # Explicit builtin exception construction is not an unknown call
                # mutation. Custom exception expressions remain unresolved.
                expr=n.exc.func if isinstance(n.exc,ast.Call) else n.exc
                exceptions=exception_names(expr)
                if expr is None:exceptions=state.active_exception or state.exception or ('?',)
                if any(name in state.env or name in flow.aliases or name in flow.functions or name in flow.classes for name in exceptions):exceptions=('?',)
                if isinstance(n.exc,ast.Call) and exceptions!=('?',):
                    possible=set();constructs=True
                    for argument in n.exc.args+[k.value for k in n.exc.keywords]:
                        _,continues,raised=evaluate(argument,state);possible.update(raised)
                        if not continues:constructs=False;break
                    if constructs:possible.update(exceptions)
                    exceptions=tuple(sorted(possible))
                elif exceptions==('?',) and n.exc is not None:
                    _,_,raised=evaluate(n.exc,state);exceptions=tuple(sorted(set(exceptions+raised)))
                if n.cause is not None:
                    _,continues,raised=evaluate(n.cause,state)
                    exceptions=tuple(sorted(set(exceptions+raised))) if continues else raised
                state.exception=exceptions;state.pending=None;normal=False
            elif kind=='dispatch':
                remaining=set(state.exception or ('?',))
                for edge in block.edges:
                    if edge.kind==E.UNHANDLED:
                        if remaining:
                            candidate=state.copy();candidate.exception=tuple(sorted(remaining));send(edge.target,candidate)
                        continue
                    accepted=set();definite=set()
                    for actual in remaining:
                        choices=[matches(actual,expected) if expected not in state.env and expected not in flow.aliases and expected not in flow.classes and expected not in flow.functions else None for expected in edge.exception_types]
                        if True in choices:accepted.add(actual);definite.add(actual)
                        elif None in choices:accepted.add(actual)
                    if accepted:
                        candidate=state.copy();candidate.exception=tuple(sorted(accepted))
                        if '?' in edge.exception_types or any(t in state.env or t in flow.aliases or t in flow.classes or t in flow.functions for t in edge.exception_types):
                            candidate.incomplete=True;flow.gap('semantic_exception_matching_incomplete')
                        send(edge.target,candidate)
                    remaining-=definite
                continue
            elif kind=='handler':
                state.active_exception=tuple(sorted(set(state.active_exception+state.exception)))
                if n.name:state.env[n.name]=UNKNOWN
                state.exception=()
            elif kind.startswith('finally_'):
                key='@finally:'+str(index)
                state.env[key]=state.pending or UNKNOWN
                # Pending exception is retained privately as a source-free set.
                state.saved_exceptions[index]=state.exception
                if kind=='finally_raise':state.active_exception=tuple(sorted(set(state.active_exception+state.exception)))
                state.pending=None;state.exception=()
                # Resume nodes are specific to this compiled finally path.

            elif kind.startswith('resume_'):
                # Builder annotates each resume with its corresponding save node.
                saved=block.save
                if kind=='resume_return':state.pending=state.env.get('@finally:'+str(saved),UNKNOWN)
                elif kind=='resume_raise':state.exception=state.saved_exceptions.get(saved,('?',));normal=False;exceptions=state.exception
            elif kind=='unsupported':
                state.incomplete=True;flow.gap('semantic_unsupported_control_or_statement')
                # Potential-only nested discovery, using the same evaluator, with
                # no positive constraints or definite reachability claim.
                def discover(item):
                    if item is not n and isinstance(item,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda)):return
                    if isinstance(item,(ast.For,ast.AsyncFor,ast.While)):
                        saved_bounds=flow.loop_bounds;flow.loop_bounds=saved_bounds+(None,)
                        for child in item.body+item.orelse:discover(child)
                        flow.loop_bounds=saved_bounds
                        return
                    expressions=[]
                    if isinstance(item,ast.Expr):expressions=[item.value]
                    elif isinstance(item,(ast.Assign,ast.AnnAssign,ast.Return)):expressions=[item.value] if item.value else []
                    elif isinstance(item,ast.withitem):expressions=[item.context_expr]
                    for expression in expressions:
                        previous=flow.current_incomplete;flow.current_incomplete=True
                        evaluate(expression,state);flow.current_incomplete=previous
                    if not expressions:
                        for child in ast.iter_child_nodes(item):discover(child)
                old_owner=flow.owner
                if getattr(n,'argus_lexical_scope',False):
                    flow.owner=flow.owners.get((n.lineno,column(n)),flow.owner)
                discover(n)
                flow.owner=old_owner
                flow.apply_effect(Effect(EffectKind.UNSUPPORTED,line=n.lineno),state.env)
            elif kind=='operation':
                if isinstance(n,(ast.Assign,ast.AnnAssign)):
                    value,normal,exceptions=evaluate(n.value,state)
                    for target in (n.targets if isinstance(n,ast.Assign) else [n.target]) if normal else []:
                        if isinstance(target,ast.Name):
                            point=Point(flow.facts.module.id,flow.owner,n.lineno,column(target))
                            effect_kind=EffectKind.SCALAR if value.numeric or value.boolean else EffectKind.FRESH if isinstance(n.value,(ast.List,ast.Tuple,ast.Set,ast.Dict,ast.Subscript)) else EffectKind.REPLACE
                            flow.apply_effect(Effect(effect_kind,(state.env.get(target.id,UNKNOWN).value_id or '',),n.lineno),state.env)
                            state.env[target.id]=replace(value,value_id=point.key('value'),normal_result=True,exception_types=())
                            flow.result.sites.append(Site(n.lineno,flow.owner,'assignment',column=point.column,upper_bound=value.size,bound_supported=value.size_verified,
                                lower_bound=value.size_lower,finite=value.finite,origins=value.origins,constraint_origins=value.constraint_origins,
                                result_id=value.result_id,origin_value_id=value.value_id,value_id=point.key('value'),
                                fact_state=FactState.KNOWN if value.size is not None else FactState.UNKNOWN))
                        elif isinstance(target,ast.Attribute) and flow.raw_name(target).startswith('self.'):
                            flow.apply_effect(Effect(EffectKind.FRESH if flow.fresh_receiver_scope else EffectKind.ATTRIBUTE,line=n.lineno),state.env)
                            state.env[flow.raw_name(target)]=replace(value,normal_result=True,exception_types=())
                        else:flow.apply_effect(Effect(EffectKind.COLLECTION,line=n.lineno),state.env)
                elif isinstance(n,ast.AugAssign):
                    value,normal,exceptions=evaluate(n.value,state)
                    if isinstance(n.target,ast.Name):
                        old=state.env.get(n.target.id,UNKNOWN)
                        if flow.language=='python' and old.numeric and value.numeric and isinstance(n.op,(ast.Add,ast.Sub)):
                            sign=1 if isinstance(n.op,ast.Add) else -1
                            lo=value.minimum if sign==1 else (-value.maximum if value.maximum is not None else None)
                            hi=value.maximum if sign==1 else (-value.minimum if value.minimum is not None else None)
                            minimum=old.minimum+lo if old.minimum is not None and lo is not None else None
                            maximum=old.maximum+hi if old.maximum is not None and hi is not None else None
                            state.env[n.target.id]=Value('possible',minimum=minimum,maximum=maximum,numeric=True,integer=old.integer and value.integer,
                                number=minimum if minimum==maximum else None,value_id=Point(flow.facts.module.id,flow.owner,n.lineno,column(n)).key('value'))
                        else:
                            flow.apply_effect(Effect(EffectKind.COLLECTION,line=n.lineno),state.env);state.env[n.target.id]=UNKNOWN
                    else:flow.apply_effect(Effect(EffectKind.ATTRIBUTE,line=n.lineno),state.env)
                elif isinstance(n,ast.Expr):_,normal,exceptions=evaluate(n.value,state)
            for edge in block.edges:
                if edge.kind==E.EXCEPTION:
                    if exceptions:
                        candidate=state.copy();candidate.exception=exceptions;candidate.pending=None;send(edge.target,candidate)
                elif kind=='raise' or kind=='resume_raise':
                    if edge.kind!=E.EXCEPTION:send(edge.target,state)
                elif normal:send(edge.target,state)
    finally:
        flow.loop_bounds=base_loops;flow.loop_origins=base_origins;flow.conditional=base_conditional
        flow.current_constraints=();flow.current_constraint_value_id=None;flow.current_constraint_applicability='unverified';flow.current_incomplete=False;flow.current_loop_ids=();flow.current_base_loops=()
    unfinished=exhausted or bool(queue) or graph.truncated
    incomplete=unfinished or any(s.incomplete for s in exits.values())
    normal_state=exits.get('normal_exit')
    if normal_state is not None:env.clear();env.update({k:v for k,v in normal_state.env.items() if not k.startswith('@')})
    return_state=exits.get('return_exit');raised_state=exits.get('raise_exit')
    returned=return_state.pending if return_state else None

    flow.solver_stats['worklist_steps']+=steps;flow.solver_stats['widenings']+=widenings
    flow.solver_stats['reachable_blocks']+=len(incoming)
    flow.solver_stats['cfg_blocks']+=len(graph.blocks)
    flow.last_exceptions=tuple(sorted(set((raised_state.exception if raised_state else ())+(('?',) if incomplete else ()))))
    flow.last_normal=incomplete or normal_state is not None or return_state is not None
    if len(flow.result.sites)>start:
        # No reachable back edge establishes at most one body entry. This uses
        # solved reachability, not the syntactic presence of a break statement.
        one_pass={block.index for block in graph.blocks if block.kind=='loop_test'
            and block.index in incoming and not any(b.kind=='back' and b.source is block.source and b.index in incoming for b in graph.blocks)}
        caps={i:incoming[i].env.get('@loop:'+str(i),UNKNOWN).size for i in incoming if graph.blocks[i].kind=='loop_test'}
        for i in one_pass:caps[i]=min(1,caps[i]) if caps[i] is not None else 1
        for offset,site in enumerate(flow.result.sites[start:],start):
            if site.owner==graph.owner_id and site.loop_ids and any(i in one_pass for i in site.loop_ids):
                bounds=site.base_loop_bounds+tuple(caps.get(i) for i in site.loop_ids)
                bound=1
                for size in bounds:
                    if size is None:bound=None;break
                    bound*=size
                flow.result.sites[offset]=replace(site,upper_bound=bound,operation_upper_bound=bound if site.operation in ('model','embedding','database','http','execution') and (site.operation not in ('model','embedding','database') or site.receiver_resolved) and site.observation_scope!='function_body' else site.operation_upper_bound)
        flow.merge_visits(start,incomplete)
    return Outcomes(normal_state is not None or unfinished,returned,raised_state is not None,incomplete)
