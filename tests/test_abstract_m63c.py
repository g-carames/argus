"""Local domain/transfer laws and graph execution controls; no external corpus."""
import ast
from itertools import product
from dataclasses import replace

import pytest

from argus.analysis.abstract import Interval, State, Effect, EffectKind
from argus.analysis.control_flow import build, EdgeKind
from argus.analysis.semantic import PythonFlow, Budgets, Value, UNKNOWN
from argus.analysis.parsing import parse
from tests.test_semantic_context import flow
from types import SimpleNamespace

INTERVALS=[Interval(),Interval(0,None),Interval(None,3),Interval(0,3),Interval(1,1),Interval(-2,7)]


def test_interval_lattice_laws():
    for a,b,c in product(INTERVALS,repeat=3):
        assert a.join(a)==a
        assert a.join(b)==b.join(a)
        assert a.join(b).join(c)==a.join(b.join(c))
        assert a.leq(a.join(b)) and b.leq(a.join(b))
        assert a.leq(a.widen(a.join(b))) and b.leq(a.widen(a.join(b)))
        meet=a.meet(b)
        if meet is not None:assert meet.leq(a) and meet.leq(b)


def test_state_join_keeps_unknown_distinct_from_incomplete():
    a=State({'x':Value(numeric=True,integer=True,minimum=1,maximum=2)})
    b=State({'x':Value(numeric=True,integer=True,minimum=2,maximum=4)},True)
    merged=a.join(b,UNKNOWN)
    assert merged.incomplete and merged.env['x'].minimum==1 and merged.env['x'].maximum==4
    assert State({'x':UNKNOWN}).incomplete is False
    assert a.join(State(),UNKNOWN).env['x'].size is None


def test_widening_stabilizes_expanding_interval():
    state=State({'x':Value(numeric=True,integer=True,minimum=0,maximum=0,number=0)})
    expanded=state.join(State({'x':Value(numeric=True,integer=True,minimum=0,maximum=1)}),UNKNOWN,True)
    assert expanded.env['x'].minimum==0 and expanded.env['x'].maximum is None
    assert expanded.join(State({'x':Value(numeric=True,integer=True,minimum=0,maximum=20)}),UNKNOWN,True)==expanded


def test_cfg_edges_and_source_anchors():
    tree=ast.parse('while flag:\n try:\n  if stop:\n   break\n  continue\n finally:\n  observe()\n')
    graph=build(tree.body)
    kinds={e.kind for b in graph.blocks for e in b.edges}
    assert {EdgeKind.TRUE,EdgeKind.FALSE,EdgeKind.BACK,EdgeKind.BREAK,EdgeKind.CONTINUE,EdgeKind.FINALLY}<=kinds
    assert all(b.source is None or b.source in set(ast.walk(tree)) for b in graph.blocks)
    assert all(0<=e.target<len(graph.blocks) for b in graph.blocks for e in b.edges)


@pytest.mark.parametrize('test,maximum', [('len(xs)<=3',3),('not len(xs)>3',3),('len(xs)<4 and len(xs)>=0',3),('len(xs)<=3 or len(xs)<=2',3)])
def test_builtin_length_refinement(test,maximum):
    facts=flow('import requests\nxs=list(source)\nif '+test+':\n for x in xs:\n  requests.get(url,timeout=2)')
    sites=[s for s in facts.sites if s.operation=='http']
    assert sites and all(s.upper_bound==maximum and s.constraint_origins for s in sites)


@pytest.mark.parametrize('source',[
    'xs=list(source)\nif len(other)>3:\n raise ValueError()\n',
    'xs=list(source)\nif len(xs)>3:\n raise ValueError()\nxs=list(other)\n',
    'xs=list(source)\nif len(xs)>3:\n raise ValueError()\nmutate(xs)\n',
    'xs=list(source)\nif len(xs)<=3 and mutate(xs):\n pass\n',
])
def test_wrong_stale_or_mutated_constraints_do_not_bound(source):
    facts=flow('import requests\n'+source+'for x in xs:\n requests.get(url,timeout=2)')
    assert all(s.upper_bound is None for s in facts.sites if s.operation=='http')


def test_worklist_reprocesses_and_widens():
    facts=flow('i=0\nwhile condition:\n i+=1')
    assert facts.statistics['worklist_steps']>facts.statistics['reachable_blocks']
    assert facts.statistics['widenings']>0
    assert not any('limit' in g for g in facts.incomplete)


def test_unknown_while_domain_does_not_establish_finiteness():
    facts=flow('while condition:\n pass')
    domains=[s for s in facts.sites if s.operation=='loop_domain']
    assert domains and all(s.upper_bound is None and not s.finite for s in domains)


def test_mutable_iteration_domain_does_not_establish_finiteness():
    facts=flow('xs=[1,2]\nfor x in xs:\n mutate(xs)')
    domains=[s for s in facts.sites if s.operation=='loop_domain']
    assert domains and all(s.upper_bound is None and not s.finite for s in domains)


def test_resource_limit_cannot_keep_positive_guarantees():
    facts=flow('import requests\nxs=[1,2]\ni=0\nwhile condition:\n requests.get(url,timeout=2)\n i+=1',Budgets(iterations=25))
    assert any('limit' in g for g in facts.incomplete)
    assert all(s.upper_bound is None and not s.limit for s in facts.sites if s.operation=='http')


def test_unknown_call_effect_is_not_pure():
    facts=SimpleNamespace(module=SimpleNamespace(id='module'),symbols=[])
    engine=PythonFlow(parse('python',b'pass'),facts,Budgets())
    env={'x':Value(size=3,collection_kind='list',constraint_origins=(('module',1),))}
    engine.apply_effect(Effect(EffectKind.CALL,line=2),env)
    assert env['x'].size is None and not env['x'].constraint_origins


@pytest.mark.parametrize('body,expected',[
    ('try:\n  return [1]\n finally:\n  return [1,2]',2),
    ('try:\n  raise ValueError()\n except ValueError:\n  return [1,2]',2),
    ('try:\n  raise KeyError()\n except LookupError:\n  return [1,2]',2),
    ('try:\n  raise ValueError()\n finally:\n  return [1,2]',2),
    ('try:\n  return [1,2]\n finally:\n  marker=1',2),
])
def test_effective_exception_return_channels(body,expected):
    facts=flow('def f():\n '+body+'\nx=f()')
    assert all(s.upper_bound==expected for s in facts.sites if s.operation=='return_bound')


def test_retained_cfg_and_ir_have_no_string_literals():
    facts=flow('token="source-only-synthetic-marker"\ndef f():\n return "another-marker"\nf()')
    for graph in facts.cfg:
        for block in graph.blocks:
            if block.source is not None:
                assert all(not isinstance(n.value,(str,bytes)) for n in ast.walk(block.source) if isinstance(n,ast.Constant))


@pytest.mark.parametrize('count', [4095,4096,4097])
def test_projection_exact_boundary(count):
    from argus.analysis.observations import project
    from argus.analysis.semantic import SemanticFacts,Site
    from argus.models.analysis import Graph
    from argus.models.semantic import ObservationKind
    from argus.models.source import SourceFile,FileKind
    file=SourceFile(id='file',root_id='root',path='synthetic.py',kind=FileKind.SOURCE,language='python')
    fact=SimpleNamespace(module=SimpleNamespace(id='module'),symbols=[],semantic=SemanticFacts(
        sites=[Site(i+1,'module','assignment',value_id=f'value-{i}',context_id='ctx') for i in range(count)]))
    evidence=[];result=project({'file':fact},{'file':file},Graph(),evidence)
    accounting=fact.semantic.projection_accounting
    assert accounting['requested_observations']==count
    assert len(result)==min(count,4096)
    if count<=4096:
        assert accounting['omitted_observations']==0 and all(o.kind==ObservationKind.ASSIGNMENT for o in result)
    else:
        assert accounting['omitted_observations']==2
        assert accounting['omitted_kinds']==('assignment_fact',)
        assert accounting['omitted_context_ids']==('ctx',)
        assert len(accounting['omitted_locations'])==2
        assert any(o.observation_scope=='projection_summary' for o in result)


def test_exception_finally_with_break_and_continue():
    facts=flow('import requests\nfor x in range(3):\n try:\n  break\n finally:\n  requests.get(url,timeout=2)')
    operations=[s for s in facts.sites if s.operation=='http']
    assert len(operations)==1 and operations[0].upper_bound==1


def test_effectful_boolean_cannot_reestablish_stale_guard():
    facts=flow('import requests\nxs=list(source)\nif len(xs)<=3 and mutate(xs):\n for x in xs:\n  requests.get(url,timeout=2)')
    assert all(s.upper_bound is None for s in facts.sites if s.operation=='http')


def test_duplicate_set_elements_do_not_get_exact_cardinality():
    facts=flow('import requests\nxs={1,1}\nif len(xs)==1:\n for x in xs:\n  requests.get(url,timeout=2)')
    sites=[s for s in facts.sites if s.operation=='http']
    assert sites and all(s.upper_bound==1 for s in sites)


def test_unknown_protocol_cannot_refine_collection_length():
    facts=flow('import requests\nxs=unknown\nif len(xs)<=3:\n for x in xs:\n  requests.get(url,timeout=2)')
    assert all(s.upper_bound is None for s in facts.sites if s.operation=='http')


def test_unknown_truthiness_after_guard_invalidates_mutable_constraint():
    facts=flow('import requests\nxs=list(source)\nif len(xs)<=3 and unknown_object:\n for x in xs:\n  requests.get(url,timeout=2)')
    assert all(s.upper_bound is None for s in facts.sites if s.operation=='http')


def test_budget_exhaustion_never_proves_raised_only_callable():
    facts=SimpleNamespace(module=SimpleNamespace(id='module'),symbols=[])
    engine=PythonFlow(parse('python',b'def f():\n return [1,2]\nf()\n'),facts,Budgets(iterations=5))
    engine.run()
    assert any('limit' in g for g in engine.gaps)
    assert engine.last_normal


def test_builtin_shadowed_handler_remains_unresolved():
    facts=flow('class ValueError(unknown):\n pass\ndef f():\n try:\n  raise RuntimeError()\n except ValueError:\n  return [1]\nf()')
    assert 'semantic_exception_matching_incomplete' in facts.incomplete
    assert all(s.upper_bound is None for s in facts.sites if s.operation=='return_bound')


def test_raise_arguments_retain_operations():
    facts=flow('import requests\nraise ValueError(requests.get(url,timeout=2))')
    assert any(s.operation=='http' for s in facts.sites)


def test_bare_reraise_preserves_known_exception():
    facts=flow('def f():\n try:\n  try:\n   raise ValueError()\n  except ValueError:\n   raise\n except ValueError:\n  return [1,2]\nx=f()')
    assert all(s.upper_bound==2 for s in facts.sites if s.operation=='return_bound')


def test_state_order_covers_joined_numeric_and_collection_facts():
    values=[UNKNOWN,Value(numeric=True,minimum=0,maximum=3),Value(size=2,size_lower=0,finite=True,collection_kind='list')]
    for a,b in product(values,repeat=2):
        left,right=State({'x':a}),State({'x':b})
        joined=left.join(right,UNKNOWN)
        assert left.leq(joined,UNKNOWN) and right.leq(joined,UNKNOWN)


def test_collection_equality_protocol_is_not_a_pure_compound_guard():
    facts=flow('import requests\nxs=list(source)\nys=list(other)\nif len(xs)<=3 and ys==[payload]:\n for x in xs:\n  requests.get(url,timeout=2)')
    assert all(s.upper_bound is None for s in facts.sites if s.operation=='http')


def test_cfg_budget_is_shared_across_cached_function_graphs():
    facts=flow('def a():\n return [1]\ndef b():\n return [2]\na()\nb()',Budgets(cfg_nodes=10))
    assert facts.statistics['prepared_cfg_nodes']<=10
    assert 'semantic_cfg_nodes_limit' in facts.incomplete
    assert all(s.upper_bound is None for s in facts.sites if s.operation=='return_bound' and 'semantic_cfg_nodes_limit' in s.incomplete)


def test_unknown_comparison_result_may_have_effectful_truthiness():
    facts=flow('import requests\nflag=unknown_a==unknown_b\nxs=list(source)\nif len(xs)>3:\n raise ValueError()\nif flag:\n for x in xs:\n  requests.get(url,timeout=2)')
    assert all(s.upper_bound is None for s in facts.sites if s.operation=='http')
