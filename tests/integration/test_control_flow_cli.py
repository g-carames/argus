"""Installed-CLI computational oracles; independent multi-module synthetic input."""
import json
import pytest
from tests.integration.test_semantic_cli import installed_cli, cli_scan, obs

pytestmark=pytest.mark.installed_cli


def operations(report,path='app.py',line=None):
    return obs(report,'timeout_setting',path,line)


def app(code):
    return {'app.py':'import requests\n'+code+'\n','support.py':'def identity(x):\n return x\n'}


@pytest.mark.parametrize('guard',[
    'if len(xs)>3:\n raise ValueError()',
    'if not len(xs)<=3:\n raise ValueError()',
    'if len(xs)<=3:\n pass\nelse:\n raise ValueError()',
])
def test_guard_rejecting_successful_path(cli_scan,guard):
    report=cli_scan(app('xs=list(source)\n'+guard+'\nfor x in xs:\n requests.get(url,timeout=2)'))
    sites=operations(report)
    assert sites and all(o['iteration_upper_bound']==3 and o['constraint_locations'] and o['reachability']=='abstract_reachable' for o in sites)
    assert all(o['operation_upper_bound']==3 for o in sites)
    assert all(o['conditional_execution'] for o in sites)


@pytest.mark.parametrize('variation',[
    'wrong','after','reassign','mutate','continuing','one_path',
])
def test_guard_adverse_controls(cli_scan,variation):
    guard='if len(xs)>3:\n raise ValueError()\n'
    pre='xs=list(source)\n'
    post=''
    if variation=='wrong':guard=guard.replace('xs','other')
    elif variation=='after':post=guard;guard=''
    elif variation=='reassign':guard+='xs=list(other)\n'
    elif variation=='mutate':guard+='mutate(xs)\n'
    elif variation=='continuing':guard='if len(xs)>3:\n pass\n'
    elif variation=='one_path':guard='if flag:\n if len(xs)>3:\n  raise ValueError()\n'
    report=cli_scan(app(pre+guard+'for x in xs:\n requests.get(url,timeout=2)\n'+post))
    sites=operations(report)
    assert sites and all(o['iteration_upper_bound'] is None and o['operation_upper_bound'] is None for o in sites)


def test_both_branches_constrain_consumed_value(cli_scan):
    report=cli_scan(app('xs=list(source)\nif flag:\n xs=xs[:2]\nelse:\n xs=xs[:3]\nfor x in xs:\n requests.get(url,timeout=2)'))
    assert all(o['iteration_upper_bound']==3 for o in operations(report))


def test_known_numeric_membership_and_range(cli_scan):
    report=cli_scan(app('n=int(source)\nif n not in (1,2,3):\n raise ValueError()\nfor x in range(n):\n requests.get(url,timeout=2)'))
    sites=operations(report)
    assert sites and all(o['iteration_upper_bound']==3 and o['constraint_locations'] for o in sites)


def test_nested_conditional_operation_count(cli_scan):
    report=cli_scan(app('flag=bool(source)\nfor x in range(2):\n for y in range(3):\n  if flag:\n   requests.get(url,timeout=2)'))
    sites=operations(report)
    assert sites and all(o['iteration_upper_bound']==6 and o['operation_upper_bound']==6 and o['conditional_execution'] for o in sites)


@pytest.mark.parametrize('statement,bound', [('break',1),('continue',3)])
def test_break_continue_bounds(cli_scan,statement,bound):
    report=cli_scan(app('for x in range(3):\n requests.get(url,timeout=2)\n '+statement+'\n requests.get(other,timeout=2)'))
    sites=operations(report)
    assert len(sites)==1 and sites[0]['iteration_upper_bound']==bound


def test_loop_convergence_and_widening(cli_scan):
    report=cli_scan(app('i=0\nwhile condition:\n requests.get(url,timeout=2)\n i+=1'))
    stats=next(s for s in report['semantic_analysis'] if s['widenings'])
    assert stats['worklist_steps']>stats['reachable_blocks']
    assert stats['worklist_steps']<4096
    assert all(o['operation_upper_bound'] is None for o in operations(report))


def test_raised_only_call_has_no_normal_continuation(cli_scan):
    report=cli_scan({'lib.py':'def reject():\n raise ValueError()\n',
        'app.py':'from lib import reject\nimport requests\nreject()\nrequests.get(url,timeout=2)\n'})
    returns=obs(report,'return_bound','lib.py')
    assert returns and all(o['exit_channels']==['raised'] for o in returns)
    assert not operations(report)


@pytest.mark.parametrize('handler,expected', [('ValueError',2),('LookupError',None)])
def test_known_exception_matching(cli_scan,handler,expected):
    report=cli_scan({'lib.py':f'def f():\n try:\n  raise ValueError()\n except {handler}:\n  return [1,2]\n',
        'app.py':'from lib import f\nx=f()\n'})
    returns=obs(report,'return_bound','lib.py')
    assert returns and all(o['upper_bound']==expected for o in returns)
    assert all(set(o['exit_channels'])==({'returned'} if expected else {'raised'}) for o in returns)


def test_unknown_exception_preserves_possible_handler(cli_scan):
    report=cli_scan({'lib.py':'def f():\n try:\n  mystery()\n except ValueError:\n  return [1,2]\n return unknown\n',
        'app.py':'from lib import f\nx=f()\n'})
    returns=obs(report,'return_bound','lib.py')
    assert returns and all(o['upper_bound'] is None and 'raised' in o['exit_channels'] and 'returned' in o['exit_channels'] for o in returns)


@pytest.mark.parametrize('prior,final,expected,channel',[
    ('return [1]','return [1,2]',2,'returned'),
    ('raise ValueError()','return [1,2]',2,'returned'),
    ('return [1]','raise TypeError()',None,'raised'),
])
def test_finally_overrides_effective_result(cli_scan,prior,final,expected,channel):
    report=cli_scan({'lib.py':f'def f():\n try:\n  {prior}\n finally:\n  {final}\n',
        'app.py':'from lib import f\nx=f()\n'})
    returns=obs(report,'return_bound','lib.py')
    assert returns and all(o['upper_bound']==expected and set(o['exit_channels'])=={channel} for o in returns)


def test_unknown_decorator_separates_body_and_callable(cli_scan):
    report=cli_scan({'lib.py':'@unknown_wrapper\ndef cap(xs):\n return xs[:3]\n',
        'app.py':'from lib import cap\nx=cap(rows)\n'})
    returns=obs(report,'return_bound','lib.py')
    body=[o for o in returns if o['observation_scope']=='function_body']
    effective=[o for o in returns if o['observation_scope']=='effective_invocation']
    assert body and all(o['upper_bound']==3 for o in body)
    assert effective and all(o['upper_bound'] is None and o['certainty']=='unknown_or_unresolved' for o in effective)
    assert all(o['upper_bound'] is None for o in obs(report,'assignment_fact','app.py'))


def test_proven_identity_decorator_preserves_callable(cli_scan):
    report=cli_scan({'lib.py':'def identity(fn):\n return fn\n@identity\ndef cap(xs):\n return xs[:3]\n',
        'app.py':'from lib import cap\nx=cap(rows)\n'})
    returns=obs(report,'return_bound','lib.py',4)
    assert returns and all(o['upper_bound']==3 and o['observation_scope']=='effective_invocation' for o in returns)


def test_unsupported_nested_operations_are_potential_only(cli_scan):
    report=cli_scan(app('with unknown_context():\n for x in range(2):\n  requests.get(url,timeout=2)'))
    sites=operations(report)
    assert sites and all(o['reachability']=='potential' and o['operation_upper_bound'] is None for o in sites)
    assert report['not_reviewed_portions_of_the_code']['semantic_analysis_gaps']


def test_distinct_guarded_callers_and_unknown_external_context(cli_scan):
    report=cli_scan({'lib.py':'import requests\ndef work(xs):\n if len(xs)>3:\n  raise ValueError()\n for x in xs:\n  requests.get(url,timeout=2)\n',
        'a.py':'from lib import work\nwork([1,2])\n',
        'b.py':'from lib import work\nwork(unknown)\n'})
    sites=operations(report,'lib.py')
    assert any(o['iteration_upper_bound']==2 for o in sites) and any(o['iteration_upper_bound'] is None for o in sites)
    assert len({o['context_id'] for o in sites})==3
    assert any('external_entry-' in path for o in sites for path in o['call_path_ids'])


def test_projection_gap_consolidation_retains_calls(cli_scan):
    prefix='var seed=0; const {name}=obj; class Thing {}; export {seed}; const options={...data};\n'
    report=cli_scan({'app.js':prefix+'\n'.join(f'let value{i}=unknown+other;' for i in range(850))+'\nping();\n'})
    calls=obs(report,'call_path','app.js')
    assert calls and all(o['relationship_ids'] for o in calls)
    stats=report['semantic_analysis'][0]
    assert stats['consolidated_gap_occurrences']>1000
    assert stats['omitted_observations']==0
    gaps=obs(report,'incomplete_analysis','app.js')
    assert len(gaps)<20
    evidence={e['id']:e for e in report['evidence']}
    assert max(len(evidence[o['evidence_ids'][0]]['locations']) for o in gaps)>500


def test_computational_guard_existing_public_bound(cli_scan):
    guarded=cli_scan(app('xs=list(source)\nif len(xs)>3:\n raise ValueError()\nfor x in xs:\n requests.get(url,timeout=2)'))
    after=cli_scan(app('xs=list(source)\nfor x in xs:\n requests.get(url,timeout=2)\nif len(xs)>3:\n raise ValueError()'))
    # Uses preexisting public fields so baseline failure demonstrates missing
    # computation, not merely the absence of new contract fields.
    bound=obs(guarded,'collection_bound','app.py')
    assert bound and all(o['upper_bound']==3 for o in bound)
    assert not obs(after,'collection_bound','app.py')


def test_computational_finally_existing_return_bound(cli_scan):
    report=cli_scan({'lib.py':'def f():\n try:\n  return [1]\n finally:\n  return [1,2]\n','app.py':'from lib import f\nx=f()\n'})
    returns=obs(report,'return_bound','lib.py')
    assert returns and all(o['upper_bound']==2 for o in returns)


def test_guard_provenance_binds_exact_consumed_value(cli_scan):
    report=cli_scan(app('xs=list(source)\nif len(xs)>3:\n raise ValueError()\nfor x in xs:\n requests.get(url,timeout=2)'))
    value=obs(report,'assignment_fact','app.py',2)[0]
    sites=operations(report)
    assert sites and all(o['constrained_value_id']==value['value_id'] and o['constraint_applicability']=='all_reaching_states' for o in sites)
    assert all({l['start_line'] for l in o['constraint_locations']}=={3} for o in sites)


def test_both_guard_branches_keep_supporting_predicates(cli_scan):
    report=cli_scan(app('xs=list(source)\nif flag:\n if len(xs)>2:\n  raise ValueError()\nelse:\n if len(xs)>3:\n  raise ValueError()\nfor x in xs:\n requests.get(url,timeout=2)'))
    sites=operations(report)
    assert sites and all(o['iteration_upper_bound']==3 and o['constraint_applicability']=='all_reaching_states' for o in sites)
    assert all({l['start_line'] for l in o['constraint_locations']}=={4,7} for o in sites)


def test_async_body_does_not_terminate_unawaited_caller(cli_scan):
    report=cli_scan({'lib.py':'async def reject():\n raise ValueError()\n','app.py':'from lib import reject\nimport requests\nreject()\nrequests.get(url,timeout=2)\n'})
    assert operations(report)
    effective=[o for o in obs(report,'return_bound','lib.py') if o['observation_scope']=='effective_invocation']
    assert effective and all(o['upper_bound'] is None and o['exit_channels']==[] for o in effective)


def test_metamorphic_control_inversion_and_rename(cli_scan):
    sources=[
        'xs=list(source)\nif len(xs)>3:\n raise ValueError()\nfor x in xs:\n requests.get(url,timeout=2)',
        'xs=list(source)\nif len(xs)<=3:\n pass\nelse:\n raise ValueError()\nfor x in xs:\n requests.get(url,timeout=2)',
        'renamed=list(source)\nmarker=7\nif len(renamed)>3:\n raise ValueError()\nfor element in renamed:\n requests.get(url,timeout=2)',
    ]
    for source in sources:
        sites=operations(cli_scan(app(source)))
        assert sites and all(o['iteration_upper_bound']==3 and o['constraint_applicability']=='all_reaching_states' for o in sites)


def test_nonempty_loop_return_excludes_zero_iteration_fallthrough(cli_scan):
    report=cli_scan({'lib.py':'def f():\n for item in [1]:\n  return [1,2]\n return unknown\n',
        'app.py':'from lib import f\nx=f()\n'})
    returns=obs(report,'return_bound','lib.py')
    assert returns and all(o['upper_bound']==2 and set(o['exit_channels'])=={'returned'} for o in returns)


def test_unresolved_suffix_does_not_establish_effect_purity(cli_scan):
    report=cli_scan({'app.py':'import openai\nxs=[1,2]\nfor x in xs:\n client.responses.create()\n'})
    model=obs(report,'operation_binding','app.py')
    assert model and all(o['certainty']=='possible_inference' and o['operation_upper_bound'] is None and o['iteration_upper_bound'] is None for o in model)
    assert all(f['assessment']['mitigation_state']!='mitigation_established_within_analyzed_scope' for f in report['findings'])


def test_current_module_receiver_binding_reaches_function(cli_scan):
    report=cli_scan({'lib.py':'from openai import OpenAI\nc=OpenAI()\ndef work(xs):\n for x in xs:\n  c.responses.create()\nwork([1,2])\n','app.py':'import lib\n'})
    sites=obs(report,'operation_binding','lib.py')
    assert sites and all(o['certainty']=='statically_established' for o in sites)
    assert any(o['operation_upper_bound']==2 for o in sites)
    assert any(o['operation_upper_bound'] is None for o in sites)


@pytest.mark.parametrize('count,requested',[(4091,4095),(4092,4096),(4093,4097)])
def test_installed_projection_boundaries(cli_scan,count,requested):
    report=cli_scan({'app.py':'@unknown()\n'*count+'def f():\n return [1]\n'})
    summary=report['semantic_analysis'][0]
    assert summary['requested_observations']==requested
    assert summary['emitted_observations']==min(4096,requested)
    calls=obs(report,'call_path','app.py')
    assert len(calls)==count and all(o['relationship_ids'] for o in calls)
    assert summary['omitted_observations']==(2 if requested>4096 else 0)
    assert bool(report['not_reviewed_portions_of_the_code']['semantic_projection_omissions'])==(requested>4096)
    # This independent graph/projection boundary intentionally exceeds the IR
    # preparation budget; that earlier gap must remain visible, not hidden.
    assert any('intermediate_representation_limit' in d['message'] for d in report['not_reviewed_portions_of_the_code']['semantic_analysis_gaps'])


def test_repository_method_unknown_effects_invalidate_guard(cli_scan):
    report=cli_scan(app('class Mutator:\n def change(self):\n  mystery()\nm=Mutator()\nxs=list(source)\nif len(xs)>3:\n raise ValueError()\nm.change()\nfor x in xs:\n requests.get(url,timeout=2)'))
    assert all(o['operation_upper_bound'] is None for o in operations(report))


def test_raised_constructor_has_no_normal_object_or_continuation(cli_scan):
    report=cli_scan({'lib.py':'class Item:\n def __init__(self):\n  raise ValueError()\n',
        'app.py':'from lib import Item\nimport requests\nx=Item()\nrequests.get(url,timeout=2)\n'})
    assert not obs(report,'assignment_fact','app.py',3)
    assert not operations(report)


def test_adverse_guard_existing_public_bounds(cli_scan):
    for code in (
        'xs=list(source)\nfor x in xs:\n requests.get(url,timeout=2)\nif len(xs)>3:\n raise ValueError()',
        'xs=list(source)\nif len(other)>3:\n raise ValueError()\nfor x in xs:\n requests.get(url,timeout=2)',
        'xs=list(source)\nif len(xs)>3:\n raise ValueError()\nmutate(xs)\nfor x in xs:\n requests.get(url,timeout=2)',
    ):
        assert not obs(cli_scan(app(code)),'collection_bound','app.py')


def test_loop_revisit_does_not_keep_first_operation_count_after_mutation(cli_scan):
    report=cli_scan(app('xs=[1,2]\nfor x in xs:\n requests.get(url,timeout=2)\n xs+=xs'))
    sites=operations(report)
    assert sites and all(o['iteration_upper_bound'] is None and o['operation_upper_bound'] is None for o in sites)


def test_unknown_decorator_does_not_publish_definite_body_invocation(cli_scan):
    report=cli_scan({'lib.py':'@unknown\ndef f():\n return [1]\n','app.py':'from lib import f\nx=f()\n'})
    relationships={r['id']:r for r in report['graph']['relationships']}
    paths=obs(report,'call_path','app.py',2)
    assert len(paths)==1
    edge=relationships[paths[0]['relationship_ids'][0]]
    assert edge['resolution']=='ambiguous' and edge['target_id'] is None and len(edge['candidate_target_ids'])==1


def test_unknown_slice_protocol_is_not_a_verified_consumption_bound(cli_scan):
    report=cli_scan(app('xs=opaque[:3]\nfor x in xs:\n requests.get(url,timeout=2)'))
    point=obs(report,'assignment_fact','app.py',2)[0]
    assert point['upper_bound']==3 and not point['bound_supported'] and point['certainty']=='possible_inference'
    sites=operations(report)
    assert sites and all(o['operation_upper_bound'] is None and o['iteration_upper_bound'] is None for o in sites)


def test_builtin_slice_is_a_verified_consumption_bound(cli_scan):
    report=cli_scan(app('xs=list(source)[:3]\nfor x in xs:\n requests.get(url,timeout=2)'))
    sites=operations(report)
    assert sites and all(o['operation_upper_bound']==3 and o['iteration_upper_bound']==3 for o in sites)


@pytest.mark.parametrize('conversion',['list(other)','int(other)','tuple(other)','f"{other}"','[x for x in other]','{other: 1}','"{}".format(other)'])
def test_unknown_conversion_protocol_invalidates_guard(cli_scan,conversion):
    report=cli_scan(app('xs=list(source)\nif len(xs)>3:\n raise ValueError()\nconverted='+conversion+'\nfor x in xs:\n requests.get(url,timeout=2)'))
    sites=operations(report)
    assert sites and all(o['operation_upper_bound'] is None and o['iteration_upper_bound'] is None for o in sites)


@pytest.mark.parametrize('expression',['other.attribute','other[:3]','f"{other}"','{other: 1}'])
def test_unknown_protocol_keeps_potential_handler_return(cli_scan,expression):
    report=cli_scan({'lib.py':'def f():\n try:\n  value='+expression+'\n  return [1]\n except Exception:\n  return unknown\n',
        'app.py':'from lib import f\nresult=f()\n'})
    returns=obs(report,'return_bound','lib.py',1)
    assert returns and all(o['upper_bound'] is None and o['certainty']=='unknown_or_unresolved' and set(o['exit_channels'])=={'returned','raised'} for o in returns)


def test_cfg_public_projection_excludes_source_and_candidate_values(cli_scan):
    marker='source-only-control-flow-marker-DO-NOT-PUBLISH'
    credential='sk-'+'Q'*24
    report=cli_scan({'lib.py':f'# {marker}\napi_key="{credential}"\ndef f():\n try:\n  return ["{marker}"]\n finally:\n  result="{marker}"\n',
        'app.py':'from lib import f\nvalue=f()\n'})
    raw=json.dumps(report)
    assert marker not in raw and credential not in raw
    assert report['credential_candidates'] and all(c['validity']=='unverified' for c in report['credential_candidates'])
    returns=obs(report,'return_bound','lib.py',3)
    assert returns and all(o['upper_bound']==1 and o['bound_supported'] and o['exit_channels']==['returned'] for o in returns)
