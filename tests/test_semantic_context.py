"""Paired local fixtures. No target code is imported or executed."""
from dataclasses import replace
from types import SimpleNamespace
import pytest
from argus.scanner import scan
from argus.analysis.parsing import parse
from argus.analysis.semantic import PythonFlow, Budgets, Value
from argus.models.semantic import MitigationState as M
from argus.reporting import JsonReportWriter


def flow(source, budgets=Budgets()):
    facts=SimpleNamespace(module=SimpleNamespace(id='module'),symbols=[])
    return PythonFlow(parse('python',source.encode()),facts,budgets).run()


def findings(tmp_path, source, rule='ARGUS-AI-002'):
    # Bound/effect controls require a genuine static receiver. Unresolved suffix
    # candidates are tested separately and never establish operation purity.
    source=source.replace('import openai\n','import openai\nclient=openai.OpenAI()\nrows=list(source)\n')
    (tmp_path/'a.py').write_text(source)
    return [f for f in scan(tmp_path).findings if f.rule_id==rule]


MODEL='client.chat.completions.create(model="synthetic", max_tokens=10)'

@pytest.mark.parametrize('collection,bounded',[
    ('[1,2,3]',True),('range(3)',True),('rows',False),('rows[:3]',True),('range(0)',True),
    ('range(2,8,2)',True),('range(runtime)',False)])
def test_local_bounds_retained_observation(tmp_path,collection,bounded):
    fs=findings(tmp_path,f'import openai\nfor x in {collection}:\n {MODEL}\n')
    if collection=='range(0)':
        assert fs==[]  # Proven unreachable body is no longer a reachable operation.
        return
    assert len(fs)==1
    assert (fs[0].assessment.mitigation_state==M.ESTABLISHED)==bounded
    assert fs[0].severity.value=='medium'  # A bound alone does not establish acceptable impact.
    assert fs[0].assessment.initial_pattern


@pytest.mark.parametrize('change',[
    'items = unknown', 'items.extend(other)', 'items += other', 'mutate(items)',
    'alias=items\nalias.append(1)', 'items[0:1]=unknown'])
def test_mutations_invalidate_bounds(tmp_path,change):
    fs=findings(tmp_path,f'import openai\nitems=[1,2,3]\n{change}\nfor x in items:\n {MODEL}\n')
    assert fs and fs[0].assessment.mitigation_state!=M.ESTABLISHED


def test_wrong_variable_and_one_branch(tmp_path):
    for source in ('limited=items[:3]\nfor x in items:',
                   'if condition:\n items=items[:3]\nfor x in items:'):
        fs=findings(tmp_path,'import openai\n'+source+'\n '+MODEL)
        assert fs and fs[0].severity.value=='medium'


def test_both_branches_and_invalidation(tmp_path):
    fs=findings(tmp_path,'import openai\nif condition:\n items=[1]\nelse:\n items=[1,2]\nfor x in items:\n '+MODEL)
    assert fs[0].assessment.mitigation_state==M.ESTABLISHED


def test_argument_return_propagation_and_alternate_callers(tmp_path):
    fs=findings(tmp_path,'import openai\ndef limit(xs):\n return xs[:3]\ndef consume(xs):\n for x in xs:\n  '+MODEL+'\nconsume(limit(rows))\nconsume(unknown)')
    assert fs and any(f.assessment.mitigation_state==M.PARTIAL for f in fs)
    assert all(f.severity.value=='medium' for f in fs)
    assert any(f.assessment.safeguards for f in fs)


def test_nested_loop_product_and_mutated_loop_domain():
    result=flow('import openai\nfor x in range(2):\n for y in range(3):\n  '+MODEL)
    site=next(s for s in result.sites if s.operation=='model')
    assert site.upper_bound==6 and site.loops==2
    result=flow('import openai\nxs=[1,2]\nfor x in xs:\n xs.append(x)\n '+MODEL)
    assert next(s for s in result.sites if s.operation=='model').upper_bound is None


def test_loop_carried_assignment_not_constant():
    result=flow('import openai\nn=2\nfor x in rows:\n n+=1\n for y in range(n):\n  '+MODEL)
    assert next(s for s in result.sites if s.operation=='model').upper_bound is None


def test_shared_wrapper_timeout_used_vs_unused(tmp_path):
    safe='import requests\ndef request(url, timeout=5):\n return requests.get(url, timeout=timeout)\nrequest(address)'
    protected=findings(tmp_path,safe,'ARGUS-REL-003')
    # A default protects omitted arguments, not unresolved external overrides.
    assert protected and protected[0].assessment.mitigation_state==M.PARTIAL
    fs=findings(tmp_path,safe.replace('timeout=timeout','other=timeout'),'ARGUS-REL-003')
    assert fs and fs[0].assessment
    fs=findings(tmp_path,safe.replace('timeout=5','timeout=None'),'ARGUS-REL-003')
    assert fs and fs[0].assessment.mitigation_state==M.UNVERIFIED


def test_limits_defined_on_wrong_value(tmp_path):
    fs=findings(tmp_path,'import openai\nlimit=10\nclient.chat.completions.create(max_tokens=other)','ARGUS-AI-001')
    assert fs and fs[0].assessment.mitigation_state==M.UNVERIFIED
    assert not findings(tmp_path,'import openai\nlimit=10\nclient.chat.completions.create(max_tokens=limit)','ARGUS-AI-001')


@pytest.mark.parametrize('ext,source',[
 ('py','import openai\ndef invoke(x):\n return client.chat.completions.create(max_tokens=10)\nfor x in rows:\n invoke(x)'),
 ('js','import OpenAI from "openai"; function invoke(x) { return client.chat.completions.create({max_tokens:10}); } for(const x of rows) { invoke(x); }'),
 ('ts','import OpenAI from "openai"; function invoke(x: string) { return client.chat.completions.create({max_tokens:10}); } for(const x of rows) { invoke(x); }'),
 ('jsx','import OpenAI from "openai"; function invoke(x) { return client.chat.completions.create({max_tokens:10}); } for(const x of rows) { invoke(x); }'),
 ('tsx','import OpenAI from "openai"; function invoke(x: string) { return client.chat.completions.create({max_tokens:10}); } for(const x of rows) { invoke(x); }')])
def test_wrapped_invocation(tmp_path,ext,source):
    (tmp_path/('a.'+ext)).write_text(source)
    fs=[f for f in scan(tmp_path).findings if f.rule_id=='ARGUS-AI-002']
    assert fs and all(f.assessment for f in fs)


def test_imported_wrapper_uses_existing_resolver(tmp_path):
    (tmp_path/'provider.py').write_text('import openai\ndef invoke():\n return client.embeddings.create(input=[])')
    fs=findings(tmp_path,'from provider import invoke\nfor x in rows:\n invoke()')
    assert fs and fs[0].assessment.call_path_relationship_ids


def test_unknown_call_names_not_provider_evidence(tmp_path):
    assert not findings(tmp_path,'for x in xs:\n llm.generate(x)\n agent.predict(x)\n safe_execute(x)')
    assert not findings(tmp_path,'def invoke():\n return unknown.complete()\nfor x in xs:\n invoke()')


def test_parameterized_sql_vs_returned_dynamic_sql(tmp_path):
    assert not findings(tmp_path,'cursor.execute("SELECT ?", (value,))','ARGUS-SEC-004')
    fs=findings(tmp_path,'def build(value):\n return f"SELECT {value}"\nquery=build(input())\ncursor.execute(query)','ARGUS-SEC-004')
    assert fs and fs[0].assessment.mitigation_state!=M.ESTABLISHED


def test_taint_known_return_and_unknown_sanitizer():
    source='def sanitize(value):\n return value\nx=input()\neval(sanitize(x))'
    assert any(s.operation=='execution' and s.tainted for s in flow(source).sites)
    result=flow(source.replace('return value','return 1'))
    assert not any(s.operation=='execution' and s.tainted for s in result.sites)
    # Unknown sanitizer cannot prove effectiveness; source taint remains possible.
    assert any(s.operation=='execution' and s.tainted for s in flow('eval(sanitize(input()))').sites)


def test_authentication_naming_is_not_a_safeguard(tmp_path):
    for gate in ('authorize(value)','safe_execute(value)','validate(value)'):
        fs=findings(tmp_path,gate+'\neval(value)','ARGUS-SEC-001')
        assert fs[0].assessment.mitigation_state==M.UNSUPPORTED
        assert not fs[0].assessment.safeguards


@pytest.mark.parametrize('source',[
    'def f(x):\n return f(x)\nf(1)',
    'def f(x):\n return g(x)\ndef g(x):\n return f(x)\nf(1)'])
def test_recursive_and_cyclic_calls(source):
    assert 'semantic_recursion_or_depth_limit' in flow(source).incomplete


@pytest.mark.parametrize('budget,source,reason',[
 (Budgets(contexts=1),'def f():\n return 1\nf()\nf()','contexts'),
 (Budgets(summary_expansions=1),'def f():\n return 1\nf()\nf()','summary_expansions'),
 (Budgets(cfg_nodes=1),'x=1\ny=2','cfg_nodes'),
 (Budgets(iterations=1),'x=1\ny=2','iterations'),
 (Budgets(paths=1),'if x:\n y=1\nif y:\n z=1','paths'),
 (Budgets(depth=1),'def f():\n return g()\ndef g():\n return 1\nf()','recursion_or_depth')])
def test_budget_exhaustion_disclosed(budget,source,reason):
    assert any(reason in gap for gap in flow(source,budget).incomplete)


def test_cfg_branch_loop_and_return_edges():
    r=flow('if x:\n y=1\nelse:\n y=2\nwhile z:\n y=3\ndef f():\n return 1')
    from argus.analysis.control_flow import EdgeKind
    blocks=[b for graph in r.cfg for b in graph.blocks]
    branch=next(n for n in blocks if n.kind=='branch')
    assert {e.kind for e in branch.edges}=={EdgeKind.TRUE,EdgeKind.FALSE,EdgeKind.EXCEPTION}
    ret=next(n for n in blocks if n.kind=='return')
    assert any(e.kind==EdgeKind.RETURN for e in ret.edges)
    loop=next(n for n in blocks if n.kind=='loop_test')
    assert any(any(e.target==loop.index and e.kind==EdgeKind.BACK for e in n.edges) for n in blocks if n.kind=='back')


def test_unknown_and_conflicting_lattice():
    assert Value('definite',number=1).join(Value('definite',number=2)).state=='conflicting'
    assert Value('definite',size=3).join(Value()).size is None
    assert Value('definite',size=3).join(Value('definite',size=2)).size==3


def test_unsupported_controls_diagnostics(tmp_path):
    original=findings(tmp_path,'import openai\ntry:\n for x in xs:\n  '+MODEL+'\nexcept Exception:\n pass')
    assert original and original[0].assessment.mitigation_state!=M.ESTABLISHED
    fs=findings(tmp_path,'import openai\nwith unknown_context():\n for x in xs:\n  '+MODEL)
    assert fs and fs[0].assessment.mitigation_state==M.INCOMPLETE
    assert any(d.code=='semantic_analysis_incomplete' for d in scan(tmp_path).diagnostics)


def test_generic_browser_credential_requires_context(tmp_path):
    literal='fictional-browser-api-key-material'
    p=tmp_path/'a.tsx'
    p.write_text('const key="'+literal+'"; fetch("/api",{body:JSON.stringify({key})});')
    r=scan(tmp_path)
    assert any(f.rule_id=='ARGUS-CRED-001' for f in r.findings)
    assert literal not in JsonReportWriter().render(r)
    p.write_text('const key="some-ordinary-dictionary-value"; fetch("/api",{body:JSON.stringify({key})});')
    assert not scan(tmp_path).findings
    p.write_text('const key="'+literal+'";')
    assert not scan(tmp_path).findings


def test_deterministic_context_report_and_privacy(tmp_path):
    (tmp_path/'a.py').write_text('import openai\napi_key="synthetic-only-private-material"\nfor x in range(3):\n '+MODEL)
    a=scan(tmp_path); b=scan(tmp_path)
    # Scan envelopes contain per-scan metadata; evidence/findings must be stable.
    assert a.findings==b.findings and a.evidence==b.evidence
    report=JsonReportWriter().render(a)
    assert 'synthetic-only-private-material' not in report
    assert 'assessment' in report and 'Not Reviewed Portions of the Code' in report


def test_ambiguous_definitions_do_not_invent_bounds():
    r=flow('def limit(xs):\n return xs[:3]\ndef limit(xs):\n return xs\nimport openai\nfor x in limit(rows):\n '+MODEL)
    assert next(s for s in r.sites if s.operation=='model').upper_bound is None


def test_budget_exhaustion_in_not_reviewed_report(tmp_path):
    (tmp_path/'a.py').write_text('def f():\n return 1\n'+'f()\n'*130)
    r=scan(tmp_path)
    import json
    gaps=json.loads(JsonReportWriter().render(r))['not_reviewed_portions_of_the_code']['semantic_analysis_gaps']
    assert any('contexts_limit' in d['message'] for d in gaps)


def test_capabilities_are_independent():
    from argus.analysis.adapters import supported_caps
    from argus.models.base import Capability as C
    assert {C.CONTROL_FLOW,C.DATA_FLOW,C.SUMMARIES,C.BOUNDS,C.TAINT} <= supported_caps('python')
    assert C.SUMMARIES in supported_caps('typescript')
    assert {C.CONTROL_FLOW,C.DATA_FLOW,C.BOUNDS,C.TAINT} <= supported_caps('typescript')


def test_unverified_safeguard_cannot_adjust_severity():
    from argus.models.semantic import Assessment
    with pytest.raises(ValueError):
        Assessment(initial_pattern='test',mitigation_state=M.UNVERIFIED,severity_adjustment='lower')


def test_large_bounds_are_not_clipped_or_low_cost(tmp_path):
    r=flow('import openai\nfor x in range(100000):\n for y in range(100000):\n  '+MODEL)
    assert next(s for s in r.sites if s.operation=='model').upper_bound==10000000000
    fs=findings(tmp_path,'import openai\nfor x in range(100000000):\n '+MODEL)
    assert fs[0].severity.value=='medium' and fs[0].assessment.severity_adjustment is None


@pytest.mark.parametrize('mutation',['mutate(xs)','helper(xs)'])
def test_unknown_loop_effect_after_operation_cannot_prove_bound(tmp_path,mutation):
    fs=findings(tmp_path,'import openai\nxs=[1,2]\nfor x in xs:\n '+MODEL+'\n '+mutation)
    assert fs and fs[0].assessment.mitigation_state!=M.ESTABLISHED


def test_assessment_references_are_validated(tmp_path):
    (tmp_path/'a.py').write_text('eval(input())')
    r=scan(tmp_path)
    f=next(f for f in r.findings if f.rule_id=='ARGUS-SEC-001')
    with pytest.raises(ValueError,match='dangling assessment evidence'):
        replace(r,findings=(replace(f,assessment=replace(f.assessment,supporting_evidence_ids=('missing',))),))
    with pytest.raises(ValueError,match='dangling assessment relationship'):
        replace(r,findings=(replace(f,assessment=replace(f.assessment,unresolved_relationship_ids=('missing',))),))


def test_contextual_registry_test_paths_exist():
    from pathlib import Path
    from argus.analysis.rules import REGISTRY
    assert sum(r.contextual_tests is not None for r in REGISTRY)==7
    assert all(Path(r.contextual_tests).is_file() for r in REGISTRY if r.contextual_tests)


def test_nonprimary_files_do_not_get_javascript_diagnostics(tmp_path):
    (tmp_path/'settings.json').write_text('{"count":3}')
    r=scan(tmp_path)
    assert not any(d.code=='semantic_analysis_incomplete' for d in r.diagnostics)
    from argus.models.base import Capability
    caps={c.capability:c.status.value for c in r.coverage.files[0].capabilities}
    assert caps[Capability.DATA_FLOW]=='unsupported'
