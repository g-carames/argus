"""Implementation-owned synthetic cases; no independent evaluation materials."""
from argus.analysis.semantic import Budgets
from argus.analysis.parsing import parse
from argus.scanner import scan
from argus.reporting import JsonReportWriter
from tests.test_semantic_context import flow


def workspace(tmp_path,files):
    for name,content in files.items(): (tmp_path/name).write_text(content)
    from argus.analysis.pipeline import Analysis
    from argus.config import AnalysisSettings
    from argus.analysis.extraction import extract
    from argus.analysis.resolution import Resolver
    from argus.analysis.workspace import WorkspaceFlow
    result=scan(tmp_path)
    by_path={f.path:f for f in result.files}
    facts={}
    for path,file in by_path.items():
        facts[file.id]=extract(file,parse(file.language,files[path].encode()))
    engine=WorkspaceFlow(facts,by_path,Resolver(by_path))
    engine.run()
    return engine,result


def test_imported_constants_defaults_aliases_and_returns(tmp_path):
    engine,result=workspace(tmp_path,{
        'limits.py':'LIMIT=7\ndef cap(xs, *, n=LIMIT):\n return xs[:n]',
        'exports.py':'from limits import cap as limited',
        'app.py':'from exports import limited as bound\nfrom limits import LIMIT as seconds\nimport requests\nitems=bound(rows)\nfor x in items:\n requests.get(url,timeout=seconds)',
    })
    app=next(f for f in engine.flows.values() if engine.paths[f.facts.module.id]=='app.py')
    site=next(s for s in app.result.sites if s.operation=='http')
    assert site.upper_bound==7 and site.limit
    assert site.origins
    assert not any(f.rule_id=='ARGUS-REL-003' for f in result.findings)


def test_cross_file_taint_and_unknown_sanitizer(tmp_path):
    engine,_=workspace(tmp_path,{
        'source.py':'def read():\n return input()\ndef transform(x):\n return mystery(x)',
        'app.py':'from source import read, transform\neval(transform(read()))',
    })
    assert any(s.operation=='execution' and s.tainted for f in engine.flows.values() for s in f.result.sites)


def test_cross_file_recursion_is_disclosed(tmp_path):
    engine,_=workspace(tmp_path,{'a.py':'from b import g\ndef f(x):\n return g(x)\nf(1)', 'b.py':'from a import f\ndef g(x):\n return f(x)'})
    assert any('recursion' in gap or 'cyclic' in gap for f in engine.flows.values() for gap in f.gaps)


def test_constructor_attributes_distinguish_instances():
    r=flow('import httpx\nclass Worker:\n def __init__(self,t):\n  self.client=httpx.Client(timeout=t)\n def fetch(self):\n  return self.client.get(url)\na=Worker(5)\nb=Worker(None)\na.fetch()\nb.fetch()')
    sites=[s for s in r.sites if s.operation=='http']
    assert len(sites)==2 and sites[0].limit and not sites[1].limit


def test_imported_class_and_factory(tmp_path):
    engine,_=workspace(tmp_path,{
        'client.py':'import httpx\nclass Worker:\n def __init__(self):\n  self.client=httpx.Client(timeout=5)\n def fetch(self):\n  return self.client.get(url)\ndef factory():\n return Worker()',
        'app.py':'from client import Worker, factory\na=Worker()\na.fetch()\nb=factory()\nb.fetch()',
    })
    sites=[s for f in engine.flows.values() for s in f.result.sites if s.operation=='http']
    assert sites and all(s.limit for s in sites)


def test_timeout_override_unknown_and_disabled():
    r=flow('import httpx\nc=httpx.Client(timeout=5)\nc.get(url)\nc.get(url,timeout=None)\nc.get(url,timeout=runtime)\nc.get(url,timeout=0)')
    assert [s.limit for s in r.sites if s.operation=='http']==[True,False,False,False]


def test_js_flow_imports_and_mutation(tmp_path):
    engine,_=workspace(tmp_path,{
        'limits.ts':'export const LIMIT=3; export function cap(xs: string[]) { return xs.slice(0,LIMIT); }',
        'app.ts':'import {cap} from "./limits"; import OpenAI from "openai"; const client=new OpenAI(); const items=cap(rows); for(const x of items) { client.chat.completions.create({max_tokens:5}); }',
    })
    sites=[s for f in engine.flows.values() for s in f.result.sites if s.operation=='model' and s.loops]
    assert sites and any(s.upper_bound==3 and s.limit for s in sites)


def test_js_local_return_and_options_argument(tmp_path):
    engine,_=workspace(tmp_path,{'app.js':'import OpenAI from "openai"; const c=new OpenAI(); function options(n){return {max_tokens:n};} c.chat.completions.create(options(4));'})
    assert any(s.operation=='model' and s.limit for f in engine.flows.values() for s in f.result.sites)


def test_no_literal_retention(tmp_path):
    secret='synthetic-private-value-never-report'
    engine,result=workspace(tmp_path,{'a.py':f'import httpx\nc=httpx.Client(headers={{"X-Key":"{secret}"}})\nc.get(url)'})
    import ast
    assert all(not isinstance(n.value,(str,bytes)) for f in engine.flows.values() for n in ast.walk(f.tree) if isinstance(n,ast.Constant))
    assert secret not in JsonReportWriter().render(result)


def test_finite_numerical_clamp_and_counter():
    r=flow('import openai\nn=min(runtime,4)\nfor x in range(n):\n client.chat.completions.create(max_tokens=1)\nattempt=0\nwhile attempt<3:\n client.chat.completions.create(max_tokens=1)\n attempt+=1')
    sites=[s for s in r.sites if s.operation=='model']
    assert [s.upper_bound for s in sites]==[4,3]
    r=flow('import openai\nattempt=0\nwhile attempt<3:\n client.chat.completions.create()\n if retry:\n  continue\n attempt+=1')
    assert next(s for s in r.sites if s.operation=='model').upper_bound is None


def test_starred_collection_is_not_one_element():
    r=flow('import openai\nfor x in [*unknown]:\n client.chat.completions.create()')
    assert next(s for s in r.sites if s.operation=='model').upper_bound is None


def test_sparse_js_array_is_not_empty(tmp_path):
    engine,_=workspace(tmp_path,{'a.js':'import OpenAI from "openai"; const c=new OpenAI(); for(const x of [,,]) { c.chat.completions.create(); }'})
    assert all(s.upper_bound is None for f in engine.flows.values() for s in f.result.sites if s.operation=='model')


def test_function_alias_preserves_return():
    r=flow('def cap(xs):\n return xs[:4]\nalias=cap\nitems=alias(rows)\nimport openai\nfor x in items:\n client.chat.completions.create()')
    assert next(s for s in r.sites if s.operation=='model').upper_bound==4


def test_cross_file_function_alias(tmp_path):
    engine,_=workspace(tmp_path,{'lib.py':'def cap(xs):\n return xs[:2]', 'a.py':'from lib import cap\nf=cap\nimport openai\nfor x in f(rows):\n client.chat.completions.create()'})
    assert any(s.upper_bound==2 for f in engine.flows.values() for s in f.result.sites if s.operation=='model')


def test_known_wrong_receiver_does_not_become_provider():
    r=flow('import openai\nimport httpx\nc=httpx.Client()\nc.chat.completions.create()')
    assert not any(s.operation=='model' for s in r.sites)


def test_async_suspension_prevents_collection_bound():
    r=flow('import openai\nasync def f():\n items=[1,2]\n for x in items:\n  await client.chat.completions.create()')
    assert any('async' in gap for gap in r.incomplete)
    assert all(s.upper_bound is None for s in r.sites if s.operation=='model')


def test_flask_decorator_is_observation_not_authorization(tmp_path):
    _,result=workspace(tmp_path,{'a.py':'from flask_login import login_required\n@login_required\ndef route():\n eval(input())'})
    f=next(f for f in result.findings if f.rule_id=='ARGUS-SEC-001')
    assert any(g.kind=='flask_login_authentication_decorator' for g in f.assessment.safeguards)
    assert f.severity.value=='medium'
    assert not f.assessment.severity_adjustment


def test_fastapi_bearer_presence_and_disabled_guard():
    yes=flow('from fastapi import Depends\nfrom fastapi.security import HTTPBearer\nbearer=HTTPBearer()\ndef route(token=Depends(bearer)):\n eval(input())')
    no=flow('from fastapi import Depends\nfrom fastapi.security import HTTPBearer\nbearer=HTTPBearer(auto_error=False)\ndef route(token=Depends(bearer)):\n eval(input())')
    assert any(s.safeguards for s in yes.sites if s.operation=='execution')
    assert not any(s.safeguards for s in no.sites if s.operation=='execution')


def test_receiver_budget_is_disclosed():
    r=flow('a.b.c.d.e()',Budgets(receiver_depth=2))
    assert 'semantic_receiver_depth_limit' in r.incomplete


def test_imported_mutable_collection_does_not_supply_stable_bound(tmp_path):
    engine,_=workspace(tmp_path,{'lib.py':'items=[1,2]', 'a.py':'from lib import items\nimport openai\nfor x in items:\n client.chat.completions.create()'})
    assert all(s.upper_bound is None for f in engine.flows.values() for s in f.result.sites if s.operation=='model')


def test_early_return_keeps_unconstrained_path():
    r=flow('def cap(xs):\n if condition:\n  return xs\n return xs[:3]\nitems=cap(rows)\nimport openai\nfor x in items:\n client.chat.completions.create()')
    assert next(s for s in r.sites if s.operation=='model').upper_bound is None


def test_early_return_keeps_taint():
    r=flow('def f():\n if condition:\n  return input()\n return 1\neval(f())')
    assert any(s.operation=='execution' and s.tainted for s in r.sites)


def test_js_custom_range_is_not_python_builtin(tmp_path):
    engine,_=workspace(tmp_path,{'a.js':'import OpenAI from "openai"; const c=new OpenAI(); for(const x of range(3)) { c.chat.completions.create(); }'})
    assert all(s.upper_bound is None for f in engine.flows.values() for s in f.result.sites if s.operation=='model')


def test_fastapi_route_source_reaches_execution():
    r=flow('from fastapi import FastAPI\napp=FastAPI()\n@app.get("/run")\ndef route(value: str):\n eval(value)')
    assert any(s.operation=='execution' and s.tainted for s in r.sites)


def test_flask_request_source_reaches_execution():
    r=flow('from flask import request\neval(request.args.get("value"))')
    assert any(s.operation=='execution' and s.tainted for s in r.sites)


def test_module_qualified_constant_and_function(tmp_path):
    engine,_=workspace(tmp_path,{'lib.py':'LIMIT=6\ndef cap(xs,n):\n return xs[:n]', 'a.py':'import lib as cfg\nimport openai\nfor x in cfg.cap(rows,cfg.LIMIT):\n client.chat.completions.create()'})
    assert any(s.upper_bound==6 for f in engine.flows.values() for s in f.result.sites if s.operation=='model')


def test_parameter_never_inherits_same_named_global():
    r=flow('n=3\nimport openai\ndef f(n):\n for x in range(n):\n  client.chat.completions.create()')
    assert all(s.upper_bound is None for s in r.sites if s.operation=='model')


def test_later_attribute_write_invalidates_constructor_timeout():
    r=flow('import httpx\nc=httpx.Client(timeout=4)\nc.timeout=None\nc.get(url)')
    assert not next(s for s in r.sites if s.operation=='http').limit


def test_module_budget_disclosed(tmp_path):
    from argus.analysis.workspace import WorkspaceFlow
    from argus.analysis.extraction import extract
    from argus.analysis.resolution import Resolver
    for name in ('a.py','b.py'): (tmp_path/name).write_text('x=1')
    result=scan(tmp_path)
    files={f.path:f for f in result.files}
    facts={f.id:extract(f,parse(f.language,b'x=1')) for f in result.files}
    engine=WorkspaceFlow(facts,files,Resolver(files),Budgets(modules=1))
    engine.run()
    assert any('semantic_cross_file_modules_limit' in f.semantic.incomplete for f in facts.values())


def test_method_mutation_does_not_reuse_constructor_attributes():
    r=flow('import httpx\nclass W:\n def __init__(self):\n  self.client=httpx.Client(timeout=3)\n def disable(self):\n  self.client=other\n def fetch(self):\n  return self.client.get(url)\nw=W()\nalias=w\nw.disable()\nalias.fetch()')
    assert not any(s.operation=='http' and s.limit for s in r.sites)
    assert 'semantic_unresolved_instance_receiver' in r.incomplete


def test_unknown_keyword_wrapper_preserves_taint():
    r=flow('eval(unknown(value=input()))')
    assert any(s.operation=='execution' and s.tainted for s in r.sites)


def test_shadowed_sdk_constructor_is_not_identified():
    r=flow('from openai import OpenAI\nOpenAI=unknown\nc=OpenAI()\nc.chat.completions.create()')
    assert not any(s.receiver_resolved for s in r.sites if s.operation=='model')


def test_shadowed_http_module_does_not_establish_timeout():
    r=flow('import requests\nrequests=unknown\nrequests.get(url,timeout=3)')
    assert not any(s.operation=='http' and s.limit for s in r.sites)


def test_equal_values_different_origins_are_not_conflicting():
    from argus.analysis.semantic import Value
    result=Value('definite',number=3,origins=(('m',1),)).join(Value('definite',number=3,origins=(('m',2),)))
    assert result.state=='definite' and result.number==3 and len(result.origins)==2


def test_unavailable_context_is_reported_without_findings(tmp_path):
    import json
    (tmp_path/'a.py').write_text('x=1')
    result=scan(tmp_path)
    assert not result.findings and not result.diagnostics
    section=json.loads(JsonReportWriter().render(result))['not_reviewed_portions_of_the_code']
    assert section['unavailable_contextual_capabilities']
    assert any('Express' in item for item in section['unavailable_contextual_capabilities'])


def test_unknown_decorator_cannot_export_bounded_return(tmp_path):
    engine,_=workspace(tmp_path,{'lib.py':'@unknown\ndef cap(xs):\n return xs[:2]', 'a.py':'from lib import cap\nimport openai\nfor x in cap(rows):\n client.chat.completions.create()'})
    assert all(s.upper_bound is None for f in engine.flows.values() for s in f.result.sites if s.operation=='model')
