"""Owned regression cases; no held-out fixtures, SDK calls or target execution."""
import json
from dataclasses import replace
import pytest
from argus.scanner import scan
from argus.reporting import JsonReportWriter
from argus.models.semantic import MitigationState as M
from argus.models.scan import Diagnostic, DiagnosticClass as D
from argus.diagnostics import consolidate
from argus.models.source import SourceLocation
from tests.test_semantic_context import flow
from tests.test_semantic_cross_file import workspace


def result(tmp_path,source):
    (tmp_path/'app.py').write_text(source)
    return scan(tmp_path)


def hits(r,rule):
    return [f for f in r.findings if f.rule_id=='ARGUS-'+rule]


@pytest.mark.parametrize('construction',[
 'from openai import OpenAI as SDK\nc=SDK()',
 'import openai as sdk\nc=sdk.OpenAI()',
 'from openai import OpenAI\nFactory=OpenAI\nc=Factory()',
 'from openai import OpenAI\ndef factory():\n return OpenAI()\nc=factory()',
])
def test_responses_operation_identity_and_specific_limit(tmp_path,construction):
    r=result(tmp_path,construction+'\nc.responses.create(max_tokens=4)')
    assert hits(r,'AI-001')  # Chat parameter does not bound Responses.
    assert any(o.kind=='operation_binding' and o.certainty=='statically_established' for o in r.semantic_observations)
    r=result(tmp_path,construction+'\nc.responses.create(max_output_tokens=4)')
    assert not hits(r,'AI-001')
    assert r.semantic_observations


def test_responses_imported_instance_attribute_and_wrapper(tmp_path):
    engine,r=workspace(tmp_path,{
        'sdk.py':'from openai import OpenAI\nc=OpenAI()\ndef invoke():\n return c.responses.create()',
        'app.py':'from sdk import c,invoke\nalias=c\nalias.responses.create()\nfor x in [1,2]:\n invoke()',
    })
    assert hits(r,'AI-001') and hits(r,'AI-002')
    assert any(s.receiver_resolved for f in engine.flows.values() for s in f.result.sites if s.operation=='model')
    r=result(tmp_path,'from openai import OpenAI\nclass Worker:\n def __init__(self):\n  self.c=OpenAI()\n def run(self):\n  self.c.responses.create()\nWorker().run()')
    assert any(o.kind=='operation_binding' and o.certainty=='statically_established' for o in r.semantic_observations)


@pytest.mark.parametrize('source',[
 'class Other:\n def create(self): pass\nOther().create()',
 'import openai\nimport httpx\nc=httpx.Client()\nc.responses.create()',
 'from openai import OpenAI\ndef OpenAI():\n return unknown\nc=OpenAI()\nc.responses.create()',
 'from openai import OpenAI\nfrom unittest.mock import Mock\nc=Mock()\nc.responses.create()',
])
def test_unrelated_and_mock_never_establish_sdk(tmp_path,source):
    r=result(tmp_path,source)
    assert not any(o.kind=='operation_binding' and o.certainty=='statically_established' for o in r.semantic_observations)


def test_injected_receiver_is_possible(tmp_path):
    r=result(tmp_path,'import openai\ndef run(client):\n client.responses.create()')
    assert any(o.kind=='operation_binding' and o.certainty=='possible_inference' for o in r.semantic_observations)
    assert all(f.assessment.mitigation_state!=M.NONE for f in hits(r,'AI-001'))


@pytest.mark.parametrize('setup,call,expected',[
 ('c=httpx.Client()','c.get(url)',False),
 ('c=httpx.Client(timeout=2.5)','c.get(url)',False),
 ('c=httpx.Client(timeout=None)','c.get(url)',True),
 ('c=httpx.Client(timeout=2)','c.get(url,timeout=None)',True),
 ('c=httpx.Client(timeout=None)','c.get(url,timeout=1.5)',False),
 ('c=httpx.Client(timeout=2)','c.get(url,timeout=runtime)',True),
 ('t=httpx.Timeout(5.0,connect=1.0)\nc=httpx.Client(timeout=t)','c.get(url)',False),
 ('t=httpx.Timeout(5.0,read=None)\nc=httpx.Client(timeout=t)','c.get(url)',True),
 ('c=httpx.Client(timeout=runtime)','c.get(url)',True),
 ('','httpx.get(url)',False),
 ('','httpx.get(url,timeout=None)',True),
])
def test_timeout_defaults_overrides_and_uncertainty(tmp_path,setup,call,expected):
    r=result(tmp_path,'import httpx\n'+setup+'\n'+call)
    assert bool(hits(r,'REL-003'))==expected
    assert any(o.kind=='timeout_setting' for o in r.semantic_observations)


def test_httpx_cross_file_factory_alias(tmp_path):
    _,r=workspace(tmp_path,{'clients.py':'import httpx\nc=httpx.Client(timeout=2.5)\ndef factory():\n return c',
        'app.py':'from clients import c,factory\na=c\na.get(url)\nb=factory()\nb.get(url)'})
    assert not hits(r,'REL-003')
    assert any(o.kind=='timeout_setting' for o in r.semantic_observations)


@pytest.mark.parametrize('source,risky',[
 ('cursor.execute("SELECT ?",(value,))',False),
 ('cursor.execute("SELECT " + "1")',False),
 ('n=7\ncursor.execute(f"SELECT {n}")',False),
 ('n=int(input())\ncursor.execute(f"SELECT {n}")',False),
 ('n=input()\ncursor.execute(f"SELECT {n}")',True),
 ('cursor.execute(f"SELECT {unknown}")',True),
 ('n=clean(input())\ncursor.execute(f"SELECT {n}")',True),
 ('n=int(input())\nn=input()\ncursor.execute(f"SELECT {n}")',True),
 ('def run(n):\n cursor.execute(f"SELECT {n}")\nrun(int(input()))',True),
 ('cursor.execute(f"SELECT * FROM {table}")',True),
 ('cursor.execute("SELECT %s" % (7,))',False),
 ('int=unknown\nn=int(input())\ncursor.execute(f"SELECT {n}")',True),
])
def test_sql_value_discrimination(tmp_path,source,risky):
    r=result(tmp_path,source)
    assert bool(hits(r,'SEC-004'))==risky
    if 'f"' in source or ' + ' in source or ' % ' in source:
        assert any(o.kind=='sql_construction' for o in r.semantic_observations)
    assert all('vulnerable' not in f.title.lower() for f in hits(r,'SEC-004'))


def test_dbapi_parameter_binding_observation(tmp_path):
    r=result(tmp_path,'import sqlite3\nc=sqlite3.connect(":memory:").cursor()\nc.execute("SELECT ?",(value,))')
    assert not hits(r,'SEC-004')
    assert any('parameter-binding' in o.conclusion for o in r.semantic_observations)


def test_bounds_authentication_and_invalidation_without_findings(tmp_path):
    r=result(tmp_path,'from flask_login import login_required\ndef cap(xs):\n return xs[:3]\nitems=cap(rows)\nunknown(items)\n@login_required\ndef route():\n return 1')
    kinds={o.kind for o in r.semantic_observations}
    assert {'return_bound','safeguard_invalidation','authentication_registration'}<=kinds
    assert not r.findings


def test_context_bounds_keep_unknown_entry(tmp_path):
    r=result(tmp_path,'from openai import OpenAI\nc=OpenAI()\ndef run(xs):\n for x in xs:\n  c.responses.create()\nrun([1,2])')
    assert any(o.kind=='argument_constraint' for o in r.semantic_observations)
    assert any(o.kind=='collection_bound' for o in r.semantic_observations)
    assert all(f.assessment.mitigation_state!=M.ESTABLISHED for f in hits(r,'AI-002'))


def test_semantic_privacy_and_determinism(tmp_path):
    secret='synthetic-private-value-61'
    r=result(tmp_path,'import httpx\nc=httpx.Client()\nc.get("'+secret+'")\napi_key="'+secret+'"')
    first=JsonReportWriter().render(r)
    assert secret not in first and str(tmp_path) not in first
    assert first==JsonReportWriter().render(scan(tmp_path))
    data=json.loads(first)
    assert data['schema_version']=='1.4.0' and data['semantic_observations']
    assert data['credential_candidates']


@pytest.mark.parametrize('value,classification,risky',[
 ('your_api_key_here','obvious_placeholder',False),
 ('<insert-token-here>','obvious_placeholder',False),
 ('test_plausible_secret_61','plausible_assignment',True),
 ('example_live_candidate_61','plausible_assignment',True),
 ('sk-'+'A1b2C3d4'*4,'recognized_pattern',True),
])
def test_credential_value_classification(tmp_path,value,classification,risky):
    (tmp_path/'example_mock_test.md').write_text('api_key="'+value+'" # dummy example')
    r=scan(tmp_path)
    assert bool(hits(r,'CRED-001'))==risky
    assert r.credential_candidates[0].classification==classification
    assert r.credential_candidates[0].documentation_context
    assert value not in JsonReportWriter().render(r)


def test_diagnostic_consolidation_preserves_locations():
    ds=tuple(Diagnostic(code='semantic_analysis_incomplete',stage='analysis',message='semantic_cross_file_modules_limit',location=SourceLocation(path=p,start_line=1,start_column=1)) for p in ('a.py','b.py'))
    combined=consolidate(ds)
    assert len(combined)==1 and combined[0].classification==D.RESOURCE
    assert combined[0].occurrences==2 and {l.path for l in combined[0].affected_locations}=={'a.py','b.py'}


def test_cli_usable_partial_report_is_success(tmp_path,capsys):
    from argus.cli import main
    (tmp_path/'a.py').write_text('def f():\n with unknown():\n  pass')
    assert main(['scan',str(tmp_path)])==0
    assert json.loads(capsys.readouterr().out)['diagnostics']
    (tmp_path/'a.py').write_text('def broken(')
    assert main(['scan',str(tmp_path)])==1


def test_module_budget_predictable_and_disclosed(tmp_path):
    for i in range(130): (tmp_path/f'm{i:03}.py').write_text('N=1')
    r=scan(tmp_path)
    ds=[d for d in r.diagnostics if d.message=='semantic_cross_file_modules_limit']
    assert len(ds)==1 and ds[0].occurrences==2 and len(ds[0].affected_locations)==2
    assert ds[0].classification==D.RESOURCE


def test_import_capture_order_is_stable(tmp_path):
    (tmp_path/'a.ts').write_text('import {x} from "./b";\nimport {y} from "./c";\nexport {z} from "./b";')
    (tmp_path/'b.ts').write_text('export const x=1;export const z=2;')
    (tmp_path/'c.ts').write_text('export const y=3;')
    first=JsonReportWriter().render(scan(tmp_path))
    assert all(JsonReportWriter().render(scan(tmp_path))==first for _ in range(5))


def test_known_parser_budget_classification(tmp_path,monkeypatch,capsys):
    import ast
    from argus.analysis.parsing import walk,ParseResourceLimit
    with pytest.raises(ParseResourceLimit): list(walk(ast.parse('x=1'),max_nodes=1))
    from argus.analysis import pipeline
    from argus.cli import main
    def exhausted(*args):raise ParseResourceLimit()
    monkeypatch.setattr(pipeline,'isolated_extract',exhausted)
    (tmp_path/'a.ts').write_text('const x=1;')
    assert main(['scan',str(tmp_path)])==0
    data=json.loads(capsys.readouterr().out)
    assert any(d['classification']=='resource_budget_exhaustion' for d in data['diagnostics'])


def test_requests_tuple_and_invalid_constructor(tmp_path):
    assert not hits(result(tmp_path,'import requests\nrequests.get(url,timeout=(1.0,2.5))'),'REL-003')
    assert hits(result(tmp_path,'import requests\nc=requests.Session(timeout=5)\nc.get(url)'),'REL-003')


def test_unconstructed_sdk_symbol_never_establishes_operation(tmp_path):
    r=result(tmp_path,'from openai import OpenAI\nc=OpenAI\nc.responses.create()')
    assert not any(o.kind=='operation_binding' and o.certainty=='statically_established' for o in r.semantic_observations)


def test_sql_identifier_observation_and_format_templates(tmp_path):
    r=result(tmp_path,'cursor.execute(f"SELECT * FROM {table}")')
    assert hits(r,'SEC-004')
    assert any('identifier interpolation' in o.conclusion for o in r.semantic_observations)
    assert hits(result(tmp_path,'q="SELECT {}".format(input())\ncursor.execute(q)'),'SEC-004')
    assert not hits(result(tmp_path,'q="SELECT {}".format(int(input()))\ncursor.execute(q)'),'SEC-004')


@pytest.mark.parametrize('extension',('js','ts','jsx','tsx'))
def test_responses_js_family(tmp_path,extension):
    p=tmp_path/('app.'+extension)
    p.write_text('import OpenAI from "openai"; const c=new OpenAI(); for(const x of [1,2]) { c.responses.create({max_output_tokens:4}); }')
    r=scan(tmp_path)
    assert hits(r,'AI-002') and not hits(r,'AI-001')
    assert any(o.operation_id=='openai.OpenAI.responses.create' for o in r.semantic_observations)


def test_uncertain_short_credential_is_retained(tmp_path):
    r=result(tmp_path,'api_key="abcdefgh"')
    assert hits(r,'CRED-001')
    assert r.credential_candidates[0].classification=='uncertain_candidate'
    assert 'abcdefgh' not in JsonReportWriter().render(r)


def test_observation_contract_validates_evidence_and_scope(tmp_path):
    from argus.models.semantic import SemanticObservation,ObservationKind,SemanticCertainty
    with pytest.raises(ValueError):
        SemanticObservation(id='id',file_id='file',scope_id='scope',kind=ObservationKind.BOUND,certainty=SemanticCertainty.ESTABLISHED,evidence_ids=(),conclusion='Bound')
    r=result(tmp_path,'import httpx\nhttpx.get(url)')
    with pytest.raises(ValueError):
        replace(r,semantic_observations=(replace(r.semantic_observations[0],scope_id='missing'),))


def test_known_mock_is_inspectable_without_provider_findings(tmp_path):
    r=result(tmp_path,'import openai\nfrom unittest.mock import Mock\nc=Mock()\nc.chat.completions.create()')
    assert not hits(r,'AI-001')
    assert any('unittest.mock receiver' in o.conclusion for o in r.semantic_observations)


def test_responses_in_unsupported_control_remains_incomplete(tmp_path):
    r=result(tmp_path,'from openai import OpenAI\nc=OpenAI()\ntry:\n for x in rows:\n  c.responses.create()\nexcept Exception:\n pass')
    assert hits(r,'AI-002')
    assert all(f.assessment.mitigation_state==M.INCOMPLETE for f in hits(r,'AI-002'))


@pytest.mark.parametrize('source',[
 'for x in range(1.5):\n pass',
 'xs=items[:2.5]',
 'i=0.0\nwhile i<3.5:\n i+=1.0',
 'n=min(runtime,3.5)\nfor x in range(n):\n pass',
])
def test_float_timeouts_do_not_enable_invalid_collection_bounds(tmp_path,source):
    r=result(tmp_path,source)
    assert not any(o.kind=='collection_bound' for o in r.semantic_observations)
    JsonReportWriter().render(r)


def test_nonfinite_timeout_is_not_established(tmp_path):
    r=result(tmp_path,'import httpx\nhttpx.get(url,timeout=1e999)')
    assert hits(r,'REL-003')
    assert any(o.timeout_state=='invalid' for o in r.semantic_observations)
