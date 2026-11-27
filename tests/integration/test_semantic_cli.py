"""Fresh wheel + isolated environment + serialized CLI oracles; synthetic inputs only."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

pytestmark = pytest.mark.installed_cli
ROOT=Path(__file__).resolve().parents[2]


def command(args,**kwargs):
    result=subprocess.run([str(a) for a in args],capture_output=True,text=True,**kwargs)
    assert result.returncode==0, result.stderr
    if Path(str(args[0])).name=='argus': assert result.stderr==''
    return result.stdout


@pytest.fixture(scope='session')
def installed_cli(tmp_path_factory):
    work=tmp_path_factory.mktemp('installed-semantic')
    wheel=os.environ.get('ARGUS_SEMANTIC_WHEEL')
    if not wheel:
        command(['uv','build','--offline','--out-dir',work/'dist',ROOT])
        wheel=next((work/'dist').glob('*.whl'))
    requirements=work/'locked.txt'
    requirements.write_text(command(['uv','export','--locked','--offline','--no-dev','--no-emit-project','--format','requirements-txt'],cwd=ROOT))
    command(['uv','venv','--offline','--python',sys.executable,work/'env'])
    python=work/'env/bin/python'
    command(['uv','pip','install','--offline','--python',python,'-r',requirements,wheel])
    return work/'env/bin/argus'


@pytest.fixture
def cli_scan(installed_cli,tmp_path):
    counter=0
    def run(files):
        nonlocal counter
        counter+=1
        root=tmp_path/str(counter);root.mkdir()
        for name,content in files.items():
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(content)
        before={p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
        env={k:v for k,v in os.environ.items() if k!='PYTHONPATH'}
        raw=command([installed_cli,'scan',root],cwd=tmp_path,env=env)
        assert raw==command([installed_cli,'scan',root],cwd=tmp_path,env=env)
        assert before=={p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
        assert str(root) not in raw
        report=json.loads(raw)
        assert 'Not Reviewed Portions of the Code' in raw
        return report
    return run


def obs(report,kind,path=None,line=None):
    files={f['id']:f['path'] for f in report['files']}
    evidence={e['id']:e for e in report['evidence']}
    return [o for o in report['semantic_observations'] if o['kind']==kind
        and (path is None or files[o['file_id']]==path)
        and (line is None or evidence[o['evidence_ids'][0]]['locations'][0]['start_line']==line)]


@pytest.mark.parametrize('body,bound,channels',[
    ('return xs[:3]',3,{'returned'}),
    ('if reject:\n  raise ValueError()\n return xs[:3]',3,{'returned','raised'}),
    ('if reject:\n  return unknown\n return xs[:3]',None,{'returned','raised'}),
    ('if reject:\n  return xs[:3]',None,{'returned','normal_fallthrough','raised'}),
    ('raise ValueError()\n return xs[:3]',None,{'raised'}),
    ('if reject:\n  raise ValueError()\n else:\n  raise TypeError()\n return xs[:3]',None,{'raised'}),
    ('try:\n  return xs[:3]\n finally:\n  return unknown',None,{'returned'}),
])
def test_successful_exit_channels(cli_scan,body,bound,channels):
    report=cli_scan({'lib.py':'def cap(xs):\n '+body+'\n','app.py':'from lib import cap\ny=cap(rows)\n',
        'native.py':'from lib import cap\ny=cap([1,2,3,4])\n'})
    returns=obs(report,'return_bound','lib.py',1)
    assert returns and all(o['upper_bound']==bound and set(o['exit_channels'])==(channels|{'raised'} if bound is not None and not o['bound_supported'] else channels) for o in returns)
    if bound is None: assert all(o['certainty']=='unknown_or_unresolved' for o in returns)
    else:
        known=obs(report,'assignment_fact','native.py',2)[0]
        native=[o for o in returns if o['result_id']==known['result_id']]
        assert len(native)==1 and native[0]['certainty']=='statically_established' and native[0]['bound_supported']
        opaque=[o for o in returns if o['result_id']!=known['result_id']]
        assert opaque and all(o['certainty']=='possible_inference' and not o['bound_supported'] for o in opaque)
    assignment=obs(report,'assignment_fact','app.py',2)
    if channels=={'raised'}:
        assert assignment==[]
        return
    assert len(assignment)==1 and assignment[0]['upper_bound']==bound
    linked=[o for o in returns if o['result_id']==assignment[0]['result_id']]
    assert len(linked)==1


def test_equal_values_distinct_callers_and_actual_formal_result(cli_scan):
    report=cli_scan({'lib.py':'def echo(xs):\n return xs\n',
        'a.py':'from lib import echo\nx=echo([1,2])\n',
        'b.py':'from lib import echo\nx=echo(xs=[3,4])\n'})
    args=obs(report,'argument_constraint','lib.py')
    known=[o for o in args if o['upper_bound']==2]
    external=[o for o in args if o['binding_kind']=='external_unknown']
    assert len(known)==2 and len(external)==1 and external[0]['upper_bound'] is None
    for field in ('context_id','callsite_id','actual_id','result_id'):
        assert len({o[field] for o in known})==2
    assert len({o['formal_id'] for o in args})==1
    assert {o['binding_kind'] for o in known}=={'positional','keyword'}
    returns=obs(report,'return_bound','lib.py')
    for arg in known:
        ret=next(o for o in returns if o['result_id']==arg['result_id'])
        assert ret['context_id']==arg['context_id'] and ret['call_path_ids']==arg['call_path_ids']
        assert arg['argument_position']==0 and arg['origin_value_id']
        evidence={e['id']:e for e in report['evidence']}
        paths={l['path'] for l in evidence[arg['evidence_ids'][0]]['locations']}
        assert 'lib.py' in paths and len(paths)==2
    assert not report['findings']
    calls=obs(report,'call_path')
    relationships={r['id']:r for r in report['graph']['relationships']}
    for arg in known:
        assert any(o['callsite_id']==arg['callsite_id'] and relationships[o['relationship_ids'][0]]['resolution']=='resolved' for o in calls)


def test_receiver_resolution_and_ambiguous_alternatives(cli_scan):
    report=cli_scan({'workers.py':'class A:\n def run(self):\n  return [1]\nclass B:\n def run(self):\n  return [1,2]\n',
        'app.py':'from workers import A, B\na=A()\ny=a.run()\nif flag:\n mixed=A()\nelse:\n mixed=B()\nz=mixed.run()\nunknown.run()\n'})
    evidence={e['id']:e for e in report['evidence']}
    edges=[r for r in report['graph']['relationships'] if r['context_ids']]
    at=lambda line:[r for r in edges if any(l['path']=='app.py' and l['start_line']==line for e in r['evidence_ids'] for l in evidence[e]['locations'])]
    assert len(at(3))==1 and at(3)[0]['resolution']=='resolved'
    assert len(at(8))==1 and at(8)[0]['resolution']=='ambiguous'
    ambiguous=at(8)[0]
    assert ambiguous['target_id'] is None and len(ambiguous['candidate_target_ids'])==2
    assert at(3)[0]['target_id'] in ambiguous['candidate_target_ids']
    assert not at(9)
    assert obs(report,'receiver_resolution','app.py',8)[0]['certainty']=='possible_inference'


def test_scoped_incompleteness_and_operation_survival(cli_scan):
    report=cli_scan({'lib.py':'import requests\ndef partial():\n with unknown_context():\n  pass\n marker=unknown\n marker=unknown\ndef clean():\n requests.get(url,timeout=3)\n',
        'app.py':'from lib import clean\nclean()\n'})
    timeout=obs(report,'timeout_setting','lib.py',8)
    assert timeout and all(o['certainty']=='statically_established' for o in timeout)
    assert all('semantic_unsupported_control_or_statement' not in ' '.join(o['limitations']) for o in timeout)
    assert obs(report,'incomplete_analysis','lib.py',2)
    assert report['not_reviewed_portions_of_the_code']['semantic_analysis_gaps']
    assert not any(f['rule_id']=='ARGUS-REL-003' for f in report['findings'])


@pytest.mark.parametrize('name,value,recognized,placeholder',[
    ('plain.py','YOUR_API_KEY',False,True),
    ('embedded.py','placeholder_sk-'+'A'*24,True,True),
    ('delimited.py','<sk-'+'B'*24+'>',True,True),
    ('guide.md','sk-'+'C'*24,True,False),
    ('unknown.py','abcdefghij',False,False),
], ids=['exact-placeholder','embedded-pattern','delimited-pattern','documentation','unknown-validity'])
def test_credential_occurrence_precedence_and_privacy(cli_scan,name,value,recognized,placeholder):
    report=cli_scan({name:'api_key="'+value+'"\n'})
    classes={c['classification'] for c in report['credential_candidates']}
    assert ('recognized_pattern' in classes)==recognized
    assert ('obvious_placeholder' in classes)==placeholder
    assert all(c['validity']=='unverified' for c in report['credential_candidates'])
    assert any(f['rule_id']=='ARGUS-CRED-001' for f in report['findings']) != (placeholder and not recognized)
    assert value not in json.dumps(report)
    assert all(c['documentation_context']==name.endswith('.md') for c in report['credential_candidates'])


def test_multiple_credential_occurrences_same_line(cli_scan):
    first='sk-'+'D'*24;second='sk-'+'E'*24
    report=cli_scan({'settings.py':f'api_key="{first}"; token="{second}"\n'})
    candidates=report['credential_candidates']
    assert len(candidates)==2 and len({c['id'] for c in candidates})==2
    assert all(c['classification']=='recognized_pattern' for c in candidates)
    assert all(v not in json.dumps(report) for v in (first,second))


def test_loop_unknown_is_not_infinite_and_plain_call_facts_survive(cli_scan):
    report=cli_scan({'lib.py':'def ping(x):\n return x\n',
        'app.py':'from lib import ping\nfor x in rows:\n ping(x)\n'})
    domains=obs(report,'loop_domain','app.py',3)
    assert domains and all(o['upper_bound'] is None and o['certainty']=='unknown_or_unresolved' for o in domains)
    assert not report['findings']
    assert obs(report,'call_path','app.py',3)


def test_metamorphic_identity_and_bound_conservation(cli_scan):
    def repo(symbol='cap',order=False,split=False,unrelated=7):
        definition=f'def {symbol}(xs):\n return xs[:2]\n'
        use=f'x={symbol}([1,2,3])\ny={symbol}(rows)\n'
        if order: use='\n'.join(reversed(use.strip().splitlines()))+'\n'
        files={'app.py':(f'from lib import {symbol}\n' if split else definition)+use+f'unrelated={unrelated}\n'}
        if split: files['lib.py']=definition
        return files
    reports=[cli_scan(repo()),cli_scan(repo(symbol='renamed')),cli_scan(repo(order=True)),cli_scan(repo(split=True)),cli_scan(repo(unrelated=99))]
    def signature(report):
        return sorted((o['upper_bound'],o['binding_kind']) for o in obs(report,'argument_constraint') if o['upper_bound'] is not None)
    assert all(signature(r)==[(3,'positional')] for r in reports)
    def call_ids(r): return {o['callsite_id'] for o in obs(r,'argument_constraint') if o['upper_bound']==3}
    assert call_ids(reports[0])==call_ids(reports[1])==call_ids(reports[4])
    for r in reports:
        bounded=obs(r,'return_bound')
        assert bounded and all(o['upper_bound']==2 for o in bounded)
        assert len({o['context_id'] for o in bounded})==3


def test_confirmed_raised_exit_regression_public_bound(cli_scan):
    def run(branch):
        return cli_scan({'lib.py':'def cap(xs):\n '+branch+'\n return xs[:3]\n',
            'app.py':'from lib import cap\nimport requests\nitems=cap(list(rows))\nfor item in items:\n requests.get(url,timeout=2)\n'})
    raised=run('if reject:\n  raise ValueError()')
    unknown=run('if reject:\n  return unknown')
    bounds=obs(raised,'collection_bound','app.py',5)
    assert bounds and all(o['upper_bound']==3 for o in bounds)
    assert not obs(unknown,'collection_bound','app.py',5)


def test_confirmed_invocation_projection_regression(cli_scan):
    report=cli_scan({'lib.py':'def echo(x):\n return x\n','app.py':'from lib import echo\necho([1])\n'})
    edges=[r for r in report['graph']['relationships'] if r['kind']=='invocation' and r['resolution']=='resolved']
    assert len(edges)==1
    paths=obs(report,'call_path','app.py',2)
    assert len(paths)==1 and paths[0]['relationship_ids']==[edges[0]['id']]


def test_graph_derived_operation_is_projected_after_contextual_analysis(cli_scan):
    report=cli_scan({'lib.py':'import openai\ndef work():\n client=openai.OpenAI()\n client.chat.completions.create(max_tokens=2)\n',
        'app.py':'from lib import work\nfor item in rows:\n work()\n'})
    inferred=obs(report,'operation_binding','app.py',3)
    assert inferred and all(o['certainty']=='possible_inference' for o in inferred)
    assert all(o['upper_bound'] is None for o in inferred)
    actual=obs(report,'operation_binding','lib.py',4)
    assert actual and all(o['certainty']=='statically_established' for o in actual)


def test_imported_constructor_keeps_original_caller_location(cli_scan):
    report=cli_scan({'model.py':'class Item:\n def __init__(self,values):\n  self.values=values\n',
        'a.py':'from model import Item\nx=Item([1])\n',
        'b.py':'from model import Item\nx=Item([2])\n'})
    args=obs(report,'argument_constraint','model.py',2)
    values=[o for o in args if o['argument_position']==1]
    assert len(values)==2 and len({o['callsite_id'] for o in values})==2
    assert len({o['context_id'] for o in values})==2
    locations={e['id']:e['locations'] for e in report['evidence']}
    assert all({l['path'] for l in locations[o['evidence_ids'][0]]} in ({'model.py','a.py'},{'model.py','b.py'}) for o in values)
    edges=[r for r in report['graph']['relationships'] if r['context_ids']]
    assert len(edges)==2
    assert all({l['path'] for eid in r['evidence_ids'] for l in locations[eid]} in ({'a.py'},{'b.py'}) for r in edges)
    assert not obs(report,'call_path','model.py')


@pytest.mark.parametrize('statement,bound,channels',[
    ('throw new Error()',3,{'raised','returned'}),
    ('return unknown',None,{'returned'}),
])
def test_typescript_shared_exit_and_projection_contract(cli_scan,statement,bound,channels):
    report=cli_scan({'lib.ts':f'export function cap(xs: string[]) {{ if (reject) {{ {statement}; }} return xs.slice(0,3); }}',
        'app.ts':'import {cap} from "./lib"; const result=cap(rows);'})
    returns=obs(report,'return_bound','lib.ts')
    assert returns and all(o['upper_bound']==bound and set(o['exit_channels'])==channels for o in returns)
    assert obs(report,'call_path','app.ts')
    assignments=obs(report,'assignment_fact','app.ts')
    assert assignments and all(o['upper_bound']==bound for o in assignments)


def test_same_line_calls_reconcile_by_exact_callsite(cli_scan):
    report=cli_scan({'lib.py':'def cap(xs):\n return xs\n',
        'app.py':'from lib import cap\na=cap([1]); b=cap([2]); unknown()\n'})
    paths=obs(report,'call_path','app.py',2)
    assert len(paths)==3 and len({o['callsite_id'] for o in paths})==3
    edges={r['id']:r for r in report['graph']['relationships']}
    assert sum(edges[o['relationship_ids'][0]]['resolution']=='resolved' for o in paths)==2
    locations={e['id']:e['locations'] for e in report['evidence']}
    assert {locations[o['evidence_ids'][0]][0]['start_column'] for o in paths}=={3,15,25}


def test_loop_domain_survives_without_calls_or_findings(cli_scan):
    report=cli_scan({'app.py':'for item in [1,2]:\n value=item\n'})
    domains=obs(report,'loop_domain','app.py',1)
    assert len(domains)==1 and domains[0]['upper_bound']==2
    assert domains[0]['certainty']=='statically_established'
    assert not report['findings']
