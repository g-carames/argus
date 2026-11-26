"""Synthetic sources only; no target execution or credential authentication."""
from dataclasses import replace
import os
import pytest
from argus.scanner import scan
from argus.config import DiscoverySettings, AnalysisSettings
from argus.reporting import JsonReportWriter

CASES = [
 ('SEC-001','eval(value)','int(value)'),
 ('SEC-002','import subprocess\nsubprocess.run(cmd, shell=True)','import subprocess\nsubprocess.run([cmd], shell=False)'),
 ('SEC-003','import pickle\npickle.loads(data)','import json\njson.loads(data)'),
 ('SEC-004','cursor.execute(f"SELECT {value}")','cursor.execute("SELECT ?", (value,))'),
 ('SEC-005','import hashlib\nhashlib.md5(data)','import hashlib\nhashlib.sha256(data)'),
 ('SEC-006','import requests\nrequests.get(url, verify=False)','import requests\nrequests.get(url, verify=True)'),
 ('SEC-007','from fastapi.middleware.cors import CORSMiddleware\napp.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)','from fastapi.middleware.cors import CORSMiddleware\napp.add_middleware(CORSMiddleware, allow_origins=["https://trusted.invalid"], allow_credentials=True)'),
 ('REL-001','try: run()\nexcept Exception: recover()','try: run()\nexcept ValueError: recover()'),
 ('REL-002','try: run()\nexcept ValueError: pass','try: run()\nexcept ValueError: raise'),
 ('REL-003','import requests\nrequests.get(url)','import requests\nrequests.get(url, timeout=5)'),
 ('REL-004','import time\nasync def f(): time.sleep(1)','import asyncio\nasync def f(): await asyncio.sleep(1)'),
 ('COST-001','for row in rows: cursor.execute(query, row)','cursor.executemany(query, rows)'),
 ('AI-001','from openai import OpenAI\nclient.chat.completions.create(model="m")','from openai import OpenAI\nclient.chat.completions.create(model="m", max_tokens=100)'),
 ('AI-002','import openai\nfor row in rows: client.embeddings.create(input=row)','import openai\nclient.embeddings.create(input=rows)'),
 ('CRED-001','api_key = "synthetic-only-value"','api_key = os.environ["API_KEY"]'),
]

@pytest.mark.parametrize('key,positive,negative',CASES)
def test_patterns_positive_negative_disabled(tmp_path,key,positive,negative):
    path=tmp_path/'a.py'
    rule='ARGUS-'+key
    path.write_text(positive)
    result=scan(tmp_path)
    assert any(f.rule_id == rule for f in result.findings)
    assert not any(f.rule_id == rule for f in scan(tmp_path, replace(DiscoverySettings(),analysis=AnalysisSettings(disabled_rules=(rule,)))).findings)
    path.write_text(negative)
    assert not any(f.rule_id == rule for f in scan(tmp_path).findings)

@pytest.mark.parametrize('extension',('js','ts','jsx','tsx'))
def test_js_security_ai_and_cost(tmp_path,extension):
    p=tmp_path/('a.'+extension)
    p.write_text('import OpenAI from "openai"; import {exec as run} from "node:child_process"; for (const x of xs) { client.chat.completions.create({model:"m"}); db.query(`SELECT ${x}`); } run(command); eval(value); crypto.createHash("md5");')
    rules={f.rule_id for f in scan(tmp_path).findings}
    assert {'ARGUS-SEC-001','ARGUS-SEC-002','ARGUS-SEC-004','ARGUS-SEC-005','ARGUS-AI-001','ARGUS-AI-002','ARGUS-COST-001'} <= rules
    p.write_text('import OpenAI from "openai"; client.chat.completions.create({max_tokens:100}); db.query("SELECT ?", [value]);')
    assert not scan(tmp_path).findings


def test_privacy_malformed_unsupported_and_exclusions(tmp_path):
    secret='sk-proj-'+'SYNTHETICONLY0123456789'*3
    for name,content in {'a.rs':'const SECRET: &str = "'+secret+'";', 'bad.py':'!!! '+secret,
                         'a.json':'{"api_key":"'+secret+'"}', 'a.pem':'-----BEGIN PRIVATE KEY-----\n'+secret,
                         '.gitignore':'hidden.py\n','hidden.py':'token="'+secret+'"'}.items():
        (tmp_path/name).write_text(content)
    result=scan(tmp_path)
    serialized=JsonReportWriter().render(result)
    assert secret not in serialized
    assert len([f for f in result.findings if f.rule_id == 'ARGUS-CRED-001']) == 5
    assert any(c.status.value == 'failed' for c in result.coverage.files)
    assert result.credentials is None  # no invented remediation tracking


def test_aliases_scope_limits_and_unknown_kwargs(tmp_path):
    (tmp_path/'a.py').write_text('import requests as r\nfrom pickle import loads as read\nimport time\nimport openai\nr.get(url, **options)\nread(value)\nasync def outer():\n def inner(): time.sleep(1)\nfor item in items:\n def later(): client.embeddings.create(input=item)\n')
    rules={f.rule_id for f in scan(tmp_path).findings}
    assert 'ARGUS-SEC-003' in rules
    assert not {'ARGUS-REL-003','ARGUS-REL-004','ARGUS-AI-002'} & rules


def test_swallow_supersedes_broad(tmp_path):
    (tmp_path/'a.py').write_text('try: f()\nexcept Exception: pass')
    rules={f.rule_id for f in scan(tmp_path).findings}
    assert 'ARGUS-REL-002' in rules and 'ARGUS-REL-001' not in rules


def test_native_crash_contained(tmp_path,monkeypatch):
    from argus.analysis import isolation
    def crash(*args): os._exit(77)
    monkeypatch.setattr(isolation,'parse',crash)
    (tmp_path/'a.js').write_text('const x = 1;')
    result=scan(tmp_path)
    assert result.coverage.files[0].status.value == 'failed'
    assert any(d.code == 'parse_or_extraction_failed' for d in result.diagnostics)


def test_occurrence_threshold(tmp_path):
    (tmp_path/'a.py').write_text('eval(value)')
    settings=replace(DiscoverySettings(),analysis=AnalysisSettings(rule_thresholds=(('occurrence_sec_001',1),)))
    assert not scan(tmp_path,settings).findings


def test_credential_prefixed_env_private_key_and_placeholders(tmp_path):
    (tmp_path/'.env.synthetic').write_text('LLM_API_KEY=synthetic-only-token\nDB_PASSWORD=synthetic-only-pass\nTOKEN=${LOCAL_TOKEN}\n')
    (tmp_path/'a.tsx').write_text('const CLIENT_SECRET="synthetic-only-browser";')
    (tmp_path/'a.pem').write_text('-----BEGIN RSA PRIVATE KEY-----\nsynthetic payload\n')
    r=scan(tmp_path)
    hits=[f for f in r.findings if f.rule_id=='ARGUS-CRED-001']
    assert len(hits)==4
    data=JsonReportWriter().render(r)
    for value in ('synthetic-only-token','synthetic-only-pass','synthetic-only-browser','synthetic payload'):
        assert value not in data


def test_pattern_ids_survive_line_shift(tmp_path):
    p=tmp_path/'a.py'
    p.write_text('eval(value)')
    before=[f.id for f in scan(tmp_path).findings]
    p.write_text('# unrelated comment\n\neval(value)')
    assert [f.id for f in scan(tmp_path).findings]==before


def test_all_security_and_ai_rules_disabled_coverage(tmp_path):
    from argus.analysis.rules import REGISTRY
    disabled=tuple(r.id for r in REGISTRY if r.category.value in ('security','ai_specific'))
    (tmp_path/'a.py').write_text('eval(value)')
    r=scan(tmp_path,replace(DiscoverySettings(),analysis=AnalysisSettings(disabled_rules=disabled)))
    assert not r.findings
    for cap in r.coverage.files[0].capabilities:
        if cap.capability.value in ('security_rules','ai_specific_analysis'):
            assert cap.status.value=='disabled' and cap.evaluated_units==0


def test_js_tls_cors_and_safe_options(tmp_path):
    p=tmp_path/'a.js'
    p.write_text('import cors from "cors"; cors({origin:true,credentials:true}); const tls={rejectUnauthorized:false};')
    assert {'ARGUS-SEC-006','ARGUS-SEC-007'} <= {f.rule_id for f in scan(tmp_path).findings}
    p.write_text('import cors from "cors"; cors({origin:"https://trusted.invalid",credentials:true}); const tls={rejectUnauthorized:true};')
    assert not scan(tmp_path).findings


def test_isolation_deadline(tmp_path,monkeypatch):
    import time
    from types import SimpleNamespace
    from argus.analysis import isolation
    from argus.analysis.parsing import ParseFailure
    def stalled(*args): time.sleep(2)
    monkeypatch.setattr(isolation,'_worker',stalled)
    start=time.monotonic()
    with pytest.raises(ParseFailure): isolation.isolated_extract(SimpleNamespace(),b'',timeout=.05)
    assert time.monotonic()-start<1.5


def test_text_credentials_do_not_hide_unsupported_structural_scope(tmp_path):
    (tmp_path/'a.go').write_text('package main\n')
    import json
    data=json.loads(JsonReportWriter().render(scan(tmp_path)))
    unsupported=data['not_reviewed_portions_of_the_code']['unsupported_languages_and_formats']
    assert any(g['language_or_format']=='go' and g['file_count']==1 for g in unsupported)
    assert data['coverage']['files'][0]['status']=='partial'
    caps={c['capability']:c['status'] for c in data['coverage']['files'][0]['capabilities']}
    assert caps['credential_detection']=='partial' and caps['structural_analysis']=='unsupported'
