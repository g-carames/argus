"""Synthetic static inputs; tests never import or execute target code."""
import json
from dataclasses import replace
import pytest
from argus.scanner import scan
from argus.reporting import JsonReportWriter
from argus.config import DiscoverySettings
from argus.analysis.parsing import parse, ParseFailure, ParseUnavailable
from argus.models.base import Capability, Status

@pytest.mark.parametrize('extension,source', [
 ('py', 'class A:\n def f(self, x):\n  if x:\n   return x\n  return 0\n'),
 ('js', 'export class A { f(x) { if(x) return x; return 0; } }'),
 ('ts', 'export class A { f(x: number): number { if(x) return x; return 0; } }'),
 ('jsx', 'export function A(x) { if(x) return <div/>; return null; }'),
 ('tsx', 'export function A(x: boolean) { if(x) return <div/>; return null; }'),
])
def test_primary_symbols_structure_and_unicode(tmp_path, extension, source):
    (tmp_path / ('sample.' + extension)).write_text(source)
    r = scan(tmp_path)
    assert len(r.modules) == 1 and any(s.kind in ('function','method') for s in r.symbols)
    assert any(m.name == 'cyclomatic_complexity' and m.value == 2 for m in r.graph.metrics)
    assert any(m.name == 'conditional_count' and m.value == 1 for m in r.graph.metrics)
    assert r.coverage.files[0].status == Status.PARTIAL
    assert next(c for c in r.coverage.files[0].capabilities if c.capability == Capability.PARSING).status == Status.COMPLETED
    assert not r.findings
    assert JsonReportWriter().render(r) == JsonReportWriter().render(scan(tmp_path))

@pytest.mark.parametrize('language,source', [('python','def ('),('javascript','const = ;'), ('typescript','function {'),
 ('jsx','const x = <div>'),('tsx','const x = <div>'),('json','{bad'),('toml','[broken'),('yaml','a: [unclosed'),
 ('bash','if then'),('html','<div><'),('css','a { color: ; broken')])
def test_malformed(language, source):
    with pytest.raises(ParseFailure):
        parse(language, source.encode())

@pytest.mark.parametrize('name,source,metric', [
 ('a.json','{"a":{"b":2},"list":[1]}','configuration_entries'),
 ('a.toml','[one]\na=1','configuration_entries'),
 ('a.yaml','one:\n  two: 1\n',None), ('a.html','<html><body><p>hello</p></body></html>',None),
 ('a.css','a { color: red; }',None), ('a.sh','hello() { if true; then echo ok; fi; }', 'function_length'),
 ('a.sql','CREATE TABLE items(id INTEGER); SELECT * FROM items;', 'sql_statement_count'),
 ('Dockerfile','FROM scratch\nCOPY a /a\n', 'docker_instruction_count'),
])
def test_additional_capabilities(tmp_path, name, source, metric):
    (tmp_path / name).write_text(source)
    r = scan(tmp_path)
    assert len(r.modules) == 1
    assert r.coverage.files[0].status == Status.PARTIAL
    if metric:
        assert any(m.name == metric and m.value > 0 for m in r.graph.metrics)
    else:
        assert r.symbols
    assert not r.findings
    assert all(c.status == Status.UNSUPPORTED for c in r.coverage.files[0].capabilities if c.capability == Capability.SECURITY)


def test_missing_grammar(tmp_path, monkeypatch):
    from argus.analysis import parsing
    (tmp_path / 'a.ts').write_text('const x = 1;')
    def missing(language):
        raise ParseUnavailable()
    monkeypatch.setattr(parsing, 'grammar', missing)
    r = scan(tmp_path)
    assert not r.modules
    assert r.coverage.files[0].reason_code == 'grammar_unavailable'


def test_source_and_exception_privacy(tmp_path):
    secret = 'sk-proj-' + 'SYNTHETIC0123456789' * 3
    for name, source in [('a.py','password = "' + secret + '"\ndef ' + secret.replace('-','_') + '(): pass'),
                         ('a.js','const x = require("' + secret + '");'),
                         ('a.json',json.dumps({'password':secret})), ('bad.py', secret + ' !!!')]:
        (tmp_path / name).write_text(source)
    data = JsonReportWriter().render(scan(tmp_path))
    assert secret not in data and secret.replace('-','_') not in data
    assert 'password' not in data


def test_parser_depth_limit(tmp_path):
    (tmp_path / 'a.js').write_text('(' * 300 + 'a' + ')' * 300)
    assert scan(tmp_path).coverage.files[0].status == Status.FAILED


def test_unicode_locations(tmp_path):
    (tmp_path / 'a.js').write_text('const café = 1; function f() {}')
    r = scan(tmp_path)
    f = next(s for s in r.symbols if s.kind == 'function')
    assert f.location.start_column == 17

@pytest.mark.parametrize('extension,source,expected', [
 ('py','def f(xs):\n for x in xs:\n  if x and xs:\n   pass\n',4),
 ('js','function f(xs) { for (const x of xs) { if (x && xs) {} } }',4),
 ('ts','function f(xs: number[]) { for (const x of xs) { if (x && xs) {} } }',4),
 ('jsx','function f(xs) { for (const x of xs) { if (x && xs) return <p/>; } }',4),
 ('tsx','function f(xs: number[]) { for (const x of xs) { if (x && xs) return <p/>; } }',4),
])
def test_loop_boolean_complexity(extension,source,expected,tmp_path):
    (tmp_path / ('a.'+extension)).write_text(source)
    r=scan(tmp_path)
    assert any(m.name == 'cyclomatic_complexity' and m.value == expected for m in r.graph.metrics)
    assert any(m.name == 'loop_count' and m.value == 1 for m in r.graph.metrics)


def test_adapter_declarations():
    from argus.analysis.adapters import descriptor
    from argus.analysis.parsing import SUPPORTED
    for language in SUPPORTED:
        adapter = descriptor(language)
        assert {c.capability for c in adapter.capabilities} == set(Capability)
        assert not next(c for c in adapter.capabilities if c.capability == Capability.SECURITY).available


def test_extraction_budget_disclosed(tmp_path,monkeypatch):
    from argus.analysis.pipeline import Analysis
    original = Analysis.inspect
    def capped(self,*args):
        self.entity_count = 50000
        return original(self,*args)
    monkeypatch.setattr(Analysis,'inspect',capped)
    (tmp_path / 'a.py').write_text('x=1')
    r=scan(tmp_path)
    assert r.coverage.files[0].reason_code == 'analysis_resource_limit'
    assert not r.modules


def test_mixed_language_coverage_counts_configuration(tmp_path):
    (tmp_path / 'a.py').write_text('x=1')
    (tmp_path / 'a.rs').write_text('fn main() {}')
    (tmp_path / 'a.json').write_text('{"x":1}')
    data=json.loads(JsonReportWriter().render(scan(tmp_path)))
    languages=data['coverage']['language_analysis_coverage']
    assert languages['json']['inventoried_files'] == 1
    assert languages['json']['capabilities']['syntax_parsing']['by_status']['completed'] == 1
    assert languages['rust']['capabilities']['syntax_parsing']['by_status']['unsupported'] == 1
    assert data['not_reviewed_portions_of_the_code']['portions']
