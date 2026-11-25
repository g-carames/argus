"""Local synthetic projects only; no external credentials or target execution."""
from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from argus.cli import main
from argus.config import DiscoverySettings, load_settings
from argus.models.base import Status
from argus.models.scan import DISCLAIMER
from argus.recognition import EXTENSIONS, RecognitionRegistry
from argus.reporting import JsonReportWriter
from argus.scanner import scan


def put(root, name, text='synthetic\n'):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def report(root, settings=None, **kwargs):
    result = scan(root, settings or DiscoverySettings(), **kwargs)
    return json.loads(JsonReportWriter().render(result))


@pytest.mark.parametrize('language,extensions', EXTENSIONS.items())
def test_all_registered_extensions(language, extensions):
    registry = RecognitionRegistry()
    for ext in extensions.split():
        assert registry.recognize('src/example.' + ext).language == language


@pytest.mark.parametrize('name,content,language', [
    ('Dockerfile', b'', 'dockerfile'), ('Dockerfile.dev', b'', 'dockerfile'),
    ('Containerfile.prod', b'', 'dockerfile'), ('Gemfile', b'', 'ruby'),
    ('.bashrc', b'', 'bash'), ('run', b'#!/usr/bin/env python3\n', 'python'),
    ('run', b'#!/usr/bin/env -S node --flag\n', 'javascript'),
    ('run', b'#!/bin/bash\n', 'bash'), ('run', b'#!/usr/bin/pwsh\n', 'powershell'),
    ('unknown', b'<?php\n', 'php'), ('unknown', b'#!/bin/notpython\n', None),
])
def test_names_and_bounded_signatures(name, content, language):
    assert RecognitionRegistry().recognize(name, content).language == language


def test_nested_ignores_negation_and_defaults(tmp_path):
    put(tmp_path, '.gitignore', '*.tmp\n!keep.tmp\nignored/\n')
    put(tmp_path, 'keep.tmp')
    put(tmp_path, 'drop.tmp')
    put(tmp_path, 'nested/.gitignore', '!local.tmp\n*.py\n!keep.py\n')
    put(tmp_path, 'nested/local.tmp')
    put(tmp_path, 'nested/drop.py')
    put(tmp_path, 'nested/keep.py')
    put(tmp_path, 'ignored/.gitignore', '!secret.py\n')
    put(tmp_path, 'ignored/secret.py')
    for folder in ('node_modules', '.venv', '__pycache__', 'dist', 'build', '.next', 'coverage', '.git', 'argus-reports'):
        put(tmp_path, folder + '/skip.py')
    data = report(tmp_path)
    excluded = {f['file_id'] for f in data['coverage']['files'] if f['status'] == 'excluded'}
    paths = {f['path'] for f in data['files'] if f['id'] not in excluded}
    assert {'keep.tmp', 'nested/local.tmp', 'nested/keep.py'} <= paths
    assert not {'drop.tmp', 'nested/drop.py', 'ignored/secret.py'} & paths
    assert len(data['coverage']['inventory_gaps']) == 10
    assert len(excluded) == 2
    assert data['inventory']['repository_file_count'] is None
    assert not data['coverage']['source_metrics']['inventory_complete']


def test_deep_and_empty_hierarchy(tmp_path):
    deep = '/'.join('d' + str(n) for n in range(80))
    put(tmp_path, deep + '/sample.py')
    (tmp_path / 'empty').mkdir()
    put(tmp_path, 'apps/web/package.json', '{"dependencies":{"next":"*"}}')
    data = report(tmp_path)
    assert data['inventory']['status'] == 'completed'
    nodes = {n['id']: n for n in data['graph']['nodes']}
    assert any(n['label'] == 'empty' for n in nodes.values())
    assert any(n['kind'] == 'package' and n['grouping_provenance'] == 'inferred' for n in nodes.values())
    for n in nodes.values():
        if n['parent_id']:
            assert n['parent_id'] in nodes and n['evidence_ids']
    assert not data['graph']['relationships']


def test_symlinks_special_objects_and_containment(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + '-outside')
    outside.mkdir()
    put(outside, 'secret.py')
    (tmp_path / 'outside').symlink_to(outside, target_is_directory=True)
    (tmp_path / 'cycle').symlink_to(tmp_path, target_is_directory=True)
    os.mkfifo(tmp_path / 'pipe')
    assert report(tmp_path)['files'] == []
    gaps = report(tmp_path)['coverage']['inventory_gaps']
    assert {g['reason_code'] for g in gaps} == {'symlink', 'special_file'}
    with pytest.raises(ValueError):
        scan(tmp_path / 'outside')


def test_analysis_is_unavailable_unknown_ambiguous_binary(tmp_path):
    put(tmp_path, 'source.py', 'this is not valid Python !!!\n')
    put(tmp_path, 'ambiguous.h')
    put(tmp_path, 'unknown.blob')
    (tmp_path / 'binary.dat').write_bytes(b'\xff\0\r\n')
    data = report(tmp_path)
    files = {f['path']: f for f in data['files']}
    assert files['ambiguous.h']['language_candidates'] == ['c', 'cpp']
    assert files['binary.dat']['physical_lines'] is None
    assert data['status'] == 'partial'
    assert data['findings'] == [] and data['credentials'] is None
    assert all(f['status'] in ('unsupported', 'unclassified') for f in data['coverage']['files'])
    assert all(c['status'] == 'unsupported' for c in data['coverage']['categories'])
    assert data['disclaimer'] == DISCLAIMER
    section = data['not_reviewed_portions_of_the_code']
    assert section['title'] == 'Not Reviewed Portions of the Code'
    assert len(section['portions']) == 4
    assert data['coverage']['source_metrics']['file_coverage']['fraction'] == 0


@pytest.mark.parametrize('setting,value,expected', [
    ('max_files', 2, 'resource_limit.max_files'),
    ('max_entries', 2, 'resource_limit.max_entries'),
    ('max_depth', 1, 'resource_limit.max_depth'),
    ('max_file_bytes', 2, 'resource_limit.max_file_bytes'),
    ('max_total_bytes', 2, 'resource_limit.max_total_bytes'),
    ('max_ignore_bytes', 2, 'ignore_unavailable'),
])
def test_resource_limits(tmp_path, setting, value, expected):
    for name in ('a.py', 'b.py', 'c.py', 'a/b/c.py'):
        put(tmp_path, name)
    if setting == 'max_ignore_bytes':
        put(tmp_path, '.gitignore', '*.foo\n')
    data = report(tmp_path, replace(DiscoverySettings(), **{setting: value}))
    codes = {g['reason_code'] for g in data['coverage']['inventory_gaps']}
    codes.update(g['reason_code'] for g in data['coverage']['files'])
    assert expected in codes
    assert data['inventory']['status'] == 'partial'


def test_unreadable_and_bad_ignore_policy(tmp_path):
    path = put(tmp_path, 'denied.py')
    path.chmod(0)
    try:
        data = report(tmp_path)
        assert data['coverage']['files'][0]['status'] == 'failed'
        assert data['files'][0]['physical_lines'] is None
    finally:
        path.chmod(0o600)
    (tmp_path / '.gitignore').write_bytes(b'\xff')
    data = report(tmp_path)
    assert not data['files']
    assert data['coverage']['inventory_gaps'][0]['reason_code'] == 'ignore_unavailable'


def test_framework_declarations_malformed_and_negative(tmp_path):
    from argus.technologies import JS, PY
    put(tmp_path, 'web/package.json', json.dumps({'dependencies': {k: '*' for k in JS}}))
    put(tmp_path, 'api/pyproject.toml', '[project]\ndependencies = ' + json.dumps(list(PY)) + '\n')
    put(tmp_path, 'Dockerfile', 'FROM scratch\n')
    put(tmp_path, 'compose.yaml', 'services: {}\n')
    put(tmp_path, 'bad/package.json', '{bad')
    put(tmp_path, 'unrelated.json', '{"react":"*"}')
    data = report(tmp_path)
    technologies = [n for n in data['graph']['nodes'] if n['kind'] == 'technology']
    assert {n['label'] for n in technologies} == set(JS.values()) | set(PY.values()) | {'Node.js', 'Docker', 'Docker Compose'}
    assert any(d['code'] == 'malformed_manifest' for d in data['diagnostics'])
    assert all('source usage' in e['observation'] for e in data['evidence'] if ': declared_dependency' in e['observation'])
    assert not data['findings']


def test_privacy_synthetic_credentials(tmp_path, capsys):
    secret = 'sk-proj-' + 'SYNTHETIC0123456789' * 3
    put(tmp_path, secret + '.py', 'password = "' + secret + '"\n')
    put(tmp_path, 'package.json', json.dumps({'dependencies': {'openai': secret}, 'password': secret}))
    serialized = JsonReportWriter().render(scan(tmp_path))
    assert secret not in serialized
    assert 'password =' not in serialized
    assert 'redacted-' in serialized
    with pytest.raises(SystemExit) as exc:
        main(['scan', str(tmp_path), '--bogus-' + secret])
    assert exc.value.code == 2
    assert secret not in capsys.readouterr().err


def test_determinism_large_repository_progress_and_no_execution(tmp_path, monkeypatch):
    for index in range(1200):
        put(tmp_path, f'packages/p{index // 20}/m{index}.py', 'raise RuntimeError("Never execute")\n')
    import socket
    import subprocess
    monkeypatch.setattr(socket, 'socket', lambda *a, **k: pytest.fail('network'))
    monkeypatch.setattr(subprocess, 'Popen', lambda *a, **k: pytest.fail('execution'))
    events = []
    first = scan(tmp_path, progress=events.append)
    assert len(first.files) == 1200 and events[-1] == 1200
    assert JsonReportWriter().render(first) == JsonReportWriter().render(scan(tmp_path))


def test_cancellation_preserves_partial_scope(tmp_path):
    for i in range(10):
        put(tmp_path, f'{i}.py')
    class Token:
        is_cancelled = False
    token = Token()
    def progress(n):
        if n == 3:
            token.is_cancelled = True
    data = report(tmp_path, progress=progress, cancellation=token)
    assert len(data['files']) == 3
    assert data['execution']['cancelled']
    assert data['inventory']['status'] == 'partial'
    assert any(g['reason_code'] == 'cancelled' for g in data['coverage']['inventory_gaps'])


def test_cli_config_json_verbose_and_output_safety(tmp_path, capsys):
    root = tmp_path / 'repo'
    root.mkdir()
    source = put(root, 'source.py')
    put(root, 'skip.ts')
    config = put(tmp_path, 'config.toml', '[discovery]\nmax_files = 50\nexcludes = ["*.ts"]\n')
    assert main(['scan', str(root), '--config', str(config), '--verbose', '--format', 'json']) == 0
    captured = capsys.readouterr()
    assert sum(f['status'] == 'excluded' for f in json.loads(captured.out)['coverage']['files']) == 1
    assert 'inventory' in captured.err
    output = tmp_path / 'report.json'
    assert main(['scan', str(root), '--output', str(output), '--exclude', '*.ts']) == 0
    assert not capsys.readouterr().out
    assert json.loads(output.read_text())['inventory']['inventoried_files'] == 2
    assert output.stat().st_mode & 0o777 == 0o600
    previous = output.read_bytes()
    assert main(['scan', str(root), '--output', str(output)]) == 2
    assert output.read_bytes() == previous
    assert main(['scan', str(root), '--output', str(source)]) == 2
    assert source.read_text() == 'synthetic\n'
    linked = tmp_path / 'link.json'
    linked.symlink_to(source)
    assert main(['scan', str(root), '--output', str(linked)]) == 2
    assert main(['scan', str(tmp_path / 'missing')]) == 2
    assert main(['scan', str(source)]) == 2


@pytest.mark.parametrize('content', ['[discovery]\nmax_files = true', '[discovery]\nmax_depth = 0',
                                      '[other]\nmax_files=1', '[discovery]\nunknown=3', 'not toml'])
def test_invalid_configs(tmp_path, content):
    path = put(tmp_path, 'config.toml', content)
    with pytest.raises(ValueError):
        load_settings(path)


def test_application_boundary_and_generated_reports(tmp_path):
    put(tmp_path, 'app/package.json', '{"scripts":{"dev":"never run"}}')
    first = scan(tmp_path)
    put(tmp_path, 'custom.json', JsonReportWriter().render(first))
    data = report(tmp_path)
    assert any(n['kind'] == 'application' and n['grouping_provenance'] == 'inferred'
               for n in data['graph']['nodes'])
    file = next(f for f in data['files'] if f['path'] == 'custom.json')
    assert next(c for c in data['coverage']['files'] if c['file_id'] == file['id'])['status'] == 'excluded'


def test_swapped_file_symlink_is_not_followed(tmp_path, monkeypatch):
    from argus.discovery import Discovery
    put(tmp_path, 'source.py')
    original = Discovery._read
    def swap(self, fd, name, limit):
        if name == 'source.py':
            (tmp_path / name).unlink()
            (tmp_path / name).symlink_to('/etc/passwd')
        return original(self, fd, name, limit)
    monkeypatch.setattr(Discovery, '_read', swap)
    data = report(tmp_path)
    assert data['files'][0]['physical_lines'] is None
    assert data['coverage']['files'][0]['status'] == 'failed'


def test_line_measurements_and_invalid_encoding(tmp_path):
    (tmp_path / 'lines.py').write_bytes(b'a\r\nb\rc\nlast')
    (tmp_path / 'empty.py').write_bytes(b'')
    (tmp_path / 'encoding.py').write_bytes(b'\xff')
    files = {f['path']: f for f in report(tmp_path)['files']}
    assert files['lines.py']['physical_lines'] == 4
    assert files['empty.py']['physical_lines'] == 0
    assert files['encoding.py']['physical_lines'] is None


def test_known_excluded_source_files_remain_in_denominators(tmp_path):
    put(tmp_path, '.gitignore', 'excluded.py\n')
    put(tmp_path, 'excluded.py', 'never read this\n')
    data = report(tmp_path)
    file = next(f for f in data['files'] if f['path'] == 'excluded.py')
    assert file['physical_lines'] is None and file['size_bytes'] == 16
    entry = next(c for c in data['coverage']['files'] if c['file_id'] == file['id'])
    assert entry['status'] == 'excluded'
    assert data['coverage']['source_metrics']['total_discovered_source_files'] == 1
    assert data['coverage']['source_metrics']['by_status']['excluded'] == 1
    assert data['coverage']['source_metrics']['line_coverage']['denominator'] is None


def test_control_and_reserved_names_do_not_break_privacy_hierarchy(tmp_path):
    from argus.privacy import safe_path
    secret = 'sk-proj-' + 'SYNTHETIC0123456789' * 2
    masked = safe_path(secret)
    put(tmp_path, secret + '/one.py')
    put(tmp_path, masked + '/one.py')
    put(tmp_path, 'line\nbreak.py')
    data = report(tmp_path)
    assert len({f['path'] for f in data['files']}) == 3
    assert secret not in json.dumps(data)
    assert all('\n' not in f['path'] for f in data['files'])


def test_inventory_contract_rejects_false_completion(tmp_path):
    put(tmp_path, 'big.py', 'synthetic content')
    result = scan(tmp_path, replace(DiscoverySettings(), max_file_bytes=2))
    with pytest.raises(ValueError):
        replace(result, inventory=replace(result.inventory, status=Status.COMPLETED))
    with pytest.raises(ValueError):
        replace(result, inventory=replace(result.inventory, inventoried_files=8))
