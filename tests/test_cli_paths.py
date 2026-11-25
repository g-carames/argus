"""Path selection regressions: no target execution, real links and injected races."""
import json
import os
from pathlib import Path
import sys

import pytest

from argus import cli
from argus.config import DiscoverySettings
from argus.discovery import Discovery
from argus.errors import CliError, MESSAGES
from argus.scanner import scan


@pytest.fixture
def project(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    (root / 'sample.py').write_text('raise RuntimeError("never execute")\n')
    (tmp_path / 'work' / 'nested').mkdir(parents=True)
    return root


def expect_error(capsys, args, code, status=2):
    assert cli.main(args) == status
    captured = capsys.readouterr()
    assert captured.out == ''
    assert captured.err == f'argus: ARGUS_{code}: {MESSAGES[code]}\n'


@pytest.mark.parametrize('selection', [
    '../../repo', './../..//repo', '../../work/../repo', '../../work/nested/../../repo',
    '{base}/work/../repo', '{base}/work/nested/../../repo', '{base}/repo/../repo',
])
def test_parent_segments_select_same_root(project, monkeypatch, capsys, selection):
    monkeypatch.chdir(project.parent / 'work' / 'nested')
    path = selection.format(base=project.parent)
    assert cli.main(['scan', path]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [f['path'] for f in data['files']] == ['sample.py']
    assert data['inventory']['repository_file_count'] == 1


@pytest.mark.parametrize('selection', ['.', './', 'nested/..', './nested/../.', '../work'])
def test_dot_and_parent_directory_selection(project, monkeypatch, capsys, selection):
    monkeypatch.chdir(project.parent / 'work')
    assert cli.main(['scan', selection]) == 0
    assert json.loads(capsys.readouterr().out)['inventory']['inventoried_files'] == 0


@pytest.mark.parametrize('output', [
    'report.json', '../report.txt', '../../report.json', '../nested/../../report.json',
    '{base}/work/nested/../../report.json',
])
def test_relative_and_absolute_output_parents(project, monkeypatch, capsys, output):
    cwd = project.parent / 'work' / 'nested'
    monkeypatch.chdir(cwd)
    selection = output.format(base=project.parent)
    assert cli.main(['scan', '../../repo', '--output', selection]) == 0
    assert capsys.readouterr().out == ''
    destination = Path(selection)
    assert destination.stat().st_mode & 0o777 == 0o600
    assert json.loads(destination.read_text())['inventory']['inventoried_files'] == 1


@pytest.mark.parametrize('suffix', ['', '/..', '/../repo', '/../work/../repo'])
def test_input_symlink_never_hidden_by_parent_segments(project, capsys, suffix):
    link = project.parent / 'alias'
    link.symlink_to(project, target_is_directory=True)
    expect_error(capsys, ['scan', str(link) + suffix], 'INPUT_SYMLINK_COMPONENT')


@pytest.mark.parametrize('suffix', ['/report.json', '/../report.json', '/../work/../report.json'])
def test_output_symlink_never_hidden_by_parent_segments(project, capsys, suffix):
    link = project.parent / 'alias'
    link.symlink_to(project.parent / 'work', target_is_directory=True)
    expect_error(capsys, ['scan', str(project), '--output', str(link) + suffix], 'OUTPUT_PARENT_SYMLINK')
    assert not (project.parent / 'report.json').exists()
    assert not (project.parent / 'work' / 'report.json').exists()


def test_dangling_component_is_reported_as_symlink(project, capsys):
    link = project.parent / 'dangling'
    link.symlink_to(project.parent / 'absent')
    expect_error(capsys, ['scan', str(link) + '/../repo'], 'INPUT_SYMLINK_COMPONENT')


@pytest.mark.parametrize('selection', ['missing', 'repo/sample.py', 'missing/../repo'])
def test_invalid_input_directory_diagnostic(project, capsys, selection):
    expect_error(capsys, ['scan', str(project.parent / selection)], 'INPUT_UNAVAILABLE')


def test_empty_input_is_not_cwd(project, capsys):
    expect_error(capsys, ['scan', ''], 'INPUT_UNAVAILABLE')


@pytest.mark.parametrize('kind', ['file', 'hardlink', 'symlink', 'dangling', 'directory'])
def test_existing_destinations_unchanged(project, capsys, kind):
    original = project.parent / 'original.txt'
    original.write_text('FICTIONAL_PRIVATE_VALUE_DO_NOT_ECHO')
    destination = project.parent / 'report.json'
    if kind == 'file':
        destination.write_text('existing')
    elif kind == 'hardlink':
        destination.hardlink_to(original)
    elif kind == 'symlink':
        destination.symlink_to(original)
    elif kind == 'dangling':
        destination.symlink_to(project.parent / 'missing')
    else:
        destination.mkdir()
    before = destination.lstat()
    content = destination.read_bytes() if kind in ('file', 'hardlink') else None
    expect_error(capsys, ['scan', str(project), '--output', str(destination)], 'OUTPUT_ALREADY_EXISTS')
    assert destination.lstat().st_ino == before.st_ino
    if content is not None:
        assert destination.read_bytes() == content
    assert original.read_text() == 'FICTIONAL_PRIVATE_VALUE_DO_NOT_ECHO'


@pytest.mark.parametrize('suffix', ['missing/report.json', 'repo/sample.py/report.json'])
def test_unavailable_output_parent(project, capsys, suffix):
    expect_error(capsys, ['scan', str(project), '--output', str(project.parent / suffix)], 'OUTPUT_PARENT_UNAVAILABLE')


@pytest.mark.parametrize('suffix', ['report.py', 'report', 'report.JSON', ''])
def test_output_suffix_diagnostic(project, capsys, suffix):
    expect_error(capsys, ['scan', str(project), '--output', suffix], 'OUTPUT_SUFFIX_INVALID')


@pytest.mark.parametrize('content', ['not toml', '[discovery]\nmax_files=false', '[discovery]\nunknown=42'])
def test_config_errors_never_echo_values(project, capsys, content):
    config = project.parent / 'api_key=FICTIONAL_CONFIG_SECRET.toml'
    config.write_text(content + '\n# FICTIONAL_PRIVATE_VALUE\n')
    expect_error(capsys, ['scan', str(project), '--config', str(config)], 'CONFIG_INVALID')


def test_missing_config_sanitized(project, capsys):
    expect_error(capsys, ['scan', str(project), '--config', 'api_key=FICTIONAL_MISSING.toml'], 'CONFIG_INVALID')


def test_write_open_failure_sanitized(project, capsys, monkeypatch):
    original_open = os.open
    def denied(path, flags, *args, **kwargs):
        if flags & os.O_CREAT:
            raise PermissionError('FICTIONAL_PRIVATE_OS_EXCEPTION')
        return original_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, 'open', denied)
    expect_error(capsys, ['scan', str(project), '--output', str(project.parent / 'report.json')], 'OUTPUT_WRITE_FAILED')


def test_write_stream_failure_closes_descriptor(project, capsys, monkeypatch):
    original_fdopen = os.fdopen
    failed_fd = []
    def fail(fd, mode, **kwargs):
        if mode == 'w':
            failed_fd.append(fd)
            raise OSError('FICTIONAL_PRIVATE_STREAM_EXCEPTION')
        return original_fdopen(fd, mode, **kwargs)
    monkeypatch.setattr(os, 'fdopen', fail)
    expect_error(capsys, ['scan', str(project), '--output', str(project.parent / 'report.json')], 'OUTPUT_WRITE_FAILED')
    assert failed_fd
    with pytest.raises(OSError):
        os.fstat(failed_fd[0])


@pytest.mark.parametrize('error', [ValueError, RuntimeError, OSError, TypeError])
def test_internal_failures_distinct_and_sanitized(project, capsys, monkeypatch, error):
    def fail(*args):
        raise error('api_key=FICTIONAL_INTERNAL_SECRET /private/sensitive/path')
    monkeypatch.setattr(cli, 'scan', fail)
    expect_error(capsys, ['scan', str(project)], 'INTERNAL_ERROR', status=70)


def test_repository_containment_after_parent_selection(project):
    outside = project.parent / 'outside'
    outside.mkdir()
    (outside / 'private.py').write_text('FICTIONAL_PRIVATE_VALUE')
    (project / 'outside').symlink_to(outside, target_is_directory=True)
    (project / 'file.py').symlink_to(outside / 'private.py')
    result = scan(str(project.parent) + '/work/../repo')
    assert [f.path for f in result.files] == ['sample.py']
    assert {g.path for g in result.coverage.inventory_gaps} == {'outside', 'file.py'}
    assert all(g.reason_code == 'symlink' for g in result.coverage.inventory_gaps)


def test_root_descriptor_remains_pinned_after_rename(project):
    moved = project.parent / 'moved'
    outside = project.parent / 'outside'
    outside.mkdir()
    (outside / 'private.py').write_text('FICTIONAL_PRIVATE_VALUE')
    discovery = Discovery(project, DiscoverySettings())
    files = discovery.files()
    first = next(files)
    project.rename(moved)
    project.symlink_to(outside, target_is_directory=True)
    assert first.path == 'sample.py'
    assert list(files) == []


def test_swapped_directory_component_is_not_followed(project, monkeypatch):
    original_open = os.open
    target = project.parent / 'outside'
    target.mkdir()
    (target / 'private.py').write_text('FICTIONAL_PRIVATE_VALUE')
    moved = project.parent / 'moved'
    def swap(path, flags, *args, **kwargs):
        if path == 'repo':
            project.rename(moved)
            project.symlink_to(target, target_is_directory=True)
        return original_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, 'open', swap)
    with pytest.raises(CliError) as failure:
        scan(project)
    assert failure.value.code == 'ARGUS_INPUT_SYMLINK_COMPONENT'


def test_output_parent_descriptor_remains_pinned(project, monkeypatch):
    selected = project.parent / 'selected'
    selected.mkdir()
    moved = project.parent / 'moved'
    outside = project.parent / 'outside'
    outside.mkdir()
    real_open = os.open
    def swap(path, flags, *args, **kwargs):
        if flags & os.O_CREAT:
            selected.rename(moved)
            selected.symlink_to(outside, target_is_directory=True)
        return real_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, 'open', swap)
    cli.write_output(selected / 'report.json', '{}')
    assert (moved / 'report.json').read_text() == '{}'
    assert not (outside / 'report.json').exists()


def test_destination_created_during_output_open_is_not_overwritten(project, capsys, monkeypatch):
    destination = project.parent / 'report.json'
    original_open = os.open
    def race(path, flags, *args, **kwargs):
        if flags & os.O_CREAT:
            destination.write_text('existing race winner')
        return original_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, 'open', race)
    expect_error(capsys, ['scan', str(project), '--output', str(destination)], 'OUTPUT_ALREADY_EXISTS')
    assert destination.read_text() == 'existing race winner'


def test_stdout_write_failure_is_sanitized(project, monkeypatch, capsys):
    class BrokenOutput:
        def write(self, text):
            raise BrokenPipeError('FICTIONAL_PRIVATE_PIPE_EXCEPTION')
    with monkeypatch.context() as patch:
        patch.setattr(sys, 'stdout', BrokenOutput())
        assert cli.main(['scan', str(project)]) == 2
    assert capsys.readouterr().err == f'argus: ARGUS_OUTPUT_WRITE_FAILED: {MESSAGES["OUTPUT_WRITE_FAILED"]}\n'


def test_stream_write_failure_retains_only_new_partial_file(project, capsys, monkeypatch):
    destination = project.parent / 'report.json'
    original_fdopen = os.fdopen
    class FailingStream:
        def __init__(self, stream):
            self.stream = stream
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.stream.close()
        def write(self, text):
            self.stream.write(text[:10])
            raise OSError('FICTIONAL_PRIVATE_WRITE_EXCEPTION')
    def fail(fd, mode, **kwargs):
        stream = original_fdopen(fd, mode, **kwargs)
        return FailingStream(stream) if mode == 'w' else stream
    monkeypatch.setattr(os, 'fdopen', fail)
    expect_error(capsys, ['scan', str(project), '--output', str(destination)], 'OUTPUT_WRITE_FAILED')
    assert len(destination.read_text()) == 10
    assert destination.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(sys.platform != 'darwin' or not Path('/tmp').is_symlink(), reason='macOS /tmp alias')
def test_macos_tmp_alias_has_helpful_diagnostics(project, capsys):
    expect_error(capsys, ['scan', '/tmp'], 'INPUT_SYMLINK_COMPONENT')
    expect_error(capsys, ['scan', str(project), '--output', '/tmp/argus-unused.json'], 'OUTPUT_PARENT_SYMLINK')
