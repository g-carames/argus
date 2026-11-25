"""Deterministic, descriptor-relative discovery of an authorized local directory.

POSIX directory descriptors pin parents; O_NOFOLLOW rejects swapped symlinks.
No target code, Git subprocesses, plugins, or network clients are invoked.
"""
from dataclasses import dataclass
import os
from pathlib import Path
import stat

from pathspec import GitIgnoreSpec

from .config import DiscoverySettings, open_directory
from .models.base import Status
from .models.coverage import InventoryGap
from .privacy import safe_path

DEFAULT_EXCLUSIONS = (
    '.git', '.git/', 'node_modules/', '.venv/', 'venv/', 'env/', '__pycache__/',
    'dist/', 'build/', '.next/', 'coverage/', 'htmlcov/', '.cache/', '.pytest_cache/',
    '.mypy_cache/', '.ruff_cache/', '.tox/', '.nox/', '.nuxt/', '.svelte-kit/',
    '.turbo/', '.parcel-cache/', '.npm/', '.yarn/', '.pnpm-store/', '.nyc_output/',
    '.coverage', '.coverage.*', '*.tsbuildinfo', 'target/', 'vendor/', '.gradle/', '.idea/', '.ipynb_checkpoints/', '*.egg-info/',
    '*.pyc', '*.pyo', '.argus/', 'argus-reports/', 'argus-records/',
    '*.argus-report.json', '*.argus-report.md', '*.argus-report.html', '*.argus-remediation.json',
)


@dataclass
class DiscoveredFile:
    path: str
    size: int | None
    content: bytes | None
    failure: str | None = None
    excluded: bool = False


class Discovery:
    def __init__(self, root, settings: DiscoverySettings, progress=None, cancellation=None):
        candidate = Path(root).absolute()
        # Root symlinks (including parent components) are rejected rather than resolved.
        try:
            canonical = candidate.resolve()
        except (OSError, RuntimeError):
            raise ValueError('Scan directory cannot be resolved safely') from None
        if candidate != canonical or not candidate.is_dir():
            raise ValueError('Scan input must be an accessible local directory without symbolic links')
        self.root = candidate
        self.settings = settings
        self.progress = progress
        self.cancellation = cancellation
        self.gaps = []
        self.directories = []
        self.visited = self.file_count = self.inspected_bytes = 0
        self.cancelled = self.stopped = False
        self.defaults = GitIgnoreSpec.from_lines(DEFAULT_EXCLUSIONS)
        self.custom = GitIgnoreSpec.from_lines(settings.excludes)

    def gap(self, path, code, status=Status.FAILED, count=None):
        self.gaps.append(InventoryGap(path=safe_path(path) if path else None, status=status,
                                      reason_code=code, file_count=count,
                                      reason={
                                          'excluded': 'Excluded by architecture discovery policy; contents not enumerated.',
                                          'symlink': 'Symbolic link skipped without following its target.',
                                          'special_file': 'Special filesystem object skipped without reading.',
                                          'unreadable': 'Filesystem entry could not be inspected safely.',
                                          'ignore_unavailable': 'Ignore policy unavailable; directory pruned to avoid unsafe inclusion.',
                                          'cancelled': 'Discovery cancelled; remaining scope unknown.',
                                      }.get(code, 'Configured discovery resource limit reached; scope incomplete.')))

    def _read(self, fd, name, limit):
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            info = os.fstat(file_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o444 == 0:
                raise OSError
            if info.st_size > limit:
                return None, info.st_size, 'resource_limit.max_file_bytes'
            remaining = self.settings.max_total_bytes - self.inspected_bytes
            if info.st_size > remaining:
                return None, info.st_size, 'resource_limit.max_total_bytes'
            with os.fdopen(file_fd, 'rb', closefd=False) as stream:
                content = stream.read(min(limit, remaining) + 1)
            self.inspected_bytes += len(content)
            if len(content) > limit or len(content) > remaining:
                return None, info.st_size, 'resource_limit.changed_file_size'
            # Concurrently changing files cannot receive reliable measurements.
            after = os.fstat(file_fd)
            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                return None, info.st_size, 'changed_during_read'
            return content, len(content), None
        finally:
            os.close(file_fd)

    def files(self):
        # One open descriptor per active ancestor; no recursion or sibling descriptors.
        stack = []
        try:
            root_fd = open_directory(self.root)
            stack.append([root_fd, '', (), 0, None])
            while stack and not self.stopped:
                if self.cancellation is not None and self.cancellation.is_cancelled:
                    raise KeyboardInterrupt
                frame = stack[-1]
                fd, base, ignores, depth, names = frame
                if names is None:
                    try:
                        if os.fstat(fd).st_mode & 0o444 == 0:
                            raise OSError
                        try:
                            data, _, failure = self._read(fd, '.gitignore', self.settings.max_ignore_bytes)
                        except FileNotFoundError:
                            data, failure = None, None
                        if failure:
                            raise ValueError
                        if data is not None:
                            ignores = ignores + ((base, GitIgnoreSpec.from_lines(data.decode('utf-8').splitlines())),)
                        remaining = self.settings.max_entries - self.visited
                        collected = []
                        with os.scandir(fd) as entries:
                            for entry in entries:
                                if len(collected) >= remaining:
                                    self.gap(base, 'resource_limit.max_entries')
                                    self.stopped = True
                                    break
                                collected.append(entry.name)
                        self.visited += len(collected)
                        self.directories.append(base)
                        frame[2] = ignores
                        frame[4] = iter(sorted(collected))
                        names = frame[4]
                        if self.stopped:
                            break
                    except (OSError, UnicodeError, ValueError):
                        self.gap(base, 'ignore_unavailable')
                        os.close(stack.pop()[0])
                        continue
                name = next(names, None)
                if name is None:
                    os.close(stack.pop()[0])
                    continue
                path = f'{base}/{name}' if base else name
                info = None
                try:
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode):
                        self.gap(path, 'symlink', Status.EXCLUDED)
                        continue
                    is_dir = stat.S_ISDIR(info.st_mode)
                    match_path = path + ('/' if is_dir else '')
                    ignored = False
                    for prefix, spec in ignores:
                        local = match_path[len(prefix) + 1:] if prefix else match_path
                        check = spec.check_file(local)
                        if check.include is not None:
                            ignored = check.include
                    if self.defaults.match_file(match_path) or self.custom.match_file(match_path) or ignored:
                        if stat.S_ISREG(info.st_mode):
                            if self.file_count >= self.settings.max_files:
                                self.gap(None, 'resource_limit.max_files')
                                self.stopped = True
                                break
                            self.file_count += 1
                            if self.progress:
                                self.progress(self.file_count)
                            yield DiscoveredFile(path, info.st_size, None, excluded=True)
                        else:
                            self.gap(path, 'excluded', Status.EXCLUDED, None if is_dir else 1)
                        continue
                    if is_dir:
                        if depth >= self.settings.max_depth:
                            self.gap(path, 'resource_limit.max_depth')
                        else:
                            child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                            stack.append([child_fd, path, ignores, depth + 1, None])
                        continue
                    if not stat.S_ISREG(info.st_mode):
                        self.gap(path, 'special_file', Status.EXCLUDED)
                        continue
                    if self.file_count >= self.settings.max_files:
                        self.gap(None, 'resource_limit.max_files')
                        self.stopped = True
                        break
                    self.file_count += 1
                    content, size, failure = self._read(fd, name, self.settings.max_file_bytes)
                    if self.progress:
                        self.progress(self.file_count)
                    yield DiscoveredFile(path, size, content, failure)
                except OSError:
                    if info is not None and stat.S_ISREG(info.st_mode):
                        yield DiscoveredFile(path, info.st_size, None, 'unreadable')
                    else:
                        self.gap(path, 'unreadable')
        except KeyboardInterrupt:
            self.cancelled = True
            self.gap(None, 'cancelled')
        except OSError:
            self.gap(None, 'unreadable')
        finally:
            for frame in stack:
                os.close(frame[0])
