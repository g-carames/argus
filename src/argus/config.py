"""Strict, bounded local TOML configuration. Never execute configuration."""
from dataclasses import dataclass, replace
import os
import stat
import tomllib

from pathspec import GitIgnoreSpec

from .errors import DirectorySymlinkError


@dataclass(frozen=True)
class DiscoverySettings:
    max_file_bytes: int = 2 * 1024 * 1024
    max_files: int = 20000
    max_entries: int = 100000
    max_depth: int = 256
    max_total_bytes: int = 256 * 1024 * 1024
    max_ignore_bytes: int = 65536
    excludes: tuple[str, ...] = ()

    def __post_init__(self):
        for key, value in vars(self).items():
            if key != 'excludes' and (type(value) is not int or not 0 < value <= 10**9):
                raise ValueError('Resource limits must be positive integers at most 1000000000')
        if (not isinstance(self.excludes, tuple) or len(self.excludes) > 1000
                or any(type(x) is not str or len(x) > 4096 for x in self.excludes)):
            raise ValueError('Invalid exclusion patterns')
        try:
            GitIgnoreSpec.from_lines(self.excludes)
        except Exception:
            raise ValueError('Invalid exclusion patterns') from None


def read_regular(path, limit: int) -> bytes:
    """No-follow final component; discovery supplies fd-relative paths for containment."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('Expected a regular file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError('File exceeds configured size limit')
        return data
    finally:
        os.close(fd)


def load_settings(path=None, excludes=()) -> DiscoverySettings:
    settings = DiscoverySettings()
    if path is not None:
        try:
            data = tomllib.loads(read_regular(path, 65536).decode('utf-8'))
            if set(data) != {'discovery'} or type(data['discovery']) is not dict:
                raise ValueError
            values = data['discovery']
            if 'excludes' in values:
                if type(values['excludes']) is not list:
                    raise ValueError
                values['excludes'] = tuple(values['excludes'])
            settings = DiscoverySettings(**values)
        except (OSError, ValueError, TypeError, UnicodeError):
            raise ValueError('Configuration is unreadable or invalid; expected a [discovery] TOML table') from None
    return replace(settings, excludes=settings.excludes + tuple(excludes))


def open_directory(path):
    """Select a directory via unnormalized, no-follow components (POSIX).

    User-selected '.' and '..' are permitted here, before a repository root is
    established. Discovery never supplies repository-derived paths to this helper.
    In particular, validate 'link' in 'link/../repo' rather than normalizing it away.
    The caller owns the returned descriptor; no resolved path is reopened.
    """
    from pathlib import Path
    target = Path(path).absolute()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in target.parts[1:]:
            if stat.S_ISLNK(os.stat(part, dir_fd=fd, follow_symlinks=False).st_mode):
                raise DirectorySymlinkError('Symbolic-link directory component rejected')
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError:
                # ENOTDIR/ELOOP vary by platform; a swapped link must also receive
                # a safe diagnostic. The no-follow open, not stat, enforces safety.
                try:
                    is_link = stat.S_ISLNK(os.stat(part, dir_fd=fd, follow_symlinks=False).st_mode)
                except OSError:
                    is_link = False
                if is_link:
                    raise DirectorySymlinkError('Symbolic-link directory component rejected') from None
                raise
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise
