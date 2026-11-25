"""Defense in depth for inventory names; not a credential detector."""
import hashlib
import re

_PATTERNS = re.compile(
    r"(?i)(?:sk-(?:proj-|ant-)?[a-z0-9_-]{12,}|AIza[a-z0-9_-]{20,}|"
    r"(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[a-z0-9]{16,}|github_pat_[a-z0-9_]{16,}|"
    r"(?:sk|rk)_(?:live|test)_[a-z0-9]{12,}|xox[baprs]-[a-z0-9-]{12,}|"
    r"eyJ[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+|"
    r"(?:password|passwd|secret|token|api[_-]?key)[=:_-][^/\s]+|"
    r"[a-z][a-z0-9+.-]*://[^/\s]+)"
)


def identity(kind: str, value: str) -> str:
    return kind + '-' + hashlib.sha256(value.encode('utf-8', errors='surrogatepass')).hexdigest()[:24]


def safe_path(path: str) -> str:
    # Hash unsafe components rather than echoing arbitrary secrets or controls.
    parts = []
    for part in path.split('/'):
        if (part.startswith('redacted-') or _PATTERNS.search(part) or any(ord(c) < 32 or ord(c) >= 127 for c in part)
                or any(c in part for c in ':\\') or len(part) > 160):
            part = identity('redacted', part)
        parts.append(part)
    return '/'.join(parts)
