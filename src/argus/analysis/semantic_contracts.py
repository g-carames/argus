"""Private source-qualified identities and structured exit channels.

Only opaque location-derived IDs and closed facts cross the public boundary.
No identity is derived from a literal, argument value or credential candidate.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING
from enum import StrEnum
from ..privacy import identity

if TYPE_CHECKING:
    from .semantic import Value


class FactState(StrEnum):
    KNOWN = 'known'
    POSSIBLE = 'possible'
    UNKNOWN = 'unknown'
    INCOMPLETE = 'incomplete'


class ExitKind(StrEnum):
    NORMAL = 'normal_fallthrough'
    RETURNED = 'returned'
    RAISED = 'raised'
    UNREACHABLE = 'unreachable'
    UNSUPPORTED = 'unsupported_control'


@dataclass(frozen=True)
class Point:
    module_id: str
    owner_id: str
    line: int
    column: int = 1

    def key(self, kind):
        return identity(kind, repr((self.module_id, self.owner_id, self.line, self.column)))


@dataclass(frozen=True)
class Outcomes:
    normal: bool = True
    returned: Value | None = None
    raised: bool = False
    incomplete: bool = False

    @property
    def channels(self):
        return tuple(k for k, yes in ((ExitKind.NORMAL,self.normal),
            (ExitKind.RETURNED,self.returned is not None), (ExitKind.RAISED,self.raised),
            (ExitKind.UNSUPPORTED,self.incomplete),
            (ExitKind.UNREACHABLE,not self.normal and self.returned is None and not self.raised and not self.incomplete)) if yes)


def join_returns(left, right):
    return right if left is None else left if right is None else left.join(right)


class SiteLedger(list):
    """Stamp facts at production, before caller/context state is restored."""
    def __init__(self, flow):
        super().__init__()
        self.flow = flow

    def append(self, site):
        f = self.flow
        point = Point(f.facts.module.id, site.owner, site.line, site.column)
        path = f.call_path
        super().append(replace(site,
            context_id=site.context_id or identity('context',repr((site.owner,path))),
            call_path_ids=site.call_path_ids or path,
            callsite_id=site.callsite_id or (f.active_call.key('callsite') if f.active_call else None),
            value_id=site.value_id or point.key('value'),
            incomplete=tuple(sorted(set(site.incomplete) | f.scope_gaps.get(site.owner,set())))))
