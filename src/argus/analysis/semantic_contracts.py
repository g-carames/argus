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
            constraint_origins=site.constraint_origins or f.current_constraints,
            constrained_value_id=site.constrained_value_id or f.current_constraint_value_id,
            constraint_applicability=site.constraint_applicability if site.constrained_value_id else f.current_constraint_applicability,
            loop_ids=site.loop_ids or f.current_loop_ids,base_loop_bounds=site.base_loop_bounds or f.current_base_loops,
            observation_scope='function_body' if f.body_only else site.observation_scope,
            reachability='potential' if f.current_incomplete or f.body_only else 'abstract_reachable',
            operation_upper_bound=site.upper_bound if site.operation in ('model','embedding','database','http','execution') and site.loops and not f.current_incomplete and not f.body_only and (site.operation not in ('model','embedding','database') or site.receiver_resolved) else None,
            incomplete=tuple(sorted(set(site.incomplete) | f.scope_gaps.get(site.owner,set())))))
