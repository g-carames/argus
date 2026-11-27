"""Private interval/state lattice and conservative effect interface.

None endpoints denote unknown, never infinity as an execution claim. Bottom is
represented by absent State, independently of a reachable state's incomplete bit.
"""
from dataclasses import dataclass, field, replace
from enum import StrEnum


@dataclass(frozen=True)
class Interval:
    lower: int | float | None = None
    upper: int | float | None = None

    def join(self, other):
        return Interval(min(self.lower,other.lower) if self.lower is not None and other.lower is not None else None,
            max(self.upper,other.upper) if self.upper is not None and other.upper is not None else None)

    def meet(self, other):
        lo=max(x for x in (self.lower,other.lower) if x is not None) if self.lower is not None or other.lower is not None else None
        hi=min(x for x in (self.upper,other.upper) if x is not None) if self.upper is not None or other.upper is not None else None
        return None if lo is not None and hi is not None and lo>hi else Interval(lo,hi)

    def leq(self, other):
        return (other.lower is None or self.lower is not None and self.lower>=other.lower) and (other.upper is None or self.upper is not None and self.upper<=other.upper)

    def widen(self, other):
        return Interval(self.lower if self.lower is not None and other.lower is not None and other.lower>=self.lower else None,
            self.upper if self.upper is not None and other.upper is not None and other.upper<=self.upper else None)


class EffectKind(StrEnum):
    SCALAR = 'local_scalar_reassignment'
    REPLACE = 'value_replacement'
    FRESH = 'fresh_value'
    COLLECTION = 'potential_collection_mutation'
    ATTRIBUTE = 'potential_attribute_mutation'
    CALL = 'unknown_call_effects'
    UNSUPPORTED = 'unsupported_effects'


@dataclass(frozen=True)
class Effect:
    kind: EffectKind
    value_ids: tuple[str, ...] = ()
    line: int = 1


@dataclass
class State:
    env: dict = field(default_factory=dict)
    incomplete: bool = False
    pending: object = None
    exception: tuple[str, ...] = ()
    conditional: bool = False
    saved_exceptions: dict = field(default_factory=dict)
    active_exception: tuple[str, ...] = ()

    def copy(self):
        return State(self.env.copy(),self.incomplete,self.pending,self.exception,self.conditional,self.saved_exceptions.copy(),self.active_exception)

    def join(self, other, unknown, widen=False):
        env={}
        for key in self.env.keys()|other.env.keys():
            a,b=self.env.get(key,unknown),other.env.get(key,unknown)
            value=a.join(b)
            if widen:
                interval=Interval(a.minimum,a.maximum).widen(Interval(value.minimum,value.maximum))
                size=a.size if a.size is not None and value.size is not None and value.size<=a.size else None
                value=replace(value,number=value.number if interval.lower==interval.upper else None,
                    minimum=interval.lower,maximum=interval.upper,size=size)
            env[key]=value
        from .semantic_contracts import join_returns
        return State(env,self.incomplete or other.incomplete,join_returns(self.pending,other.pending),
            tuple(sorted(set(self.exception+other.exception))),self.conditional or other.conditional,
            {k:tuple(sorted(set(self.saved_exceptions.get(k,())+other.saved_exceptions.get(k,())))) for k in self.saved_exceptions.keys()|other.saved_exceptions.keys()},tuple(sorted(set(self.active_exception+other.active_exception))))


    def leq(self, other, unknown):
        """Information order for supported value components; provenance is a may
        union, predicate applicability a must property, incompleteness independent.
        Identity labels are evidence anchors rather than a numeric domain order.
        """
        if self.incomplete and not other.incomplete:return False
        if not set(self.exception)<=set(other.exception):return False
        if self.pending is not None and other.pending is None:return False
        if self.pending is not None and not State({"pending":self.pending}).leq(State({"pending":other.pending}),unknown):return False
        for key in self.env.keys()|other.env.keys():
            a,b=self.env.get(key,unknown),other.env.get(key,unknown)
            if b.numeric and (not a.numeric or not Interval(a.minimum,a.maximum).leq(Interval(b.minimum,b.maximum))):return False
            if b.size_verified and b.size is not None and (not a.size_verified or a.size is None or a.size>b.size):return False
            if b.size_lower is not None and (a.size_lower is None or a.size_lower<b.size_lower):return False
            if b.finite and not a.finite:return False
            if b.collection_kind and a.collection_kind!=b.collection_kind:return False
            if a.taint and not b.taint or a.dynamic_sql and not b.dynamic_sql:return False
            if b.constraint_must and not a.constraint_must:return False
        return True
