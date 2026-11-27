"""Independent synthetic regression and contract controls, not benchmark fixtures."""
from types import SimpleNamespace
from dataclasses import replace
import ast

import pytest

from argus.analysis.semantic import PythonFlow, Budgets, Value
from argus.analysis.semantic_contracts import Point, Outcomes, ExitKind, FactState
from argus.analysis.parsing import parse
from argus.analysis.risks import credential_candidates
from argus.scanner import scan
from argus.models.semantic import ObservationKind


def flow(source):
    f=PythonFlow(parse('python',source.encode()),SimpleNamespace(module=SimpleNamespace(id='module'),symbols=[]),Budgets())
    f.run()
    return f


@pytest.mark.parametrize('branch,bound',[
    ('if flag:\n  raise ValueError()',3),
    ('if flag:\n  return unknown',None),
    ('if flag:\n  return xs[:2]',3),
    ('if flag:\n  raise ValueError()\n else:\n  raise TypeError()',None),
    ('try:\n  raise ValueError()\n except Exception:\n  return unknown',None),
    ('try:\n  return xs[:3]\n finally:\n  raise ValueError()',None),
])
def test_compatible_exit_joins(branch,bound):
    f=flow('def cap(xs):\n '+branch+'\n return xs[:3]\nx=cap(rows)\n')
    assert f.exports['x'].size==bound


def test_unknown_value_and_absent_return_are_distinct_channels():
    a=Outcomes(False,Value())
    b=Outcomes(False,None,True)
    assert a.channels==(ExitKind.RETURNED,) and b.channels==(ExitKind.RAISED,)
    assert Outcomes(False).channels==(ExitKind.UNREACHABLE,)
    assert Outcomes().channels==(ExitKind.NORMAL,)
    assert Outcomes(False,None,False,True).channels==(ExitKind.UNSUPPORTED,)


def test_identity_ignores_values_but_qualifies_source():
    p=Point('a','scope',7,3)
    assert p.key('callsite')==Point('a','scope',7,3).key('callsite')
    assert len({p.key('callsite'),replace(p,module_id='b').key('callsite'),replace(p,column=4).key('callsite')})==3


def test_unknown_join_does_not_create_numeric_or_receiver_certainty():
    a=Value('definite',size=2,receiver='class@a:A')
    b=Value('definite',size=2,receiver='class@a:B')
    joined=a.join(b)
    assert joined.size==2 and joined.receiver is None
    assert set(joined.receiver_options)=={'class@a:A','class@a:B'}
    assert a.join(Value()).size is None


@pytest.mark.parametrize('call', ['cap(xs=[1],bad=2)','cap([1],xs=[2])','cap([1],[2])','cap()'])
def test_invalid_binding_cannot_establish_return(call):
    f=flow('def cap(xs):\n return xs[:2]\nx='+call)
    assert f.exports['x'].size is None
    assert 'semantic_invalid_or_unsupported_argument_binding' in f.gaps


def test_positional_only_keyword_is_not_supported_binding():
    f=flow('def cap(xs,/):\n return xs[:2]\nx=cap(xs=[1])')
    assert f.exports['x'].size is None


def test_utf8_source_positions_and_rename_stability(tmp_path):
    p=tmp_path/'app.py'
    p.write_text('α=1; β=[1,2]\ndef cap(xs):\n return xs\nx=cap(β)\n')
    first=scan(tmp_path)
    locations={e.id:e.locations for e in first.evidence}
    assignment=next(o for o in first.semantic_observations if o.kind==ObservationKind.ASSIGNMENT and o.upper_bound==2 and locations[o.evidence_ids[0]][0].start_line==1)
    assert locations[assignment.evidence_ids[0]][0].start_column==6
    ids={s.id for s in first.symbols if s.kind=='function'}
    p.write_text(p.read_text().replace('cap','renamed'))
    second=scan(tmp_path)
    assert ids=={s.id for s in second.symbols if s.kind=='function'}


def test_candidate_identity_uses_occurrences_not_values(tmp_path):
    p=tmp_path/'settings.py'
    p.write_text('api_key="sk-'+'A'*24+'"; token="sk-'+'B'*24+'"')
    first=scan(tmp_path)
    p.write_text('api_key="sk-'+'C'*24+'"; token="sk-'+'D'*24+'"')
    second=scan(tmp_path)
    assert [c.id for c in first.credential_candidates]==[c.id for c in second.credential_candidates]
    assert len(first.credential_candidates)==2


def test_exact_placeholder_and_conflicting_span_evidence():
    exact=credential_candidates(b'api_key="placeholder_here"')
    conflicting=credential_candidates(('api_key="placeholder_sk-'+'Z'*24+'"').encode())
    assert [k for _,k,_ in exact]==['obvious_placeholder']
    assert {k for _,k,_ in conflicting}=={'obvious_placeholder','recognized_pattern'}


def test_source_free_ir_never_contains_credential_literal():
    token='sk-'+'F'*24
    f=flow('api_key="'+token+'"\ndef echo(x):\n return x\necho(api_key)')
    assert all(not isinstance(n.value,(str,bytes)) for n in ast.walk(f.result.program) if isinstance(n,ast.Constant))
    assert token not in repr(f.result.sites)


def test_completed_facts_do_not_retain_interpreter_owner():
    f=flow('secret="source-only-synthetic-marker"\ndef cap(xs):\n return xs[:2]\ncap(rows)')
    assert type(f.result.sites) is list
    assert not hasattr(f.result.sites,'flow')


def test_computed_receiver_alternatives_are_not_silently_truncated():
    joined=Value('definite',receiver='class@module:C0')
    for index in range(1,40): joined=joined.join(Value('definite',receiver=f'class@module:C{index}'))
    assert joined.receiver is None and len(joined.receiver_options)==40
