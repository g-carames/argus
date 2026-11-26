from dataclasses import replace
import pytest
from argus.scanner import scan
from argus.config import DiscoverySettings, AnalysisSettings, load_settings
from argus.analysis.rules import REGISTRY


def run(tmp_path, sources, thresholds=(), disabled=()):
    for path, source in sources.items():
        (tmp_path / path).write_text(source)
    return scan(tmp_path, replace(DiscoverySettings(), analysis=AnalysisSettings(rule_thresholds=thresholds, disabled_rules=disabled)))

@pytest.mark.parametrize('rule_id,sources,param,limit', [
 ('ARGUS-ARCH-001', {'a.py':'import b\n','b.py':'import a\n'},None,0),
 ('ARGUS-ARCH-002', {'a.py':'','b.py':'import a\n','c.py':'import a\n'},'incoming_coupling',1),
 ('ARGUS-ARCH-003', {'a.py':'import b\nimport c\n','b.py':'','c.py':''},'outgoing_coupling',1),
 ('ARGUS-MAINT-001', {'a.py':'def f():\n x = 1\n return x\n'},'function_length',2),
 ('ARGUS-MAINT-002', {'a.py':'x=1\nx=2\nx=3\n'},'module_length',2),
 ('ARGUS-MAINT-003', {'a.py':'def f(x):\n if x:\n  if x:\n   return 1\n'},'nesting_depth',1),
 ('ARGUS-MAINT-004', {'a.py':'def f(x):\n if x:\n  return 1\n return 0\n'},'cyclomatic_complexity',1),
 ('ARGUS-ARCH-004', {'a.py':'import b\n','b.py':'import a\n'},'degree_centrality',1),
 ('ARGUS-ARCH-005', {'a.py':'import b\n','b.py':'import a\n'},'total_coupling',1),
])
def test_every_rule_positive_negative_and_disabled(tmp_path, rule_id, sources, param, limit):
    thresholds = ((param,limit),) if param else ()
    r = run(tmp_path,sources,thresholds)
    findings = [f for f in r.findings if f.rule_id == rule_id]
    assert findings
    for f in findings:
        assert f.locations and f.evidence_ids and f.limitations and f.acceptance_criteria
        assert f.remediation and f.corrective_actions and f.rule_version
    disabled = run(tmp_path,sources,thresholds,(rule_id,))
    assert not any(f.rule_id == rule_id for f in disabled.findings)
    if param:
        negative = run(tmp_path,sources,((param,10000),))
        assert not any(f.rule_id == rule_id for f in negative.findings)
    else:
        for p in tmp_path.glob('*.py'):
            p.write_text('')
        assert not scan(tmp_path).findings


def test_threshold_boundary_and_nested_scope_separation(tmp_path):
    r = run(tmp_path, {'a.py':'def outer():\n def inner(x):\n  if x:\n   if x:\n    return x\n return inner\n'}, (('nesting_depth',1),))
    assert len([f for f in r.findings if f.rule_id == 'ARGUS-MAINT-003']) == 1
    r = run(tmp_path, {'a.py':'def f():\n pass\n'}, (('function_length',2),))
    assert not any(f.rule_id == 'ARGUS-MAINT-001' for f in r.findings)


def test_configuration_and_registry(tmp_path):
    p = tmp_path / 'settings.toml'
    p.write_text('[analysis]\ndisabled_rules=["ARGUS-ARCH-001"]\n[analysis.thresholds]\nfunction_length=25\ndegree_centrality=0.8\n')
    settings = load_settings(p)
    assert settings.analysis.thresholds['function_length'] == 25
    assert len({r.id for r in REGISTRY}) == 24
    for content in ('[analysis.thresholds]\nnope=1', '[analysis.thresholds]\nfunction_length=true',
                    '[analysis]\ndisabled_rules=["unknown"]'):
        p.write_text(content)
        with pytest.raises(ValueError):
            load_settings(p)


def test_rule_documentation_is_current():
    import runpy
    from pathlib import Path
    generated = runpy.run_path('tools/generate_rule_docs.py')['generate']()
    for path,text in generated.items():
        assert path.read_text() == text
    for rule in REGISTRY:
        assert Path(rule.tests).exists()
        assert rule.positive and rule.negative and rule.rationale and rule.confidence


def test_all_architecture_rules_disabled_capability(tmp_path):
    from argus.models.base import Capability, Category, Status
    disabled=tuple(r.id for r in REGISTRY if r.category == Category.ARCHITECTURE)
    r=run(tmp_path, {'a.py':'import a\n'}, disabled=disabled)
    coverage=next(c for c in r.coverage.files[0].capabilities if c.capability == Capability.ARCHITECTURE)
    assert coverage.status == Status.DISABLED and coverage.evaluated_units == 0
    assert not r.findings
