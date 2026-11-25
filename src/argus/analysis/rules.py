"""Central rule metadata and deterministic evaluation; no source-derived instructions."""
from dataclasses import dataclass
from ..models.analysis import Finding
from ..models.base import Category, Confidence, Provenance, Severity
from ..models.source import Evidence
from ..privacy import identity
from .parsing import PRIMARY

@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: Category
    parameter: str
    default: int
    methodology: str
    positive: str
    negative: str
    remediation: str
    validation: str
    capabilities: tuple[str, ...]
    rationale: str = 'Concentrated responsibilities, branching or dependency cycles may increase maintenance and change coordination risk.'
    version: str = '1.0.0'
    secondary_categories: tuple = ()
    severity: str = 'medium'
    confidence: str = 'medium: exact structural measurement with heuristic architectural interpretation'
    status: str = 'implemented'
    tests: str = 'tests/test_analysis_rules.py'
    languages: tuple = PRIMARY
    limitations: str = 'Thresholds are configurable heuristics, not universal architecture standards. Static incomplete graphs and generated code can cause false positives or omissions.'

REGISTRY = (
    Rule('ARGUS-ARCH-001', 'Circular module dependencies', Category.ARCHITECTURE, 'cyclic_component_size', 0,
         'NetworkX strongly connected components; emit once per cyclic component, including self imports.',
         'a imports b; b imports a', 'a imports b; b imports nothing',
         'Review module responsibilities and introduce an appropriate dependency boundary.',
         'Re-scan equivalent complete scope and verify no cyclic component remains.', ('dependency_resolution',)),
    Rule('ARGUS-ARCH-002', 'Excessive incoming coupling', Category.ARCHITECTURE, 'incoming_coupling', 10,
         'Count distinct incoming resolved local module neighbors; strict greater-than threshold.',
         '11 distinct modules import a shared module', '10 or fewer importing modules',
         'Review shared responsibilities and the stability of the public interface.',
         'Confirm reviewed incoming coupling meets the chosen threshold or record a justified exception.', ('dependency_resolution',)),
    Rule('ARGUS-ARCH-003', 'Excessive outgoing coupling', Category.ARCHITECTURE, 'outgoing_coupling', 10,
         'Count distinct outgoing resolved local module neighbors; strict greater-than threshold.',
         'A module imports 11 distinct local modules', '10 or fewer local dependencies',
         'Separate responsibilities and reduce unnecessary direct dependencies.',
         'Re-scan and review outgoing dependencies against the chosen threshold.', ('dependency_resolution',)),
    Rule('ARGUS-MAINT-001', 'Excessive function length', Category.MAINTAINABILITY, 'function_length', 50,
         'Inclusive physical start/end span of each function or method, including comments and nested definitions; strict greater-than.',
         'Function spans 51 physical lines', 'Function spans 50 physical lines',
         'Extract cohesive responsibilities while preserving behavior.',
         'Review function spans and run appropriate project behavioral tests separately.', ('structural_analysis',)),
    Rule('ARGUS-MAINT-002', 'Excessive module length', Category.MAINTAINABILITY, 'module_length', 500,
         'Physical file lines including comments and blank lines; strict greater-than.',
         'Module has 501 physical lines', 'Module has 500 physical lines',
         'Review whether cohesive responsibilities belong in separate modules.',
         'Confirm module boundaries and measured lengths match the chosen policy.', ('structural_analysis',)),
    Rule('ARGUS-MAINT-003', 'Excessive nesting depth', Category.MAINTAINABILITY, 'nesting_depth', 4,
         'Maximum nested control structures per function; nested function/class bodies excluded; strict greater-than.',
         'Five nested conditional/loop/try structures', 'Four or fewer nested control structures',
         'Consider guard clauses and cohesive helper functions.',
         'Confirm nesting meets policy and behavior remains covered by project tests.', ('complexity_analysis',)),
    Rule('ARGUS-MAINT-004', 'Elevated cyclomatic complexity indicator', Category.MAINTAINABILITY, 'cyclomatic_complexity', 10,
         'One plus decisions: Python if/if-expression/loops/handlers/comprehensions/match cases and boolean alternatives; JS conditions/loops/catches/cases/ternaries/short-circuit operators. Nested scopes excluded; strict greater-than.',
         'Function indicator exceeds 10', 'Straight-line function indicator is 1',
         'Review branching responsibilities and simplify independently testable paths.',
         'Recompute the indicator and review branch-focused tests separately.', ('complexity_analysis',)),
    Rule('ARGUS-ARCH-004', 'Concentration of architectural dependencies', Category.ARCHITECTURE, 'degree_centrality', 1,
         'Directed degree centrality > configurable threshold; sum of degrees/(n-1), singleton 0.',
         'A bidirectional hub has centrality greater than 1', 'Disconnected modules have centrality 0',
         'Review hub stability, layering and dependency direction.',
         'Review graph coverage and confirm a justified hub or reduced concentration.', ('dependency_resolution',)),
    Rule('ARGUS-ARCH-005', 'Potentially oversized or overly coupled module', Category.ARCHITECTURE, 'total_coupling', 20,
         'Sum of incoming and outgoing local degree > threshold; alternative oversized condition uses module_length threshold.',
         'A module has total coupling 21 or more, or exceeds configured module length',
         'A short module has total coupling at most 20',
         'Review module cohesion and split independent responsibilities when appropriate.',
         'Review coupling and module size against policy with equivalent scan coverage.', ('structural_analysis', 'dependency_resolution')),
)
BY_ID = {r.id: r for r in REGISTRY}


def evaluate(rule, value, scope, location, evidence, threshold, relationships=(), parameter=None, affected=()):
    eid = identity('evidence', rule.id + ':' + scope)
    evidence.append(Evidence(id=eid, observation=f'{parameter or rule.parameter}={value}; threshold={threshold}; structural observation only.',
        producer=rule.id, producer_version=rule.version, provenance=Provenance.OBSERVED,
        confidence=Confidence.HIGH, locations=(location,)))
    return Finding(id=identity('finding', rule.id + ':' + scope), rule_id=rule.id, rule_version=rule.version,
        category=rule.category, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
        provenance=Provenance.HEURISTIC, title=rule.name, explanation=rule.methodology + ' This may increase maintenance or change coordination risk.',
        remediation=rule.remediation, evidence_ids=(eid,), affected_ids=affected or (scope,), locations=(location,),
        corrective_actions=(rule.remediation,), acceptance_criteria=(rule.validation,),
        relationship_ids=relationships, limitations=(rule.limitations,))
