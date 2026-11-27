# Analysis parameter catalog

The authoritative registry is `src/argus/analysis/rules.py`. Documentation for
[architecture](architecture.md) and [maintainability](maintainability.md) is generated
by `uv run python tools/generate_rule_docs.py`; tests prevent metadata/document drift.
Twenty-four rules are implemented: nine structural rules and fifteen pattern rules.
See generated [security](security.md), [credentials](credentials.md),
[reliability](reliability.md), [AI](ai_specific.md) and [cost](cost_efficiency.md)
catalogs alongside architecture/maintainability. Metadata and docs are drift-tested.
Framework declarations support relationships; they are not authentication rules.
Dependency-health remains unavailable.

All thresholds are strict greater-than comparisons, configurable in
[configuration](../configuration.md). Cycles are reported once per cyclic strongly
connected component, including self imports; `cyclic_component_size=0` reports all
cyclic components. This is a component summary, not an ordered elementary cycle.
Oversized/coupled modules use an OR: `total_coupling > 20` or `module_length > 500`;
its evidence names whichever parameter triggered the finding. Multiple rules may
legitimately flag the same location; no aggregate score is computed.

File-length thresholds count physical lines including comments and blanks.
Function spans include nested definitions; complexity and nesting exclude bodies
of nested functions/classes. Python `elif` is represented as a nested AST `if`,
so it contributes nesting. The indicators are syntax-specific approximations,
not McCabe equivalence across all languages. Arrow functions, methods and generators
are included in the JavaScript family; anonymous scopes use deterministic ordinal
identities. Identifier labels are opaque for privacy; locations support inspection
in an independently developed interface. No source snippets are retained.

Structural finding IDs derive from rule and entity IDs; module findings survive line shifts.
Pattern findings use rule/file identity and ordinal among matched lines, never secret
values or raw line numbers. Unrelated line insertions preserve IDs, but adding/removing
an earlier occurrence can shift ordinals. These are not credential identities or a
persistent comparison/remediation engine.
Symbol IDs use module/kind/line/Unicode-column coordinates as of 6.3B; moves
can change identity while same-location renames preserve it. Export marker identities
currently include offsets. No baseline comparison or resolution tracking is implemented.

Rule coverage units are inventoried primary-language files (including excluded and
failed files). Evaluated units are successfully extracted primary-language modules.
Rule status remains partial because graph/semantic completeness cannot be established.
Function rules evaluate all extracted eligible functions inside those evaluated modules;
counts are file units, not a claim of complete symbol discovery or branch coverage.
An explicitly disabled rule has zero evaluations and cannot emit findings. Categories
remain partial or unsupported; syntax success never implies a security review.


Pattern coverage counts all inventoried candidate files (credential scanning), or
registered language files, including excluded/failed candidates. Evaluated counts are
eligible UTF-8 text files or successfully extracted applicable modules respectively.
Credential scanning is independent of parsing success. Rules emit once per matched
physical line, even if multiple same-rule sites share it. Severity/confidence are
medium with observed source-free evidence and heuristic risk provenance. Evidence
contains trusted descriptions, never target snippets or literal values.

ARCH-004 is directed normalized total degree, not eigenvector centrality, PageRank,
service criticality or safety. For n>1, (in_degree+out_degree)/(n-1); n counts extracted
primary modules including isolated nodes. Singleton is explicitly zero. Reciprocal
edges and self-loops count in each direction. Centrality can exceed one (up to two
without self-loops). Default >1 tests degree >n-1 and is sensitive to graph size and
missing coverage. ARCH-002/003 test directional degree >10; ARCH-005 tests total >20
or the same size observation as MAINT-002. These are correlated views of shared
observations, not distinct independently proven defects; never add severities or
interpret finding count as a safety score. No thresholds were tuned to lab fixtures.


Seven existing rules have Milestone 5 contextual refinements, documented in their
generated catalog entries and [contextual methodology](../milestone-5.md). Other
pattern rules retain their observation with undetermined contextual applicability;
structural measurements retain their existing scope. There are still 24 rules.

Milestone 6.1 updates AI-001/002, REL-003, SEC-004 and CRED-001 to version 1.3.0.
The central registry and generated category pages describe the corrective scope;
[release validation](../milestone-6.1.md) separates regression tests from independent
evaluation. Observations do not create findings or alter disabled-rule behavior.

Milestone 6.3B versions AI-001/002, COST-001, REL-003, SEC-001/004 and
CRED-001 at 1.4.0. Rules and severity thresholds are unchanged. Exit-channel,
identity, projection and credential-precedence corrections are documented in
[the validation report](../milestone-6.3B.md); the installed-CLI tier requires exact
public linkage and uncertainty evidence, alongside the retained unit tests.

## Milestone 6.3C contextual computation

The six existing contextual rules AI-001, AI-002, COST-001, REL-003, SEC-001 and SEC-004 advance to version 1.5.0 for CFG-based reachability, predicates and exit/effect semantics. CRED-001 stays 1.4.0. No rule, threshold or severity is added or silently changed. Syntax relationships survive even when an operation is abstractly unreachable; those operations no longer produce contextual risk candidates. Supported guard evidence may establish scoped applicability without reducing severity. See [the complete owner review](../milestone-6.3C.md).
