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
Symbol IDs use hashed lexical scope/name/kind and same-name ordinal; duplicate or
anonymous-scope insertions and renames may change identity. Export marker identities
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
