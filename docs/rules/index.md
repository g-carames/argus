# Analysis parameter catalog

The authoritative registry is `src/argus/analysis/rules.py`. Documentation for
[architecture](architecture.md) and [maintainability](maintainability.md) is generated
by `uv run python tools/generate_rule_docs.py`; tests prevent metadata/document drift.
Nine rules are implemented, version 1.0.0. No security, credential, dependency-health,
reliability, performance, framework, AI or cost rules are implemented.

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

Finding IDs derive from rule and entity IDs; module findings survive line shifts.
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
