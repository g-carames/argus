# Local configuration

`argus scan ROOT --config settings.toml` accepts bounded UTF-8 TOML. It does not
execute configuration. Existing `[discovery]` settings and exclusions remain valid.
Both tables are optional but at least one must be present; unknown fields fail safely.

```toml
[discovery]
max_file_bytes = 2097152
max_files = 20000
max_entries = 100000
max_depth = 256
max_total_bytes = 268435456
max_ignore_bytes = 65536
excludes = []

[analysis]
disabled_rules = []

[analysis.thresholds]
cyclic_component_size = 0
incoming_coupling = 10
outgoing_coupling = 10
function_length = 50
module_length = 500
nesting_depth = 4
cyclomatic_complexity = 10
degree_centrality = 1
total_coupling = 20
```

Threshold values must be finite nonnegative numbers, never booleans. Settings
are exact scalar thresholds, not universal quality standards. Unknown rule IDs or
threshold names fail configuration validation. Disabling a rule records disabled
rule coverage with zero evaluations. Measurements still run and remain visible.

## Milestone 4 resolution and pattern parameters

Prepared package.json
files remain strict JSON. tsconfig.json, jsconfig.json and .jsonc accept lexical
comments and trailing commas without altering quoted strings. Extended .json files
with compilerOptions/extends may also use JSONC. No JS configuration executes.
Local relative extends paths resolve from their declaring file, at most 16 links;
cycles, missing/ignored parents, escaping roots or package-based extends leave
references unresolved. baseUrl is rooted at its declaring config. paths retains
its declaring directory when no baseUrl applies. Exact paths keys win; otherwise
longest literal prefix wins. Zero/one-star patterns only; at most 1024 mappings
and 128 alternatives per selected key. Multiple viable file candidates remain
ambiguous rather than assuming runtime extension or condition precedence.
Nearest tsconfig wins over jsconfig in the same directory. Config parse/resource
failures remain disclosed; no runtime downloads or dependency installation occurs.

Declared npm/Yarn workspaces (list or packages-list object) and simple pnpm
packages block-list globs identify internal packages. * respects directory boundaries;
** spans directories. pnpm advanced YAML/inline/anchored/negated forms are unsupported.
Package exports supports exact/subpath wildcard targets and nested condition objects;
all statically visible condition alternatives are candidates, without selecting a
runtime environment. Missing exported subpaths stay unresolved, even when a file
exists. main/module/types and indexes remain conservative alternatives when exports
is absent. Python source-root/package behavior is unchanged.

All new pattern rules use a per-matching-line occurrence value of 1 and a default
threshold of 0, with strict greater-than. A threshold >=1 suppresses findings;
prefer disabled_rules to record intentional disabling. Parameters:

- occurrence_sec_001 through occurrence_sec_007
- occurrence_rel_001 through occurrence_rel_004
- occurrence_ai_001 and occurrence_ai_002
- occurrence_cost_001
- credential_occurrences

Detection semantics and nonnumeric exact parameters are in the generated
[rule catalog](rules/index.md). No per-pattern allowlist, entropy threshold, provider
validation, history switch or persistent-state option is supplied. Threshold settings
do not expand detector scope. Missing SDK limit indicators can be supplied through
wrappers/runtime settings; the rule never confirms globally absent limits.

Native parsing/extraction now has a five-second parent deadline, three CPU seconds,
one-second parser timeout and disabled core dumps. Retained entities are capped at
50000 and total import/call/request declarations at 100000. Existing per-file bytes,
200000-node and 256-depth traversal budgets remain. HTTP candidate matching is capped
at 1000000 comparisons with unresolved declarations and explicit failure diagnostics
when exhausted. No scan-wide hard memory/time sandbox is claimed.


## Milestone 5.1 contextual subset

See [Milestone 5.1](milestone-5.1.md) for exact supported syntax, abstract domains,
receiver identities, cross-file flow, framework observations, budgets and remaining
approved work. All primary languages have independent partial flow capabilities.
Fixed programmatic budgets include 128 workspace modules/contexts, receiver depth 8
and 8192 retained source-free IR nodes per file; no new TOML settings. Unknown
external arguments do not inherit defaults. No general authorization, Express
middleware ordering, database query-limit enforcement, retry/backoff policy, shared
agent budget or sanitizer/redaction verification is claimed. Observations remain
separate from mitigation and severity. Actual budget/unsupported-flow diagnostics
and unavailable contextual capabilities appear in **Not Reviewed Portions of the
Code**, including scans with no findings. No semantic completeness claim.
