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

Static resolution reads already-discovered strict JSON package.json and tsconfig.json
only. TS aliases support nearest tsconfig `compilerOptions.paths` with zero/one-star
patterns and local `baseUrl`; multiple candidates remain ambiguous. JSONC, extends,
references, conditional exports, bundler plugins and executable configs are not
resolved. A tsconfig with extends leaves bare imports conservatively unresolved.
Package main/module/types entry paths are candidates; conflicting entries remain
ambiguous. No dependencies are installed and no package manager runs during scanning.

Extraction budgets currently fixed in code: 200000 traversed nodes per source tree,
256 tree depth, one-second Tree-sitter parsing timeout, 50000 retained analysis
entities and 100000 retained imports per scan. Files exceeding extraction budgets
are failed with safe diagnostics; buffers release between files. Repeated graph
reachability metrics are unavailable above 2000 primary modules. These safeguards
are not a hard process memory or CPU limit. Existing discovery budgets also apply.
