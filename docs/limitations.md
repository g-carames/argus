# Analysis limitations

Argus provides static structural observations and heuristic findings, not safety
certification. Every JSON report preserves the exact disclaimer and **Not Reviewed
Portions of the Code**. Reports are confidential local artifacts; source excerpts,
raw credential values, raw parser exceptions and target identifier text are not
included. Hashes and opaque symbol/reference labels reduce accidental disclosure;
repository layout and structural metadata can still be sensitive.

Unsupported or failed files remain inventoried graph file nodes. Resolved references
to unparsed targets can point to those file nodes, with no invented module identity.
Unresolved/ambiguous references have no target. External means outside the indexed
scope, not a proven installed package. No call graph, inheritance resolution,
embedded-language analysis, cross-language HTTP/database contract extraction, framework
rules, security/credential/AI/cost rules, remediation, persistence or comparison runs.

Python resolution indexes root and conventional src layouts and identifiable package
roots. Duplicate roots remain ambiguous; arbitrary sys.path changes, namespace-package
assembly, custom loaders, generated modules and package re-export semantics are not
modeled. `from package import symbol` can be indistinguishable from submodule loading;
static module candidates take precedence, with no runtime proof. JS relative paths,
index candidates, package entry candidates and simple TS aliases are supported;
conditional exports, workspace manager configuration and runtime loaders are not.

Graph projection `resolved-local-imports-v1` contains successfully extracted primary
modules and resolved module-import edges only. Edge direction is importer → dependency;
type-only, dynamic and conditional imports are included. Parallel references collapse
for metrics; original evidence-bearing relationships remain separate. External,
unresolved and unsupported-file targets are excluded from the projection, so all
reported graph measurements are conditional on incomplete static scope. Unsupported
nodes remain in the full reporting graph. There is no aggregate safety score.

SCC membership and cyclic SCCs use NetworkX. Cycle records contain sorted component
members and internal relationships, not an ordered path. Incoming/outgoing coupling
count distinct neighbors; total coupling sums the two. Directed degree centrality
is (in+out)/(n−1), singleton zero, potentially above one. SCC size includes singleton
components. Reachability counts descendants; blast radius counts ancestors, excluding
self, and never establishes actual runtime damage. Dependency depth is the longest
outgoing path to a sink only where the reachable subgraph is acyclic; reachable cycles
produce unavailable depth. No enumeration of all cycles or paths occurs. Repeated
reachability metrics above 2000 modules are unavailable with reasons; the explicit
backend reachability query still computes one requested set.

Native parsers execute trusted installed native libraries on untrusted data; no
process isolation currently protects against native bugs. AST/JSON/TOML/SQL parsing
has no enforceable wall-clock/memory sandbox. Discovery and traversal budgets limit
ordinary workloads but do not guarantee large-repository performance. Reports and
normalized graph data remain in memory. No caching, workers or incremental reuse.
Cancellation checkpoints are discovery checkpoints; finishing graph/rule work is
not interruptible through the cancellation token. Filesystem mutation remains a
snapshot consistency limitation. Existing no-follow discovery and ignore protections
are preserved; target source/configuration is never imported or executed.

File status remains partial because capabilities are independently unavailable.
Successful syntax validation is completed parsing only. Reviewed physical lines
mean processed for listed structural capabilities, not full semantic or security
review. No rule coverage claims all conceivable architecture/maintainability defects.
Inventory status is partial when analysis failures are present to preserve the
existing contract invariant; discovery counts and gaps remain independently visible.

See [language matrix](language-support.md), [catalog](rules/index.md), and
[measured laboratory evaluation](milestone-3-evaluation.md) for precise scope.
