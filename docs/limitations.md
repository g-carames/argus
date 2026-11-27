# Analysis limitations

Argus supplies observations and heuristic risk indicators, never safety certification.
Every report includes the exact disclaimer and **Not Reviewed Portions of the Code**.
No snippets, credential values, raw exception text or source identifiers are included.
Opaque labels reduce disclosure but repository layout remains confidential metadata.

Milestone 4 implements a tested subset: seven security patterns, four Python
reliability patterns, two SDK-evidence AI patterns, a shared query-loop cost/performance
indicator and textual credential candidates, alongside nine structural rules. Harmless checksums, test TLS settings, non-SQL query helpers and intentional exception
policies can produce false positives. Exact
parameters, examples and limits are in the [catalog](rules/index.md).

No complete authentication/authorization review, dataflow/taint, insecure configuration
assessment, shell/SQL/Dockerfile security rules, dependency-health, unbounded retry or
polling rules, general resource lifetime review, prompt-injection defense, model-output
validation, provider coupling, agent tools/human approval, sensitive-data egress,
cost estimation, comparison engine or automatic remediation is implemented. Absence
of these findings means unavailable analysis, not a passing result.

Credential scanning inherits architectural discovery exclusions. It has no separate
tracked-source policy or ignored-path authorization override, no Git history reads,
no protected keyed reuse fingerprints, no persistent remediation records or state
transitions. Current textual candidates are potential exposure only. Proper local
storage/current/historical exposure cannot be conclusively classified. Removal,
replacement, rotation and revocation are not inferred. `credentials` is null rather
than simulated lifecycle data; finding remediation status remains open. No provider
is contacted. Credential literals exist transiently only in the bounded input buffer
and matching operations; reports/evidence/IDs never include them. Heuristic candidates
include false positives and miss arbitrary/unrecognized secrets. Text candidates do
not prove tracked or public exposure. Templates with realistic values can be flagged.

Only declared, inventoried configurations influence JS resolution. Aliases are never
assumed from @/ or ~/ conventions, framework names or executable bundler scripts.
Local extends chains only; package-based extends, project references, runtime export
condition selection, plugins, virtual modules and generated configuration are absent.
Conditional exports yield all observed candidates, hence may be ambiguous. Workspace
membership needs declared npm/Yarn/pnpm globs; directory/package containment alone
never implies service communication. Python root/src/package layouts remain static;
namespace-package assembly, custom sys.path, imports via runtime loaders and symbol
re-export forwarding remain incomplete. Unsupported targets may receive import edges
to file nodes, never invented modules. Unknown references preserve unresolved state.

Direct/imported call resolution is conservative and incomplete: unknown receiver
methods, default exports, barrel symbols, dynamic calls and rebinding/closure semantics
may be unresolved or incorrectly inferred. Unique static bindings are inferred,
not runtime call guarantees. HTTP matching supports only the source evidence listed
in the [matrix](language-support.md); methods and parameter-compatible literal paths
are candidates without service/deployment proof. Multiple candidates are ambiguous;
external absolute URLs are external. General API base configs, client wrappers,
Django, Express mount composition and broad Next routing are unavailable.
Matching stops after 1,000,000 request/endpoint comparisons: skipped requests remain
unresolved with diagnostics. Endpoint/request declarations and locations are retained.

Graph projection `resolved-local-imports-v1` includes extracted primary modules and
resolved local import edges only; calls/HTTP endpoints are outside that metric graph.
Importer → dependency direction includes type-only/dynamic/conditional references.
Parallel references collapse for metrics; original relationships remain distinct.
Missing files/languages invalidate completeness. No aggregate safety score exists.
NetworkX supplies SCCs, topology, centrality and reachability. Cycles are component
summaries, not ordered cycle paths. Exact degree and concentration definitions and
rule overlaps are documented in [architecture rules](rules/architecture.md).
Overlapping indicators are not independently confirmed defects or additive severity.

Native Tree-sitter parse/extraction is isolated per file with bounded CPU/wall time
and disabled core dumps. Native bugs are contained, not repaired or proved absent.
Python AST/JSON/TOML/SQL parsing has no hard wall-time/memory isolation. Reports and
normalized graphs remain in memory; no scan-wide hard memory cap or scan deadline.
Traversal, file reads, extracted entities/declarations and HTTP matching are bounded;
complexity of all resolution/graph operations is not globally budgeted. Repeated
reachability is unavailable above 2000 modules. Isolation uses fork only for the
single-threaded POSIX path; spawn elsewhere is not independently platform-tested.
There is no worker pool, caching or incremental reuse. Cancellation is checked during
discovery, not every graph/rule operation. Filesystem mutation invalidates snapshot
consistency. No target scripts/modules/dependencies execute during analysis.

Files remain partial under the full requested scope. Parsing success is syntax only.
Physical lines processed for listed capabilities are not semantic/security completeness.
Credential-only files retain unreviewed structural line counts. Unknown denominators
remain unavailable; pruned excluded directories are not enumerated to manufacture
coverage. Rules count eligible inventoried candidate files and successfully processed
files, not every possible semantic site. Disabled rules have zero evaluation coverage.
Inventory becomes partial for analysis failures under the existing contract invariant.

See the [Milestone 4 record](milestone-4.md) and
[independent evaluation](milestone-4-evaluation.md). Earlier milestone documents are
historical and do not describe current implementation scope.


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

## Corrective release 6.1

- Semantic evidence is now independent of findings, but is deliberately selective;
  absence of an observation is not evidence of absence. Budget exhaustion and
  unsupported control flow remain prominently disclosed in coverage diagnostics.
- Workspace interpretation still selects at most 128 modules by sorted path. No
  dependency-directed scheduler or partitioned interpreter is implemented. The
  large laboratory therefore remains substantially outside cross-file semantic scope.
- SDK recognition establishes static import/construction bindings, not installed
  SDK versions or runtime identity. Mocks, monkey patching, injected clients,
  subclass behavior and dynamic wrappers remain unresolved. Imported suffix
  candidates are possible inferences, never genuine-provider proof.
- HTTPX defaults are documented library assumptions, not measured deployment
  behavior. Inactivity timeouts do not bound complete operations, retries or cost.
  With/context-manager controls remain unsupported; no universal framework timeout
  or general infrastructure safeguard inference exists.
- Python integer-only interpolation is assessed only on established builtin flow
  and execution paths reaching the sink; unknown callers remain separate. SQL
  construction is not proof of vulnerability. Dialect/driver semantics, identifier
  quoting, arbitrary sanitization, broader string methods and general taint analysis
  remain unverified. JS coercion refinements are unavailable.
- Placeholder classification uses an intentionally narrow value grammar. Real
  credentials can resemble placeholders and synthetic values can resemble real
  credentials. Documentation context never dismisses a candidate. Values and
  value-derived hashes are absent from classification outputs. Validity, history,
  reuse, lifecycle persistence and revocation verification remain unavailable.
- Known traversal/native-parser timeout/memory budget events are resource limits;
  unclassified native process deaths remain failures. Usable partial reports can
  exit 0; this is not an analytical pass or certification.
- No held-out benchmark was accessed or run. Independent baseline aggregates are
  scope-specific synthetic results; no post-correction benchmark improvement is claimed.
