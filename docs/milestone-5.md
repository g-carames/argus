# Milestone 5: bounded contextual analysis subset

Milestone 5 improves existing observations without claiming complete semantic or
framework verification. There are still 24 rules. Seven receive specific contextual
refinement: SEC-001/004, REL-003, AI-001/002, COST-001 and CRED-001. Other pattern
findings carry an explicit undetermined assessment; structural rules retain their
measured graph/structure scope. This is a deliberately incomplete milestone subset.
No GUI, target execution, network analysis, automated remediation or persistence.

## Components and methodology

`models/semantic.py` defines source-free Assessment, Safeguard and five mitigation
states. `analysis/semantic.py` provides language-independent Value, Site, FlowNode,
SemanticFacts and Budgets contracts and Python AST / JS-family Tree-sitter adapters.
These internal facts are distinct from report contracts. AST/CST and literal strings
are discarded after extraction; only opaque owners, line numbers, operation kinds,
numeric collection domains and uncertainty indicators survive. No source snippets,
credential values or value fingerprints enter evidence.

Python builds structured control-flow successors for straight-line statements,
if branches, for/while loops and return/raise exits. This is a partial CFG: exception,
with/match, break/continue, comprehension and coroutine scheduling edges are absent.
Unsupported statements produce incomplete-analysis diagnostics. The structured
interpreter follows the same supported statement forms, rather than running a
NetworkX graph algorithm or performing exhaustive symbolic execution.

The abstract value lattice distinguishes definite, possible, conflicting and unknown
states. Integer constants (magnitude <=1e9), literal collection cardinalities, standard
range cardinalities and `xs[:N]` bounds are supported. Unknown join operands cannot
supply a finite bound; two finite alternatives join to their maximum. General
interval arithmetic and condition-based numerical narrowing are unavailable.
Both unknown branch alternatives are analyzed and joined; terminal return/raise
branches do not provide facts to the surviving branch. Conditions are not proved
true/false. This is basic path sensitivity, not feasible-path enumeration.

Intraprocedural assignments and module-level function positional/keyword arguments,
defaults and simple return values propagate locally. Each function also receives
an unknown-argument entry context. A constrained caller cannot establish a bound
for all other callers. Recursion is cut off as unknown. Decorated/variadic functions,
methods, closures, higher-order calls and mutable globals are not evaluated as local
function bodies. Keyword-only defaults are not propagated. Unknown calls invalidate
all known collection bounds, conservatively accounting for aliases. Explicit
collection mutation and loop-carried writes invalidate/widen bounds. Loop bodies
are analyzed once after widening; no loop fixed-point completeness is claimed.
Unknown side effects can cause false negatives in safeguard recognition.

Function operation summaries carry observed model, embedding, database, HTTP and
execution operation kinds. Python local interpretation follows direct unique
functions. Across files and all five primary languages, existing uniquely resolved
CALL relationships propagate operation kinds up to four rounds. Only model,
embedding and database operations in caller loops create additional rule candidates.
No cross-file value, timeout, token-budget or taint propagation is claimed. Existing
resolver shadowing/default-export/receiver limitations remain; graph summaries are
inferences, not observed SDK operations. A provider import plus the existing suffix
patterns is heuristic receiver evidence, not a proven SDK instance type.

Source-to-sink tracking is limited to Python input(), simple local value propagation,
unknown call return influence and direct eval/exec/os.system/os.popen sites. It does
not identify request/database/model output sources, prove sanitation, or verify
shell/data isolation. SEC-001 direct execution findings are never suppressed.
SQL construction flags flow through assignments, local arguments and returns;
parameterized literal queries remain negative controls. SQL parameter binding,
dialects, driver identity and sanitizer effectiveness are not verified.

## Safeguards and applicability

Recognized mitigations are Python literal/range/slice iteration-domain bounds and
positive integer output-token/request-timeout configuration. Simple function defaults
can supply a timeout; a defined but unused variable cannot. Unknown/nonpositive
supplied values produce unverified candidates. Expanded kwargs preserve the inherited
unknown/suppressed initial timeout/token syntax scope: this remains a possible false
negative. JS nested config presence remains an unverified syntactic negative control.
No external infrastructure or database .limit API enforcement is assumed.

Bounded loop observations remain findings at their original severity. A bound alone
does not establish acceptable operational impact. Assessment records contradictory
evidence; no severity reductions are implemented in this subset. Partial contexts,
unknown callers, mutations or incomplete work cannot establish scope-wide mitigation.
Bounds assume standard builtin behavior and nonmutating recognized external-operation
candidates; receiver identity is unverified. Bounds do not establish low cost,
acceptable latency or total lifetime invocation
counts. Branch/path coverage is partial, not proof that all runtime paths are protected.
Authentication/authorization, validation/redaction names, batching/caching, rate limits,
throttling, resource cleanup, retries/backoff, tool permissions, approval gates and
shared agent execution budgets are not recognized as effective safeguards.

CRED-001 adds a conservative browser candidate: JS-family literal `key` assignment
>=16 characters, value marker secret/api-key/access-token/browser-key, fetch syntax
and JSON.stringify use of key. This is lexical request-use context, not binding or
exposure verification. Generic ordinary keys do not qualify; synthetic labels and
unrelated same-name scopes can still produce false positives. No authentication or
revocation inference. The tests include ordinary values and missing request context.

## Enforced analysis budgets

| Budget | Bound and scope |
| --- | --- |
| Interprocedural depth / recursion | 4 active local functions; recursive revisit stops as unknown |
| Call contexts | 128 per Python file, including unconstrained entries |
| CFG nodes | 2048 per Python file |
| Transfer/expression work | 4096 interpreter steps per Python file |
| Branch exploration | 64 branch joins per Python file |
| Local function expansions | 256 per Python file |
| Graph summary expansion | 256 newly expanded owners, at most 4 graph rounds per scan |
| Graph-derived operation sites | 4096 additions per scan |
| JS-family semantic sites | 2048 per file |

Budgets are fixed trusted defaults, not TOML options. `Budgets` validates programmatic
positive integer test overrides; extraction uses the defaults. Limits preserve
unknowns and produce source-free `semantic_analysis_incomplete` diagnostics. The
JSON **Not Reviewed Portions of the Code** includes `semantic_analysis_gaps`, also
when there are no findings. Partial capabilities do not become completed semantic
review. Existing file/parser/native child isolation remains unchanged. No hard
scan-wide time/memory bound, work scheduling or cancellation implementation added.

## Examples and tests

- `for x in range(3): provider_call()` retains an observed loop finding with a local
  bound; `for x in rows: ...` cannot infer a bound.
- `limited=rows[:3]; consume(limited)` contributes a bound for that caller;
  `consume(unknown)` and unconstrained entry remain unprotected.
- `rows=[1,2]; mutate(rows); ...` loses a previously known collection bound.
- `if condition: rows=rows[:3]` does not establish an all-branch bound.
- `requests.get(url, timeout=seconds)` uses a propagated positive integer;
  `timeout=5; requests.get(url)` still produces a timeout observation.
- A uniquely resolved wrapper around recognized SDK syntax retains invocation
  semantics; a method named generate/predict/complete is insufficient.
- `query=build(input()); cursor.execute(query)` carries constructed SQL evidence;
  `cursor.execute('SELECT ?', (value,))` has no construction candidate.

`tests/test_semantic_context.py` covers paired bounded/unbounded, mutation/alias,
wrong-variable, branch, caller, timeout, wrapper, nested-loop, SQL, taint, naming-only
security, ambiguous binding, recursion, budgets, deterministic evidence and masking
cases. Existing tests cover malformed/unsupported/native failures and rule-doc drift.
These implementation examples are not independent benchmark validation.

## Remaining work and deviations

Deferred from the full approved scope: JS/TS/JSX/TSX CFG/dataflow, general intervals,
framework-aware safeguard enforcement, database result-limit reasoning, class/custom
receiver resolution, cross-file argument/return flow, full taint sources/sinks,
retry/security/sensitive-data safeguard integration, function-summary value schemas,
independent accuracy benchmarking and stronger scan-wide resource isolation.
All are necessary before broader contextual completeness claims. No unrelated
features, dependencies, cloud APIs, commits or pushes were introduced.

See [evaluation](milestone-5-evaluation.md), [capabilities](language-support.md),
[contracts](data-contract.md), [configuration](configuration.md) and the generated
[rule catalog](rules/index.md).

## Disclaimer

Argus is a software architecture analysis and decision-support tool. It does not certify or guarantee software safety, security, correctness, reliability, regulatory compliance, or AI alignment. Findings are derived from static analysis, observable source-code relationships, configurable rules, and heuristic indicators. Analysis may produce false positives, false negatives, incomplete results, or inaccurate architectural inferences. The absence of findings does not establish the absence of vulnerabilities, particularly where portions of the codebase have not been reviewed. Argus is intended to complement, not replace, professional security assessments, runtime analysis, comprehensive software testing, code review, and qualified human engineering judgment.
