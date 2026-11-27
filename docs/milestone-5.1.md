# Milestone 5.1 — bounded cross-file semantic intelligence

This implementation extends Milestone 5 rather than replacing its parser, resolver,
rule engine or report contracts. It adds no dependencies, target execution, network
requests, GUI, persistent state, or automatic remediation. There remain 24 rules.
The approved milestone's broader objectives are **not all implemented**: the precise
supported subset and unresolved capabilities are described below. No independent
corpus, annotations, generator or evaluation materials were accessed. Synthetic unit
tests are development validation, not independent accuracy measurements.

## Components and retained information

- `analysis/semantic.py`: abstract values, bounded structured interpreter, Python
  receiver construction, numerical constraints and operation sites.
- `analysis/javascript.py`: separate Tree-sitter lowering for JS/TS/JSX/TSX. It does
  not transpile or execute JavaScript. Only enumerated syntax maps to the flow IR.
- `analysis/workspace.py`: bounded module linking using the existing Resolver and
  already inventoried files; no additional target reads. Functions and re-exports
  must have unique statically identified definitions.
- `analysis/safeguards.py`: narrow Flask-Login decorator and FastAPI HTTPBearer
  dependency observations, not generic authentication or authorization inference.
- `analysis/contextual.py`, pipeline and reporting: observations, separate mitigation
  assessments and source-free provenance locations. No automatic severity reduction.

The internal IR uses restricted Python AST node containers for both adapters. It
retains identifiers, import references, locations and bounded numeric constants, but
no source buffers, parser/CST objects, string/byte literals, credential values or
value-derived credential fingerprints. Registered dictionary configuration keys are
represented as field identifiers. It is internal extraction data, never included
in reports. This changes Milestone 5's no-retained-AST implementation: sanitized
syntax is necessary to bind cross-file arguments after extraction; raw AST/source
is not retained. Report evidence contains opaque module identities, line locations
and trusted explanations. No target modules are imported.

## Abstract domains and merge behavior

Values distinguish definite, possible, conflicting and unknown states. Independent
fields represent exact integer values, optional numeric minimum/maximum, finite
collection cardinality upper bounds, possible untrusted/sensitive influence,
constructed-query influence, receiver identity, recognized timeout configuration,
constructor attributes and bounded module/line provenance.

A join keeps an exact integer, receiver, timeout or attribute map only when both
alternatives agree. Two known finite cardinality bounds merge to the larger;
unknown alternatives erase a finite bound. Interval minima merge to the lesser,
maxima to the greater, and unknown endpoints remain unknown. Taint, sensitivity and
query-construction indicators merge by union; this is possible influence, not proof
of exploitability. Provenance is a deterministic union of at most 32 origins.
Exhausted tracked provenance produces a semantic_provenance_limit diagnostic; truncation is not full-path completeness.

Unknown values are never labeled definitely unbounded. Branches are both explored;
conditions are not proved feasible. Early returns remain in the return-value join,
including paths returning before a later bounded value. Loop bodies are widened and
interpreted once. No loop fixed-point or exhaustive path enumeration is claimed.
Unsupported statements invalidate environments and produce diagnostics.

## Cross-file functions, values and receivers

Unique Python imported/module-qualified functions and constants, import aliases,
function aliases and simple `from ... import ...` re-exports propagate values.
Positional arguments, keyword arguments, positional and keyword-only defaults,
nested calls and simple returns are supported. Unknown external-argument contexts
are analyzed separately; defaults apply to omitted arguments at actual call sites,
not all external callers. A function parameter never inherits a same-named global.
Imported mutable collections supply no stable bound. Module initialization cycles,
recursive expansion, ambiguous exports and unresolved imports do not invent values.

Simple Python classes support local/imported construction, constructor-assigned
`self` fields, object aliases, method wrappers and factories returning identifiable
objects. Different constructed instances retain different attribute values. A
statically supplied object can flow through a simple injection argument; unresolved
injection does not gain a type. Inheritance, descriptors/properties, metaclasses,
class decorators, dynamically replaced methods and arbitrary heap mutation are not
resolved. After an instance method call, constructor attributes are invalidated for
the object and its known aliases; later unresolved instance receivers are disclosed. Receiver analysis supplements existing call edges without claiming that
all inferred receiver calls become resolved graph relationships.

OpenAI/Anthropic constructors and requests.Session/httpx.Client/AsyncClient receivers
are recognized. A known wrong receiver does not acquire provider identity solely
from a call suffix. Legacy import-plus-suffix observations remain heuristic and are
not deleted, including potential mock/test-double false positives. No SDK is imported
or contacted to verify runtime identity. Google/LangChain/LangGraph observations
retain their earlier syntactic scope; semantic constructor support is not claimed.

## JS-family semantic subset

All four adapters now independently declare partial control-flow, data-flow,
summary, collection-bound and taint capabilities. Supported syntax includes local
assignments, literal arrays, direct object options, top-level functions/arrows,
arguments/defaults/simple returns, named imports, exported declarations, uniquely
resolved cross-file calls, if/ternary joins, for-of loops and recognizable calls.
Array mutation and unknown calls invalidate bounds. Sparse/spread arrays do not
acquire a falsely small bound. SDK option objects remain positional objects through
local wrappers, then are interpreted at recognized external-operation boundaries.

JavaScript arithmetic is not Python arithmetic: coercion-heavy expressions preserve
influence but cannot establish numerical bounds. A JS function named range is not
the Python builtin. Await suspension invalidates mutable facts and loop bounds.
Closures, captured environments, classes/method definitions, prototypes, getters,
var hoisting, destructuring/rest/spread, general counter loops, re-export forwarding,
CommonJS semantic binding, promise scheduling and external mutation remain partial
or unavailable. TS annotations do not prove runtime values. JSX expressions outside
the supported flow syntax remain unsupported, rather than reviewed frontend logic.

## Bounds, HTTP and security integration

Python literal/range/slice domains, integer constants and finite alternatives remain
supported. `min`/`max` numeric clamps can establish one-sided numeric bounds, including
`range(min(runtime, N))` under ordinary numeric/builtin semantics. A while counter
requires known start/stop, a positive constant increment as its final unconditional
statement, exactly one counter write and no bypass/suspension constructs. This can
bound a simple retry-style iteration domain; it does not establish a retry policy,
backoff, idempotency, shared budget or global invocation limit. Nested domains
multiply. Bounded work is not necessarily efficient or inexpensive.

Unknown calls, mutation, reassignment, attribute writes and asynchronous suspension
conservatively invalidate applicable facts. Alias handling invalidates collections
broadly rather than implementing a complete heap model. Mutable global invariants
and cross-invocation object changes are not verified. Database `.limit()` semantics
are explicitly unavailable; no arbitrary method name supplies a result-size bound.

Positive integer requests/httpx constructor timeouts apply only through identified
receivers; explicit per-request overrides take precedence, including unknown, zero
and disabled values. Module-level clients and straightforward wrapper defaults can
contribute facts. Requests Session has no assumed universal timeout default.
Float/timeouts-by-phase objects, framework defaults and arbitrary configuration
mutation are not verified. A token/timeout limit in some contexts is separate from
unprotected or unknown contexts and does not remove an initial observation.

Python input, narrow FastAPI route-input/Request and Flask request-data candidates,
possible model-output influence, environment-derived sensitivity, constructed SQL,
function argument/return flow and unknown-call influence are tracked. Existing
SEC-001/004 and AI/COST/REL assessments consume applicable sites. Literal parameterized
SQL remains a negative control; driver binding, dialect safety, arbitrary validation,
escaping, redaction and sandbox effectiveness are not proved. Possible sensitive
influence can appear in existing operation evidence; there is no new credential
reuse/history or provider-disclosure rule. Environment-derived sensitivity is not
proof that the value is a credential. No raw values are included.

Flask-Login's imported login_required decorator is a framework observation. A
FastAPI Depends relationship to a constructed HTTPBearer with default auto_error
records bearer-presence checking; disabled/unknown auto_error does not qualify.
Bearer presence/format is not token validity, identity verification or authorization.
Defined but unapplied safeguards do not attach to operations. Arbitrary decorators,
conditional checks, router/global dependencies, gateway/proxy/identity-provider
configuration and Express middleware execution/order/bypass verification remain
unavailable. No endpoint is declared public because a local guard was not recognized.

## Enforced budgets and disclosure

Trusted programmatic defaults (not new TOML settings):

| Budget | Limit |
| --- | --- |
| Active local/cross-file function or re-export depth | 4 |
| Local call contexts per file/pass | 128 |
| Cross-file function/method contexts per scan pass | 128 |
| Cross-file participating modules | 128 |
| Receiver attribute-chain depth | 8 |
| CFG statement nodes per file | 2048 |
| Retained sanitized IR nodes per file | 8192 |
| Abstract transfer/expression steps per file/pass | 4096 |
| Branch joins per file/pass | 64 |
| Function expansions per file/pass | 256 |
| Value provenance origins | 32, deterministically truncated |
| Existing graph expansion | 4 rounds, 256 owner expansions, 4096 derived sites |

Extraction performs local analysis, then a distinct workspace pass. Budgets apply
per pass; totals are not a single wall-clock or memory quota. Missing/skipped IR,
module limits, recursion, receiver limits, unsupported constructs and exhausted
work produce source-free semantic diagnostics. Stale exported constants are not
reused after a transfer budget is exhausted. Existing parser/file/native-process
limits remain. No hard scan-wide memory cap, workers, cache or cancellation added.

Not Reviewed Portions of the Code includes actual semantic_analysis_gaps and an
explicit unavailable_contextual_capabilities list even with no findings. General
unavailable capabilities do not turn an otherwise ordinary CLI scan into a diagnostic
failure; actual semantic diagnostics retain the existing nonzero CLI exit behavior.
Partial capability declarations are never semantic completeness or software safety.

## Validation and remaining milestone work

`tests/test_semantic_cross_file.py` adds paired synthetic tests for cross-file bounds,
constants/aliases/re-exports, imports, classes/factories, taint, overrides, mutation,
unknown callers, early returns, recursion, sparse/starred arrays, JS options and
builtin distinctions, numeric clamps/counters, framework observations and budgets.
`tests/test_semantic_context.py` now requires unknown external callers to remain
unprotected even when a real caller uses defaults, and declares tested JS capabilities.
Existing parsing/privacy/determinism/reporting tests remain required.

Unfinished approved objectives include Express middleware verification, general
framework authorization/path verification, semantic retry/backoff policies and
shared agent budgets, database API result-limit reasoning, broader JS receiver and
closure analysis, general range narrowing/validation, driver-specific parameter
binding, and verified redaction. These remain explicit unavailable capabilities,
not claims of completed negative review. Next development should address these
before declaring the entire Milestone 5.1 scope complete. Independent evaluation
must remain separate from implementation-owned tests and must not influence frozen
implementation through inspection of ground truth.

## Validation result and changed files

Implementation-owned validation: `uv run pytest -q` — **415 passed**;
`git diff --check` — clean. These are regression results, not independent detection
precision/recall measurements. No commits or pushes were performed.

Created: `analysis/javascript.py`, `analysis/workspace.py`,
`analysis/safeguards.py` (under `src/argus/`),
`tests/test_semantic_cross_file.py`, and `docs/milestone-5.1.md`.

Modified: `src/argus/analysis/semantic.py`, `contextual.py`, `pipeline.py`,
`adapters.py`, `rules.py`; `src/argus/reporting.py`;
`tests/test_semantic_context.py`; `README.md`; `docs/configuration.md`,
`docs/data-contract.md`, `docs/language-support.md`, `docs/limitations.md`;
and generated `docs/rules/ai_specific.md`, `cost_efficiency.md`, `credentials.md`,
`reliability.md`, `security.md`. Architecture/maintainability catalog files were
regenerated and remain unchanged because those rule definitions did not change.

## Final pre-commit verification — 2026-11-27

Verification only: implementation, fixtures, manifests, lockfile and generated
catalogs were not modified. Only this milestone record was updated. No commit or
push occurred. The independent held-out benchmark and unrelated projects were not
accessed. All scans used the authorized seven original repositories, read-only;
no target scripts, imports, dependencies or services were executed or installed.

- `uv run --locked --offline pytest -q`: **415 passed in 5.38 seconds**.
  This includes `test_rule_documentation_is_current`, which compares every generated
  category catalog against registry output and verifies referenced rule tests.
- `uv build --offline --out-dir <fresh temporary directory>/dist`: source
  distribution and wheel built successfully; uv built the wheel from the sdist.
- Created a fresh uv environment with CPython 3.12.16. Exported runtime requirements
  with `uv export --locked --offline --no-dev --no-emit-project`; installed all ten
  runtime dependencies with `uv pip install --offline --require-hashes`, then the
  newly built wheel with `--no-deps`. No dependency changes or network downloads.
  uv needed filesystem approval to use its existing local cache.
- Installed `argus --help`, `argus --version` (0.1.0) and all seven actual CLI scans
  ran from the temporary directory with PYTHONPATH and VIRTUAL_ENV removed.
  An isolated (`python -I`) evaluation process confirmed package origin under the
  fresh environment's `site-packages`, outside the development checkout.
- Reused the unchanged `tools/evaluate_lab.py` mapping with the installed package
  for ground-truth and M5 comparison. Separately saved all seven CLI JSON reports
  and stderr files. Comparison keys: rule ID, affected repository-relative paths,
  and source lines. Measurements below are evaluation-process timings; they are
  observations, not performance guarantees or independent accuracy benchmarking.

| Repository | M5 findings | M5.1 findings | Retained | New / missing | Failed files | Semantic diagnostics M5 → M5.1 | Installed CLI exit | Seconds |
| --- | ---: | ---: | ---: | --- | ---: | --- | ---: | ---: |
| 01_clean_python | 0 | 0 | 0 | 0 / 0 | 0 | 3 → 3 | 1 | 0.0750 |
| 02_flawed_python | 11 | 11 | 11 | 0 / 0 | 0 | 1 → 1 | 1 | 0.0110 |
| 03_clean_fullstack | 0 | 0 | 0 | 0 / 0 | 0 | 6 → 19 | 1 | 0.1036 |
| 04_vibecoded_fullstack | 7 | 7 | 7 | 0 / 0 | 0 | 4 → 14 | 1 | 0.0483 |
| 05_unsupported_languages | 0 | 0 | 0 | 0 / 0 | 0 | 0 → 0 | 0 | 0.0053 |
| 06_discovery_edge_cases | 0 | 0 | 0 | 0 / 0 | 3 | 2 → 2 | 1 | 0.0316 |
| 07_large_monorepo | 0 | 0 | 0 | 0 / 0 | 0 | 200 → 573 | 1 | 2.9899 |

All **18 findings retained**, **0 newly detected**, **0 missing**, **0 severity
adjustments**, and **0 mitigation-state or safeguard-count changes**. No measured
finding regression or test failure was discovered. Both clean controls still have
zero findings; that does not establish complete review or general precision.
All laboratory findings remain without established/partial mitigation evidence.

The unchanged 22 ground-truth issues remain **9 detected, 2 missed, 1 partially
evaluated, 10 outside supported scope**. The two model-loop misses remain the
Python local string-concatenating MockModel and JavaScript injected/unresolved
receiver; their original labels are preserved, without inventing provider semantics.
Write amplification remains only partially evaluated through query-in-loop effects.
The six M5 findings not adjudicated as distinct planted defects remain unadjudicated
(four architectural degree indicators and two service observations).

### Not Reviewed Portions of the Code

The larger diagnostic counts are an observable change in incomplete-analysis
reporting and must not be presented as improved detection or completed review.
The clean fullstack report includes unsupported expressions/statements,
destructuring, re-exports, object spread/methods, asynchronous scheduling and
unresolved imported values. The flawed fullstack report adds unresolved imported
values and counter-loop bounds. The monorepo's 573 diagnostics comprise 200 general
JS limitation notices, **173 workspace module-limit diagnostics**, 100 unsupported
JS statements and 100 unsupported Python statements. Six CLI scans exit 1 due to
actual diagnostics; the edge fixture additionally has three existing explicit
malformed/undecodable file failures. These are review limitations, not CLI crashes.
The unsupported-language fixture exits 0 while prominently disclosing unavailable
capabilities; exit 0 is not a passing security result.

The unsupported-language report lists 17 unsupported source formats (C, C++, C#,
Dart, Go, GraphQL, Java, Kotlin, Lua, PHP, PowerShell, R, Ruby, Rust, Svelte, Swift,
Vue), plus Terraform configuration and Markdown. Other reports disclose Markdown,
Git-ignore and other unreviewed portions as applicable. The evaluation helper's
`unsupported_files` counter is zero because credential-only partial review can
make aggregate file status partial; it is **not** a count of unsupported structural
languages. Capability-level report disclosures remain authoritative.

General authorization/identity validation, Express middleware order/bypass,
retry/backoff and shared budgets, database-limit enforcement, general validation
and redaction effectiveness, dynamic dispatch, mutable globals, closures, JS
prototypes/getters and scheduling remain unavailable. Credential history, reuse,
persistence and remediation verification remain unavailable. This verification
adds no capability and does not resolve the unfinished approved objectives above.

### Integrity, privacy and pending-change review

All seven repository fixture sets match the original manifest SHA-256 values.
A separate before/after inventory fingerprinted **1,125 file/symlink entries** across
those seven roots and `expected_results`; every entry was unchanged. Symlinks were
fingerprinted as link text, not followed. This proves current manifest agreement
and no changes during verification; no historical M5 manifest digest was available
to independently establish manifest provenance beyond the existing M5 record.

The existing evaluation checked six credential candidate occurrences. A separate
check deduplicated these into **five distinct values**, including the planted
browser literal, and found none in any of the seven CLI JSON reports or seven
stderr files. All evaluation-rendered reports also passed candidate absence checks.
This is bounded candidate verification, not a guarantee against every encoding or
all sensitive metadata. No raw credential values are recorded here.

Reviewed all **22 pending paths** (tracked changes and untracked files), their
names/types, documentation diff and credential-pattern/candidate checks. Pattern
matches were limited to explicit synthetic examples in central rule metadata, its
generated credential catalog, and a synthetic semantic test. No supplied fixture
credential values, private keys, generated scan reports, crash dumps, unrelated
files or unexpected sensitive artifacts were identified in pending changes.
Existing author metadata is unchanged. `git diff --check` passed. Generated outputs
remain outside Git; existing report/remediation exclusion patterns remain intact.

Fresh temporary artifacts: `/private/tmp/argus-m51-final-yyWy0A` (builds, environment,
seven reports, evaluation, comparison summary, fingerprint records and verification
scripts). Prior M5 comparison input:
`/private/tmp/argus-m5-submission-evaluation.json`. Raw local artifacts are not
committed and should remain private. Only `docs/milestone-5.1.md` was changed by
this final verification task.

### Freeze assessment

Packaging, automated regression checks, rule-doc currency, installed execution,
fixture integrity and supplied-candidate privacy checks pass. No implementation
was changed in response to verification. The **implemented subset** is verified;
the **full approved Milestone 5.1 scope remains incomplete**, so an unconditional
full-scope freeze is blocked by the unfinished capabilities already documented.
The increased incomplete-analysis diagnostics and module-budget gaps also require
explicit acceptance as limitations of any subset freeze. Next step: owner review
of this measured subset and deferred scope before committing; independent benchmark
validation remains separate and was not performed.

## Disclaimer

Argus is a software architecture analysis and decision-support tool. It does not certify or guarantee software safety, security, correctness, reliability, regulatory compliance, or AI alignment. Findings are derived from static analysis, observable source-code relationships, configurable rules, and heuristic indicators. Analysis may produce false positives, false negatives, incomplete results, or inaccurate architectural inferences. The absence of findings does not establish the absence of vulnerabilities, particularly where portions of the codebase have not been reviewed. Argus is intended to complement, not replace, professional security assessments, runtime analysis, comprehensive software testing, code review, and qualified human engineering judgment.
