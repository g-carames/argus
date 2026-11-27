# Milestone 6.3C — owner review

Status: implementation and validation complete for owner review; no commit or push. Independent evaluation has not been run or claimed. All mechanisms described as supported below are bounded static computations, not runtime guarantees.

## 1. Verified baseline

Frozen HEAD: `b5440f5ac326946e9d5974f386dd87f17148f285`. The initial implementation tree was clean apart from the explicitly authorized sanitized evaluation report. Both authorized reports were read completely before implementation and remain local, untracked and excluded through `.git/info/exclude`. No independent fixtures, ground truth or evaluator-only reports were accessed. The baseline locked offline suite passed **525 tests in 17.04 seconds**. The owner-supplied prior independent evaluation reported 46/120 fully correct, 0/120 incorrect, 43/120 partial and 31/120 unsupported assertions; safeguard recognition 10/33, relationships 13/23, uncertainty handling 17/32 and full matched pairs 0/10. These are prior benchmark-specific measurements, not product accuracy or results for this implementation. A tracked-source archive of that commit supplied the separately installed baseline wheel for synthetic differential checks.

## 2. Confirmed defects reproduced

An unresolved decorator around a body returning `xs[:3]` exposed a body bound as an effective return guarantee, while the invocation assignment was unknown. The repair separates body observations from effective callable behavior rather than deleting valid body evidence.

A separately constructed JS workload with 850 repetitive assignments and several unsupported constructs produced 4,096 public observations: 3,584 incomplete records and 512 assignments, with no call-path observation despite an invocation relationship. Its repaired projection has 861 observations, including eight consolidated gaps and the call path. Source locations remain attached to the consolidated gaps.

Independent guard and finally controls established missing computation: a rejecting length guard did not constrain subsequent iteration, and `finally: return [1,2]` did not establish the effective bound two. Unknown truthiness, arbitrary slice protocols and suffix-based effect assumptions were also checked with adverse controls during implementation.

## 3. Architectural design and alternatives

The existing expression interpreter, Value/Site ledger, source-qualified identities and workspace resolver remain the single analytical pipeline. The former recursive statement walk and decorative CFG are replaced by an executable CFG and deterministic worklist. New private modules are `control_flow.py`, `abstract.py`, `predicates.py` and `solver.py`; each drives real execution or invalidation. This avoids a parallel engine with incompatible facts. A general heap solver or a larger context-sensitive recursive solver was deferred because the available identity/effect evidence cannot support it soundly in this scope.

The evidence flow is extraction → sanitized frontend IR → CFG/existing expression transfers → workspace context expansion → receiver reconciliation → NetworkX-backed graph analysis → contextual assessment → public projection. Contextual operation facts are constructed before projection. Private AST/state/effects are not serialized. Sanitization happens before retaining CFG references; workspace reuse avoids another deep copy of the same sanitized program.

## 4. Exact supported CFG semantics

Each basic block has one source operation; entry/exits, dispatch and finally save/resume nodes are administrative and have no invented source location. Deterministic block identities include module, lexical owner, operation kind, graph index and real source coordinates. Typed edges mean normal continuation, predicate true/false, loop back, return, raise, break, continue, exceptional transfer, candidate handler, unhandled exception or finally entry.

Python supports sequential assignments/expressions, if, for, while, return, explicit raise, break/continue, loop else and supported try/except/else/finally. A false loop edge enters else; break bypasses else; continue enters the back transfer. Exits preserve fallthrough, returned value, raised exception and incomplete behavior separately. Absent incoming state is unreachable. Syntax relationships remain visible even for paths not reached by the abstract interpreter. Unsupported nodes retain nested potential operations and explicit gaps; they do not establish definite execution or a bound.

## 5. Abstract domains and lattice

A reachable state contains abstract bindings, a separate incomplete flag, pending returned value and exception sets. Unknown is a reachable value, not bottom and not an unsupported operation. Values retain known numbers/booleans, partial numeric intervals, collection lower/upper cardinality, finiteness, alternative receivers, provenance and predicate/value linkage. String/credential contents are not retained by the semantic IR.

Numeric order is interval containment. Collection order permits a tighter verified upper/lower bound below a weaker bound; unknown endpoints are unavailable bounds. Join is convex hull for intervals/cardinality, may-union for provenance, taint, exceptions and possible targets, and conjunction for must facts such as verified type/domain and universal guard applicability. Missing bindings join with unknown. Identity anchors survive only when equal; distinct caller records do not merge because values agree. The state-order helper covers supported numeric/cardinality/type/taint/control components, not a general heap order.

At loop heads after three prior visits, expanding endpoints widen to unknown; stable endpoints remain. Unknown upper bounds never mean infinite execution. No general narrowing or complete symbolic disjunction domain is implemented. Domain tests exercise idempotence, commutativity, associativity, join upper bounds, intersection containment, widening containment/stability and state joins/order. Mutable facts are invalidated when their dependencies can change.

## 6. Worklist and convergence under limits

A deterministic deque propagates states, joins incoming states and re-enqueues changed blocks. For-loop abstract counters separate zero iteration, body and completion; scalar interval updates drive supported while loops. Normal and exceptional states use different edges. This is repeated fixed-point computation, not a renamed single pass. Public statistics demonstrate reprocessing and widening.

Termination is bounded by existing limits: 4,096 successful budgeted transfers, 64 branch-path expenditures, 128 contexts, call depth four, 256 summary expansions, 128 workspace modules, receiver depth eight and 2,048 CFG preparation nodes per flow. Graph preparation is shared across cached bodies, including failed over-limit construction. Transfer counts can include failed probes; `cfg_blocks` and reachable blocks are context-summed, while `prepared_cfg_nodes` accounts for actual cached preparation. No unbounded path enumeration occurs. Expanding loop heads widen, and unsupported/nonconverged computation exhausts explicitly rather than yielding a safety guarantee. There is no new hard wall-time or process-memory cap.

## 7. Predicate refinements

Python refinement covers supported builtin numeric equality/inequality/comparisons, builtin collection length comparisons, integer literal membership, chained comparisons, conjunction, disjunction and negation. True and false constraints propagate separately. Rejecting raises/returns leave only the successful continuation; branch joins establish a universal bound only when every relevant incoming state supports it. Disjunction conservatively joins short-circuit alternatives under the same budgets.

Guards bind to the exact current value identity and source locations. Wrong-value guards, guards after consumption, one-path-only guards, replacement after validation and potential mutation do not establish an operation maximum. Unknown overloaded comparison/truthiness, effectful compound predicates, arbitrary membership and unknown collection protocols remain uncertain. Numeric floating comparisons may retain inclusive overapproximations; integer strict comparisons can tighten by one. Disequality generally refutes a singleton rather than creating interval holes.

## 8. Loop and operation bounds

Supported native literal collections, slices, ranges, refined lengths and narrow monotonic counter loops supply iteration maxima. A known finite collection can have an unknown maximum; an unknown while loop does not establish finiteness. Potentially mutating iteration loses both its bound and iteration-finiteness claim. Known nonempty domains avoid a spurious zero-iteration fallthrough. An unreachable back edge can establish at most one body entry, scoped to its own lexical graph.

Nested loop maxima multiply only when every participating bound is known. Operation maxima additionally require supported operation placement and binding; conditional execution is explicit. An unconditional break can reduce a maximum to one; continue skips following operations. Repeated visits merge facts: a later invalidation cannot leave the first visit's count as a guarantee. Output-token/timeout configuration is distinct from loop and operation count. No monetary cost is inferred.

A slice on an unknown receiver preserves only a possible parameter hint (`bound_supported=false`), since arbitrary `__getitem__` can return anything. That hint never supplies loop/operation bounds. Native list/tuple/range slices can provide verified cardinality. This is a deliberate correction to earlier overconfident slice evidence.

## 9. Exception and finally semantics

Explicit known builtin raises transfer to applicable handlers using a bounded builtin exception hierarchy. Unmatched exceptions remain raised; unknown types retain possible handlers and unhandled continuation. Shadowed or dynamic handler types add incomplete evidence. Raised arguments/cause expressions are discovered, and bare reraises preserve supported exception sets.

Return and normal continuation through try use else/finally correctly within the supported slice. Finally runs for normal, return, raise, break and continue channels; its return or raise replaces an earlier pending exit. Unknown returned values remain unknown even when other returns are bounded. A resolved synchronous raised-only function or simple constructor can terminate caller continuation. Incomplete, async or unresolved-decorated behavior cannot establish that termination.

Nested active exceptions use conservative unions, not a complete runtime exception stack. Arbitrary protocol/import exceptions, exception groups, context-manager semantics, async scheduling and custom exception hierarchy resolution remain incomplete.

## 10. Decorator and effective callable correction

`function_body` observations retain body bounds and are marked potential where wrapper/async behavior prevents invocation guarantees. `effective_invocation` observations remain unknown for unresolved decorators. Only the narrow statically established local synchronous identity decorator that returns its sole parameter unchanged preserves the callable guarantee. Decorator names or framework registration do not establish this behavior. Async body returns likewise do not describe the value of an unawaited invocation.

The installed report verifies body bound three alongside unknown effective result, and the unresolved decorated invocation becomes an ambiguous candidate relationship rather than a definite invocation of the body. Proven identity decoration is a paired positive control.

## 11. Effects and invalidation

The usable Effect interface distinguishes local scalar assignment, replacement, known fresh creation, potential collection mutation, potential attribute mutation, unknown calls and unsupported effects. It is invoked during transfers and records private effect counts. Unknown collection/numeric conversions, formatting, dictionary-key protocols, calls, attribute protocols and unsupported effects conservatively invalidate mutable bounds, attributes and guard applicability. No purity inference comes from suffixes, annotations or repository locality.

Only narrowly computed simple constructor/read-only method behavior and qualified supported library operations receive limited effects. Unknown protocol effects additionally retain a generic possible raised outcome, so a potentially applicable handler is not silently omitted. Complex bases, descriptors, metaclasses, decorators and special object protocols prevent simple-constructor assumptions. Immutable active tuple/range iterators may retain iteration cardinality across unknown calls; ordinary mutable bindings do not. General alias/heap analysis and recursive interprocedural effect summaries remain future work.

## 12. Safeguard applicability

Recognition and effectiveness remain separate. Public evidence links constrained value identity, guard locations, operation location, context/call path, reachability and all/some/unverified applicability. A guard on another identity, after consumption, on one path only or invalidated by mutation cannot establish universal applicability. Distinct constrained and unconstrained callers, including unknown external entries, remain separately visible.

Contextual conclusions require all relevant operation contexts and no affected gap for established applicability. Incomplete evidence takes precedence. Framework registration remains observed/unverified. Existing severity thresholds are unchanged and no severity reduction is introduced. Bounds are scoped static maxima, not deployment/runtime guarantees.

## 13. Projection-budget repair

Gaps consolidate only for the same file, lexical owner, caller context and missing-mechanism/reason. All affected locations remain in evidence; no arbitrary value/formal/result identity is attached to the consolidated gap. Distinct callers remain distinct. Requested, emitted, omitted and consolidated occurrence counts are separate.

The unchanged 4,096-observation per-file limit prioritizes call paths, results, arguments/bounds, domain/operation/settings/receiver/invalidation evidence, gaps and assignments. Ties are deterministic. Above the cap, one slot holds a summary disclosing omitted categories, scopes, contexts and locations; Not Reviewed Portions of the Code also exposes omissions. At 4,097 requested records, 4,095 originals plus one summary are emitted, so two originals are explicitly omitted.

Both pure projector tests and installed-CLI tests exercise 4,095/4,096/4,097 requests. The CLI boundary workload also exceeds the earlier IR preparation limit, which remains visible; it does not claim successful computation of the omitted IR. Repetitive-gap stress retains the call path without increasing the cap.

## 14. Performance investigation and optimizations

Two controlled workloads were measured: the independently generated 850-assignment repetitive-gap JS repository and the unchanged 1,003-file laboratory 07. Frozen and repaired wheels were installed with the same locked dependencies in separate temporary environments. Three alternating-order `/usr/bin/time -l <installed-cli> scan <root>` trials measure full process wall time and peak RSS; `--version` measures startup separately. No analyzed application runs. The profile uses stdlib cProfile and nested phase timers; it requires no new dependency.

| Installed workload | Wall seconds (median) | Peak RSS bytes (median) | Report bytes |
|---|---:|---:|---:|
| startup | 0.07 → 0.06 | 28311552 → 28459008 | 6 → 6 |
| stress | 0.74 → 0.69 | 111378432 → 97075200 | 10226177 → 4579165 |
| laboratory | 4.28 → 4.42 | 180551680 → 183779328 | 19349579 → 19629719 |

On these samples, stress wall time is about 7% lower, peak RSS 13% lower and report size 55% lower; laboratory 07 wall time is about 3% higher, peak RSS 2% higher and report size 1.45% higher. Startup differs by 0.01 seconds. These are local three-trial medians with coarse wall-clock resolution and variable machine load, not precise universal estimates. The larger laboratory still has measured runtime/memory/report growth; this remains an owner-review consideration.


Parent-process stage profiling (seconds, instrumented samples) separates the following costs; overlapping inclusive timings are not summed:

| Stage | Stress baseline → repaired | Laboratory 07 baseline → repaired |
|---|---:|---:|
| Python parsing | not separately sampled → not separately sampled | 0.1249 → 0.1254 |
| Semantic execution (inclusive) | 0.0736 → 0.2036 | 0.0264 → 0.1524 |
| Call-context expansion (exclusive of instrumented child phases) | not separately sampled → not separately sampled | 0.0177 → 0.0268 |
| Workspace (inclusive of semantic/context work) | 0.0749 → 0.2050 | 0.0173 → 0.0740 |
| Resolution | not separately sampled → not separately sampled | 0.0003 → 0.0003 |
| Graph reconciliation | 0.0012 → 0.0012 | 0.0052 → 0.0057 |
| Contextual assessment | 0.0001 → 0.0002 | 0.0015 → 0.0015 |
| Projection/deduplication | 0.6432 → 0.4076 | 0.1091 → 0.1342 |
| Serialization/record validation | 0.8468 → 0.5058 | 2.2269 → 2.2615 |

The separate prepared-frontend JS sample measures parsing 0.0049 → 0.0044 seconds and lowering 0.0074 → 0.0075 seconds. Native isolated-worker parsing/lowering and child process startup are not precisely attributable from parent cProfile; they are not reported as zero. Timing differences in these small samples are not universal estimates.

Profiling identified repeated creation/validation of redundant evidence, per-observation rebuilding of reference sets/counts and another sanitized AST copy. Repairs consolidate gaps before materializing public records, use lightweight prioritized drafts, precompute graph/scope membership sets and observation counts once, reuse sanitized IR and cache bounded CFG preparation within the scan. Repeated-visit deduplication costs about 0.0126 seconds on stress and 0.0012 on laboratory 07; it preserves conservative joined facts instead of emitting every visit. No coverage or safety control was removed for timing.

The repaired stress solve reports 858 worklist steps, zero widenings and zero function contexts; its observations change 4,096 → 861 (852 assignments, eight gaps, one call path). Laboratory 07 reports 1,402 steps, four widenings and 202 aggregate contexts across files, not a violation of the per-flow context budget. Its observations change 608 → 550: incomplete records 273 → 215, with 202 returns and 102 arguments retained. Baseline had no corresponding worklist statistics, so unavailable counts are not represented as zero.

The solver itself costs more: its actual repeated state computation is measured separately from projection savings. Large-report serialization remains a major cost. No claim is made that the earlier independently measured 6.1-relative slowdown is eliminated.


## 15. Python versus JS/TS

Python has the supported predicate/handler/finally slice described above. JS/TS retains existing native parsing, limited bindings, imports, calls, array/range-like lowering, slices and return/throw channels. Shared graph mechanics do not apply Python truthiness, coercion, handler, async or object semantics to JS. JS predicates are not refined with Python rules; unsupported control/parameter forms preserve potential nested operations and gaps. No new language or parity claim is made.

## 16. Baseline-failing and repaired controls

The exact same installed-CLI oracles using preexisting public fields were run against the frozen wheel: rejecting-guard bound, finally effective-return bound and call-path survival under repetitive gaps all failed (three expected failures); adverse before/after/unrelated guard controls passed (one test). Repaired implementation passes these oracles. These demonstrate computation/projection corrections rather than failure solely because a new field is absent. They do not establish independent benchmark improvement.

## 17. Existing and new test results

The final full locked offline suite passes **622 tests in 56.37 seconds**. Existing tier: **525 retained cases** (499 non-CLI and 26 installed CLI). New tier: **97 cases** (39 lattice/transfer/CFG/projector tests and 58 installed-CLI controls). No test is skipped or removed. The full run includes 84 installed-CLI cases. The separate final installed tier passes **84 tests in 35.04 seconds** (538 non-CLI cases deselected).

Whitespace (`git diff --check`), Python compile checks and generated-rule documentation drift checks pass. No separately configured linter/type checker or new static-quality dependency exists; none was installed.

Existing expectations were not silently loosened: supported try/finally and raised-only continuation expectations were updated to their implemented effective semantics; unsupported-with controls remain. Zero-iteration bodies no longer generate reachable contextual candidates. Unknown truthiness retains possible raised outcomes. Positive SDK/collection controls now construct real receivers/native values; opaque-protocol and unresolved suffix controls remain negative. The existing CLI exit matrix retains opaque callers and adds native-list callers, asserting their different certainty and result linkage. Schema assertions deliberately advance to 1.6.0.

## 18. Installed-CLI evidence-level scenarios

The integration tier builds a wheel and installs it with locked runtime dependencies into a clean temporary uv environment. It runs the installed executable on independently constructed multi-module repositories, never reconstructed WorkspaceFlow objects. Every scan is repeated byte-for-byte, target bytes are checked unchanged, host paths are absent and the Not Reviewed field is present.

Assertions verify exact guard bounds/counts and value/guard provenance; before/after/wrong-value/reassignment/mutation controls; both versus one constrained branch; membership/chained/negated comparisons; known versus unknown domains; loop reprocessing/widening; nested maximum six with conditional execution; break one/continue three; unreachable operations absent; raised-only calls/constructors; known/unmatched/unknown exception handlers; finally overrides; body/effective decorator scopes; identity decorators; async uncertainty; unsupported nested potential operations; distinct caller constraints and unknown external entries; current module receiver bindings; ambiguous decorator edges; repeated-visit invalidation; projection boundaries and retained gap locations; and source/credential privacy through try/finally.

Metamorphic controls include identifier renaming, branch inversion, unrelated insertion/value change, caller ordering and module splitting. Original tests retain equal-value caller identities, actual/formal/result linkage, cross-file receiver alternatives, identical line numbers across files, observation survival without findings and occurrence-level credential precedence.

## 19. Seven original laboratory comparisons

| Laboratory | Files | Findings | Observations | Relationships | Diagnostics | JSON bytes |
|---|---:|---:|---:|---:|---:|---:|
| 01_clean_python | 13 | 0 → 0 | 122 → 111 | 84 → 84 | 1 → 1 | 710392 → 746946 |
| 02_flawed_python | 7 | 11 → 11 | 55 → 99 | 37 → 37 | 1 → 0 | 397313 → 534270 |
| 03_clean_fullstack | 22 | 0 → 0 | 168 → 77 | 45 → 46 | 9 → 9 | 1055191 → 910005 |
| 04_vibecoded_fullstack | 17 | 7 → 7 | 196 → 127 | 46 → 46 | 8 → 11 | 984567 → 926685 |
| 05_unsupported_languages | 22 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 | 483848 → 484119 |
| 06_discovery_edge_cases | 22 | 0 → 0 | 10 → 10 | 1 → 1 | 2 → 2 | 475377 → 484485 |
| 07_large_monorepo | 1003 | 0 → 0 | 608 → 550 | 13 → 13 | 4 → 4 | 19349579 → 19629719 |

Coverage records and denominators are byte-equivalent in all seven comparisons. Counts describe these laboratory repositories only. JSON size is serialized UTF-8 bytes, including the new accounting/provenance fields.

All 18 findings persist at the same locations and severities. No finding is added or removed. Four assessments change in laboratory 02: COST-001 at app.py:9 becomes undetermined after supported try traversal exposes the unresolved operation context; SEC-001 at app.py:36 and REL-001 at app.py:37 change incomplete to unsupported because try is no longer the missing mechanism but broader safeguard reasoning remains unavailable; REL-003 at services.py:6 changes limitations only. Six assessments change in laboratory 04: gateway.js:10 COST-001 retains incomplete status with updated supporting context; backend/app.py:16 COST-001 and four CRED-001 findings (gateway.js:1, App.tsx:3, .env.synthetic:1/2) change limitation text only. No new positive mitigation or severity change is inferred.

Laboratory 03 adds one resolved static getExhibits binding at frontend/src/App.tsx:9 under the callback owner. Nested unsupported structure is now retained, with its incompleteness disclosed; this binding is not a guarantee of callback execution. Laboratory 02 loses the obsolete unsupported-try diagnostic. Laboratory 04 adds async-scheduling, unresolved-decorator and unsupported-expression diagnostics previously obscured by traversal limitations. The unsupported expression now also retains potential nested evidence instead of silently preserving mutable facts. Other diagnostic sets remain unchanged. Observation reductions primarily reflect consolidation/unsupported-scope corrections; finding-free repositories retain semantic evidence.

## 20. Privacy and integrity

Both sanitized reports remain local/untracked through repository-local exclusion. `uv.lock` and dependencies are unchanged. The 1,112 original laboratory regular-file hashes match baseline; every laboratory report was generated twice identically. Installed synthetic scans verify target bytes before/after, deterministic serialized output and absence of private absolute roots. Credential candidates remain unverified and values are absent; source-only string/comment markers through retained CFG/finally do not appear publicly. Private retained AST/CFG strings are sanitized, with a direct regression check.

No target application/import execution, target dependency installation, network provider checks, telemetry or new service was introduced. Existing discovery containment, parser isolation, bounded reads, coverage denominators and disclaimer are retained. Prepared uv operations are offline and affect only analysis/package test environments. The final wheel Python files were compared byte-for-byte with the source tree, and neither wheel nor source distribution contains either sanitized input report. Performance artifacts and generated scan reports stay in temporary storage, outside the change inventory.

## 21. Schema, rules and compatibility

Root JSON schema advances 1.5.0 → **1.6.0**; semantic observation contract advances 1.1.0 → **1.2.0**. Additions describe lower/upper verification, finiteness, operation/iteration maxima, conditional execution, body/effective scope, reachability, exact constrained identity and guard locations, plus per-file solver/projection accounting. Historical documentation is retained with explicit current-version sections.

The six existing contextual rules AI-001, AI-002, COST-001, REL-003, SEC-001 and SEC-004 advance 1.4.0 → **1.5.0** for changed computation. CRED-001 remains 1.4.0. There are still 24 registered rules; no thresholds or severity defaults change. Generated catalog pages are checked against metadata. Adapter producer versions advance to distinguish the implemented semantics, without new coverage capability claims.

Deliberate compatibility corrections: unreachable/zero-domain operations stop producing contextual candidates; unknown decorators no longer expose body guarantees as callable facts; arbitrary slice hints require `bound_supported=false`; finally overrides and possible unknown-protocol exceptions change effective exit facts. Consumers must honor the new schema, certainty and scope rather than reading a raw bound alone.

## 22. Complete modified-file inventory

**37 implementation, documentation and test files** (new files marked new):

1. `README.md`
2. `docs/architecture.md`
3. `docs/configuration.md`
4. `docs/data-contract.md`
5. `docs/language-support.md`
6. `docs/limitations.md`
7. `docs/milestone-6.3C.md` — new
8. `docs/rules/ai_specific.md`
9. `docs/rules/cost_efficiency.md`
10. `docs/rules/index.md`
11. `docs/rules/reliability.md`
12. `docs/rules/security.md`
13. `src/argus/analysis/abstract.py` — new
14. `src/argus/analysis/adapters.py`
15. `src/argus/analysis/contextual.py`
16. `src/argus/analysis/control_flow.py` — new
17. `src/argus/analysis/javascript.py`
18. `src/argus/analysis/observations.py`
19. `src/argus/analysis/pipeline.py`
20. `src/argus/analysis/predicates.py` — new
21. `src/argus/analysis/relationships.py`
22. `src/argus/analysis/rules.py`
23. `src/argus/analysis/semantic.py`
24. `src/argus/analysis/semantic_contracts.py`
25. `src/argus/analysis/solver.py` — new
26. `src/argus/analysis/workspace.py`
27. `src/argus/models/scan.py`
28. `src/argus/models/semantic.py`
29. `src/argus/reporting.py`
30. `tests/integration/test_control_flow_cli.py` — new
31. `tests/integration/test_semantic_cli.py`
32. `tests/test_abstract_m63c.py` — new
33. `tests/test_corrections_m61.py`
34. `tests/test_coverage_reporting.py`
35. `tests/test_semantic_context.py`
36. `tests/test_semantic_contracts_m63b.py`
37. `tests/test_semantic_cross_file.py`

No laboratory file, dependency lock, UI asset, independent input or generated scan artifact belongs to this inventory. `.git/info/exclude` is local metadata only and is not a publishable implementation file. No changes are staged, committed or pushed.

## 23. Remaining defects, unsupported capabilities and concerns

There is no general heap/points-to solver, recursive summary fixed point, complete predicate logic, path-correlation domain, general narrowing, arbitrary callable/decorator/protocol resolution, exception groups, context-manager implementation or async execution model. JS/TS does not have Python semantic parity. Unsupported nested discovery is potential, not definite reachability. Unknown external callers remain intentionally unresolved.

Broad conservative mutable invalidation can lose useful facts even when a future heap/effect solver could prove noninterference. Scoped unsupported control may make an entire callable outcome incomplete. Nested active exception union can overapproximate handlers. Only a narrow constructor/read-only-method slice is supported; no arbitrary local purity claim is made. Import-time/global effects and unknown runtime/library behavior remain outside guarantees. Public bounds under standard library models assume ordinary bindings, with external monkey patching unavailable.

Widening can lose exact loop results; budgets can stop otherwise analyzable functions. Projection still truncates distinct evidence at its fixed cap, explicitly disclosed. Consolidated evidence location lists can be large. There is no hard memory or global wall-time enforcement. Resource/timing samples are local workload measurements, not universal product performance. No independent accuracy or matched-pair gain is claimed. No known failing locked regression remains at the final recorded validation; that does not establish absence of analytical defects.

## 24. Prerequisites for the next heap/context/effect milestone

Independently evaluate this frozen candidate before interpreting benchmark gains. Preserve the public evidence oracles and adverse controls. Next establish allocation/object identities, alias relations and dependency sets for mutable facts; extend effects with sound interprocedural summaries; only then narrow invalidation selectively. Add recursive summary convergence and context merging with explicit unknown external entries and budgets. Improve exception-stack/protocol/import semantics without changing potential reachability into definite execution. Expand JS/TS lowering with language-specific transfers and end-to-end controls. Profile representative larger real repositories before adding caching or concurrency, and retain public accounting, privacy and deterministic projections throughout.

## Required disclaimer

Argus is a software architecture analysis and decision-support tool. It does not certify or guarantee software safety, security, correctness, reliability, regulatory compliance, or AI alignment. Findings are derived from static analysis, observable source-code relationships, configurable rules, and heuristic indicators. Analysis may produce false positives, false negatives, incomplete results, or inaccurate architectural inferences. The absence of findings does not establish the absence of vulnerabilities, particularly where portions of the codebase have not been reviewed. Argus is intended to complement, not replace, professional security assessments, runtime analysis, comprehensive software testing, code review, and qualified human engineering judgment.
