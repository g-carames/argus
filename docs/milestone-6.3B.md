# Milestone 6.3B — Semantic contracts and information preservation

Owner-review completion report. No commit or push was made. This is implementation-owned validation, not independent evaluation.

## 1. Baseline and confirmed root causes

Frozen HEAD: `aec4cca0f1ef6514875b64d5b32fa4144954cb1a`. The initial working tree was clean. The subsequently supplied `docs/milestone-6.3A-sanitized.md` was the sole independent investigation input and was read completely. No independent benchmark, evaluator-only report, ground truth, individual benchmark fixture or unrelated project was accessed. The existing locked offline suite passed **479 tests in 5.84 s** before edits.

Independent synthetic reproductions established:

- A slice upper bound of 3 survived a plain return but became unknown with a conditional raised exit. `block()` represented both raise and return as `(Value, exited)` and joined them together.
- A legitimate unknown-return alternative also produced unknown; that conservative control remains unknown after repair.
- The graph contained one `invocation` but projection emitted zero `call_path` observations: the projector compared the typed enum value with `call`.
- An enclosing placeholder hint suppressed a separately recognized embedded token occurrence. Assignment-wide classification and the subsequent substring veto both contributed.
- Source inspection verified cross-file context reset, argument sites without formal/actual identity or origins, value-based projection deduplication, graph construction before receiver flow, contextual operation expansion after projection, and file-wide unsupported-control coarsening.

Preserved invariants: offline/read-only scans, bounded parser/extraction/workspace processing, root containment, prepared parsers, conservative mutation invalidation, unknown external function entries, source-free public evidence, no safety score and independently declared partial capabilities.

## 2. Contracts and stage ownership

`semantic_contracts.py` adds only contracts used by the existing engine: source-qualified `Point`, `FactState`, `ExitKind`, structured `Outcomes`, return-channel joining and production-time `SiteLedger` stamping. Existing Value/Site/SemanticFacts and public records are reused. Completed site collections become plain lists, dropping the interpreter-owner reference; retained programs are sanitized syntax.

Symbol IDs use module/kind/source-line/Unicode-column. Callsites use module, lexical owner and source coordinates. Formal IDs use function plus parameter position. Actual IDs use callsite, parameter position, supported binding kind and call path. Result IDs use function plus call path. Assignment/expression identities use source coordinates. External entries have an explicit unknown-entry path identity. None of these new IDs depends on argument contents, source literals or credentials. Moving code can change location identities; same-location renaming preserves them.

Extraction owns symbols and exact syntax callsites. Workspace analysis preserves qualified caller paths and actual/formal/result records while computing existing value facts. Receiver evidence reconciles into the graph before NetworkX algorithms and contextual investigation. Contextual graph-derived operation candidates append to the same site collection. Projection runs last and emits closed privacy-safe records independently of findings. Cross-file evidence locations retain the originating file; legacy context_lines contains same-file positions only.

## 3. Exact exit semantics

- Normal fallthrough, explicit return and raised exits have separate channels. Only explicit successful-return values join each other; possible fallthrough contributes unknown to a successful result.
- An unknown successful return still contaminates a known bound. A raised branch does not contribute a returned unknown value.
- A block with no normal continuation does not analyze its subsequent statements. Both-branch raised exits retain raised status and do not execute the subsequent return transfer.
- A raised-only function has no known successful result; its caller receives unknown because exceptional interprocedural continuations are not solved.
- Unsupported controls and exhausted transfer work retain incomplete status and cannot establish a successful-return bound. Unsupported work does not manufacture an observed explicit-return channel.
- try/except/finally, with, general break/continue effects and exception matching remain unsupported. Handler/finally bodies can change returns, so their presence precludes a successful-return guarantee. No new handler semantics or predicate refinement is claimed. Loop transfers remain conservative single-structured traversals, not a CFG fixed-point solver.

## 4. Projection and evidence flow

Invocation dispatch uses RelationshipKind.CALL rather than an incompatible string. The relationship-kind audit found that imports, HTTP matches and extension kinds were not alternative semantic call kinds; their existing graph records are retained without relabeling them invocations. Typed observation enums remain the public dispatch boundary.

Projection now retains computed assignment facts, known/unknown argument and return facts, actual/formal/result links, caller paths, receiver alternatives, supported loop-domain facts (including loops without calls), operation observations and scoped incomplete facts. Known domains on ordinary calls also survive. Unknown domains never imply infinite execution. Source/provenance/exit-channel distinctions participate in deduplication. Graph-only operation candidates remain possible inferences; they do not inherit validated receiver identity or positive safeguards. Contextual production now precedes projection, avoiding the former copied-list ordering loss.

## 5. Caller/value preservation and incomplete scope

Equal-sized inputs from two source files at identical line numbers retain different callsites, contexts, actuals and results while sharing the correct formal identity. Supported positional, keyword, default and external-unknown bindings are explicit. Missing/duplicate/unsupported Python argument bindings cannot establish successful results. Assignment observations retain their producing result and input-value identity where computed. Unresolved syntax remains present.

Function-local gaps affect the function and its observations instead of unrelated functions. Module/import, resource and unlocalized gaps remain broad; file-level coverage and diagnostics remain visible. Unknown external function entries are preserved separately from known callers. Comprehensive external method/constructor entry enumeration, arbitrary call contexts and full context-sensitive solving remain unavailable.

## 6. Graph reconciliation

One deterministic pass processes at most 4,096 computed callsites per workspace. It indexes exact shared callsite IDs, avoiding line-only attribution and repeated scans of all relationships. Unique static targets receive inferred resolved binding evidence attached to matching syntax edges. Observed syntax evidence is retained. Implicit initializer invocations can remain distinct from the class-construction syntax edge. Synthetic constructor transfer nodes never create invented callee callsites or value origins.

Possible/ambiguous receiver alternatives retain candidate node IDs and no definite target. All computed receiver alternatives are preserved under the existing transfer/path budgets rather than silently truncated. Unresolved references remain unresolved. Existing HTTP/deployment inference is unchanged. Candidate/evidence references are validated. Import metrics and contextual summaries use the reconciled graph; no downstream stage consumes the earlier graph. Exhaustion remains explicit. This is not receiver redesign, recursive summary iteration or advanced HTTP matching.

## 7. Credential precedence

Candidates are identified by occurrence spans while raw text is available, then reduced to source-free classifications. A separately recognized token span survives an enclosing placeholder classification. Exact placeholders without stronger evidence remain filtered. Documentation does not dismiss candidates. Multiple candidates on the same line retain separate public IDs based on location/ordinal/classification, never candidate values or hashes. Validity stays unverified. Bounded reads, file-size protection, exclusions and provider-free operation remain unchanged.

## 8. Installed-CLI semantic gates

`tests/integration/test_semantic_cli.py` is a distinct `installed_cli` tier. A session fixture builds a wheel, exports locked runtime dependencies, creates a clean temporary environment, installs offline, clears PYTHONPATH and invokes the installed executable from outside the repository. It never imports or executes target applications or installs target dependencies. Every scan checks byte-identical repeat output and unchanged target bytes.

The **26 scenarios** cover normal/raised/unknown/fallthrough/unsupported exits; Python and TypeScript multi-module flow; invocation evidence; equal-valued distinct callers; positional/keyword actual/formal/result linkage; cross-module receiver resolution and ambiguous alternatives; scoped gaps; graph-derived operation projection; synthetic constructor provenance; exact same-line callsites; standalone loop domains; observation survival without findings; exact/embedded/delimited/documentation/unknown credential controls; multiple same-line candidates; privacy; and metamorphic renaming, caller order, module splitting and unrelated-value changes. Assertions inspect exact IDs, source locations, uncertainty, linkage and relationships rather than category presence alone.

The same isolated public-bound/invocation/credential oracles were run against a wheel built from the frozen Git archive. **Four expected failures and three passing controls**: raised-return bound loss, dead invocation projection, and two enclosing-placeholder conflicts failed; exact-placeholder, documentation and unknown-validity controls passed. A broader new-contract subset additionally failed where baseline fields did not exist; those failures are contract evidence, not proof of additional computation defects.

## 9. Automated and quality results

| Tier | Result |
| --- | --- |
| Existing frozen baseline | 479 passed |
| Existing retained tests after repair | 479 passed |
| New semantic contract/regression instances | 20 passed |
| New installed-CLI instances | 26 passed |
| Complete locked offline suite | **525 passed in 16.91 s** |
| Rule registry/document drift checks | Passed (13-test rule module) |
| Whitespace and Python compilation | git diff --check and compileall passed |

Two existing tests were updated only to require schema 1.5.0 instead of 1.4.0. Existing detection, relationship and conservative-control expectations were retained. Initial duplicate-edge and shadowed-import failures were repaired, not weakened. An existing imported-call branch could bypass a shadowing local unknown; it now respects the local binding and explicit constructor identities. No project-configured linter/type checker or available ruff executable was found; none was installed.

## 10. Seven laboratory repositories

All seven originals were scanned before and after; raw reports and integrity manifests stayed in the authorized temporary testing area. No laboratory source was changed. Findings below are matched by rule/location; symbol-derived IDs migrate.

| Laboratory | Files | Findings before → after | Observations before → after | Relationships before → after | Diagnostics before → after | JSON bytes before → after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 01_clean_python | 13 | 0 → 0 | 1 → 122 | 80 → 84 | 1 → 1 | 483039 → 710392 |
| 02_flawed_python | 7 | 11 → 11 | 3 → 55 | 37 → 37 | 1 → 1 | 300102 → 397313 |
| 03_clean_fullstack | 22 | 0 → 0 | 0 → 168 | 44 → 45 | 9 → 9 | 686566 → 1055191 |
| 04_vibecoded_fullstack | 17 | 7 → 7 | 1 → 196 | 46 → 46 | 8 → 8 | 582558 → 984567 |
| 05_unsupported_languages | 22 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 | 483510 → 483848 |
| 06_discovery_edge_cases | 22 | 0 → 0 | 0 → 10 | 1 → 1 | 2 → 2 | 455884 → 475377 |
| 07_large_monorepo | 1003 | 0 → 0 | 0 → 608 | 13 → 13 | 4 → 4 | 18054252 → 19349579 |

Coverage objects are exactly unchanged in every laboratory. There are no new, removed or severity-changed findings. All five changed assessments were inspected: only call_path_relationship_ids/unresolved_relationship_ids changed through symbol/relationship ID migration (flawed Python COST-001, REL-003 and SEC-001; vibecoded backend and gateway COST-001). All other assessment fields are identical. Two structural findings (MAINT-003 and MAINT-004 at flawed-Python app.py line 5) migrate finding, affected-entity, evidence and relationship IDs with their source-qualified function; their locations, measured conclusions, severity and all other finding fields are unchanged. Nine findings carry the explicit rule-version update. Diagnostic records compare exactly equal, not merely equal in count. The added relationships are qualified implicit initializer calls in the clean Python/fullstack repositories. Source locations were audited; synthetic callee locations discovered during development were repaired.

Every final laboratory report rendered identically on a second scan. SHA-256 manifests match all **1,112 regular non-symlink laboratory files** before/after; discovered/excluded inventories were not altered to improve denominators. Large-monorepo cross-file selection remains limited to 128 modules; 1,003 inventoried files do not imply complete semantic review.

## 11. Schema and rule compatibility

JSON schema: **1.5.0**; semantic observations: **1.1.0**. Relationship/observation additions are documented in data-contract.md. Seven existing rules use **1.4.0**: AI-001/002, COST-001, REL-003, SEC-001/004, CRED-001. No rule, dependency, threshold, severity, CLI option or configuration key was added. uv.lock is unchanged. IDs migrate from lexical symbol identities to location identities; no persistent cross-version matching or resolution claim is supplied. The package version remains 0.1.0.

## 12. Privacy, packaging and resource verification

Fresh offline source distribution and wheel builds succeeded; clean temporary installation used only the locked, prepared runtime dependencies. The installed-CLI tier independently builds and installs the tested source. No analyzed application, project script or target import ran. No target dependencies, network credential checks, telemetry or external services were introduced. Full reports remain in temporary storage; only aggregate laboratory information appears here.

Synthetic credentials and source-only markers are absent from public JSON, stderr and retained semantic site records in the tested cases. Candidate identifiers remain unchanged when synthetic candidate values change at the same occurrences. Source string/byte literals are removed from the retained sanitized syntax; source identifiers remain private analytical input. Reports contain the mandatory disclaimer and explicit unsupported/incomplete portions. These checks validate the tested privacy boundary, not arbitrary future producers.

Three separate installed-CLI subprocess trials per version scanned the 1,003-file large laboratory with `/usr/bin/time -l`. Baseline elapsed seconds: 4.34, 4.07, 4.05; repaired: 6.11, 4.34, 4.27. Median elapsed **4.07 → 4.34 s** (approximately 6.6% higher). Median reported peak resident memory **163.9 → 172.1 MiB** (approximately 5.0% higher); observed maxima **164.0 → 177.1 MiB**. The first repaired run was slower; startup/cache state and ordinary timing noise limit interpretation. These are local command resource counters, not simultaneous total process-tree memory or a broad performance benchmark.

Largest JSON: **18,054,252 → 19,349,579 bytes** (7.17% growth). Small-repository growth ranges up to 69.01%, largely explicit call/unknown/incomplete evidence. Existing transfer/module/path/observation limits are unchanged; the added reconciliation stage has its own disclosed bound. There is no hard memory cap, and more observations can consume the existing output budget sooner. No measured operating expense or savings is claimed.

## 13. Complete changed-file inventory

| File | Change |
| --- | --- |
| `README.md` | Modified |
| `docs/architecture.md` | Modified |
| `docs/configuration.md` | Modified |
| `docs/data-contract.md` | Modified |
| `docs/language-support.md` | Modified |
| `docs/limitations.md` | Modified |
| `docs/milestone-6.3B.md` | Created |
| `docs/rules/ai_specific.md` | Modified |
| `docs/rules/cost_efficiency.md` | Modified |
| `docs/rules/credentials.md` | Modified |
| `docs/rules/index.md` | Modified |
| `docs/rules/reliability.md` | Modified |
| `docs/rules/security.md` | Modified |
| `pyproject.toml` | Modified |
| `src/argus/analysis/contextual.py` | Modified |
| `src/argus/analysis/extraction.py` | Modified |
| `src/argus/analysis/javascript.py` | Modified |
| `src/argus/analysis/observations.py` | Modified |
| `src/argus/analysis/pipeline.py` | Modified |
| `src/argus/analysis/relationships.py` | Modified |
| `src/argus/analysis/risks.py` | Modified |
| `src/argus/analysis/rules.py` | Modified |
| `src/argus/analysis/semantic.py` | Modified |
| `src/argus/analysis/semantic_contracts.py` | Created |
| `src/argus/analysis/workspace.py` | Modified |
| `src/argus/models/analysis.py` | Modified |
| `src/argus/models/scan.py` | Modified |
| `src/argus/models/semantic.py` | Modified |
| `src/argus/reporting.py` | Modified |
| `tests/integration/test_semantic_cli.py` | Created |
| `tests/test_corrections_m61.py` | Modified |
| `tests/test_coverage_reporting.py` | Modified |
| `tests/test_semantic_contracts_m63b.py` | Created |

`docs/milestone-6.3A-sanitized.md` is the expected owner-supplied input, not an implementation edit. Its SHA-256 is `2c569126f4052a8796af69e872688632e82a2df808093b40ea8d0cfd2fbb003b`. Git HEAD remains the frozen commit. No commit, push, history rewrite, dependency addition or UI work occurred.

## 14. Remaining analytical deficiencies

No complete CFG/worklist, predicate feasibility/refinement, exception matching/finally effects, exceptional call-continuation solver, recursive interprocedural summaries, general heap/points-to model or alias-effect summaries are implemented. Unknown-call/mutation havoc remains conservative. Operation summaries remain operation-kind sets; they are not parametric effects or runtime guarantees. Frontend lowering still loses unsupported JS/class/closure/coercion structure. Receiver alternatives exist only where the current domain computes them. HTTP candidate/deployment matching, general framework guards, driver/policy reasoning, credential history/persistence/revocation and dependency-directed module scheduling remain incomplete/unavailable.

## 15. Known regressions and unresolved concerns

No observed finding, severity, coverage or diagnostic regression remains in the tested laboratories or retained suite. That is a bounded validation result. Known compatibility costs are migrated symbol/derived IDs and larger reports: laboratory JSON grows approximately 0.07–69.01%, with the largest report growing 7.17%. More explicit evidence can reach the unchanged 4,096-observation cap sooner. Resource overhead is recorded above; no hard memory enforcement or broad repository performance guarantee is claimed.

A raised-only callee still cannot establish caller continuation reachability. Same-file legacy context_lines is not a complete call-path model. Public opaque value/formal IDs do not constitute a general def-use or heap graph. Some provenance identities can reference facts omitted by partial/bounded projection; truncation remains disclosed. Unknown external method entry contexts are not fully enumerated. These limits must remain visible during review and future comparisons. No independent benchmark improvement or safety certification is claimed.

## 16. Prerequisites for Milestone 6.3C

Owner review and freeze this corrected baseline, retaining the installed-CLI evidence oracles. Define monotone CFG transfers/lattice joins for normal/returned/raised/unreachable/incomplete states, supported exception/finally edges and conservative exceptional call effects before claiming continuation reachability. Specify predicate refinement and effect ordering with paired adverse controls; retain original observations and caller-specific uncertainty. Define parametric summaries and recursive scheduling budgets separately from heap/alias effects. Preserve frontend unsupported nodes and source-qualified identities, and measure broader resource workloads before changing budgets. Obtain fresh independent evaluation separately; do not tune to or access evaluator-only fixtures.

## Disclaimer

Argus is a software architecture analysis and decision-support tool. It does not certify or guarantee software safety, security, correctness, reliability, regulatory compliance, or AI alignment. Findings are derived from static analysis, observable source-code relationships, configurable rules, and heuristic indicators. Analysis may produce false positives, false negatives, incomplete results, or inaccurate architectural inferences. The absence of findings does not establish the absence of vulnerabilities, particularly where portions of the codebase have not been reviewed. Argus is intended to complement, not replace, professional security assessments, runtime analysis, comprehensive software testing, code review, and qualified human engineering judgment.
