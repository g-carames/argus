# Milestone 5 laboratory comparison and completion record

Measured 2026-11-25, macOS arm64 / CPython 3.12.16. The final wheel was built from
its source distribution and installed offline into a newly created uv environment.
The installed package scanned all seven existing laboratories. Target modules,
scripts, services and dependencies were not executed or installed. Fixture and
manifest files were unchanged. No credentials or source excerpts are included here.

Baseline: private Milestone 4 submission evaluation, with the same default thresholds,
rule mapping and planted locations. Finding comparisons use rule ID, affected paths
and lines, since baseline output predates assessment fields. This is a controlled
laboratory reevaluation, **not independent accuracy benchmark validation**. Examples
and credential patterns were developed with knowledge of these fixtures. External
fixtures and ground truth were not edited or relabeled.

| Repository | M4 findings | M5 findings | Retained | New | Failed files | M5 seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 01_clean_python | 0 | 0 | 0 | 0 | 0 | 0.0952 |
| 02_flawed_python | 11 | 11 | 11 | 0 | 0 | 0.0092 |
| 03_clean_fullstack | 0 | 0 | 0 | 0 | 0 | 0.095 |
| 04_vibecoded_fullstack | 6 | 7 | 6 | 1 | 0 | 0.0425 |
| 05_unsupported_languages | 0 | 0 | 0 | 0 | 0 | 0.0056 |
| 06_discovery_edge_cases | 0 | 0 | 0 | 0 | 3 | 0.0296 |
| 07_large_monorepo | 0 | 0 | 0 | 0 | 0 | 2.8151 |

Individual times are observations, not throughput guarantees. Unsupported languages
remain structurally unsupported; credential text review does not change that status.
Three malformed/undecodable edge-case files still fail explicitly. Semantic gaps,
including unsupported control flow and JS value analysis, are separately disclosed
in diagnostics and Not Reviewed Portions of the Code.

## Outcomes and prior misses

All 17 baseline findings remain; one browser credential candidate is newly detected.
There are 18 findings total. Both clean negative controls retain zero findings.
Of the unchanged 22 ground-truth issues: **9 detected, 2 missed, 1 partially evaluated,
10 outside supported scope** (M4: 8/3/1/10). Detection uses the exact inherited rule
and location mapping; no broader vulnerability count or precision/recall claim.

- The generic browser `key` miss now has value-marker plus request-use evidence and
  a CRED-001 potential-exposure finding. It is never authenticated or reported raw.
- The Python custom receiver resolves on manual source inspection to a local
  MockModel.complete that concatenates strings. No provider SDK operation exists
  in that implementation. It remains a miss against the original manifest's broader
  model-loop label; this is not evidence of external model consumption. Automatic
  class/receiver semantic resolution remains unsupported.
- The JS `llm.complete` receiver is injected, with no uniquely identified local or
  provider implementation. It remains a potential false negative, explicitly
  unresolved; naming alone is insufficient. Evidence-backed SDK wrappers are now
  detected in targeted tests for Python, JavaScript, TypeScript, JSX and TSX.

No laboratory finding has established/partial mitigation evidence, and no severity
changed. Bounded synthetic pairs demonstrate retained observations and safeguards;
no finding is suppressed or lowered merely because an iteration bound exists.
The six additional M4 findings unadjudicated as distinct defects remain unadjudicated:
four architectural degree-concentration indicators and two service observations.
No new unexpected finding was introduced beyond the planted browser candidate.
That observation and two zero-finding controls do not establish general precision.

Write amplification remains partially evaluated as query-in-loop consequences.
Authorization, tenancy, unbounded retries, full-table reads, model-output security,
shared state and other unsupported scopes remain outside exact implemented rules.
False negatives remain likely for unresolved/injected/class wrappers, dynamic
configuration, unsupported controls and broader taint sources. False positives can
arise from heuristic provider-import/suffix evidence, query method names, lexical
browser context, conservatively invalidated safeguards and existing binding limits.
Unknown safeguards do not suppress findings.

## Integrity and validation

All seven fixture sets matched manifest hashes before scanning and remained unchanged
afterward. All six checked credential candidates, including the prior missed browser
literal, were absent from every generated report. This verifies the supplied
candidates, not arbitrary sensitive encodings or every possible private filename.
Raw source/credentials are not retained in semantic facts or diagnostic messages.

- Full automated suite: **379 passed**, including 53 new contextual cases. Existing
  parser/isolation, malformed/unsupported input, privacy, CLI and rule-doc drift
  tests pass. No tests were weakened. One schema-version expectation was updated
  for the additive 1.3.0 contract.
- `uv build --offline`: source distribution and wheel built successfully.
- Fresh uv environment: all 11 packages installed offline from the existing cache;
  final wheel reinstalled without dependency changes. Installed package origin,
  CLI version, schema and contextual smoke scan were verified. The first smoke
  path used macOS /var's symlink alias and was rejected by existing containment
  protections; repeating with a canonical /private/tmp root passed.
- Development used no network or external AI inference. Using uv's existing user
  cache required filesystem approval for package management; scans stayed offline.
- Temporary outputs: `/private/tmp/argus-m5-submission-dist`,
  `/private/tmp/argus-m5-install`, `/private/tmp/argus-m5-submission-evaluation.json`.
  The raw local evaluation JSON is not committed.

## Delivered subset, limits and next step

Shared source-free semantic/assessment contracts; Python structured CFG, local
constant/collection/argument/return flow, branch joins and limited input taint;
operation summaries across existing resolved calls in five primary languages;
retained contextual findings; explicit budget diagnostics; seven refined rules;
conservative browser credential classification. Total rules remain 24.

Fixed limits: depth 4, 128 Python contexts, 2048 CFG nodes, 4096 transfer/expression
steps, 64 branch joins, 256 local expansions per Python file; four graph rounds,
256 graph owner expansions and 4096 derived sites per scan; 2048 JS sites per file.
These are bounded approximations, not hard scan-wide memory/time guarantees.

The full approved semantic scope is **not complete**. Deferred work includes
JS-family CFG/value flow, general intervals, cross-file values/taint, class receivers,
framework authentication/authorization and safeguard verification, database limit
semantics, retry/backoff/security-sensitive-data safeguards and shared agent budgets.
See [exact methodology and deviations](milestone-5.md). The next coherent step is
cross-file value summaries and receiver resolution with an independent test corpus;
independent accuracy benchmarking remains its own milestone.

Documentation updates include AGENTS contextual-investigation policy, central rule
metadata/generated catalogs, capability matrix, contracts 1.3.0, configuration,
architecture, limitations, README, this evaluation and the implementation scope.
No GUI, paid service, new dependency, remediation, credential persistence/history,
commit or push was introduced. All changes await owner review.

## Files created or modified

Created:
- `src/argus/models/semantic.py`
- `src/argus/analysis/semantic.py`, `src/argus/analysis/contextual.py`
- `tests/test_semantic_context.py`
- `docs/milestone-5.md`, `docs/milestone-5-evaluation.md`

Modified:
- `src/argus/analysis/adapters.py`, `extraction.py`, `pipeline.py`, `risks.py`, `rules.py`
- `src/argus/models/analysis.py`, `base.py`, `scan.py`; `src/argus/reporting.py`
- `tests/test_coverage_reporting.py`
- `tools/evaluate_lab.py`, `tools/generate_rule_docs.py`
- `AGENTS.md`, `README.md`
- `docs/architecture.md`, `configuration.md`, `data-contract.md`,
  `language-support.md`, `limitations.md`
- `docs/rules/index.md`, `architecture.md`, `maintainability.md`, `security.md`,
  `credentials.md`, `reliability.md`, `ai_specific.md`, `cost_efficiency.md`

## Disclaimer

Argus is a software architecture analysis and decision-support tool. It does not certify or guarantee software safety, security, correctness, reliability, regulatory compliance, or AI alignment. Findings are derived from static analysis, observable source-code relationships, configurable rules, and heuristic indicators. Analysis may produce false positives, false negatives, incomplete results, or inaccurate architectural inferences. The absence of findings does not establish the absence of vulnerabilities, particularly where portions of the codebase have not been reviewed. Argus is intended to complement, not replace, professional security assessments, runtime analysis, comprehensive software testing, code review, and qualified human engineering judgment.
