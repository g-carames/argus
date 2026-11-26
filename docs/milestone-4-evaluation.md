# Milestone 4 independent laboratory evaluation

Measured 2026-11-25 on macOS arm64, CPython 3.12.16, using default thresholds.
The final built wheel was installed offline into a fresh environment. That installed package performed these scans; no target scripts, modules, dependencies, servers or services executed.
All manifest-listed file hashes matched the unchanged ground truth before scanning and remained unchanged afterward. No external fixtures or expected results were modified.

Reproduce: `uv run python tools/evaluate_lab.py LAB_ROOT NEW_OUTPUT_JSON`.
The measured installed-package output is private local data at `/private/tmp/argus-m4-submission-evaluation.json`, excluded from this repository.

| Fixture | Files | Modules | Symbols | Relationships | Findings | Failed files | Seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 01_clean_python | 13 | 11 | 31 | 80 | 0 | 0 | 0.0684 |
| 02_flawed_python | 7 | 5 | 9 | 37 | 11 | 0 | 0.008 |
| 03_clean_fullstack | 22 | 20 | 48 | 44 | 0 | 0 | 0.085 |
| 04_vibecoded_fullstack | 17 | 14 | 37 | 46 | 6 | 0 | 0.0359 |
| 05_unsupported_languages | 22 | 0 | 0 | 0 | 0 | 0 | 0.0054 |
| 06_discovery_edge_cases | 22 | 9 | 8 | 1 | 0 | 3 | 0.0262 |
| 07_large_monorepo | 1003 | 901 | 1206 | 13 | 0 | 0 | 2.4027 |

Relationship totals now include calls and HTTP alongside imports. Import-only metrics retain their original projection. Times are individual scan runs, not benchmarks or guarantees. Three malformed/undecodable files fail in the discovery-edge fixture. Unsupported languages now receive textual credential review only; their structural capability remains unavailable and explicitly listed in the unsupported-language summary.

## Ground-truth classification

Of 22 planted issues: **8 detected, 3 missed, 1 partially evaluated, 10 outside supported scope**. Detection uses explicit rule mapping, affected file and planted line membership (component membership for architecture findings). Exact mapping and reasons are in tools/evaluate_lab.py. Partial consequences never count as full detection.

| Fixture | Detected issue IDs | Missed | Partially evaluated | Outside supported scope |
| --- | --- | --- | --- | --- |
| 02_flawed_python | cycle, complexity, broad-exception, request-timeout, unsafe-execution, query-loop | — | — | coupling |
| 04_vibecoded_fullstack | persistence-model-cycle, synthetic-config-secrets | synthetic-exposed-secret, loop-model-calls, javascript-model-loop | write-amplification | cross-boundary, duplication, shared-state, client-role, tenant-isolation, model-html-injection, unvalidated-model-output, unbounded-retries, full-table-read |

The missed browser credential is stored under a generic key identifier and does not match the selected provider-token formats. The detector deliberately does not treat every variable named key as a credential. The two model-loop misses use mock/custom complete wrappers rather than the imported SDK evidence and suffixes required by AI-002. These are disclosed implementation gaps, not claimed detections or an assertion that the applications are safe.

The write-amplification case receives a database-call-in-loop finding at backend/app.py:16. Retention, quotas, billing, transaction semantics and complete write amplification are not analyzed, so its classification remains partial. Broad coupling is outside the exact default >10 directional-coupling rules; this four-module fixture does not exceed those thresholds. Concentration observations are treated separately below.

## Unexpected findings and adjudication

No findings occurred in either manifest-designated negative control (01 and 03). That small sample does not establish general precision.

The flawed Python fixture has 11 findings: seven exact supporting findings for six detected issues (two complexity indicators) plus four ARCH-004 degree-concentration indicators. The latter meet the documented directed degree threshold and were reviewed as correlated measurements, not independently proven defects. Their defect-level status remains unadjudicated.

The flawed full-stack fixture has six findings: the planted cycle, two configuration credential candidates, one additional hardcoded service credential candidate, and two query-in-loop indicators. The second .env candidate corroborates the planted configuration issue rather than a separate ground-truth defect. The backend query finding partially supports write amplification. The services/gateway.js credential and query-loop observations have syntactic evidence, but whether they constitute separate intended defects remains unadjudicated. Credentials were not authenticated; no provider was contacted. No finding was automatically labeled true or false based solely on absence from the manifest.

There are therefore six additional findings unadjudicated as distinct defects: four concentration indicators and two service observations. Finding count is not a count of independent vulnerabilities. No aggregate precision/recall or safety score is claimed.

## Credential privacy and unsupported scope

The report check compared 6 candidate literals, including the planted browser credential missed by detection, against generated JSON. All were absent. Dedicated synthetic tests additionally cover provider keys, hardcoded secrets, private-key material, malformed files, unsupported languages and excluded files. This checks the supplied candidates, not every conceivable credential encoding or arbitrary sensitive filename.

Configuration env values are potential exposures under the inherited discovery policy. Git tracked status, history, ignored-file overrides and remediation lifecycle are not implemented. No revocation or safe-local-storage inference is made. No complete authentication, tenant isolation, raw-model HTML/dataflow, custom model wrappers, retries, full-table reads, global resource safeguards or persistent credential review is claimed.

## Disclaimer

Argus is a software architecture analysis and decision-support tool. It does not certify or guarantee software safety, security, correctness, reliability, regulatory compliance, or AI alignment. Findings are derived from static analysis, observable source-code relationships, configurable rules, and heuristic indicators. Analysis may produce false positives, false negatives, incomplete results, or inaccurate architectural inferences. The absence of findings does not establish the absence of vulnerabilities, particularly where portions of the codebase have not been reviewed. Argus is intended to complement, not replace, professional security assessments, runtime analysis, comprehensive software testing, code review, and qualified human engineering judgment.
