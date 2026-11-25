# Milestone 3 independent laboratory evaluation

Measured 2026-11-25 on macOS arm64, CPython 3.12.16, using default thresholds.
The authorized laboratory was read only; no fixture scripts, target imports, dependencies, servers or external services were executed.
All manifest-listed fixture hashes matched before scanning and remained unchanged afterward.
The existing manifests and expected results were not modified.

Reproduce: `uv run python tools/evaluate_lab.py LAB_ROOT NEW_OUTPUT_JSON`.
The output is confidential local data; keep it in an ignored or external location.
The final measured JSON was written to `/private/tmp/argus-m3-final-evaluation.json`.

| Fixture | Inventoried files | Extracted modules | Symbols | Imports | Cyclic SCCs | Findings | Failed files | Seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 01_clean_python | 13 | 11 | 31 | 26 | 0 | 0 | 0 | 0.0635 |
| 02_flawed_python | 7 | 5 | 9 | 12 | 1 | 7 | 0 | 0.0059 |
| 03_clean_fullstack | 22 | 20 | 48 | 15 | 0 | 0 | 0 | 0.0322 |
| 04_vibecoded_fullstack | 17 | 14 | 37 | 8 | 1 | 1 | 0 | 0.0186 |
| 05_unsupported_languages | 22 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0047 |
| 06_discovery_edge_cases | 22 | 9 | 8 | 0 | 0 | 0 | 3 | 0.0134 |
| 07_large_monorepo | 1003 | 901 | 1206 | 2 | 0 | 0 | 0 | 0.8804 |

## Ground-truth comparison

Exact scope mapping is explicit in `tools/evaluate_lab.py`: `cycle` and
`persistence-model-cycle` map to ARGUS-ARCH-001; `complexity` maps to nesting/complexity
rules ARGUS-MAINT-003/004. Matching uses file/component membership, including all SCC
members. The complexity match also starts at the planted function location (app.py:5).

- Detected: 3 distinct supported ground-truth issues; 4 matching findings (two cycle findings and two function-indicator findings).
- Missed within this exact mapping: 0 of 3. This small mapping does not establish broad recall.
- False positives on manifest-designated negative controls (01 and 03): 0 findings.
- Additional findings: 4 ARGUS-ARCH-004 dependency-concentration heuristics in 02 (app.py, database.py, reporting.py, services.py). They satisfy measured centrality > 1 and corroborate dense coupling, but are not independently labeled distinct defects by the manifest. Their defect-level false-positive status remains unadjudicated; no global precision claim is made.
- Outside implemented rule scope: 19 planted issues. No findings for these are counted as successful detection or as misses of an implemented rule.
- 07_large_monorepo produced no findings; it is not designated a negative control by its manifest.

| Fixture | Detected issue IDs | Outside implemented scope |
| --- | --- | --- |
| 02_flawed_python | cycle, complexity | coupling, broad-exception, request-timeout, unsafe-execution, query-loop |
| 04_vibecoded_fullstack | persistence-model-cycle | cross-boundary, duplication, shared-state, client-role, tenant-isolation, synthetic-exposed-secret, synthetic-config-secrets, model-html-injection, unvalidated-model-output, loop-model-calls, javascript-model-loop, unbounded-retries, full-table-read, write-amplification |

## Interpretation and gaps

The broad qualitative `coupling` label is outside the exact excessive-in/out-degree
threshold rules: the four-module fixture does not exceed their defaults of 10.
Concentration findings are separately reported above. No adjustment of thresholds
or expected results was made to improve laboratory results.

The discovery-edge fixture reports three failed analysis files (malformed Python/JSON
and invalid UTF-8), alongside exclusions and skipped links. Unsupported-language probes
remain unsupported/unclassified and produce no passing safety result. The flawed
frontend import reference does not point to its apparent intended service path; it
remains unresolved rather than inventing an edge. Mixed-language graph completeness
and runtime behavior remain unverified.

SQL/Dockerfile extraction is limited; no SQL syntax validation or embedded shell
security review occurs. Measurements above are single runs, not benchmarks or
repository-size guarantees. Scanning and JSON rendering were exercised; reported
seconds measure scanning, not package installation or full serialization cost.
Most threshold rules have synthetic positive/negative tests rather than planted
laboratory cases. No security, AI or cost effectiveness is measured.

## Disclaimer

Argus is a software architecture analysis and decision-support tool. It does not certify or guarantee software safety, security, correctness, reliability, regulatory compliance, or AI alignment. Findings are derived from static analysis, observable source-code relationships, configurable rules, and heuristic indicators. Analysis may produce false positives, false negatives, incomplete results, or inaccurate architectural inferences. The absence of findings does not establish the absence of vulnerabilities, particularly where portions of the codebase have not been reviewed. Argus is intended to complement, not replace, professional security assessments, runtime analysis, comprehensive software testing, code review, and qualified human engineering judgment.
