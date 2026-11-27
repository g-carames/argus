# Milestone 6.1 — targeted corrective release

Implementation and local verification completed on November 27, 2026. Uncommitted
review candidate against frozen baseline `cc4a55ac6ea64dc977ffd4d7c3c009e13b03b214`.
No commit or push performed. No held-out benchmark accessed or executed.

## Investigated causes and implemented corrections

1. Provider operations were scattered suffix lists, omitted Responses, and could
   confuse imported names with client instances. An exact operation registry now
   handles constructed OpenAI/AsyncOpenAI Responses, chat, completion, embedding and
   Anthropic messages operations. Responses specifically uses max_output_tokens.
   Resolved aliases, module instances, imported clients, factories and simple
   instance attributes feed existing token/loop/cost-context rules. Known unittest
   mocks remain inspectable without provider findings; unresolved injected clients
   remain possible candidates. Generic method names never establish SDK identity.
2. Timeout flow retained only integers and ignored HTTPX defaults. Positive finite
   float/int settings, complete HTTPX phase objects, constructor defaults, aliases,
   imported instances, wrappers and request overrides now have distinct states.
   None disables; unknown/partial settings remain uncertain. HTTPX's documented
   five-second inactivity default is applicable evidence; Requests has no default.
   Positive Requests connect/read tuples apply. Invalid Session constructor timeout
   is not treated as mitigation. Float values cannot establish integer iteration bounds.
3. SQL syntax construction flags were overinclusive. Python constant-only and
   established builtin-int flows now retain construction observations without
   injection findings. Unknown/untrusted strings, reassignment, unconstrained
   callers, dynamic identifiers and unverified sanitizers remain candidates, never
   assertions of exploitability. Simple literal str.format and percent construction
   are covered. Known DB-API parameter arguments are observed separately from SQL text.
4. Contextual facts were exposed mostly through findings. Schema 1.4.0 adds typed,
   versioned independent semantic observations with certainty, trusted SDK operation
   IDs, timeout states, scope, evidence, assumptions and limitations. Collection,
   argument/return, authentication-registration, invalidation and relevant resolved/
   unresolved call facts can exist without a finding. Cap: 4,096 observations/file.
5. Safeguard fallback states could imply a meaningful search where unsupported.
   Unsupported and incomplete are explicit states; positive scope-specific evidence
   remains separate from original risk observations. No severity reductions added.
6. Placeholder prefix heuristics could dismiss plausible values. Classification is
   now value-based: recognized patterns, plausible assignments, short uncertain
   candidates (8–11 characters), obvious placeholders and documentation context.
   Test/mock/example filenames/comments do not dismiss credentials. No validity check,
   raw values, value-derived candidate hashes, history or lifecycle tracking added.
7. Diagnostics previously made every limitation exit 1. Exact repeated reasons now
   group with occurrence counts and all affected locations. Unsupported, unresolved,
   partial, known budget exhaustion and actual failures have separate classes.
   Known traversal/parser timeout/memory exhaustion is resource-classified; unknown
   native worker deaths remain actual failures. Usable limited reports can exit 0.
8. Laboratory repeat scans exposed unstable Tree-sitter query-capture iteration.
   Sorting import captures by source position makes import IDs/report ordering stable.

Rules AI-001, AI-002, REL-003, SEC-004 and CRED-001 are version 1.3.0. Other rule
IDs/versions remain unchanged. No UI, HTML, new analysis category, target execution,
automated remediation, history, persistence or AI export was introduced.

## Verification

- Frozen baseline automated suite: **415 passed**.
- Final `uv run --locked pytest -q`: **479 passed**, including 64 new corrective
  cases. Generated rule-documentation drift checks pass. Positive, negative,
  ambiguous, mock, malformed-input, privacy, numeric edge and resource-limit cases
  are covered. `git diff --check` passes.
- Existing test expectation changes are intentional: schema assertion 1.3.0 →
  1.4.0 in test_coverage_reporting; authentication naming fallback now expects
  UNSUPPORTED, and unsupported control flow expects INCOMPLETE in
  test_semantic_context. Detection/coverage/privacy assertions were not weakened.
- Offline `uv build --offline` produced wheel and source distribution. A fresh
  temporary Python 3.12.16 environment installed the wheel and dependencies with
  `uv pip install --offline`; final rebuilt wheel was reinstalled and checked from
  outside the repository. CLI version, schema, Responses recognition, default
  HTTPX timeout and integer-constrained SQL smoke checks pass. No target module ran.
- Temporary full reports/builds live under `/private/tmp/argus-m61-*`, outside Git.
  Comparison records contain the required disclaimer; raw candidates are absent.

## Original seven laboratory comparison

Read-only scans used exactly the seven original numbered laboratory directories.
All **18 baseline findings** are retained by rule ID and source location. No added
or removed laboratory finding is claimed. These laboratories do not exercise every
new corrective distinction; new risk recognition and false-positive corrections
are demonstrated by implementation-owned regression cases, not laboratory deltas.

| Laboratory | Baseline findings | Current findings | Diagnostic records → groups | Semantic observations |
| --- | ---: | ---: | ---: | ---: |
| 01_clean_python | 0 | 0 | 3 → 1 | 1 |
| 02_flawed_python | 11 | 11 | 1 → 1 | 3 |
| 03_clean_fullstack | 0 | 0 | 19 → 9 | 0 |
| 04_vibecoded_fullstack | 7 | 7 | 14 → 8 | 1 |
| 05_unsupported_languages | 0 | 0 | 0 → 0 | 0 |
| 06_discovery_edge_cases | 0 | 0 | 5 → 2 | 0 |
| 07_large_monorepo | 0 | 0 | 573 → 4 | 0 |

All seven repeated full JSON reports are deterministic. Hash snapshots for
**1112 regular fixture/ground-truth files** are unchanged. Symlinks were not
read as source. No fixtures, annotations or ground truth were modified.

Diagnostic grouping preserves all 615 original occurrences across these laboratories.
The large repository retains 573 occurrences in four groups, rather than hiding
unreviewed files. Final risk assessment states in flawed Python include three
incomplete and one narrow-scope no-safeguard result; flawed full-stack includes four
incomplete and two unsupported assessments. Architectural findings do not acquire
unimplemented security assessments. No new applicable safeguard in these original
laboratories is claimed. Controlled regressions establish timeout/bound distinctions.

## Independent evaluation boundary

The user-supplied frozen aggregates remain: 20/20 reports, zero crashes; 19 fully
correct, four incorrect, 59 partially evaluated and 38 unsupported assertions out
of 120; 0/33 safeguards, 0/4 directly relevant applicability judgments, 7/23 fully
correct relationships, 9/32 uncertainty assertions and 0/10 matched pairs. The narrow
six-site SQL evaluation was TP 1, FP 4, TN 1, FN 0 (precision 20%, recall 100%, FPR
80%). These correlated synthetic results are not generalizable accuracy estimates.
No post-correction independent metrics exist and no improvement is claimed.

## Remaining defects, scope gaps and release gates

The 128-module cross-file limit remains. Sorted selection is predictable, but can
omit semantically important dependencies in larger repositories. Dependency-directed
closures/partitioning would need cycle, global-state and invalidation designs; they
were evaluated conceptually and deferred rather than arbitrarily raising budgets.
Selected-out modules retain local initial analysis with explicit cross-file gaps.
No repository-wide completeness, memory hard limit or incremental analysis is claimed.

General authorization, arbitrary database limits, comprehensive retry enforcement,
SDK subclass/dynamic receiver behavior, with/try semantic execution, broad sanitizers,
general taint, SQL dialect/identifier quoting, broader string APIs and JS coercion
refinements remain unsupported or incomplete. Documentation context is not a proven
documentation example or a reason to dismiss exposure. Placeholder classification
can still misclassify real or synthetic material. Library defaults are documented
assumptions; no installed target SDK version or deployment behavior is verified.

Engineering review: no dependency added; operation metadata and reporting projection
have separate responsibilities; credential classification is computed once per file;
source-free indexed lookups and explicit budgets bound the new projection. The
pre-existing abstract interpreter and pipeline remain complex and conservative;
this milestone does not claim a comprehensive complexity refactor or sound symbolic
execution. No tests were relaxed to conceal defective detection.

Academic release gates: owner review/freeze, then a separate held-out reevaluation
and acceptance of the prominently documented scope limits. Next logical step is
that independent evaluation, not additional roadmap implementation. Work stops here.

## Files created or modified

- `README.md`
- `docs/architecture.md`
- `docs/configuration.md`
- `docs/data-contract.md`
- `docs/language-support.md`
- `docs/limitations.md`
- `docs/milestone-6.1.md`
- `docs/rules/ai_specific.md`
- `docs/rules/credentials.md`
- `docs/rules/index.md`
- `docs/rules/reliability.md`
- `docs/rules/security.md`
- `src/argus/analysis/contextual.py`
- `src/argus/analysis/extraction.py`
- `src/argus/analysis/isolation.py`
- `src/argus/analysis/observations.py`
- `src/argus/analysis/operations.py`
- `src/argus/analysis/parsing.py`
- `src/argus/analysis/pipeline.py`
- `src/argus/analysis/risks.py`
- `src/argus/analysis/rules.py`
- `src/argus/analysis/semantic.py`
- `src/argus/cli.py`
- `src/argus/diagnostics.py`
- `src/argus/models/credentials.py`
- `src/argus/models/scan.py`
- `src/argus/models/semantic.py`
- `tests/test_corrections_m61.py`
- `tests/test_coverage_reporting.py`
- `tests/test_semantic_context.py`

## Authoritative behavior references

- [OpenAI Responses create signature](https://github.com/openai/openai-python/blob/main/src/openai/resources/responses/responses.py): max_output_tokens and request timeout override.
- [HTTPX timeouts](https://www.python-httpx.org/advanced/timeouts/): documented defaults, client settings, phase objects and None.
- [Requests timeout behavior](https://requests.readthedocs.io/en/latest/user/quickstart/#timeouts): no default timeout; inactivity differs from total duration.
- [Anthropic SDK](https://github.com/anthropics/anthropic-sdk-python): messages.create and max_tokens.

## Disclaimer

Argus is a software architecture analysis and decision-support tool. It does not certify or guarantee software safety, security, correctness, reliability, regulatory compliance, or AI alignment. Findings are derived from static analysis, observable source-code relationships, configurable rules, and heuristic indicators. Analysis may produce false positives, false negatives, incomplete results, or inaccurate architectural inferences. The absence of findings does not establish the absence of vulnerabilities, particularly where portions of the codebase have not been reviewed. Argus is intended to complement, not replace, professional security assessments, runtime analysis, comprehensive software testing, code review, and qualified human engineering judgment.
