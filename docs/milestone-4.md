# Milestone 4 implementation and review record

Implemented a bounded, tested subset of the approved scope, prioritizing the offline
CLI and useful rules. This record includes the additionally authorized resolver,
workspace, HTTP and call relationship work. No UI, HTML/CSS, visualization, automated
remediation, remote provider integration, commit or push is included.

## Rules and parameters

All rules are centrally registered; generated documentation includes methodology,
parameters, languages, confidence, examples, remediation, acceptance criteria and
limitations. Fifteen new rules supplement the nine existing structural rules.
All pattern findings have medium severity/confidence, observed source-free evidence,
heuristic risk provenance and open remediation status. One finding per rule/file/
matching physical line; multiple consequences use additional categories and one
ResourceImpact record instead of duplicate category findings.

| Rule | Exact implemented detection boundary | Languages |
| --- | --- | --- |
| SEC-001 | Direct eval/exec; JS eval/Function | Python; JS/TS/JSX/TSX |
| SEC-002 | os.system/popen, subprocess shell=True; imported child_process exec/execSync | Primary languages |
| SEC-003 | pickle/dill load(s), yaml.unsafe_load, yaml.load without explicit SafeLoader/CSafeLoader | Python |
| SEC-004 | execute/executemany/query first argument f-string/BinOp or JS interpolated template/binary expression | Primary languages |
| SEC-005 | hashlib.md5/sha1; literal crypto.createHash md5/sha1 | Primary languages |
| SEC-006 | requests HTTP call verify=False; JS object rejectUnauthorized:false | Primary languages |
| SEC-007 | Imported FastAPI/Starlette CORSMiddleware, wildcard allow_origins + allow_credentials=True; imported JS cors origin true/* + credentials true | Primary languages |
| REL-001 | Bare except or Exception/BaseException handler, including tuples | Python |
| REL-002 | Handler body only pass or constant expressions; supersedes REL-001 at same handler | Python |
| REL-003 | requests HTTP verb/request without timeout; expanded kwargs suppress unknown configuration | Python |
| REL-004 | time.sleep or requests HTTP call inside async function; nested synchronous function excluded | Python |
| COST-001 | execute/executemany/query lexically inside for/while/async-for; function scope resets loop context | Primary languages |
| AI-001 | Provider import evidence and recognized completion/generation suffix without detectable output-limit keyword/config | Primary languages |
| AI-002 | Same import evidence and model/embedding call suffix inside lexical loop; function scope resets loop context | Primary languages |
| CRED-001 | Provider-token families, private-key PEM headers, quoted secret assignments, unquoted .env secret assignments; fully withheld values | Eligible UTF-8 text independently of language/parser |

Pattern parameters default to zero and compare per-line occurrence 1 > threshold:
occurrence_sec_001–007, occurrence_rel_001–004, occurrence_ai_001–002,
occurrence_cost_001 and credential_occurrences. Threshold >=1 suppresses emission;
disabled_rules records explicit zero evaluated coverage. Exact token lengths,
assignment names/placeholder exclusions, call suffixes and argument semantics are in
[generated catalogs](rules/index.md) and [configuration](configuration.md).
No prices, operating expenses, loss estimates or savings claims are generated.

ARCH-004/005 metadata now documents directed degree/(n−1), singleton convention,
self-loops, default concentration threshold and correlated overlap with directional
coupling and MAINT-002 size. These indicators are not independent confirmed defects,
criticality scores or additive severity. Existing structural rule behavior is retained.

## Language, framework and relationship capabilities

The [public matrix](language-support.md) lists independently available capabilities.
Python and JS/TS/JSX/TSX have the rule subsets above, structural extraction and module
imports. Other supported formats retain their previous narrow parsing/structure scope
plus eligible textual credential scanning. No broad shell, SQL or Dockerfile security
review is claimed. Native syntax success is not security completeness.

Resolution uses inventoried data only: relative/index/extension alternatives,
TypeScript/JavaScript baseUrl and paths, JSONC project configs, local extends (16-link
bound with cycle/missing-parent rejection), npm/Yarn/pnpm workspace globs, internal
package entries/exports and conditional target ambiguity. Exact alias keys take
precedence, otherwise longest wildcard prefix; mappings/alternatives have documented
bounds. No @/ or ~/ alias is assumed without configuration. Executable bundler
configuration, package-manager commands and project scripts never run. Python root,
src and identifiable package layouts continue to work; duplicate candidates remain
ambiguous. React/Vite conventional aliases are not assumed, and framework-specific
bundler evaluation is not implemented.

CALL edges preserve direct and straightforward imported bindings, aliases, selected
module-qualified calls and local class construction. Unique targets are inferred;
unknown receivers, ambiguous declarations, default exports, barrel forwarding,
rebinding and general methods remain unresolved or limited. No full type/call graph
claim. Import/re-export module edges remain distinct from symbol forwarding.

HTTP endpoint nodes retain observed FastAPI/Flask, Express and limited Next app route
handler declarations. Frontend fetch/imported Axios literals or module const strings
retain request evidence, methods and locations. Compatible method/path/parameter
matches are inferred; competing endpoints remain ambiguous; unknown/computed paths
remain unresolved; absolute HTTP(S) requests are external. Service identity/runtime
communication is never established from matching strings. No generic client-wrapper,
baseURL environment evaluation, Django URL resolution or complete router mounting.
Calls/HTTP edges do not change the established local-import metric projection.

## Credential scope and remaining remediation work

CRED-001 scans eligible bounded UTF-8 text even when its structural adapter is absent
or parsing fails. Recognizable keys, prefixed hardcoded credential assignments and
private-key headers are candidates, not authenticated or confirmed public exposures.
Literal values and source snippets never enter findings/evidence/logs/identifiers.
Finding identity uses rule/file/occurrence ordinal, never a credential-value hash.
Unrelated line insertions preserve these IDs; earlier new occurrences can shift them.

The milestone does **not** implement keyed reuse fingerprints, persistent records,
tracked-file overrides, ignored-local-file authorization, Git history or lifecycle
comparison. `credentials` remains null instead of pretending to populate remediation
states. Proper local storage versus current/historical exposure and removal,
replacement, rotation, user-attested revocation, independently verified revocation
and unverified revocation are not classified by an engine. Candidates stay open.
Removal/replacement never implies revocation. No provider is contacted or credential
validity tested. These are explicit deviations by omission from the full approved
feature set, permitted by the user's tested-subset priority.

Local scanner approaches were reviewed, not integrated or benchmarked:
[Gitleaks](https://github.com/gitleaks/gitleaks) offers local directory/Git scanning
and redaction; [detect-secrets](https://github.com/Yelp/detect-secrets) offers Python
plugins/baseline workflows; [TruffleHog](https://github.com/trufflesecurity/trufflehog)
offers credential verification and a no-verification mode. A future integration
must pin prepared tooling, prohibit target-defined plugins/config execution, disable
all network/verification and intercept raw values before logs/output. None is a
substitute for protected local keyed lifecycle records. The small internal detector
was selected for this milestone to preserve the existing bounded-read and source-free
reporting path without an unvalidated external-process/output surface.

## Dependencies, privacy and resources

No dependencies introduced; pyproject.toml and uv.lock are unchanged. Existing
NetworkX and prepared parser packages remain. New code uses only the standard library.
No runtime downloads, telemetry, paid services or network requests are used. Generic
public documentation research did not transmit repository source or scan results.

Existing no-follow descriptor-relative discovery, ignore policy, bounded reads,
report-output exclusivity/0600 permissions, safe diagnostics and escaping remain.
Generated reports and future records are ignored by existing .gitignore rules.
Native Tree-sitter parsing/extraction now runs in a short-lived trusted process:
one-second parser timeout, three CPU seconds, five-second parent wait, core dumps
disabled and native stdout/stderr discarded. Crash/timeout/resource failures are disclosed per
file; this contains rather than fixes the previously observed native callback bug.
The callback route remains unused. POSIX single-threaded CLI uses fork; other modes
use spawn but are not independently validated across platforms. No hard memory cap.
Python/JSON/TOML/SQL are not process-isolated. Source tree limits remain 200000 nodes
and depth 256; retained entities 50000; imports/calls/requests 100000. HTTP matching
is capped at 1000000 comparisons with diagnostics and unresolved skipped matches.
No worker pool, cache, incremental scan, Git acquisition or target execution.

Unavailable sub-capabilities, disabled rules, unreadable/failed files and coverage
limitations remain in Not Reviewed Portions of the Code. Per-file/rule/category
coverage is partial and does not imply semantic safety. Unknown counts stay unknown;
excluded directory contents are not read to invent repository-wide denominators.

## Validation and package results

`uv run pytest -q`: **326 passed in 3.94 seconds**, zero failures. Tests include
positive/negative/disabled patterns, malicious/malformed text, credential withholding,
unsupported-language disclosure, native abnormal exit and deadline containment,
shadowed names, config cycles, JSONC string preservation, workspace boundaries,
ambiguous exports, call bindings and route method/parameter ambiguity.

`uv build --offline` produced source distribution and wheel successfully under
/private/tmp/argus-m4-reviewed-dist. A fresh uv environment under
/private/tmp/argus-m4-reviewed-install installed the wheel and all ten existing
runtime dependencies offline from cache. Installed argus --version returned 0.1.0;
its CLI scanned the clean full-stack fixture successfully with 22 files, zero findings
and honest partial status. The fresh installed package also performed the complete
seven-fixture evaluation: 8 detected, 3 missed, 1 partially evaluated and 10 outside
scope; all manifest hashes unchanged/matching and all six candidate credential
literals withheld. Details and unexpected-finding adjudication are in
[the evaluation record](milestone-4-evaluation.md). Build/install operations prepared
only Argus dependencies, never target dependencies. Tests measure this macOS/Python
configuration, not all platforms.

## Files and review boundary

Modified backend components: analysis/adapters.py, extraction.py, pipeline.py,
resolution.py, rules.py; recognition.py and CLI finding terminology. New components:
analysis/risks.py, isolation.py, jsonc.py and relationships.py. Existing typed contracts and import-graph algorithms remain unchanged. The backend
JSON renderer now keeps structurally unsupported languages visible in the prominent
unreviewed summary even when textual credential scanning makes file status partial.

Tests added: test_risk_rules.py, test_resolution_m4.py and test_relationships_m4.py.
Existing parsing/rule/inventory/packaging tests now assert the new availability rather
than Milestone 3's unavailable categories; prior detection assertions remain.
Resolution test helper filters import edges now that call/HTTP edges also exist.
Tools updated: central documentation generator and independent laboratory evaluator.
Documentation updated: README, language matrix, configuration, limitations, data
contract notes, catalog/index and generated category catalogs; new milestone/evaluation
records. No UI or frontend assets changed. No commits or pushes performed.

Recommended next step is owner review of this tested subset and explicit prioritization
of protected credential policy/persistence versus deeper framework/AI analysis. Do not
start another milestone or commit before review.

## Disclaimer

Argus is a software architecture analysis and decision-support tool. It does not certify or guarantee software safety, security, correctness, reliability, regulatory compliance, or AI alignment. Findings are derived from static analysis, observable source-code relationships, configurable rules, and heuristic indicators. Analysis may produce false positives, false negatives, incomplete results, or inaccurate architectural inferences. The absence of findings does not establish the absence of vulnerabilities, particularly where portions of the codebase have not been reviewed. Argus is intended to complement, not replace, professional security assessments, runtime analysis, comprehensive software testing, code review, and qualified human engineering judgment.
