# Milestone 6.3B contract revision: 1.5.0

Semantic observations use contract `1.1.0`. Additive fields preserve `context_id`,
`callsite_id`, qualified `call_path_ids`, `formal_id`, `actual_id`, `result_id`,
`value_id`, `origin_value_id`, `argument_position`, `binding_kind`,
`candidate_target_ids`, `fact_state` and `exit_channels`. Null means unavailable,
not zero or proof of absence. Existing bound/argument/return kinds also carry
unknown facts; inspect certainty and nullable upper_bound. Unknown cardinality
never establishes infinite execution.

New kinds: `assignment_fact`, `receiver_resolution`, `loop_domain`,
`incomplete_analysis`. Invocation projection uses the typed `invocation` relationship
kind and includes unresolved syntax. Relationship additions are `callsite_id`,
`context_ids`, and `candidate_target_ids`. Candidates reference existing graph
nodes; ambiguous alternatives have no definite target. An aggregate call-path
observation references the relationship whose context_ids identify its scoped
static resolutions. It does not claim universal runtime dispatch.

Symbols now use module/kind/line/Unicode-column identity instead of lexical names.
Renaming at a fixed location preserves symbol IDs; moving definitions can change
them. Existing symbol and derived relationship/structural-finding IDs therefore
migrate in this release. This is not an implemented cross-version comparison or
remediation engine. Pattern finding IDs keep their existing generation policy.

Callsites use module, lexical owner and source coordinates; formal IDs use function
and parameter position; actual IDs use callsite, parameter position, binding kind
and call path; result IDs use function and call path. Value identities derive from
source locations, never literal or credential contents. External function entries
have distinct unknown-entry path IDs and no fabricated caller callsite. Legacy
`context_lines` is same-file only; use qualified callsite/path IDs and relationship
and value evidence locations for cross-file provenance. Constructor transfer nodes
are private implementation details and never create invented callee syntax.

The private contracts and evidence flow are documented in
[Milestone 6.3B](milestone-6.3B.md). No raw syntax, source strings, credential values,
or value-derived credential fingerprints are added to the public interface.

---

# Milestone 5 additive contract revision: 1.3.0

`Finding.assessment` is optional for compatibility. It contains initial_pattern,
mitigation_state, supporting/contradictory evidence IDs, typed safeguards with
applicability and reasons, call-path/unresolved relationship IDs, assumptions,
remaining_risk, limitations and an optional evidence-backed severity_adjustment.
Remediation and validation remain Finding.corrective_actions/acceptance_criteria.
ScanResult validates assessment evidence/relationship references. No raw source,
literals, AST/CST or semantic internal graphs are serialized.

Five states: mitigation_established_within_analyzed_scope, partially_mitigated,
safeguard_observed_applicability_unverified, no_applicable_safeguard_detected,
undetermined. Established mitigation is limited to analyzed scope, never a safety
assertion; unresolved/incomplete paths remain disclosed. Severity and confidence
remain separate. Uncertain mitigation cannot lower severity or remove observations.

Five independent capability members declare control flow, local data flow,
function-operation summaries, collection bounds and source-to-sink tracking.
`not_reviewed_portions_of_the_code.semantic_analysis_gaps` holds incomplete semantic
diagnostics including budgets and unsupported controls even when no findings exist.
Existing denominators and partial-review meanings remain unchanged. Internal
language-agnostic Value/Site/FlowNode/SemanticFacts contracts are not report fields.
See [Milestone 5](milestone-5.md) for methodology, examples, assumptions and tests.
Older milestone text below is historical where superseded.

> Milestone 4 uses the existing 1.2.0 typed fields without schema changes.
> Findings now include security/credential/reliability/AI/cost pattern indicators,
> additional categories and ResourceImpact. CALL/HTTP relationships and endpoint nodes
> retain observed declaration evidence and inferred binding/matching provenance.
> Unknown/ambiguous targets have no invented IDs. Credential candidate findings do not
> populate the lifecycle `credentials` collection (still null); history and remediation
> storage are unavailable. See [current scope](milestone-4.md). Older text below is historical.

> Milestone 3 update: parsing/extraction, conservative resolution, NetworkX graph
> analysis and structural rules are now implemented in `src/argus/analysis/`.
> See [Milestone 3](milestone-3.md), [language capabilities](language-support.md),
> [rules](rules/index.md) and [limitations](limitations.md) for current behavior.
> Historical milestone descriptions below describe their original scope.
> JSON schema is now 1.2.0: existing records represent analysis data; the writer adds
> per-language/per-capability coverage counts (including configuration formats);
> no parser or NetworkX objects cross the reporting boundary.

# Argus JSON contract 1.2.0

Milestone 3 adds `coverage.language_analysis_coverage`: counts by language, capability
and status over all inventoried files including configurations, exclusions and failures.
The existing `coverage.by_language` remains the source-file ratio projection.
Modules, symbols, relationships, metrics, evidence and findings use the existing
typed fields. Unknown metrics remain null with reasons. No raw parser/library objects
are serialized. The pre-Milestone-3 scope descriptions below are historical.

## Contract conventions

The typed definitions in `src/argus/models/` are the authoritative executable
in-process contract. `JsonReportWriter` projects `ScanResult` to JSON. There is
no JSON ingestion API or generated JSON Schema document in this milestone.
Unknown JSON fields are not accepted through a decoder because none exists yet.
Major versions indicate breaking contract changes; additions require explicit
schema-version review. Consumers must reject unsupported major versions and
preserve unknown optional fields when forwarding reports.

All records are frozen, keyword-only dataclasses with validated runtime types and
immutable tuple collections. No automatic coercion: enum strings must be converted
explicitly to enums by future input handlers; booleans are not accepted as counts.
Floats must be finite. Validation errors do not interpolate submitted values.
Constructors validate invariants; protocols are structural typing contracts, not
runtime guarantees about an implementation's safety or behavior.

Identifiers must be nonempty, opaque, deterministic producer-assigned strings.
Finding IDs should survive unrelated edits and remain independent of line shifts,
timestamps, severity, and secret values. Rule-version changes and renamed entities
require an explicit future reconciliation policy; this milestone supplies no ID
generation/matching engine. File/module/symbol/graph namespaces should be distinct,
with corresponding graph nodes referencing the same entity identity deliberately.
The result validates unique IDs within each collection and referential integrity.

Paths are canonical repository-relative POSIX strings: no absolute, parent traversal,
backslashes, drive prefixes, controls, redundant separators, or `.` segments. These
are lexical checks, not filesystem containment checks. Future readers must enforce
containment and no-follow semantics when opening files. Locations use one-based
Unicode code-point columns and lines, exclusive end coordinates, and paired optional
end positions. Adapters must translate AST/CST byte offsets explicitly.

## Shared records

| Record | Required information and important optional fields |
| --- | --- |
| SourceFile | Opaque ID, relative path, source/configuration/other/unknown kind; recognized language/format and physical line count may be unknown |
| Module | ID, file reference, qualified name, language; names need not be globally unique |
| Symbol | ID, module reference, name, extensible kind, source location, optional parent symbol |
| Evidence | ID, safe observation, producer/version, observed/inferred/heuristic provenance, confidence, locations, limitations; no source excerpts |
| GraphNode | ID, extensible kind, safe label, optional language/file/layer, evidence references, limitations; layer assignment requires evidence |
| Relationship | ID, source and optional target, kind, language, provenance, confidence, resolution, evidence, target reference, limitations, optional dependency phase |
| Finding | Stable ID, rule ID/version, primary and optional additional categories, severity/confidence/provenance, title, explanation, remediation summary, actions, acceptance criteria, evidence, affected entities, locations, relationships, limitations, remediation status/evidence |
| ResourceImpact | Consumption mechanism, potential financial consequences, explicit assumptions/limitations, fixed `potential_static_exposure` basis |
| Metric | Name, definition, entity/graph scope ID, projection definition, algorithm version, finite value or unavailable reason, limitations |
| Cycle | Member node and relationship IDs, graph projection; represents an asserted cycle, not an implementation of detection |
| Diagnostic | Safe code/stage/message and optional location; risk findings are separate |
| FindingComparison | Stable finding ID, prior/current scan IDs, comparison status, reason, current file/rule status, verification evidence |

Relationship kinds include module imports, invocations, HTTP requests, database
interactions, external services, LLM providers, agent tools, configuration,
infrastructure, and containment. `extension` plus a namespaced `extension_kind`
accommodates additional kinds. Direction is always source → target. Resolution is
resolved/external/unresolved/ambiguous; unresolved/ambiguous relationships cannot
invent target IDs. Multiple distinct edges between entities are preserved.
Observing import/call syntax does not establish runtime reachability or a uniquely
resolved service. Evidence and limitations must explain each inference.

Severity: info/low/medium/high/critical. Confidence: low/medium/high, not numerical
probability. Categories: architecture, security, credentials, maintainability,
dependency health, reliability, performance/scalability, AI-specific, cost efficiency.
Each finding is serialized once, with additional categories as references. Cost
findings require `ResourceImpact`; actions and acceptance criteria are required for
all findings. No aggregate safety score or actual expense estimate is defined.

## Capability and coverage records

Every adapter independently declares each capability with availability, reason,
and limitations, plus adapter/parser/grammar versions. Every file coverage entry
accounts for each capability even if that capability was outside requested scope:

- Syntax parsing, symbols, structural analysis.
- Dependency extraction and dependency resolution.
- Complexity, architectural rules, security rules.
- Credential detection, framework analysis, AI-specific analysis, configuration analysis.

File status is completed/partial/unsupported/excluded/failed/disabled/unclassified.
Completed means completed within `scope.requested_capabilities` only. It requires
those capabilities to be marked completed and does not imply that all categories
were evaluated. The Not Reviewed section still lists every other capability gap.
Partial requires evidence that some capability ran. Unsupported means no applicable
capability is implemented/enabled. Recognition and capability availability are
separate. Unclassified means the language/format could not be identified.

`Coverage` contains exactly one `FileCoverage` per inventoried file, one explicit
`CategoryCoverage` per category, rule coverage entries, inventory gaps, and limitations.
Category completion is scoped to listed rule IDs, never all conceivable risks.
Rule/capability units include explicit eligible/evaluated counts where known; either
may be null. Completed with zero findings differs from unsupported or disabled.
The orchestrator must truthfully supply performed-work records; model validation
cannot independently prove analysis occurred.

`InventoryGap` represents an excluded or unreadable scope whose contents were not
safely enumerated. Relative path and file count may be withheld/unknown. Exclusions
are not silently omitted or counted as reviewed. Individual known excluded files
have file coverage records; unenumerated directories have gaps. A nonexistent
scanner does not currently collect any of these observations.

## Metric denominators

`coverage.source_metrics` and `coverage.by_language` provide:

| Metric | Definition |
| --- | --- |
| Total discovered source files | Number of inventoried records classified as source, including known excluded source files; configuration/other/unknown kinds are separate file records |
| Completed/partial/unsupported/excluded/failed/disabled/unclassified source files | Disjoint source-file counts by file status; successfully analyzed source files are the completed count |
| File coverage | Completed source files / all inventoried source files, including unsupported and known excluded files |
| Line coverage | Reviewed physical source lines / total physical lines of all inventoried source files, only when every contributing count is reliable |
| Per-language coverage | Same source-file numerator/denominator filtered to the recognized language; unknown-language source records remain in overall counts |
| Rule coverage | Evaluated units / eligible units for that rule and stated unit, only when both are known and denominator is positive |
| Category coverage | Explicit status/reason and evaluated rule IDs, not a fabricated percentage across undefined possible rules |

Source statuses and total counts are nested under `source_metrics.by_status` and
`total_discovered_source_files`. Ratios include numerator, denominator, definition,
fraction, and unavailable reason. No denominator or a zero denominator yields null
fraction, not zero. If any line count is unavailable, the aggregate line numerator,
denominator, and fraction are null, rather than a misleading partial percentage.
Reviewed physical lines mean processed within declared scope, not semantically
understood lines. They include blanks/comments; semantic LOC is not claimed.

Inventory gaps set `inventory_complete` false. Ratios still describe inventoried
files only; repository-wide totals and coverage are unknown. Unclassified files
may be source and further limit those denominators. Unsupported configuration
formats have separate group counts/paths in Not Reviewed, not invented source LOC.

## JSON envelope and Not Reviewed

The envelope includes schema/tool versions, scope, status, file/module/symbol
inventories, coverage, evidence, findings, graph, credentials, diagnostics,
limitations, exact disclaimer, and evidence-handling policy. Scan status is
completed/partial/failed. A completed scan cannot contain incomplete file coverage
or inventory gaps, but can still have unevaluated categories outside declared scope.
The future orchestrator must disclose category-level partial analysis prominently.

`not_reviewed_portions_of_the_code.title` is exactly
**Not Reviewed Portions of the Code** and is always emitted, including zero findings.
Its structured fields provide:

- `portions`: file IDs, privacy-controlled paths, language/kind, status/reason,
  known physical/unreviewed lines, and individual unavailable capabilities.
- `unsupported_languages_and_formats`: language/format/kind groups, file counts,
  privacy-controlled paths, and unreviewed physical lines or null.
- `inventory_gaps`: exclusions/failures without invented contents/counts.
- `categories_not_fully_evaluated` and `rules_not_fully_evaluated` with reasons.
- `implications`: graph and cross-language incompleteness, unavailable repository-wide
  denominators, coverage limits, and absence-of-findings caveats.

Unknown metrics remain null. Report text is not proof of safety. Data fields retain
meaningful architectural identities, relationships, layers and evidence, cycle
members, metrics/projections, findings, and unsupported components for a future
manually developed Explorer; they contain no colors, coordinates, styles, or layouts.

## Credentials and remediation

`credentials: null` means unavailable/not evaluated; an empty array must only be
used when the declared credential scope was actually evaluated without exposures.
Capability and category coverage must corroborate that state. No credential scanning
or verification is implemented. Fingerprints are omitted from JSON report projections.

`CredentialPolicy` separates tracked files, explicitly authorized ignored paths,
optional accessible history, and credential-specific exclusions from architecture
scope. `CredentialExposure` retains exposure context (local storage versus potential
or observed exposure), scoped presence, protected HMAC fingerprint, evidence, events,
unresolved/resolved assertion and resolution evidence. A fixed `[REDACTED]` identifier
avoids leaking credential prefixes/suffixes. Matching fingerprints enables future
reuse tracking under the same protected local key; key rotation needs migration.

Remediation actions are removal/replacement/rotation/revocation. Events record
timezone-aware time, scope, evidence, and user-attested/independently verified
assurance. No action silently changes presence or resolution. A prior exposure
cannot be marked resolved based on removal/replacement/rotation alone. Independent
verification means only the evidence's documented scope, never inferred provider
authentication. Network authentication with discovered secrets is forbidden.

Finding remediation is open/in-progress/user-attested/verified/unverifiable, with
evidence for attestation/verification. Comparison is new/persistent/resolved/
unverifiable. The model rejects resolved comparisons where the current file or
rule is incomplete, unsupported, excluded, disabled, failed, or unclassified.
Future comparison must additionally check scope and rule compatibility; no
comparison algorithm or automatic state transition is implemented here.

## Security and serialization

JSON output uses sorted keys, fixed formatting, ASCII escapes, and rejects nonfinite
numbers. Tuple order is meaningful and producers must supply deterministic ordering.
Serialization accepts contract records, not arbitrary objects or dictionaries.
No parser AST/CST, NetworkX object, raw credential, source buffer, or local key is
part of a report. Identical supplied records produce identical JSON; no runtime
timestamp is injected. This is a one-way report projection, not lossless persistence.

Source evidence is untrusted data. Corrective actions/acceptance criteria must come
from trusted installed Argus rules, never automatically copied instructions from
source. JSON escaping is not secret detection. Producer text must already be safe;
arbitrary text cannot be certified secret-free by these foundational models.
`ReportPrivacy(disclose_relative_paths=False)` withholds dedicated path fields;
opaque IDs and safe free text remain producer responsibilities. Future Markdown
must use explicit evidence boundaries and escape delimiter attempts. Report
generation never sends data externally, executes actions, or writes target files.

## Multiple roots, scalable execution, hierarchy, and targeted exports

`ScanResult.scan_id` is an explicit opaque identifier for provenance and future
comparisons. `ScanScope.roots` contains unique authorized root descriptors; file and
location identity is `(root_id, path)`, allowing matching relative paths in different
services. Inventory gaps also identify roots. Default root ID is `root`. Actual
authorization/containment still belongs to future input handling. Root kinds are local
directory, prepared archive, or authorized Git checkout; non-directory roots require
a preparation reference. They never contain absolute host paths or acquisition URLs.

`ResourceBudget` declares positive file-byte, memory, worker, optional file/graph, and
archive/extracted-byte/member limits. Null scope budget means no enforcement information
was supplied, not unlimited verified capacity. No enforcement is implemented.
Future skipped records use explicit `reason_code` values such as
`resource_limit.max_file_bytes`, `resource_limit.max_files`, `cancelled`, `unreadable`,
or `parse_error`, with human-readable reasons. Not Reviewed retains these fields,
inventory gaps, execution cancellation/freshness, and limitations.

`ExecutionMetadata` distinguishes fresh/cached/mixed processing, incremental baseline,
origin-scan/entity/analysis-signature/invalidation provenance, cancellation and limitations.
Reuse cannot be declared fresh; non-fresh reuse requires provenance. Incremental work
requires a baseline. No cache, incremental scanner, or comparison is implemented.
An incremental result may be fresh if all supplied results were recomputed, but must
retain its incremental mode/baseline. Completion is a separate coverage assertion;
cached completion never means complete *fresh* analysis. `ProgressEvent` provides
phase, completed units, optional total, and unit; unknown progress denominator remains
unknown. `ProgressSink` and `CancellationToken` supply interfaces, not runtime scheduling.

`GraphNode.parent_id` and `grouping_provenance` support extensible architectural levels:
system/application/service/package/directory/module/class/function/symbol. Parents
must exist; grouping needs evidence and cannot be self-parented. Full hierarchy-cycle
validation is deferred to the NetworkX implementation. `RiskSummary` contains node,
finding references, descendant-inclusion scope, coverage status, and limitations.
Aggregate `Metric` records use explicit component scope and projection definitions;
no aggregate safety score or rendering coordinates exist.

`RemediationExportFilter` declares severity, category, finding IDs, languages,
directories, services, components, roots, maximum findings and output bytes. Selection,
pagination, truncation metadata, Markdown escaping, and progressive graph querying
remain future implementations. No filtering is performed by `JsonReportWriter`.
Large graph serialization currently materializes structured data and JSON in memory;
this foundational milestone makes no large-repository throughput guarantees.

## Milestone 2 additive revision (1.1.0)

The same versioned JSON envelope now accepts optional `SourceFile.size_bytes`,
`recognition_basis`, and `language_candidates`. A null language with nonempty
candidates records ambiguity, not supported analysis. Null physical lines remain
unavailable. UTF-8 text is counted using CRLF/CR/LF physical terminators, including
blank and comment lines; a final unterminated line counts once.

Optional `ScanResult.inventory` independently describes inventory status,
inventoried files, encountered entries, inspected bytes, repository file count
(null when directories/scopes were pruned), traversal limits and limitations.
The JSON projection adds all-file counts by language/format and kind, measurable
physical lines and number of files whose line counts are unavailable. Measurable
line sums are explicitly partial observations, never a repository-wide denominator.
Existing `coverage.by_language` continues to describe **source files only**.

All recognized files have unsupported analysis coverage; unknown/ambiguous files
are unclassified; read/resource failures are failed. No file receives completed
analysis coverage. `inventory.status=completed` is independent of the scan's
`status=partial`. Every category and every per-file analysis capability remains
unsupported. The empty rule list means no installed/evaluated rules, not a passed
rule set. No dependency graph, credential observations or risk findings are claimed.

Graph nodes represent observed roots/directories/files, manifest-inferred packages
and applications, and technology evidence grouped under the manifest. Grouping has
explicit observed/inferred provenance and evidence. No calls/import/service edges
are invented. Application suggestions come only from declared Node start/dev scripts
or Python project scripts, without executing those scripts. These are candidates,
not confirmed deployed services. Stable opaque IDs derive from relative identities,
not host paths, timestamps or source contents. Future multi-root discovery remains
unimplemented; the current authorized root ID is `root`.

`ResourceBudget.max_file_bytes`/`max_files` are enforced. Inventory separately records
max entries/depth/total inspected bytes/ignore bytes. One worker is used; the declared
memory budget is informational and **not enforced**, as stated in limitations.
Exclusion pattern values supplied by users are withheld from reports (indexed
policy references), because patterns may contain secrets. Defaults are explicit.
Diagnostics contain fixed producer text and safe paths, never raw exceptions.
Path masking preserves hierarchy using deterministic hashed components, including
reserved redaction-like names, and does not constitute credential tracking.

Earlier descriptions of discovery as future work apply to the Milestone 1
foundation only; Milestone 2 behavior above supersedes those statements. Model-only
callers may omit the optional inventory record. Consumers must tolerate these
additive 1.1 fields while continuing to reject unsupported major versions.

Milestone 5.1 adds `unavailable_contextual_capabilities` to JSON's
`not_reviewed_portions_of_the_code`, alongside actual `semantic_analysis_gaps`.
Context evidence locations may include bounded source-free module/line value origins.
Internal sanitized flow IR is never part of the report contract. See
[Milestone 5.1](milestone-5.1.md) for provenance truncation and partial coverage.

## Schema 1.4.0 compatibility (Milestone 6.1)

Compared with 1.3.0, reports add `semantic_observations` and
`credential_candidates` arrays, independent of `findings`. Empty arrays mean no
observations emitted in the evaluated scope, never complete semantic coverage.
Each semantic record uses contract version `1.0.0`, a typed kind and certainty
(directly observed, statically established, possible inference, unknown/unresolved),
file/scope identities, evidence IDs, invocation line context, assumptions and
limitations. Known SDK operations carry a trusted `operation_id`; timeout records
carry a typed `timeout_state`. Optional upper bounds describe collection/iteration
sizes, never token consumption or operational cost. Locations live in referenced
evidence, including bounded source-free value-flow origins. No query text, credential
values, repository-derived instructions or host paths are added. Root identity is
obtained through `file_id`. Consumers must preserve unknown enum values when reading
future schema versions and prominently render coverage gaps.

Credential candidate records distinguish recognized patterns, plausible assignments
and obvious placeholders, with a documentation-context flag and unverified validity.
Non-placeholder assignments of 8–11 characters are classified as uncertain candidates;
longer non-pattern assignments are plausible, not verified credentials.
These records are not lifecycle exposures: `credentials` remains unavailable.

Assessments add `safeguard_analysis_unsupported` and `safeguard_analysis_incomplete`.
`no_applicable_safeguard_detected` means only the evaluated narrow scope; it is never
an authorization/security assurance. Initial observations remain separate. No severity
reductions are implemented in this milestone.

Diagnostics add classification, occurrence count and `affected_locations`.
`location` is the first sorted location for compatibility. Grouping uses exact
code/stage/message equality and retains every distinct affected location. Consumers
must use the location array rather than assuming one diagnostic means one file.
Known resource exhaustion is distinct from malformed input. Native worker deaths
with an unknown cause remain failures, not guessed resource exhaustion.
