> Milestone 3 update: parsing/extraction, conservative resolution, NetworkX graph
> analysis and structural rules are now implemented in `src/argus/analysis/`.
> See [Milestone 3](milestone-3.md), [language capabilities](language-support.md),
> [rules](rules/index.md) and [limitations](limitations.md) for current behavior.
> Historical milestone descriptions below describe their original scope.
> JSON schema is now 1.2.0: existing records represent analysis data; the writer adds
> per-language/per-capability coverage counts (including configuration formats);
> no parser or NetworkX objects cross the reporting boundary.

# Backend architecture — foundational milestone

## Implemented scope

Argus supplies immutable shared records, strict validation, component protocols,
versioned JSON serialization, and a functional offline inventory CLI. Milestone 2
adds `cli.py` (composition and safe output), `config.py` (bounded TOML input),
`discovery.py` (descriptor-relative traversal and Git ignore handling),
`recognition.py` (language registry), `technologies.py` (manifest observations),
`privacy.py` (defensive path masking), and `scanner.py` (inventory orchestration).
These modules never execute/import target code or perform network operations.
Analysis adapters, risk rules, graph algorithms, credential/history scanning,
persistence, Markdown/HTML renderers, and graphical interfaces remain unimplemented.

The CLI uses the existing ScanResult/coverage/graph contracts. Schema 1.1.0 adds
optional file recognition/size fields and an independent inventory summary, without
changing analysis completion semantics. Parent references model containment only;
no established graph algorithms are reimplemented. NetworkX remains deferred until
an authorized graph algorithm milestone. Parsing boundaries and the planned shared
Tree-sitter service remain unchanged. See [Milestone 2](milestone-2.md) for enforced
limits, recognition scope, output safety and known limitations.

Python >=3.12 is supported. The development interpreter is pinned to the 3.12
minor series, without limiting consumers to that minor version. Use `uv sync`,
`uv run pytest`, and `uv build`. The lockfile records the resolved environment.
Installation can retrieve free tooling; future scans must operate offline.

## Boundaries

| Boundary | Contract | Future implementation responsibility |
| --- | --- | --- |
| Recognition | `SourceFile.language` and `kind` | Classify recognizable files independently of installed adapters; report unclassified files |
| Syntax | `SyntaxParser`, `ParsedUnit` | Native AST or prepared Tree-sitter grammar; parser objects never serialized |
| Semantic extraction | `SemanticExtractor`, `Extraction` | Normalize symbols, modules, relationships, locations, and evidence |
| Resolution | `DependencyResolver`, `ResolutionResult` | Resolve static references using repository indices; preserve ambiguity |
| Adapter | `LanguageAdapter`, `AdapterDescriptor` | Compose reusable parser/extractor/resolver components; declare each capability |
| Rules | `AnalysisRule`, `RuleDescriptor`, `RuleSettings`, `RuleResult` | Evaluate supported facts, emit findings/evidence and explicit rule coverage |
| Graph | `GraphBackend`, `Graph` | NetworkX-backed algorithms behind Argus-owned types |
| Reports | `ReportWriter`, `ReportFormat` | Deterministic local projections preserving coverage, evidence boundaries, and disclaimer |
| Persistence | `RemediationStore` | Protected local fingerprints and append-only remediation history; preserve unresolved records |

`models/` depends only on the standard library. Protocols depend on models.
Reporting depends on those contracts; neither models nor interfaces import a
specific parser or NetworkX. A future application composition root supplies
trusted installed components to a language-agnostic orchestrator. It must never
load plugins, execute scripts, import modules, or install dependencies from a target.

Rules receive an immutable `ScanResult` snapshot as their current context and return
new findings/evidence/coverage. Snapshot completion is scoped work, not a safety
verdict. Future orchestration must check required capabilities before evaluating
rules and merge results without changing earlier observations.

## Multilingual objective and parser evaluation

Broad multilingual analysis is central to auditing AI-generated applications,
regardless of whether Codex, Claude Code, Gemini, or another agent generated them.
The primary release targets are Python, JavaScript, TypeScript, JSX, and TSX.
Next: SQL, HTML, CSS, JSON, YAML, TOML, Bash/shell, and Dockerfile configuration.
Further priorities: Go, Rust, Java, C#, C, C++, Swift, Kotlin, Dart, PHP, Ruby,
and HCL/Terraform. Language identifiers are open strings, not a closed enumeration.
Recognition does not advertise operational analysis support for any of these yet.

| Candidate | Advantages | Constraints and recommendation |
| --- | --- | --- |
| Python native AST | Useful Python semantics and standard-library availability | Grammar follows interpreter; retain for Python-specific extraction |
| Tree-sitter Python bindings | Reusable CST traversal, locations, error recovery, declarative queries | Language grammars/queries still differ; syntax trees alone do not provide name resolution or security analysis |
| Individually packaged Tree-sitter grammars | Explicit release-target dependency set; preinstalled grammars | Verify ABI, grammar versions, licensing, platform wheels, and query compatibility together |
| Tree-sitter Language Pack | Broad grammar inventory and common access API | Current distribution supports first-use downloads; evaluate explicit preparation and guaranteed offline lookup before adoption |

Reference evaluation: [Tree-sitter bindings](https://tree-sitter.github.io/py-tree-sitter/),
[individual Python grammar](https://pypi.org/project/tree-sitter-python/),
[Language Pack](https://github.com/xberg-io/tree-sitter-language-pack), and
[its architecture](https://docs.tree-sitter-language-pack.xberg.io/concepts/architecture/).
These are design evaluations, not installed integrations or compatibility test results.

Recommendation for a later authorized parsing milestone: native Python AST plus a
shared Tree-sitter service with explicitly installed JS/TS/JSX/TSX grammars. Evaluate
Language Pack for broad preparation efficiency without allowing its lazy network
path during scans. Pin tested grammar/query combinations through uv. Check required
assets before analysis; report missing assets as unavailable capabilities. No parser
downloads, external requests, shelling out, or source execution during scans.

Adapters compose common parser services and extraction/query helpers. Extractors
normalize function/class symbols and structural observations; resolvers preserve
language semantics such as type-only, dynamic, conditional, or runtime imports via
relationship fields and evidence/limitations. Embedded/multiple languages can be
represented through multiple modules/symbols and locations in one file. Future
discovery must account for embedded-language capability gaps rather than assigning
whole-file semantic completeness based on the primary language.

Framework-specific rules remain separate from syntax infrastructure. Identification
of React, Next.js, FastAPI, Flask, Express, Supabase, Firebase, PostgreSQL,
OpenAI/Anthropic/Google Gen AI SDKs, LangChain, or LangGraph requires source or
configuration evidence. Framework entities may use graph nodes with evidence and
typed relationships; framework rules must declare prerequisites and limitations.

## Graph decisions

Use NetworkX for SCCs, circular dependencies, centrality, traversal, and reachability
or blast radius. No graph implementation or NetworkX runtime dependency is introduced
in this contracts-only milestone. Add it with its first authorized implementation.
[NetworkX installation requirements](https://networkx.org/documentation/stable/install.html)
include Python 3.12; actual pinned-version behavior remains to be tested then.
No NumPy, SciPy, or visualization extras are needed for the proposed initial algorithms.

Relationships are directed from source to target. Unresolved references have no
invented target node; external/unsupported entities may have explicitly identified
nodes. Parallel relationships remain distinct. Metric projections must document
included edge types, observed/inferred treatment, traversal direction, weighting,
and unresolved/external-node treatment. Reverse dependency reachability is a
possible blast-radius indicator, not proof that all reachable components fail.

## Reporting, remediation, and cost

JSON is implemented as a projection of supplied records, not as a scanning service.
Interactive HTML is a future owner-controlled presentation responsibility. Future
AI-agent Markdown must be generated from static trusted templates and rule-authored
corrective actions/acceptance criteria, with clearly delimited untrusted evidence.
No external AI API, report transmission, automatic remediation execution, or target
modification is allowed. All formats must retain the coverage disclosures and exact
disclaimer in `models/scan.py`. Declaring `ReportFormat` values does not implement them.

Findings have stable producer-assigned identifiers, multiple categories without
duplication, architectural relationship references, and remediation status. Comparison
assertions cannot label a finding resolved unless the current file and rule were
reviewed and resolution evidence exists. A future comparator must also validate
equivalent rule version, scope, exclusions, capability availability, and identity.
It must classify disappearance under coverage loss as unverifiable. Comparison
execution and persistence are not implemented.

Cost efficiency is a dedicated category. `ResourceImpact` describes a potential
consumption mechanism and potential financial consequences. Future rules can cover
LLM calls in loops, unbounded agents/retries/context, missing token limits/quotas,
redundant requests/embeddings, model selection, queries in loops, missing pagination,
polling, storage/upload limits, realtime subscriptions, background jobs, autoscaling,
logging, duplicate schedules, cleanup, and missing resource safeguards.
Static findings cannot assert actual expenses or guaranteed savings. A future local
estimator needs a separate hypothetical-estimate contract with explicit supplied
pricing, usage assumptions, units, currency, time window, and uncertainty; it must
not fetch billing data. No estimator or cost rules are present.

## Credential and privacy boundary

Architecture and credential exclusions are deliberately separate. Future architecture
discovery respects repository-local ignores and skips symlinks; excluded/pruned scopes
are disclosed without enumerating sensitive contents merely to obtain counts.
Future credential scope includes tracked source/configuration, explicitly authorized
ignored local configuration, and optional accessible history. Proper local storage
is not automatically exposure. Shared protected fingerprints permit future reuse
identification; raw secrets and fingerprint keys have no model fields.

Use HMAC-SHA256 with a protected local random key and opaque key ID when fingerprinting
is implemented. Key storage, filesystem permissions, migration, encryption requirements,
and reuse matching are not implemented. JSON reports omit fingerprint records.
Removal/replacement/rotation/revocation are independent events with scoped evidence
and attested/verified assurance. Absence from the current scope never proves revocation.
The model conservatively requires a revocation event and explicit evidence to mark
prior exposure resolved; that assertion is not automatically independently verified.

Records exclude raw source bytes and excerpts. Producers must emit safe descriptions,
not arbitrary source strings or raw parser exceptions, into textual fields. JSON
escaping prevents syntax breakage, not secret discovery. This milestone does not
implement a secret detector or general-purpose sanitizer; callers must not feed
secret-bearing text into summaries, IDs, labels, settings, or diagnostics.
The path privacy option withholds dedicated path fields only; producers must use
opaque IDs and avoid copying paths into free text. Reports remain confidential.
Default Git ignore rules protect conventional report/state locations, not arbitrary
paths chosen by callers. No scanner writes to the analyzed directory.

## Incremental next steps

1. Authorize safe inventory/discovery and CLI configuration: broad language/format
   recognition, exclusions, local ignore semantics, bounded reads, symlink safety,
   explicit coverage gaps, JSON scan output, and synthetic fixtures.
2. Authorize reusable parsing/extraction: native Python AST and shared Tree-sitter
   preparation design, then tested JS/TS/JSX/TSX capabilities. Maintain per-capability
   coverage; never equate parser availability with analysis completion.
3. Authorize static resolution, NetworkX backend, and evidence-backed architectural
   rules across the primary release targets. Add deterministic agent Markdown.
4. Incrementally add priority configuration/language and framework capabilities,
   security/AI/cost rules, then separately authorized credential/history analysis
   and protected remediation persistence.

Each milestone requires its relevant tests and user review. No graphical work,
HTML templates, visualization logic, frontend assets, or camera interaction is
authorized. No commits or pushes have been made by this milestone.

## Large-codebase strategy

Primary input remains a recursively discovered local root, without individual-file
uploads. `RootScope` and root-qualified file/location identities permit future
monorepos and separately located services. Prepared archives and explicitly authorized
Git checkouts have preparation references, not automatic acquisition behavior.
Future ZIP preparation must reject traversal, symlink escapes, special files, and
decompression bombs; enforce archive/member/extracted-byte and nesting limits in an
isolated staging area before authorizing the extracted root. Git acquisition is a
separately authorized operation before offline scanning, with no target hooks/scripts.

`ResourceBudget`, `ProgressEvent`, `ProgressSink`, `CancellationToken`, cache provenance,
execution freshness, and partial-result models define boundaries only. Future readers
must process bounded file contents incrementally and release parser/source buffers
after extraction. Workers must have explicit bounds, safe cancellation checkpoints,
and deterministic merge order. Memory budgets may require process isolation and
platform-specific enforcement; record unsupported enforcement rather than promising it.
The current JSON writer materializes structured results/output in memory, never reads
raw files, and is not a streaming report implementation. Graph and report scaling
must be measured before claiming large-repository operational support.

Future local content caches must key on content plus root identity, language/grammar,
query/extractor/resolver versions, configuration/exclusions, rule versions, and
relevant dependencies. Changed exports/resolution can invalidate dependent components;
graph-wide metrics require projection-wide invalidation, not just changed-file work.
Keep cache data protected like reports and avoid raw credential persistence.
`ExecutionMetadata` makes fresh/cached/mixed, baseline and reuse provenance explicit.
Cancellation requires partial/failed status. Resource-limited files/scopes carry
reason codes and Not Reviewed disclosures; never silently publish an incomplete
inventory as a complete fresh assessment. Algorithms, workers, caches, and invalidation
mechanisms are intentionally deferred.

Graph node kinds are extensible and may identify systems, applications, services,
packages, directories, modules, classes, functions, and symbols. Parent references
require evidence and observed/inferred grouping provenance. `Metric.scope_id` supports
component rollups; `RiskSummary` references findings and records coverage limitations,
not a fabricated safety score. Hierarchy cycle checks and scalable subgraph access
belong to the future NetworkX/backend implementation, not custom algorithms here.
No layout or visualization behavior is included.

`RemediationExportFilter` declares future severity/category/finding/language/directory/
service/component/root selection and output/finding budgets. The future writer must
retain context, coverage, disclaimer, stable ordering, continuation/truncation metadata,
and evidence/instruction separation. It must not silently drop context or treat a
filtered export as comprehensive. Filtering and Markdown generation are not implemented.


## Milestone 5 contextual subset

See [Milestone 5](milestone-5.md) for exact methodology, safeguards, assumptions,
fixed resource budgets, examples, tests and deferred scope. Python adds bounded
structured flow and local function contexts; JavaScript/TypeScript/JSX/TSX add
operation summaries through existing resolved calls. No general framework security,
database-limit enforcement or cross-file value flow. Findings retain observations;
uncertain safeguards cannot suppress them. Budget/unsupported-control diagnostics
appear in **Not Reviewed Portions of the Code**. No semantic completeness claim.

## Corrective semantic release (6.1)

The existing bounded workspace and Python abstract interpreter remain in place.
`analysis/operations.py` centralizes exact constructed SDK operations and output
parameter metadata. Imported symbols alone are not constructed clients. Unresolved
suffix candidates retain possible-inference status. `analysis/observations.py`
projects useful source-free facts into independent typed contracts after workspace
flow, before contextual risk assessment. No finding is manufactured to expose a fact.
`diagnostics.py` groups diagnostic reasons and preserves affected locations.

The 128-module workspace budget remains deterministic by sorted repository-relative
path. Skipped modules retain initial local facts but explicitly disclose unavailable
cross-file interpretation. This is not a repository-wide semantic guarantee.
Dependency-directed scheduling could improve relevance but requires bounded closure,
cycle, shared-global and invalidation policies; component partitioning could lose
cross-component dependencies. Neither is implemented for this release. No caches,
workers beyond existing parser isolation, network acquisition or runtime execution
were added. Semantic observations are capped at 4,096 per file, including relevant
call relationships, with explicit exhaustion diagnostics. Existing source-free CFG,
context, recursion, iteration and module budgets remain applicable.

## Semantic information flow (6.3B)

Extraction owns source-qualified symbol identities. `semantic_contracts.py` defines
private Point/FactState/ExitKind/Outcomes contracts and stamps existing Site records
at production. Workspace transfer retains qualified caller contexts, supported
actual/formal/result bindings and unknown external function entries. Completed
collections drop interpreter-owner references and retain sanitized syntax only.

A single deterministic reconciliation pass attaches computed static receiver/call
evidence to syntax relationships (or retains distinct implicit constructor calls).
NetworkX algorithms and contextual summaries consume that final graph. Contextual
operation expansion appends to the same site collection used by projection; no
second copied observation collection exists. Projection follows contextual fact
production and emits source-free typed records independently of risk findings.
Public models validate evidence, relationship and candidate-target references.
See [contracts](data-contract.md) and [validation](milestone-6.3B.md).
