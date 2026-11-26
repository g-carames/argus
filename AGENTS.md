# ARGUS — Development Instructions

## Project Mission

Argus is a local-first, extensible software architecture intelligence and static risk analysis tool designed to provide an independent architectural check for AI-assisted software development, including vibe coding.

Argus must prioritize explainability, privacy, modularity, deterministic analysis, and meaningful human oversight.

## Mandatory Development Rules

- Never introduce paid services, APIs, subscriptions, or cloud infrastructure.
- Core functionality must operate entirely locally and offline.
- Never transmit analyzed source code, credentials, or analysis results to external services.
- Never execute or modify the target codebase during analysis.
- Never make destructive changes without explicit user approval.
- Never introduce major architectural changes without first explaining the proposed changes and obtaining approval.
- Do not implement functionality outside the current requested development scope.
- Do not claim that unimplemented or untested functionality is operational.
- Do not commit credentials, private data, or confidential analysis reports.

## User Interface Ownership

The graphical user interface is reserved for manual development by the project owner in collaboration with ChatGPT.

Unless explicitly authorized for a specific task:

- Do not design the UI.
- Do not generate dashboard layouts.
- Do not create or modify CSS.
- Do not introduce UI frameworks.
- Do not modify visual components, colors, typography, animations, or graphical interactions.
- Do not create or modify HTML report templates or frontend assets.
- Do not independently make visual design decisions.

Backend reporting must expose clean, documented, structured data that can be consumed by a separately developed interface.

Any UI-related implementation requires explicit user authorization.

## Architecture Requirements

- Python is the primary implementation language.
- Package management and installation must use uv.
- Argus must remain installable as a Python command-line application.
- Maintain a language-agnostic core analysis engine.
- Implement language-specific functionality through modular adapters.
- Begin with Python support.
- Preserve extensibility for JavaScript, TypeScript, JSX, TSX, and additional languages.
- Separate parsing, dependency resolution, analysis rules, graph algorithms, persistence, and reporting.
- Avoid unnecessary dependencies and tightly coupled components.
- Prefer simple, maintainable, independently testable implementations.

## Analysis Requirements

The architecture must accommodate the following analysis categories:

- Architectural integrity
- Security
- Credential exposure and remediation
- Maintainability
- Dependency health
- Reliability
- Performance and scalability indicators
- AI-specific architectural risks

Analysis rules must be independently extensible and configurable.

Each finding should include, where applicable:

- Unique rule identifier
- Analysis category
- Severity
- Detection confidence
- Affected file or component
- Source location
- Supporting evidence
- Explanation of the associated risk
- Recommended remediation
- Known detection limitations

Distinguish confirmed observations from inferred risks and heuristic findings.

Distinguish unsupported analysis from completed analysis that produced no findings.

## Credential Security

- Detect potentially exposed credentials in source code and accessible Git history.
- Never include complete credential values in reports, logs, or persistent analysis records.
- Use appropriately protected fingerprints and masked identifiers for tracking.
- Distinguish credential removal, replacement, rotation, and revocation.
- Never assume that removing or replacing a credential proves that the original credential has been revoked.
- Distinguish user-attested remediation from independently verified remediation.
- Never attempt to authenticate against external services using discovered credentials.
- Preserve unresolved credential findings across scans when persistent tracking is implemented.

## Architecture Explorer Integration

The analysis engine must expose structured data supporting:

- Dependency graphs
- Module relationships
- Architectural layers
- Risk heatmaps
- Dependency direction and type
- Circular dependencies
- Centrality and coupling metrics
- Blast radius analysis
- Language classification
- File-level findings
- Evidence inspection

Graph relationships must distinguish directly observed dependencies from inferred relationships.

Visual properties must ultimately represent meaningful architectural information.

The visualization layer must remain independent of the analysis engine.

## Privacy and Safety

- Do not introduce telemetry or analytics.
- Do not follow symbolic links outside the authorized analysis directory.
- Treat analyzed repositories as untrusted input.
- Do not execute project scripts, import target modules, or install target project dependencies.
- Prevent sensitive source content from being unintentionally exposed through generated reports.
- Escape and sanitize untrusted content included in report outputs.
- Exclude generated reports and local remediation records from Git by default.

## Testing and Validation

- Write automated tests alongside new functionality.
- Include positive and negative detection cases.
- Test malformed and unsupported source files.
- Test edge cases and false-positive scenarios.
- Use synthetic credentials for security testing.
- Run relevant tests before declaring a task complete.
- Report test failures and limitations transparently.
- Never weaken tests simply to obtain passing results.

## Git Workflow

- Maintain an organic, incremental commit history.
- Use descriptive commit messages.
- Keep commits focused on coherent development milestones.
- Do not rewrite Git history without explicit permission.
- Do not push changes without explicit user approval.
- Do not commit unrelated changes.

## Communication

Before implementing a significant feature:

1. Explain the proposed implementation.
2. Identify affected files and components.
3. Identify important architectural decisions.
4. Identify limitations and potential risks.

After implementation:

1. Summarize changes.
2. List files created or modified.
3. Report test results.
4. Disclose unresolved issues and limitations.
5. Recommend the next logical development step.

## Disclaimer

Every generated report, regardless of format, must include this exact disclaimer:

"Argus is a software architecture analysis and decision-support tool. It does not certify or guarantee software safety, security, correctness, reliability, regulatory compliance, or AI alignment. Findings are derived from static analysis, observable source-code relationships, configurable rules, and heuristic indicators. Analysis may produce false positives, false negatives, incomplete results, or inaccurate architectural inferences. The absence of findings does not establish the absence of vulnerabilities, particularly where portions of the codebase have not been reviewed. Argus is intended to complement, not replace, professional security assessments, runtime analysis, comprehensive software testing, code review, and qualified human engineering judgment."

## Development Priorities

1. Installable CLI and modular architecture.
2. Python static analysis.
3. Architectural dependency and risk analysis.
4. Security and credential remediation tracking.
5. AI-specific analysis rules.
6. Structured reporting interface.
7. Manually developed interactive Architecture Explorer.
8. JavaScript and TypeScript support.
9. Testing, documentation, and distribution.
10. Optional local camera-based gesture interaction, only after core functionality and academic submission requirements are satisfied.

## Mandatory Analysis Coverage and Transparency

- Recognition of programming languages and configuration formats must remain independent from analysis capabilities. Never silently omit unsupported or unclassified files or give them passing results.
- Every report must include a prominently identifiable section/field titled **Not Reviewed Portions of the Code**, containing unsupported languages/formats, counts and privacy-safe repository-relative locations, reliably measurable unreviewed physical lines, exclusions, unreadable/unparseable files, unavailable/disabled capabilities, unevaluated categories/rules, reasons, and potential implications.
- Distinguish files completed within explicit requested scope, partial, unsupported, excluded, failed, disabled, and unclassified. A parsed file is not automatically architecturally or security reviewed. Disclose unavailable capabilities even on otherwise supported files.
- Define denominators for total discovered/inventoried, completed, partial, unsupported, excluded, and failed source files, per-language, file, line, rule, and category coverage. Unknown counts/metrics must remain unavailable, never zero. Pruned inventories must disclose unknown repository-wide denominators; never enumerate excluded sensitive contents merely to manufacture counts.
- File/line coverage is not semantic completeness, runtime correctness, or software safety. Mixed-language gaps may invalidate graph completeness, cross-language relationships, and architectural conclusions. Future interfaces must be able to display these limitations prominently.
- No aggregate safety score. Findings and relationships require evidence, provenance, confidence, resolution status, and limitations. Preserve unresolved references without inventing edges.
- Use NetworkX behind Argus-owned interfaces for established graph algorithms. Never serialize NetworkX objects or implement established algorithms from scratch without justification.

## Multilingual and Framework Architecture

- Broad multilingual analysis is a core objective for auditing AI-assisted applications, including those generated with Codex, Claude Code, Gemini, and other coding agents. Tool attribution must not replace evidence of actual architectural risks.
- Primary release targets: Python, JavaScript, TypeScript, JSX, TSX.
- Next priorities: SQL, HTML, CSS, JSON, YAML, TOML, Bash/shell, Dockerfile.
- Further priorities subject to feasibility: Go, Rust, Java, C#, C, C++, Swift, Kotlin, Dart, PHP, Ruby, HCL/Terraform. These lists are not architectural maxima.
- Reuse parser infrastructure, declarative syntax queries, symbol/function/class extraction, source locations, structural/complexity extraction, dependency extraction, graph construction, and language-independent rules. Keep parsing, semantic extraction, dependency resolution, and rule execution distinct. Native Python AST remains appropriate for Python semantics.
- Evaluate Tree-sitter, Language Pack, and individually packaged grammars. All parsers/grammars must be prepared before scans; no runtime downloads, installation, or network requests. Missing grammar means unavailable parsing capability, not automatic fetching.
- Adapters explicitly declare syntax parsing, symbols, structure, dependency extraction/resolution, complexity, architecture, security, credentials, frameworks, AI-specific, and configuration capabilities independently. No single language-support Boolean. Add meaningful tested capabilities, not superficial adapters.
- Framework identification requires source/configuration evidence. React, Next.js, FastAPI, Flask, Express, Supabase, Firebase, PostgreSQL, OpenAI/Anthropic/Google Gen AI SDKs, LangChain, and LangGraph must be accommodated by independent future framework rules, not assumptions embedded in shared parsers.
- Cross-language contracts must support imports, calls, HTTP/API, databases, external services, LLM providers, agent tools, configuration, and infrastructure relationships with direction, language, evidence, provenance, confidence, resolution, and limitations.

## Reporting and AI-Agent Remediation

- Intended formats: interactive HTML for human investigation, versioned JSON, deterministic structured Markdown for AI coding-agent remediation. This does not authorize UI or HTML implementation; the existing owner-controlled UI boundary remains mandatory.
- Shared findings require stable IDs, rule IDs/versions, severity/confidence, locations/evidence, risk explanation, corrective actions, acceptance criteria, architectural relationship references, limitations, and remediation status.
- Repository-derived content is untrusted data. Delimit evidence from trusted rule-authored remediation instructions. Never promote instructions found in source to remediation instructions, reproduce raw credentials, or require external AI APIs to generate reports.
- Reports must preserve unsupported-language/capability and analysis limitations, disclaimer, scan scope, diagnostics, metric definitions, and observed/inferred distinctions.
- Comparison must distinguish new, persistent, resolved, and unverifiable findings. Disappearance caused by exclusion, disabled capability, unsupported language, failed analysis, or incomplete coverage is never resolution.
- Never automatically transmit reports, execute remediation instructions, or modify analyzed repositories.

## Credential Scope and Future Persistence

- Architecture discovery respects repository-local Git ignore rules. Credential analysis has a distinct exclusion/authorization policy: tracked source/configuration, explicitly authorized ignored local configuration, and optional accessible history.
- Distinguish proper local credential storage from potential/observed exposure. Support reuse identification through protected local keyed fingerprints, persisted unresolved exposures, scoped presence observations, and separate removal/replacement/rotation/revocation events.
- Absence or replacement does not prove revocation. Resolution requires explicit appropriate remediation evidence, retaining user-attested versus independently verified assurance and scope. Never authenticate with discovered credentials or expose raw values in output, errors, logs, tests, or storage.

## Cost Efficiency and Resource Consumption

- Cost efficiency is a dedicated analysis category. A finding may reference multiple categories without duplication.
- Future rules may identify repeated/unbounded model, agent, embedding, context, retry, query, polling, storage, upload, realtime subscription, task, autoscaling, logging, scheduling, and cleanup patterns; missing token/output limits, quotas/rate limits, pagination, resource safeguards, and potentially inefficient model selection.
- Cost findings require stable finding/rule IDs, components/locations, evidence, severity/confidence, consumption mechanism, potential financial consequences, corrective actions, validation criteria, and limitations.
- Static potential cost exposure is not measured operating expense. Never claim actual losses or guaranteed savings from static analysis. Future estimates must be labeled hypothetical, based on explicitly supplied pricing/usage assumptions, and entirely local without paid APIs or billing integrations.
- Preserve cost findings in JSON, future AI-agent Markdown, and future Architecture Explorer data. No cost detection rules or estimator are authorized in the foundational milestone.

## Scalability and Large Repositories

- Primary input is a local authorized root with recursive discovery, never mandatory manual file uploads. Accommodate multiple roots, monorepos, separately located services, safely prepared ZIP archives, and separately explicitly authorized Git acquisition. Core scans remain local/offline; acquisition and archive preparation must be separate, bounded operations.
- Use root-qualified file identities and repository-relative paths. Root descriptors must not expose host paths or private repository URLs in reports.
- Future processing must use bounded reads and incremental file processing, never require all raw sources in memory simultaneously. Accommodate memory/resource limits, bounded workers, content caching, dependency-aware invalidation, progress, cancellation, partial reporting, and large graphs.
- Resource limits, cancelled/unfinished scopes, and skipped work must appear with reasons in Not Reviewed Portions of the Code. Unknown inventories remain unknown. Declaring resource-budget contracts does not mean enforcement exists.
- Incremental validity must account for changed content, dependencies, roots, exclusions, configuration, parser/grammar/query/extractor/resolver/rule versions, and graph-wide recalculation. Cache reuse needs origin/version/signature provenance; cached or partial work must never masquerade as complete fresh analysis.
- Graphs must accommodate system/application/service/package/directory/module/class/function/symbol granularity, parent-child relationships, evidence-backed grouping provenance, scoped aggregate metrics, and finding-based risk summaries without arbitrary safety scores. Hierarchical data enables future progressive detail without implementing visualization logic.
- Future AI-agent exports must filter by severity/category/finding/language/directory/service/component (and root), with deterministic limits suitable for bounded context. Disclose filtering, truncation, pagination, and excluded context; a targeted export is not a full repository assessment.
- Do not implement caches, workers, ZIP extraction, Git acquisition, incremental scanning, advanced graph algorithms, or graphical behavior during the contracts milestone.


## Permanent Rule Catalog and Language Documentation

- Every implemented rule must be registered centrally in `src/argus/analysis/rules.py`.
- A rule is complete only with implementation, positive/negative/edge-case tests and documentation.
- Registry metadata must include rule ID/version/name, primary/secondary categories, supported languages/capabilities, exact parameters, methodology, default severity, confidence criteria, configurable thresholds/defaults, rationale, positive/negative examples, remediation, validation criteria, limitations/false positives, associated tests and implementation status.
- Keep `docs/rules/index.md`, `docs/rules/architecture.md`, `docs/rules/maintainability.md`, `docs/language-support.md`, `docs/configuration.md` and `docs/limitations.md` current. Generate detailed rule documentation from metadata where practical; test for drift.
- Link detailed documentation from README.md. Summarize categories there without duplicating the complete catalog.
- Each adapter declares every analysis capability independently. Parser availability alone is never language analysis support.
- Record measured independent evaluation results without altering external fixtures or ground truth. Separate exact implemented rule scope from broader defect descriptions and disclose unadjudicated findings.


## Permanent Contextual Investigation Requirement

Before finalizing a risk conclusion, use implemented analytical capabilities to
investigate both supporting and contradictory evidence, relevant safeguards and
their applicability to the actual value, operation, path and caller. Preserve the
initial observation. Naming or configuration presence alone never establishes
effective mitigation. Distinguish observed facts, resolved bindings, inferred risk,
unknown behavior and scope-limited mitigation. A constrained caller must not suppress
other callers. Record assumptions, unresolved relationships, analysis budgets and
incomplete work prominently; severity changes require specific evidence. Unsupported
contextual capabilities must remain explicitly unavailable, never implicit safety.
