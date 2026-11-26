## The Problem: The Hidden Risks of Vibe Coding

AI coding agents have dramatically reduced the barrier to software development, enabling individuals to build increasingly sophisticated applications through natural language instructions. This emerging development practice, commonly referred to as *vibe coding*, has accelerated prototyping, reduced development costs, and democratized access to software engineering.

However, the ability to generate functional software does not necessarily translate into the ability to evaluate its underlying architecture.

As developers increasingly delegate implementation decisions to AI coding agents, architectural complexity can accumulate faster than human understanding of the system. Functional success can create a false sense of confidence, while security vulnerabilities, structural weaknesses, and technical debt remain undetected.

A software system can pass linting checks, compile successfully, and satisfy its functional requirements while still containing:

- Excessive architectural coupling
- Circular dependencies
- Weak security and authorization boundaries
- Exposed or improperly rotated credentials
- Unnecessary architectural complexity
- Fragile dependency structures
- Potential scalability bottlenecks
- Unsafe LLM and autonomous agent integrations
- Architectural decisions that developers neither explicitly approved nor fully understand

## Argus as an Independent Architectural Check

Argus is designed to introduce an independent, deterministic layer of architectural scrutiny into AI-assisted software development.

Rather than relying on the same generative intelligence responsible for producing the code to evaluate its own work, Argus is intended to use static analysis, graph algorithms, and configurable rules to identify observable structural risks and provide evidence-backed findings.

Its purpose is not to discourage vibe coding, but to make AI-assisted development more accountable, transparent, and technically responsible.

Argus aims to serve as a checkpoint between code generation and human approval, helping developers:

- Understand the architecture of the software they generate.
- Identify risks that conventional linting may overlook.
- Recognize unintended architectural consequences.
- Investigate security weaknesses before deployment.
- Make more informed decisions about accepting AI-generated changes.
- Retain meaningful oversight of increasingly autonomous development workflows.

**The ability to build software faster should not come at the expense of understanding what has been built.**

Argus is designed to help bridge that gap, while recognizing that static analysis cannot replace comprehensive testing, security assessments, or human engineering judgment.

# argus
Local-first, multilingual software architecture intelligence and static risk analysis for AI-assisted development.

## Current development status

Milestone 4 adds fifteen security, textual credential, reliability, AI and cost
pattern rules to the nine structural rules, plus configuration/workspace resolution,
limited call bindings and inferred HTTP relationships. Detailed tested scope and
remaining gaps are in the [Milestone 4 record](docs/milestone-4.md) and
[independent evaluation](docs/milestone-4-evaluation.md).
No remediation storage, Markdown/HTML renderer or graphical interface is implemented.

Requires Python >=3.12 and uv:

```sh
uv sync
uv run argus --help
uv run argus --version
uv run pytest
uv build
```

```sh
uv run argus scan /path/to/project
uv run argus scan /path/to/project --format json --verbose
uv run argus scan /path/to/project --output /private/tmp/project.argus-report.json
uv run argus scan /path/to/project --config inventory.toml --exclude '*.generated.*'
```

JSON is the default and currently only report format. Progress and controlled
diagnostics go to stderr. Output locations must be explicit, new `.json`/`.txt`
files in existing directories; existing files and links are never overwritten.
Input and output paths may contain `.` and `..`; each actual directory component
is checked before traversal, so `link/../project` still rejects the link. Symlink
components remain prohibited, including macOS `/tmp`; use `/private/tmp` instead.
See [Milestone 2 operation and limitations](docs/milestone-2.md) for configuration,
recognition lists, coverage definitions, safety behavior and validation.
See [Milestone 2.1 validation](docs/milestone-2.1.md) for diagnostic codes, regression
coverage, and the independent seven-repository inventory revalidation.

Inventory may complete while the scan remains `partial`: supported files receive
listed static capabilities, while unavailable capabilities remain **Not Reviewed**.
Installation can download free dependencies; backend operation is entirely local.

See [backend architecture](docs/architecture.md) and the
[versioned data contract](docs/data-contract.md). Every generated report includes
**Not Reviewed Portions of the Code**, explicit capability/category limitations,
and the mandatory disclaimer. Coverage and absence of findings never establish safety.

Generated reports and local records belong in ignored `argus-reports/`,
`argus-records/`, or `.argus/` locations. Treat reports as confidential; ignore
patterns do not protect arbitrary output paths. Do not commit real credentials or
analysis reports. The graphical interface remains reserved for manual development
by the project owner in collaboration with ChatGPT.

## Closing the AI-Assisted Development Loop

Argus is designed not only to identify architectural risks, but also to facilitate their remediation.

In addition to human-readable architectural reports and machine-readable analysis results, Argus aims to generate AI-agent-compatible remediation reports containing structured findings, source locations, supporting evidence, recommended corrective actions, and validation criteria.

Once implemented, these reports could be provided directly to AI coding agents such as OpenAI Codex, Anthropic Claude Code, Google Gemini, or other development assistants, enabling targeted remediation of identified issues.

By introducing an independent, deterministic analysis layer between AI-generated implementation and subsequent remediation, Argus aims to establish a more accountable development workflow:

**Generate → Analyze → Review → Remediate → Reanalyze**

Argus does not automatically authorize or apply modifications to the analyzed codebase. Developers retain control over which findings are addressed, which changes are accepted, and whether additional verification is required.

The existing JSON serializer operates locally, and planned report formats must do so as well. Users should review and sanitize sensitive architectural information before voluntarily sharing reports with external AI services.

The objective is to make AI-assisted software development more transparent, iterative, and technically responsible without sacrificing the productivity benefits of generative AI.

## Analysis Capabilities

Current implemented subsets are listed in the [capability matrix](docs/language-support.md). The broader categories below include future goals:

- Architectural integrity: dependency graphs, module relationships, architectural layers, dependency direction and type, circular dependencies, centrality, coupling, and blast radius indicators.
- Security: evidence-backed indicators of weak security and authorization boundaries.
- Credential exposure and remediation: detection in source/configuration and optionally accessible Git history, protected local reuse tracking, and separate removal, replacement, rotation, and revocation records. Removal or replacement must never be treated as proof of revocation; user-attested and independently verified remediation must remain distinct.
- Maintainability: unnecessary complexity and structural weaknesses.
- Dependency health: fragile dependency structures and related risks.
- Reliability: static indicators of fragile behavior and failure risks.
- Performance and scalability: potential bottlenecks and missing resource safeguards.
- AI-specific architectural risks: unsafe LLM integrations, autonomous agent tools, and evidence-backed risks in AI-assisted applications, without treating tool attribution as evidence of risk.
- Cost efficiency: potential excessive consumption from repeated or unbounded model/agent calls, embeddings, context, retries, queries, polling, storage, uploads, subscriptions, jobs, autoscaling, logging, and scheduling; missing limits, quotas, pagination, cleanup, and potentially inefficient model selection. Static exposure is not measured operating expense or guaranteed savings. Any future local estimates must use explicit hypothetical pricing and usage assumptions, without billing integrations or paid APIs.

Rules are intended to be independently extensible and configurable. Findings must retain identifiers, severity, confidence, locations, supporting evidence, risk explanations, corrective actions, validation criteria, remediation status, and detection limitations. Observed dependencies must remain distinct from inferred relationships; unresolved references must not become invented edges. No aggregate safety score is planned.

Planned reporting includes versioned JSON, deterministic structured Markdown for AI-agent remediation, and an independently developed interactive HTML Architecture Explorer. Only versioned JSON reporting is currently implemented. Repository-derived evidence is untrusted data and must remain separate from trusted rule-authored remediation instructions.

## Current implementation

Python, JavaScript, TypeScript, JSX and TSX now produce entities, static imports,
resolved/unresolved relationships, module graphs, NetworkX metrics and nine
configurable architecture/maintainability heuristics. SQL, HTML, CSS, YAML, JSON,
TOML, Bash/shell and Dockerfile have narrower extraction capabilities.
Milestone 4 adds the tested pattern and relationship subsets described above; persistent
credential remediation, history, broad framework security and deeper AI dataflow remain unavailable.
No UI, HTML templates, automatic remediation, commits or remote reporting are included.

Install prepared dependencies with `uv sync --locked`; run `uv run argus scan PATH`.
Scans operate offline without importing target code. JSON retains explicit partial
coverage, failures, unsupported portions and the mandatory disclaimer.

- [Rule catalog](docs/rules/index.md)
- [Architecture rules](docs/rules/architecture.md)
- [Maintainability rules](docs/rules/maintainability.md)
- [Exact language capability matrix](docs/language-support.md)
- [Configuration and thresholds](docs/configuration.md)
- [Analysis and graph limitations](docs/limitations.md)
- [Measured independent laboratory evaluation](docs/milestone-4-evaluation.md)
- [Implementation and validation record](docs/milestone-4.md)

## Multilingual Support and Coverage Transparency

The language-agnostic core is intended to support modular adapters, beginning with Python. Python, JavaScript, TypeScript, JSX, and TSX are primary release targets. Next priorities include SQL, HTML, CSS, JSON, YAML, TOML, Bash/shell, and Dockerfile; further priorities include Go, Rust, Java, C#, C, C++, Swift, Kotlin, Dart, PHP, Ruby, and HCL/Terraform. Primary adapters now implement static parsing, extraction, conservative resolution and structural rules. Additional formats have limited extraction capabilities; see the capability matrix below.

Language and configuration-format recognition must remain independent of analysis capability. Parsing alone must never imply architectural or security review. Future adapters must declare parsing, symbols, structure, dependency extraction/resolution, complexity, architecture, security, credentials, frameworks, AI-specific, and configuration capabilities separately. Framework identification must require source or configuration evidence.

Every generated report includes **Not Reviewed Portions of the Code**. The current contracts and JSON serializer represent unsupported languages/formats, privacy-controlled repository-relative locations, known unreviewed physical lines, exclusions, unreadable/unparseable files, unavailable or disabled capabilities, and unevaluated categories/rules, with reasons and implications. The inventory scanner supplies discovery observations; the serializer does not discover files.

Coverage distinguishes completed work within explicit scope from partial, unsupported, excluded, failed, disabled, and unclassified files. File, language, line, rule, and category metrics require defined denominators; unknown values remain unavailable. Pruned inventories cannot establish repository-wide totals. File or line coverage does not establish semantic completeness, runtime correctness, or safety, and mixed-language gaps can invalidate graph completeness and architectural conclusions. A finding disappearing because coverage was lost must not be reported as resolved.

## Privacy and Human Oversight

Argus's core must operate locally and offline, without paid services, cloud infrastructure, telemetry, or analytics. Analyzed source code, credentials, and analysis results must never be transmitted automatically. Installation may retrieve free dependencies; future parsers and grammars must be prepared before scans, with no runtime downloads.

Analyzed repositories are untrusted input. Future analysis must not execute project scripts, import target modules, install target dependencies, modify the target codebase, or follow symbolic links outside the authorized directory. Credential analysis must use its own explicit scope and authorization policy, never authenticate with discovered credentials, and never expose full credential values in reports, logs, or persistent records.

Defensive inventory path masking and JSON escaping are not a credential detector or general-purpose sanitizer. Callers must supply privacy-safe text; dedicated path withholding does not sanitize free-text fields. Reports and local remediation records remain confidential and should stay out of Git. Users retain control over any voluntary external sharing and all remediation decisions.

## Disclaimer

Argus is a software architecture analysis and decision-support tool. It does not certify or guarantee software safety, security, correctness, reliability, regulatory compliance, or AI alignment. Findings are derived from static analysis, observable source-code relationships, configurable rules, and heuristic indicators. Analysis may produce false positives, false negatives, incomplete results, or inaccurate architectural inferences. The absence of findings does not establish the absence of vulnerabilities, particularly where portions of the codebase have not been reviewed. Argus is intended to complement, not replace, professional security assessments, runtime analysis, comprehensive software testing, code review, and qualified human engineering judgment.
