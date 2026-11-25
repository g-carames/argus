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

Argus does not certify or guarantee software safety, security, correctness, reliability, regulatory compliance, or AI alignment.

The tool provides evidence-backed static analysis findings and heuristic risk indicators intended to support, not replace, human engineering judgment.

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