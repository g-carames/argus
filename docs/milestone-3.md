# Milestone 3 implementation and validation

Milestone 3 introduces a functional structural architecture auditor, with explicit
partial analysis. Changes are uncommitted for owner review. No UI, HTML/CSS assets,
credential-history scanning, advanced security, AI/cost rules, automatic remediation,
agent Markdown rendering, telemetry or network behavior during scans was added.

## Components and files

Created analysis components:

- `src/argus/analysis/__init__.py`: analysis package boundary.
- `src/argus/analysis/parsing.py`: native AST/stdlib parsing, prepared grammar service, bounded tree traversal, SQL tokenization and Dockerfile instruction reader.
- `src/argus/analysis/extraction.py`: language-aware extraction into source-free module/symbol/import/structural facts; shared JS/TS declarative import/export query.
- `src/argus/analysis/adapters.py`: independent capability declarations and installed parser/grammar version metadata.
- `src/argus/analysis/resolution.py`: repository-index dependency resolution.
- `src/argus/analysis/graphs.py`: NetworkX behind Argus-owned graph records/interfaces.
- `src/argus/analysis/rules.py`: authoritative metadata registry and source-free finding construction.
- `src/argus/analysis/pipeline.py`: incremental collector, evidence, rules and coverage composition.

Modified runtime files:

- `src/argus/scanner.py`: invoke analysis while discovery yields each bounded file; finalize normalized records.
- `src/argus/config.py`: immutable validated analysis settings and bounded TOML threshold/disable configuration.
- `src/argus/cli.py`, `src/argus/errors.py`: current CLI help/progress and safe configuration diagnostics.
- `src/argus/reporting.py`: explicit per-language/per-capability counts including configurations.
- `src/argus/models/scan.py`: additive JSON schema 1.2.0; existing typed fields carry analysis records.
- `pyproject.toml`, `uv.lock`: installed free parser/graph dependencies.

Created tests: `tests/test_analysis_parsing.py`, `tests/test_analysis_resolution.py`,
`tests/test_analysis_graphs.py`, `tests/test_analysis_rules.py`.
Updated `tests/test_inventory.py`, `tests/test_packaging.py` and
`tests/test_coverage_reporting.py` for actual partial/failed analysis and schema 1.2.0.
Existing no-follow, race, privacy, resource, CLI and deterministic-inventory checks
continue to run; no independent fixtures or expectations were changed.

Created documentation/tooling: `docs/rules/index.md`, `docs/rules/architecture.md`,
`docs/rules/maintainability.md`, `docs/language-support.md`, `docs/configuration.md`,
`docs/limitations.md`, `docs/milestone-3.md`, `docs/milestone-3-evaluation.md`,
`tools/generate_rule_docs.py`, `tools/evaluate_lab.py`.
Updated `AGENTS.md` with permanent catalog requirements, `README.md` with current
scope and detailed links, and `docs/architecture.md`/`docs/data-contract.md` with the
new implementation and schema status.

## Dependencies and architecture choices

| Dependency | Tested lock version | Reason |
| --- | --- | --- |
| tree-sitter | 0.25.2 | Shared local CST and query infrastructure |
| tree-sitter-javascript | 0.25.0 | Prepared JavaScript/JSX grammar |
| tree-sitter-typescript | 0.23.2 | Prepared TypeScript/TSX grammars |
| tree-sitter-bash | 0.25.1 | Prepared Bash/subset shell grammar |
| tree-sitter-html | 0.23.2 | Element extraction and syntax parsing |
| tree-sitter-css | 0.25.0 | Style-rule extraction and syntax parsing |
| tree-sitter-yaml | 0.7.2 | YAML syntax and block mapping extraction |
| sqlparse | 0.5.5 | Non-validating SQL statement tokenization |
| networkx | 3.7 | Established SCC, topology, centrality and reachability algorithms |

Python AST, JSON and TOML use the standard library; existing pathspec is retained.
All new dependencies are free/open source. Installation prepares grammars; scans
never fetch assets. Individually packaged grammars were selected over Language Pack
to avoid lazy acquisition and keep installed scope explicit. The native timeout is
used after the binding callback path crashed during validation. Native process
isolation is not implemented; see limitations. Python 3.12.16/macOS arm64 is the
measured environment, with package metadata retaining Python >=3.12.

## Implemented capabilities and rules

The [exact language matrix](language-support.md) independently declares syntax,
symbol, structure, dependency extraction/resolution, complexity, architecture and
configuration capabilities. Python/JS/TS/JSX/TSX implement the initial structural
rule set. Bash/shell, HTML, CSS, YAML, JSON, TOML, SQL and Dockerfile have precisely
limited extraction; SCSS and other recognized language probes remain unsupported.
Function/class relationships currently mean lexical parent-child containment;
call graphs and inheritance resolution remain unavailable, explicitly disclosed.

The [catalog](rules/index.md) lists nine rules and complete parameter metadata:
cyclic component size > 0, incoming/outgoing local degree > 10, function span > 50,
module physical lines > 500, nesting > 4, complexity indicator > 10, directed degree
centrality > 1, and total coupling > 20 OR module physical lines > 500. Thresholds
are configurable; rules can be disabled. Findings preserve evidence, confidence,
provenance, locations, actions, validation criteria, relationships and limitations.
No universal architecture judgment or aggregate safety score is asserted.

Resolution handles Python absolute/relative modules, conventional src/package roots,
JS relative/extension/index candidates, literal CommonJS/dynamic imports, ESM
re-exports, simple package main/module/types entries and nearest strict-JSON TS
paths/baseUrl aliases. Ambiguity/unresolved status is preserved without invented
edges. External references do not establish installed dependency presence.
Runtime/type-only/commonjs/dynamic and conditional phases remain distinct.

Graph metrics: incoming/outgoing/total coupling, degree centrality, SCC size,
forward reachability count, reverse reachability blast radius and DAG dependency
depth. Cyclic SCCs summarize cycles without enumerating paths. Reachable cycles
make depth unavailable; repeated reachability metrics above 2000 primary modules
are unavailable. Definitions/projection assumptions are in [limitations](limitations.md).
Hierarchy remains separate from dependency metrics; unsupported file nodes remain
in the full graph. No NetworkX object crosses reporting contracts.

## Validation and evaluation

`uv run --locked pytest -q`: **280 passed**, 3.04 seconds on the final code run.
The suite includes all 222 original cases (with milestone-specific expectations
updated) plus 58 new cases for adapters, malformed input, Unicode locations,
loops/complexity, relative/conditional/type/dynamic imports, ambiguity, aliases,
external and excluded targets, SCCs/cycles/DAGs/disconnected nodes, singleton
centrality, unavailable metrics, thresholds/disabling, privacy, mixed coverage,
resource limits and generated-document drift.

`uv build` produced both wheel and source distribution. A separate CPython 3.12.16
uv environment at `/private/tmp/argus-milestone3-install` installed the built wheel
and all dependencies. Clean installed CLI checks include version/help, an offline
mixed Python/TypeScript cycle scan and malformed-source coverage/reporting.
No target dependencies were installed or target code executed.

[Independent evaluation](milestone-3-evaluation.md): all seven authorized fixtures
scanned with matching unchanged hashes. Three exact-scope planted issues detected,
zero misses in that mapping; clean controls produced zero findings. Four extra
concentration heuristics satisfy structural thresholds but remain unadjudicated
as separate defects. Nineteen planted issues are outside implemented rule scope.
The 1003-file fixture scanned in 0.8804 seconds in one run; this is not a benchmark
or scalability guarantee. Most rule sensitivity is tested with synthetic fixtures.

## Limits, deviations and recommended next milestone

The approved separation of parsing, extraction, resolution, graph algorithms, rules
and reporting is preserved. No major architectural deviation or UI work was introduced.
The incremental collector uses small internal fact dataclasses before normalizing
into the existing reporting records; it is not a dynamic plugin loader. JSON 1.2.0
adds a computed per-language coverage field without changing existing entity types.

Scope limitations: no resolved function calls/inheritance; broader languages and
SCSS remain unsupported. SQL/Dockerfile are structural readers, not full validators.
Some primary-language declarations/exports and runtime resolution semantics remain
partial. Names/references are opaque for privacy, reducing immediate human readability;
source locations and IDs remain available. No per-process hard memory/time isolation,
streaming reports, graph cancellation, cache or repository-size guarantee exists.
Parser/resource/coverage failures are disclosed; incomplete scope never establishes
absence of risk. No credential detection or revocation assurance is claimed.

Recommended next milestone: owner review and independent validation of this analysis
baseline, then separately authorize parser isolation, richer Python/TS resolution,
call/inheritance relationships and priority SQL/configuration semantics before adding
framework/security/credential rules. The owner-controlled interface remains separate.

## Disclaimer

Argus is a software architecture analysis and decision-support tool. It does not certify or guarantee software safety, security, correctness, reliability, regulatory compliance, or AI alignment. Findings are derived from static analysis, observable source-code relationships, configurable rules, and heuristic indicators. Analysis may produce false positives, false negatives, incomplete results, or inaccurate architectural inferences. The absence of findings does not establish the absence of vulnerabilities, particularly where portions of the codebase have not been reviewed. Argus is intended to complement, not replace, professional security assessments, runtime analysis, comprehensive software testing, code review, and qualified human engineering judgment.
