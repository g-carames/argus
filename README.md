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

Rather than relying on the same generative intelligence responsible for producing the code to evaluate its own work, Argus uses static analysis, graph algorithms, and configurable rules to identify observable structural risks and provide evidence-backed findings.

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

Milestone 1 establishes backend contracts only: immutable typed models, component
interfaces, explicit coverage accounting, deterministic JSON serialization, and
validation tests. No repository scanner, language analysis, credential detection,
cost rules, graph algorithms, remediation storage, or graphical interface is
implemented. Broad multilingual analysis is a core objective; Python, JavaScript,
TypeScript, JSX, and TSX are primary release targets, not currently supported analyzers.

Requires Python >=3.12 and uv:

```sh
uv sync
uv run argus --help
uv run argus --version
uv run pytest
uv build
```

`argus scan` is reserved for a future milestone and currently returns an argument
error. Reports serialize supplied contract records; they do not perform analysis.
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
