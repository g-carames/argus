# Milestone 2: operation and validation

Implemented: functional CLI; deterministic, safe local repository inventory;
multilingual recognition; bounded manifest/configuration technology observations;
observed directory/file hierarchy and explicitly inferred package/application
candidates. No analysis adapters, risk rules, credential scanning, source usage
confirmation, dependency graph algorithms, or UI are implemented. Reports always
include the exact disclaimer and **Not Reviewed Portions of the Code**. Inventory
completion never implies architectural, security, reliability, AI-risk or cost review.

## CLI

```sh
uv run argus --help
uv run argus --version
uv run argus scan /path/to/project
uv run argus scan /path/to/project --format json --verbose
uv run argus scan /path/to/project --output /private/tmp/project.argus-report.json
uv run argus scan /path/to/project --config inventory.toml --exclude '*.generated.*'
```

JSON is the default and only report format; no HTML or Markdown renderer is added.
`--exclude` is repeatable. Relative paths resolve against the caller's working
directory. Progress (first file and every 100 files) and fixed diagnostics go to
stderr; stdout contains only JSON unless `--output` is supplied. Progress has no
invented total. Exit codes: 0 inventory produced without inspection errors (normal
exclusions and unavailable analysis are allowed); 1 inspection errors, resource gaps
or malformed inspected manifests; 2 invalid arguments/input/configuration/output;
130 cancelled. A partial analysis report with zero findings is not a passed audit.

Ctrl-C during discovery produces a partial report where feasible, preserving a
cancellation gap. Cancellation before discovery or during final report serialization
may prevent finalization. The library accepts an optional cancellation token and
progress callback. Discovery does not install signal handlers or execute target code.

Output must be an explicit new `.json`/`.txt` file in an existing non-symlink directory.
Existing files, hard links and symbolic links are never overwritten; new output uses
exclusive creation and owner-only permissions (0600 on POSIX). Source-like output
suffixes are rejected. A supplied path inside the analyzed root explicitly authorizes
that new report file only. Prefer `argus-reports/` or `*.argus-report.json`; those names
are excluded by default and already ignored in this project's Git policy. Arbitrary
output locations in other repositories are not automatically Git-ignored. Existing
Argus JSON envelopes with custom `.json`/`.txt` names are recognized and excluded
when they can be read within limits; oversized custom names remain failed/unreviewed.
Output write failures may leave a partial new report file; no existing file is replaced.

## Configuration and enforced bounds

The optional config is UTF-8 TOML, at most 64 KiB, with exactly one table:

```toml
[discovery]
max_file_bytes = 2097152
max_files = 20000
max_entries = 100000
max_depth = 256
max_total_bytes = 268435456
max_ignore_bytes = 65536
excludes = ["*.generated.*", "fixtures/private/"]
```

These are the defaults. Values must be positive integers at most 1,000,000,000;
unknown keys and booleans are rejected. Exclusions are limited to 1,000 patterns,
4,096 characters each. CLI patterns append to configured patterns. User-provided
pattern text is withheld from reports because it can contain secrets; the scope
uses indexed policy references. The effective numeric bounds appear in the report.
The inherited ResourceBudget memory field is informational, **not enforced**.

The file limit includes known individually excluded regular files. Entry limits
include files/directories encountered while listing; directory listings are bounded
before sorting. Depth starts at zero for the root. File size limits are checked
before reads. Total inspected bytes include ignore policy reads and may count an
ignore file again when inventoried; a read can use one sentinel byte to detect a
concurrently growing file. Files are read one at a time, never all retained as raw
source. Structured entities, paths and JSON are still materialized in memory.

Traversal uses an explicit stack and POSIX directory descriptors, with no-follow
opens for every root/output parent component and every discovered directory/file.
Links and special filesystem objects are skipped. No target imports, shell commands,
Git subprocesses, dependency installation, runtime downloads or network access occur.
This implementation requires POSIX descriptor-relative filesystem APIs; Windows
portability is not claimed. Live mutation is not a consistent filesystem snapshot.
Unavailable descriptors, permissions, changing files, or invalid ignore policies are
reported safely. Memory, wall-clock, I/O timeouts and OS descriptor limits are not
hard-enforced. Deep traversal can encounter platform descriptor/path limits.

Default exclusions cover Git internals, node_modules, virtual environments, Python
bytecode, common caches, dist/build/target/vendor, .next/.nuxt/.svelte-kit, coverage,
and Argus report/remediation state. Repository-local `.gitignore` files apply with
nested precedence and Git-style negation via pathspec 0.12.1. A file can be re-included
only while its parent directory is traversable; ignored directories are never opened
merely to find a nested negation. Defaults and explicit exclusions are separate from
Git ignores and cannot be undone by a target's ignore negation. Architecture inventory
applies ignore patterns regardless of tracked membership; Git index/global excludes
and .git/info/exclude are not inspected. Future credential inspection has a separate
authorization/scope policy, including ignored local configuration and optional history.

Known individually excluded files receive file inventory and excluded coverage
records without content reads. Pruned directories have unknown contents/counts and
inventory gaps. Counts describe inventoried files only; repository-wide denominators
are unavailable whenever gaps remain. Known file sizes are stat observations;
physical line counts are supplied only for successfully read UTF-8 text without NUL
bytes, using CRLF/CR/LF. Unknown/binary/oversized/unreadable counts remain null. Every
analysis capability and category is unavailable; no parsing completion is asserted.

## Recognition

The centralized, extensible registry recognizes:

Python; JavaScript; TypeScript; JSX; TSX; SQL; HTML; CSS; SCSS; JSON/JSONL; YAML;
TOML; Bash; shell (sh/zsh/ksh); PowerShell; Dockerfile/Containerfile; Go; Rust; Java;
C#; C; C++; Swift; Kotlin; Dart; PHP; Ruby; R; Lua; HCL; Terraform; GraphQL; Vue;
Svelte; XML/SVG; Jupyter notebooks. Markdown, Git ignore files, dotenv templates,
Python requirement files and Go module/checksum manifests are also recognized.
See `recognition.py` for explicit extension/name tables and version-controlled
variants. Custom registry instances can supply additional mappings.

Extensionless executable text can be identified using a bounded 4 KiB shebang
prefix (Python, Node, shell, Ruby, PHP, PowerShell and Lua); the PHP opening signature
is also recognized. No interpreter is executed. `.h`, `.m`, `.pl`, and `.v` are
explicitly ambiguous, with candidates and null primary language. Unknown files remain
unclassified. Primary format recognition does not analyze embedded notebook/Vue/
Svelte/HTML languages. Suffix/name heuristics can be misleading; no syntax validity
or semantic completeness is claimed, including malformed source files.

## Technology evidence and hierarchy

Safe package.json dependency sections, pyproject project/optional/group and Poetry
dependencies, and requirement names identify declarations for React, Next.js, Vue,
Svelte, Express, FastAPI, Flask, Django, Supabase, Firebase, PostgreSQL drivers, OpenAI,
Anthropic, Google Gen AI, LangChain and LangGraph. Node.js is identified by package.json
presence; this does not establish a Node server/runtime. Docker/Docker Compose and
Next/Vue/Svelte configuration filenames supply configuration evidence only.

Only fixed installed technology names and evidence-type labels are emitted; versions,
URLs, scripts, manifest values and source excerpts are never echoed. Malformed inspected
JSON/TOML manifests produce fixed diagnostics; declaration observations from them are
discarded. Other configuration files are recognized without claiming syntax validation.
YAML internals, lockfile dependency graphs, aliases, dynamic dependencies, source imports
and confirmed source usage are not inspected. No framework-specific security review occurs.

Root/directory/source/configuration/other file nodes preserve parent references,
root-qualified identities and evidence. Manifest presence suggests package candidates;
Node start/dev scripts or Python project scripts suggest application candidates.
These groupings are explicitly inferred, not confirmed deployed services. No architectural
relationships, layers, safety scores, symbols, or rendering properties are invented.
Flat structured records with stable opaque IDs support future hierarchical querying;
backend pagination/progressive loading and visualization are not implemented.

## Privacy limitations

No raw source or manifest values appear in reports. Dedicated path masking replaces
components containing recognizable credential patterns, URL-like strings, control/
non-ASCII characters, invalid contract delimiters, or excessive length with stable hashes.
Recognizers include common OpenAI/Anthropic/Google/AWS/GitHub/Slack/Stripe/JWT forms
and credential-labelled assignments. Raw exceptions and invalid CLI argument values
are never printed. This is defensive sanitization, not a credential detector: arbitrary
unlabelled secrets, private project names and architectural metadata can still be
sensitive. Hashes are opaque identities, not protected credential fingerprints or
proof against dictionary guessing. Treat reports as confidential. JSON is escaped
and repository observations remain untrusted evidence, not remediation instructions.
There is no telemetry, automatic transmission, authentication, history inspection or
remediation persistence. Existing ignored report/remediation patterns were retained.

## Validation and actual CLI output

On Python 3.12.16, `uv run pytest -q` passed **164 tests**, including a 1,200-file
synthetic monorepository, 80 nested directories, all registry extensions, nested
ignore/negation, containment and swapped symlink cases, resource bounds, unreadable
and malformed input, unsupported coverage, determinism, cancellation, redaction,
framework declarations, hierarchy and exclusive output safety. Existing contract
assertions remain; obsolete Milestone 1 CLI/schema expectations were updated to the
approved implementation. Tests do not benchmark production-scale memory or claim
cross-platform guarantees.

`uv build` produced the source distribution and wheel. The wheel and cached pathspec
were installed using `uv pip install --offline` into a fresh uv-created Python 3.12
environment. Installed `argus --help`, `--version` and `scan` were exercised.

Actual installed `argus --version` output:

```text
0.1.0
```

For a synthetic project containing one `main.py`, the installed command
`argus scan /private/tmp/argus-m2-u2y8wnmy/project --format json --verbose --output /private/tmp/argus-m2-u2y8wnmy/example.argus-report.json`
returned 0, stdout was empty, and stderr was:

```text
argus: inventory inspected 1 files; total unknown
argus: inventory completed; 1 files; 0 gaps; analysis Not Reviewed
```

Selected actual report values: `schema_version="1.1.0"`, `inventory.status="completed"`,
`inventory.inventoried_files=1`, `status="partial"`, file `main.py`, language `python`,
file analysis status `unsupported`, and title `Not Reviewed Portions of the Code`.
The complete report includes the disclaimer and every unavailable capability/category.

## Changes and next step

New: `src/argus/{cli,config,discovery,privacy,recognition,scanner,technologies}.py`,
`tests/test_inventory.py`, and this document. Modified: README.md,
`docs/{architecture,data-contract}.md`, pyproject.toml, uv.lock,
`src/argus/__init__.py`, `src/argus/models/{source,scan,analysis}.py`,
`src/argus/reporting.py`, `tests/{test_packaging,test_coverage_reporting}.py`.
The only new dependency is free, open-source pathspec (MPL-2.0), required for
well-tested Git ignore matching rather than a custom partial implementation.

No major architecture deviations: existing language-neutral contracts and JSON
writer are retained; the reviewed additive schema revision is 1.1.0. File-size and
independent inventory completion metadata were necessary additions. No NetworkX
algorithm is introduced. No UI, frontend assets or prohibited milestone features
were changed. Nothing is committed or pushed.

Recommended Milestone 3: approve and implement prepared offline parsing infrastructure,
starting with Python AST and shared Tree-sitter service for explicit JS/TS/JSX/TSX
grammars, independently declared parsing/extraction capabilities, syntax failure tests
and source-location normalization. Keep dependency resolution and risk-rule claims
bounded to separately authorized and tested functionality.
