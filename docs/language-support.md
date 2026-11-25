# Implemented language capabilities

Recognition is independent of this table. S = implemented with stated static
limitations (reported partial), V = syntax validation completed when successful,
— = unavailable. All supported files remain partial under the requested full
capability scope. Malformed inputs fail extraction; missing prepared grammars are
unsupported, never fetched. No grammar alone establishes semantic support.

| Language | Syntax | Symbols | Structure | Dependencies | Resolution | Complexity | Architecture rules | Configuration |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Python | V, native AST | S | S | S | S | S | S | — |
| JavaScript | V, Tree-sitter | S | S | S | S | S | S | — |
| TypeScript | V, Tree-sitter | S | S | S | S | S | S | — |
| JSX | V, JS grammar | S | S | S | S | S | S | — |
| TSX | V, TSX grammar | S | S | S | S | S | S | — |
| Bash | V, Bash grammar | functions | S | — | — | S | — | — |
| Shell | V, Bash subset | functions | S | — | — | S | — | — |
| HTML | V, HTML grammar | element spans | S | — | — | — | — | — |
| CSS | V, CSS grammar | style-rule spans | S | — | — | — | — | — |
| YAML | V, YAML grammar | block-mapping entry spans | S | — | — | — | — | — |
| JSON | V, stdlib | — | entry counts | — | — | — | — | entry counts |
| TOML | V, stdlib | — | entry counts | — | — | — | — | entry counts |
| SQL | —, tokenization only | — | statement counts | — | — | — | — | — |
| Dockerfile | —, instruction recognition | — | instruction counts | — | — | — | — | — |

Security, credentials, frameworks and AI capabilities are unavailable in every row.
Dependency-health, reliability, performance and cost categories have no rules.
Bash complexity covers parsed `if`/`elif`/loops/cases conservatively, not command
execution, expansions or external programs. Generic shell parsing uses the Bash
grammar; zsh/ksh-specific constructs can fail. HTML embedded script/style and CSS
preprocessors are not extracted. YAML flow-mapping entries lack symbol spans.
JSONL is recognized as JSON but non-single-document input fails JSON parsing.
SQL tokenizer accepts malformed SQL and must never be treated as SQL validation.
Dockerfile arguments, stages, JSON forms, heredocs and embedded shell are not
semantically validated; unsupported instruction forms may fail conservatively.

Primary extractors provide module records, classes, functions/methods, variable
symbol declarations, lexical parent-child containment, locations, imports and JS
export markers. Python lambdas are included; JS interfaces/types/enums are class-like
symbols, not runtime classes. Import binding symbols, Python `__all__`, Python
comprehension/lambda scope declarations, full destructuring symbols, overload
semantics, decorators, inheritance and call-target resolution are not complete.
Type-only imports and mixed type/runtime imports are distinguished; dynamic imports
and CommonJS references retain phases. Conditions/functions mark conditional loading;
shadowed `require`, `__import__` and `importlib` names can produce false positives.
Computed references remain unresolved. No target imports or scripts execute.

SCSS, Go, Rust, Java, C#, C/C++, Swift, Kotlin, Dart, PHP, Ruby, HCL and other recognized
formats remain unsupported. Ambiguous headers and unknown extensions remain unclassified.
Future broad adapters require meaningful extraction, independent capability declarations,
tests, documentation and explicit missing-capability disclosure.

## Parser selection and preparation

`uv sync --locked` installs explicitly packaged JS, TS, Bash, HTML, CSS and YAML
grammars and the Tree-sitter bindings. Python AST, JSON and TOML use the standard
library. SQL uses sqlparse for non-validating tokenization. No setup runs during scans.
Individual grammar packages were chosen over Language Pack: they provide a small,
explicit installed asset set without any lazy grammar fetching. Tree-sitter offers
shared traversal and declarative queries; the shared JS/TS import/export query is
combined with grammar-specific semantic handling. Bindings 0.25.2 and grammar
versions in uv.lock were tested together on CPython 3.12, macOS arm64.

References: [Tree-sitter binding API](https://tree-sitter.github.io/py-tree-sitter/),
[NetworkX SCC API](https://networkx.org/documentation/stable/reference/algorithms/generated/networkx.algorithms.components.strongly_connected_components.html).
The tested 0.25 binding's progress-callback route caused a native crash in validation;
the implementation uses its native one-second timeout with byte input instead.
Native parser crashes cannot be contained by Python exceptions; process isolation
remains future work. Other operating systems and architectures were not measured.
