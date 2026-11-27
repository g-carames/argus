# Implemented language capabilities

Recognition remains independent of analysis. S = limited static capability, V =
syntax validation on successful parsing, — = unavailable. Every file remains
partial, failed, excluded or unclassified under the full requested capability scope.
No row means a safety review. Missing prepared grammars are never downloaded.

| Language | Syntax | Symbols/structure | Imports/resolution | Complexity | Architecture | Security | Credentials | Framework routes | AI/cost |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Python | V, AST | S | S | S | S | SEC-001–007 | text patterns | FastAPI, Flask | AI-001/002, COST-001 |
| JavaScript, TypeScript, JSX, TSX | V, Tree-sitter | S | S | S | S | SEC-001/002/004–007 | text patterns | Express, Next app route handlers | AI-001/002, COST-001 |
| Bash, shell | V, Bash grammar | functions/structure | — | S | — | — | text patterns | — | — |
| HTML, CSS, YAML | V, prepared grammar | element/style/mapping spans | — | — | — | — | text patterns | — | — |
| JSON, JSONC, TOML | V, stdlib/JSONC lexical reader | entry counts | configuration used for JS resolution only | — | — | — | text patterns | — | — |
| SQL | tokenization only | statement counts | — | — | — | — | text patterns | — | — |
| Dockerfile | instruction recognition | instruction counts | — | — | — | — | text patterns | — | — |
| Other recognized languages and unknown UTF-8 text | — | — | — | — | — | — | text patterns only | — | — |

Python reliability rules REL-001–004 cover broad/swallowed exceptions, explicit
requests timeouts and selected blocking calls inside async functions. Cost and
performance consequences share findings through additional categories. The existing
capability enum has no separate reliability/performance/cost member; rule and category
coverage express those scopes without adding contract fields.

Credential patterns run independently of structural adapters and syntax success,
only on eligible bounded UTF-8 text without NUL bytes. Discovery exclusions still
apply. Credential-only review does not establish language/structural support; unknown
language remains unclassified and other capabilities remain unavailable. Ignored
local files, tracked-source overrides, accessible history and persistent remediation
are **not implemented**. Proper local storage cannot be distinguished from exposure
without that policy/history evidence. `credentials` stays null; candidate findings
are reported under ARGUS-CRED-001. No raw values or unkeyed credential fingerprints
are generated. Fully masked source-free evidence is used throughout.

## Framework and provider evidence

| Evidence | Implemented use | Unavailable scope |
| --- | --- | --- |
| Python FastAPI/APIRouter, Flask/Blueprint imported constructor bound to module variable | Literal decorator paths/methods, literal constructor prefix, same-module include_router prefix | General dependency injection, authentication/authorization, cross-file router mounting, conditional/multiple mounts |
| ES import of Express; module const app=express() or router=express.Router() | Literal HTTP verb declarations | CommonJS app binding, app.use/router mount composition, middleware semantics |
| next/server import and exported HTTP verb function under app/api/.../route | Literal filesystem endpoint; single [parameter] segments | pages/api handlers, catch-all/interception/group routing, rewrites, middleware, deployment |
| fetch; imported Axios default binding | Literal URL or module const string; literal method, parameter-compatible path matching | General wrappers, Axios instances/baseURL, dynamic URL interpolation, environment base URLs, service/deployment identity |
| OpenAI, Anthropic, Google, LangChain/LangGraph import evidence and recognized call suffix | Explicit output-limit indicator and calls/embeddings inside lexical loops | Provider instance/type validation, arbitrary complete/invoke wrappers, agent termination, output taint, prompt injection, sensitive-data flow, human approval |

Provider recognition is syntactic evidence, not proof a particular client variable
belongs to the imported SDK. Supported Python import roots are openai, anthropic,
google, langchain, langgraph; JS exact module names are openai, @anthropic-ai/sdk,
@google/generative-ai, @google/genai, langchain, @langchain/openai,
@langchain/langgraph. Exact suffixes and keyword checks are in the generated catalog.
Recognizable wrappers now propagate operation kinds through unique static calls; arbitrary/mock complete methods remain unsupported as provider evidence.
No AI alignment, agent safety or prompt-injection resistance is certified.

## Dependency and call extraction

Primary extraction includes module/class/function/declaration symbols, containment,
locations, static imports/exports, CommonJS, literal dynamic imports, re-exports,
type-only and conditional imports. Module import resolution supports relative omitted
extensions, index candidates, JS-to-TS extension alternatives, local TS/JS configs,
baseUrl, zero/one-star paths, local extends chains, workspace declarations and package
exports. Details and bounds are in [configuration](configuration.md).

Calls preserve declaration evidence and inferred unique direct/imported bindings,
including straightforward Python import aliases, JS named imports, module-qualified
functions and local class instantiation. Unknown bindings retain unresolved call
edges. Generic methods, receiver type inference, inheritance, default export binding,
barrel symbol forwarding, destructured/CommonJS call bindings and full lexical
shadowing/closure/assignment semantics are not complete. Call relationships do not
enter the established module-import metric projection. HTTP declarations and inferred
matches retain evidence and locations; matching route strings never proves runtime
communication. Ambiguous matches have no invented target.

Bash uses a subset grammar for generic shell; zsh/ksh constructs can fail. Embedded
HTML script/style, CSS preprocessors, YAML flow-entry symbols, executable configs and
cross-language type semantics are unavailable. JSONL multi-document input fails
single-document validation. SQL tokenization is not SQL syntax validation. Dockerfile
arguments/stages/heredocs/embedded shell are not semantically analyzed.

## Prepared parsers and isolation

`uv sync --locked` prepares individually packaged JS, TS, Bash, HTML, CSS and YAML
grammars with Tree-sitter 0.25 bindings. No Language Pack lazy fetching is used.
Python AST, JSON/TOML stdlib and SQL sqlparse remain local. The previously observed
native crash was associated with the binding's progress-callback route; that route
remains unused. Native parse/extraction now executes in a short-lived trusted process,
with one-second parser timeout, three CPU seconds, five-second parent deadline and
core dumps disabled. Abnormal exits/timeouts become file failures; source/exception
text is withheld. This contains failures rather than claiming the upstream native
bug is fixed. No hard memory cap; Python/JSON/TOML/SQL are not isolated. POSIX CLI on
macOS arm64 is measured; other platforms and multithreaded spawn are not validated.


## Milestone 5.1 independent semantic capabilities

| Language | Control flow | Local/cross-file data flow | Summaries | Bounds | Source-to-sink |
| --- | --- | --- | --- | --- | --- |
| Python | partial structured CFG | unique functions/constants, arguments/returns, simple classes | bounded local + resolved CALL graph | literal/range/slice, numeric clamps, simple counters | bounded input/framework/model/environment influence |
| JavaScript, TypeScript, JSX, TSX | restricted structured lowering | assignments, top-level functions/arguments/returns and named imports | bounded local + resolved CALL graph | dense arrays/slice, conservative mutation invalidation | possible influence through supported flow; no general request-source verification |
| Other formats | unavailable | unavailable | unavailable | unavailable | unavailable |

Every column is an independent partial capability, never complete language support.
Python OpenAI/Anthropic and requests/httpx constructors, simple class fields/factories
and narrow Flask-Login/FastAPI bearer-presence observations supplement legacy syntax.
General authorization, Express middleware ordering, database limits, retry/backoff,
JS closures/prototypes/getters and scheduling remain unavailable. Existing route and
provider tables above describe base syntactic extraction; semantic refinements and
all exclusions are in [Milestone 5.1](milestone-5.1.md). No runtime safeguard proof.

## Milestone 6.1 capability refinements

| Capability | Python | JavaScript / TypeScript / JSX / TSX |
| --- | --- | --- |
| Constructed OpenAI Responses operation recognition | Tested aliases, module instances, imported instances, simple instance attributes, resolved wrappers | Existing bounded lowering plus exact constructed OpenAI receiver metadata; partial |
| Timeout applicability | Tested requests / HTTPX, documented defaults, positive float/int settings, complete HTTPX phase objects, request overrides, disabled/unknown settings | Unavailable; no new HTTP timeout support claimed |
| SQL value discrimination | Tested constant construction, builtin integer conversion, joins/reassignment, local/imported flow, unknown/untrusted inputs, simple str.format, parameter argument observation for sqlite3/psycopg cursor APIs | Constructed-query candidates retained; coercion/sanitizer discrimination unavailable |
| Independent semantic observations | Tested bounded arguments/returns/iteration, timeout state, SDK identity, authentication registration, invalidation and relevant call relationships | Restricted lowering only; gaps remain explicit |
| General authorization, database limits, retry enforcement | Unavailable | Unavailable |

Parser availability remains independent of every capability. Authentication
registration does not establish effective authentication, authorization or caller
protection. See the exact regression scope in `tests/test_corrections_m61.py`.

## Milestone 6.3B information preservation

Python's bounded structured interpreter separates explicit returns, raised exits
and fallthrough; the existing JS-family lowering consumes the same exit contract.
Neither implements a general exception/CFG solver. Handler/finally statements remain
unsupported and cannot establish successful-return bounds. No new language or
framework capability is claimed.

Source-qualified caller/argument/formal/result identities and calculated assignment,
loop, receiver and unknown facts survive projection. Existing resolved Python
receivers reconcile with the final call graph; alternatives remain ambiguous.
External function entries stay unknown. External method/constructor entry coverage
is not comprehensive. See [6.3B](milestone-6.3B.md) and the installed-CLI oracles.
