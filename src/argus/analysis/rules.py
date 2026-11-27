"""Central rule metadata and deterministic evaluation; no source-derived instructions."""
from dataclasses import dataclass, replace
from ..models.analysis import Finding
from ..models.base import Category, Confidence, Provenance, Severity
from ..models.source import Evidence
from ..privacy import identity
from .parsing import PRIMARY

@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: Category
    parameter: str
    default: int
    methodology: str
    positive: str
    negative: str
    remediation: str
    validation: str
    capabilities: tuple[str, ...]
    rationale: str = 'Concentrated responsibilities, branching or dependency cycles may increase maintenance and change coordination risk.'
    evaluator: str = 'structural'
    version: str = '1.0.0'
    secondary_categories: tuple = ()
    severity: str = 'medium'
    confidence: str = 'medium: exact structural measurement with heuristic architectural interpretation'
    status: str = 'implemented'
    tests: str = 'tests/test_analysis_rules.py'
    languages: tuple = PRIMARY
    contextual_tests: str | None = None
    contextual_analysis: str = 'No rule-specific semantic refinement; structural measurement or original pattern retained. Semantic applicability is undetermined where unavailable.'
    limitations: str = 'Thresholds are configurable heuristics, not universal architecture standards. Static incomplete graphs and generated code can cause false positives or omissions.'

REGISTRY = (
    Rule('ARGUS-ARCH-001', 'Circular module dependencies', Category.ARCHITECTURE, 'cyclic_component_size', 0,
         'NetworkX strongly connected components; emit once per cyclic component, including self imports.',
         'a imports b; b imports a', 'a imports b; b imports nothing',
         'Review module responsibilities and introduce an appropriate dependency boundary.',
         'Re-scan equivalent complete scope and verify no cyclic component remains.', ('dependency_resolution',)),
    Rule('ARGUS-ARCH-002', 'Excessive incoming coupling', Category.ARCHITECTURE, 'incoming_coupling', 10,
         'Count distinct incoming resolved local module neighbors; strict greater-than threshold.',
         '11 distinct modules import a shared module', '10 or fewer importing modules',
         'Review shared responsibilities and the stability of the public interface.',
         'Confirm reviewed incoming coupling meets the chosen threshold or record a justified exception.', ('dependency_resolution',)),
    Rule('ARGUS-ARCH-003', 'Excessive outgoing coupling', Category.ARCHITECTURE, 'outgoing_coupling', 10,
         'Count distinct outgoing resolved local module neighbors; strict greater-than threshold.',
         'A module imports 11 distinct local modules', '10 or fewer local dependencies',
         'Separate responsibilities and reduce unnecessary direct dependencies.',
         'Re-scan and review outgoing dependencies against the chosen threshold.', ('dependency_resolution',)),
    Rule('ARGUS-MAINT-001', 'Excessive function length', Category.MAINTAINABILITY, 'function_length', 50,
         'Inclusive physical start/end span of each function or method, including comments and nested definitions; strict greater-than.',
         'Function spans 51 physical lines', 'Function spans 50 physical lines',
         'Extract cohesive responsibilities while preserving behavior.',
         'Review function spans and run appropriate project behavioral tests separately.', ('structural_analysis',)),
    Rule('ARGUS-MAINT-002', 'Excessive module length', Category.MAINTAINABILITY, 'module_length', 500,
         'Physical file lines including comments and blank lines; strict greater-than.',
         'Module has 501 physical lines', 'Module has 500 physical lines',
         'Review whether cohesive responsibilities belong in separate modules.',
         'Confirm module boundaries and measured lengths match the chosen policy.', ('structural_analysis',)),
    Rule('ARGUS-MAINT-003', 'Excessive nesting depth', Category.MAINTAINABILITY, 'nesting_depth', 4,
         'Maximum nested control structures per function; nested function/class bodies excluded; strict greater-than.',
         'Five nested conditional/loop/try structures', 'Four or fewer nested control structures',
         'Consider guard clauses and cohesive helper functions.',
         'Confirm nesting meets policy and behavior remains covered by project tests.', ('complexity_analysis',)),
    Rule('ARGUS-MAINT-004', 'Elevated cyclomatic complexity indicator', Category.MAINTAINABILITY, 'cyclomatic_complexity', 10,
         'One plus decisions: Python if/if-expression/loops/handlers/comprehensions/match cases and boolean alternatives; JS conditions/loops/catches/cases/ternaries/short-circuit operators. Nested scopes excluded; strict greater-than.',
         'Function indicator exceeds 10', 'Straight-line function indicator is 1',
         'Review branching responsibilities and simplify independently testable paths.',
         'Recompute the indicator and review branch-focused tests separately.', ('complexity_analysis',)),
    Rule('ARGUS-ARCH-004', 'Concentration of architectural dependencies', Category.ARCHITECTURE, 'degree_centrality', 1,
         'Directed unweighted import graph with n extracted primary modules (including isolated nodes). For n>1, degree_centrality=(in_degree+out_degree)/(n-1); singleton 0. Each self-loop contributes one to each directional degree. Strict greater-than; default 1 means total degree > n-1, not a normalized safety/importance score. Shares degree observations with ARCH-002/003/005; overlapping findings are correlated indicators, not independent defects.',
         'A bidirectional hub has centrality greater than 1', 'Disconnected modules have centrality 0',
         'Review hub stability, layering and dependency direction.',
         'Review graph coverage and confirm a justified hub or reduced concentration.', ('dependency_resolution',)),
    Rule('ARGUS-ARCH-005', 'Potentially oversized or overly coupled module', Category.ARCHITECTURE, 'total_coupling', 20,
         'total_coupling=in_degree+out_degree (reciprocal directions count separately, each self-loop contributes two). Strict total_coupling > threshold OR physical module_length > configured module_length (default 500). Overlaps ARCH-002/003/004 degree observations and MAINT-002 size observation; no independent defect or cumulative severity is implied.',
         'A module has total coupling 21 or more, or exceeds configured module length',
         'A short module has total coupling at most 20',
         'Review module cohesion and split independent responsibilities when appropriate.',
         'Review coupling and module size against policy with equivalent scan coverage.', ('structural_analysis', 'dependency_resolution')),
)
# Pattern rules use a configurable occurrence threshold (default zero), per site.
RISK_SPECS = (
 ('SEC-001','Dynamic code execution',Category.SECURITY,(), 'Direct eval/exec calls (Python) or eval/Function calls (JS family).', 'eval(user_input)', 'literal parsing without execution'),
 ('SEC-002','Shell execution boundary',Category.SECURITY,(), 'Python os.system/os.popen or subprocess calls with literal shell=True; JS child_process exec/execSync imported binding.', 'subprocess.run(command, shell=True)', 'subprocess.run([program, argument])'),
 ('SEC-003','Unsafe deserialization',Category.SECURITY,(), 'Python pickle.load/loads, dill.load/loads, yaml.unsafe_load and yaml.load without Loader keyword resolving to yaml.SafeLoader or yaml.CSafeLoader. Positional loaders and expanded keyword options are not resolved and can be flagged.', 'pickle.loads(data)', 'json.loads(data)'),
 ('SEC-004','Dynamically constructed SQL',Category.SECURITY,(), 'execute/executemany/query first argument is a Python f-string, addition or percent expression, or JS template interpolation/addition.', 'cursor.execute(f"SELECT {value}")', 'cursor.execute("SELECT ?", (value,))'),
 ('SEC-005','Legacy cryptographic digest',Category.SECURITY,(), 'Python hashlib.md5/sha1 or JS crypto.createHash with literal md5/sha1.', 'hashlib.md5(data)', 'hashlib.sha256(data)'),
 ('SEC-006','Explicitly disabled TLS verification',Category.SECURITY,(), 'Python requests HTTP verb calls with literal verify=False; JS object pair rejectUnauthorized:false.', 'requests.get(url, verify=False)', 'requests.get(url, verify=True)'),
 ('SEC-007','Credentialed permissive CORS',Category.SECURITY,(), 'Python FastAPI/Starlette CORSMiddleware passed to add_middleware with allow_origins containing literal * and allow_credentials=True; JS imported cors call with origin true or * and credentials true.', 'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)', 'app.add_middleware(CORSMiddleware, allow_origins=["https://trusted.invalid"], allow_credentials=True)'),
 ('REL-001','Broad exception handler',Category.RELIABILITY,(), 'Python bare except or handler naming Exception/BaseException, including tuples.', 'except Exception: recover()', 'except ValueError: recover()'),
 ('REL-002','Silently swallowed exception',Category.RELIABILITY,(), 'Python handler body consists exclusively of pass or constant expression statements; supersedes broad-handler finding at the same handler.', 'except ValueError: pass', 'except ValueError: raise'),
 ('REL-003','Missing explicit request timeout',Category.RELIABILITY,(), 'Python requests.get/post/put/delete/patch/head/options/request calls without timeout keyword; **kwargs makes timeout unknown and suppresses finding.', 'requests.get(url)', 'requests.get(url, timeout=5)'),
 ('REL-004','Blocking call in async function',Category.RELIABILITY,('performance_scalability',), 'Python time.sleep or requests HTTP call lexically inside async function; nested synchronous functions excluded.', 'async def f(): time.sleep(1)', 'async def f(): await asyncio.sleep(1)'),
 ('COST-001','Database call inside loop',Category.COST,('performance_scalability',), 'execute/executemany/query call lexically within for/while (Python includes async for); nested function scopes reset loop context.', 'for row in rows: cursor.execute(query, row)', 'cursor.executemany(query, rows)'),
 ('AI-001','Model call without explicit output limit',Category.AI,('cost_efficiency',), 'Provider import evidence: Python roots openai, anthropic, google, langchain, langgraph; JS exact modules openai, @anthropic-ai/sdk, @google/generative-ai, @google/genai, langchain, @langchain/openai, @langchain/langgraph. Call suffixes .chat.completions.create, .completions.create, .messages.create, .generate_content, .generateContent. No explicit max_tokens, max_completion_tokens, max_output_tokens, generationConfig or config keyword/object key. Python **kwargs and JS spread/non-object arguments suppress unknown configuration. Presence of a config key suppresses detection without validating its contents. Object/client type is not resolved.', 'client.chat.completions.create(model="m", messages=[])', 'client.chat.completions.create(max_tokens=100)'),
 ('AI-002','Model or embedding call inside loop',Category.AI,('cost_efficiency',), 'Same provider-import and model-call suffix evidence as AI-001, plus embedding suffixes .embeddings.create, .embed_content, .embedContent. Call lexically within Python for/async-for/while or JS for/for-in/while/do; function boundaries reset loop context. Import evidence does not prove receiver SDK type. No inference from a generic complete/invoke function name.', 'for item in items: client.embeddings.create(input=item)', 'client.embeddings.create(input=items)'),
)
REGISTRY += tuple(Rule('ARGUS-'+key, name, cat, 'occurrence_'+key.lower().replace('-', '_'), 0,
    method, positive, negative, 'Review the observed boundary; use safe APIs, explicit validated limits and appropriate batching or error handling.',
    'Re-scan the same scope and verify the risky pattern is removed or document a reviewed exception.',
    ('security_rules' if key.startswith('SEC') else 'ai_specific_analysis' if key.startswith('AI') else 'structural_analysis',),
    evaluator='pattern', confidence='medium: exact named syntax observed; runtime binding, exploitation and omitted safeguards unverified', secondary_categories=secondary, languages=PRIMARY if key in ('SEC-001','SEC-002','SEC-004','SEC-005','SEC-006','SEC-007','COST-001','AI-001','AI-002') else ('python',),
    rationale='Observed static patterns may expose data, execution boundaries or resources. Cost consequences are potential, not measured expense.',
    tests='tests/test_risk_rules.py',
    limitations='Initial syntactic matching; contextual supplement applies only where explicitly documented. Aliases supported for Python imports and JS child_process named imports. General shadowing, dynamic indirect calls, arbitrary wrappers, framework authentication and runtime configuration are not resolved. Missing local limits may be supplied elsewhere.')
    for key,name,cat,secondary,method,positive,negative in RISK_SPECS)
REGISTRY += (Rule('ARGUS-CRED-001','Potential embedded credential',Category.CREDENTIALS,'credential_occurrences',0,
    'Bounded UTF-8 text: recognizable provider tokens, PEM private-key headers, or quoted secret assignments (including prefixed names) of at least 8 characters, or unquoted .env secret assignments of at least 8 non-whitespace characters. One finding per matching line; no raw evidence or value-derived ID. Token regex families: sk-(proj-|ant-)? suffix length >=20, AIza suffix >=30, AKIA/ASIA +16, gh[pousr]_ suffix >=20, github_pat_ suffix >=20, xox[baprs]- suffix >=20. PEM private-key header variants: RSA, EC, OPENSSH, DSA, ENCRYPTED or unqualified. Assignment names end in password/passwd/api_key/apikey/secret/secret_key/access_token/auth_token/token; optional underscore prefix. Placeholders beginning ${, <, your_, your-space, example, placeholder, changeme, test_, test-, dummy, ***, [redacted] are suppressed for assignments; provider-token matches are retained.',
    'api_key = "synthetic-value"', 'api_key = os.environ["API_KEY"]',
    'Remove exposed material and investigate rotation and revocation separately with the provider using a trusted manual process.',
    'Confirm source removal and independently establish appropriate revocation; removal alone is insufficient.', ('credential_detection',),
    evaluator='pattern', confidence='medium: unvalidated textual candidate; no authentication or exposure verification', languages=('all eligible UTF-8 text',), tests='tests/test_risk_rules.py',
    rationale='Embedded secrets may permit unauthorized use. Values are never reported.',
    limitations='Heuristic candidates, not validated credentials. Templates can be false positives. Discovery exclusions apply; ignored local configuration, tracked-file override, history, persistence, reuse and remediation transitions are unavailable.'),)
# Contextual methodology supplements the original observation; no new rules.
CONTEXT_METHODS = {
    'ARGUS-AI-001': 'Python positive integer token limits propagated through simple local assignments, arguments and defaults. Unknown/nonpositive supplied limits produce retained candidates with unverified applicability. Nested config dictionaries are not verified. JS remains syntactic.',
    'ARGUS-AI-002': 'Python bounded literal/range/slice iteration domains, branch joins and local argument/return flow; nested domains multiply. Mutation/unknown calls invalidate bounds. All primary languages propagate observed operation kinds through uniquely resolved call relationships, depth 4; arbitrary names/mock SDKs never establish provider semantics. Retain bounded observations and original severity; bounds alone do not establish acceptable impact.',
    'ARGUS-COST-001': 'Same bounded iteration and operation-summary methodology as AI-002 for execute/executemany/query candidates. No receiver/database typing or database result-limit enforcement. Bounded observations remain findings at their original severity; bounds do not establish acceptable cost.',
    'ARGUS-REL-003': 'Python positive integer timeout values through local assignments, function parameters and defaults. Configured but unknown/nonpositive timeouts produce unverified candidates. **kwargs remains unknown under inherited syntax scope; requests sessions, client constructors and external infrastructure unavailable.',
    'ARGUS-SEC-004': 'Python dynamically constructed SQL flags propagate through simple assignments, arguments and returns, including possible branch joins. Parameterized literals produce no syntax candidate. Unknown sanitizer calls do not establish safety; no SQL dialect, driver or escaping effectiveness verification.',
    'ARGUS-SEC-001': 'Python input() source influence propagates through simple local assignments, arguments, returns and unknown function calls to direct execution sinks. Evidence does not prove exploitability or sanitizer effectiveness; original execution observation always retained.',
    'ARGUS-CRED-001': 'Additionally recognize generic JS-family browser key literal assignments (>=16 characters) only with a credential-like value marker secret/api-key/access-token/browser-key, fetch call and JSON.stringify use of key. Ordinary key values and naming/comments alone do not qualify. No raw value retained; potential exposure only.',
}
for _rule in ('ARGUS-AI-001','ARGUS-AI-002','ARGUS-COST-001','ARGUS-REL-003','ARGUS-SEC-004','ARGUS-SEC-001'):
    CONTEXT_METHODS[_rule] += ' Milestone 5.1 extends this with bounded uniquely resolved cross-file function/constant/alias/re-export flow, keyword-only defaults, unknown external-argument entries, and separate JS-family restricted syntax lowering. Simple Python receiver/constructor/factory identities and requests.Session/httpx constructor timeouts are tracked; request overrides take precedence. Python numerical min/max clamps and monotonic final-increment counters can bound per-invocation domains. Early returns join rather than discard alternate values. Async suspension, mutation, unknown calls, recursion and exhausted budgets cannot establish safety. Python FastAPI input/Flask request influence and narrow Flask-Login/FastAPI bearer-presence observations are retained without authorization or runtime-enforcement claims. See docs/milestone-5.1.md and tests/test_semantic_cross_file.py for exact exclusions and paired tests.'
REGISTRY = tuple(replace(r, version='1.2.0', contextual_analysis=CONTEXT_METHODS[r.id],
    contextual_tests='tests/test_semantic_context.py',
    limitations=r.limitations+' Contextual refinement is bounded and partial; see docs/milestone-5.1.md for exact supported scopes and budgets.')
    if r.id in CONTEXT_METHODS else r for r in REGISTRY)
# Corrective release metadata replaces superseded methodology rather than appending claims.
CORRECTIONS = {
    'ARGUS-AI-001': ('Model operation without established output limit',
        'Exact constructed OpenAI/AsyncOpenAI Responses, chat completion, completion and embedding receivers and Anthropic/AsyncAnthropic messages use operations.py metadata. Responses accepts max_output_tokens; chat accepts max_tokens/max_completion_tokens; completions and messages accept max_tokens. Positive numerical limits through bounded aliases/arguments/returns are established. Imported suffix candidates with unresolved receivers remain possible, not genuine SDK recognition. Generic create/complete/generate names alone never establish provider identity.'),
    'ARGUS-AI-002': ('Model or embedding call inside loop',
        'Same operation registry and receiver distinctions as AI-001. Include Responses create. Preserve loop observations and independent unknown-caller contexts; collection bounds do not prove acceptable cost. Bounded graph summaries propagate operation candidates, never validated safeguards.'),
    'ARGUS-REL-003': ('Request without an established applicable timeout',
        'Recognized requests and HTTPX methods, client aliases, simple instance attributes, imported instances and statically resolved wrappers. HTTPX documented default is five seconds of network inactivity, not total duration. Constructor defaults and explicit request overrides are distinguished. Positive integer/float and complete HTTPX Timeout phase settings establish applicability; None disables, unknown/spread/partial settings remain uncertain. Requests has no default timeout; positive request timeouts and positive connect/read tuples apply. Session constructor timeout is not supported by Requests. External infrastructure and arbitrary wrappers remain unverified.'),
    'ARGUS-SEC-004': ('Dynamic SQL with unresolved string influence',
        'execute/executemany/query candidates: constructed SQL is an observation, not proof of vulnerability. Python constant-only construction and statically established builtin-int flows produce semantic observations without injection candidates; ambiguous/untrusted strings, dynamic identifiers and unknown sanitizers retain candidates. Reassignments and joins preserve uncertainty; one constrained caller does not protect unknown entries. Recognize parameter arguments on resolved sqlite3/psycopg/psycopg2 cursor APIs; binding does not sanitize separately constructed query text. No general taint, SQL dialect, identifier quoting or sanitizer verification.'),
    'ARGUS-CRED-001': ('Potential exposed credential material',
        'Bounded UTF-8 text uses TOKEN and ASSIGNMENT regexes in risks.py, PEM private-key headers, .env assignments and narrow browser-key contexts. Candidate-value full matches to the placeholder grammar are classified separately and do not create findings. Test/mock/example names or comments never establish a placeholder. Recognized patterns and plausible assignments remain potential exposure, including documentation; validity is unverified. Classification records omit values and value-derived hashes. No history or persistent lifecycle tracking.'),
}
REGISTRY=tuple(replace(r,version='1.3.0',name=CORRECTIONS[r.id][0],methodology=CORRECTIONS[r.id][1],
    contextual_analysis=CORRECTIONS[r.id][1]+' Independent typed semantic observations remain available without findings. See docs/milestone-6.1.md.',
    contextual_tests='tests/test_corrections_m61.py',
    limitations='Bounded static scope only; runtime behavior, arbitrary dispatch and general safeguards remain unverified. Exhausted budgets remain disclosed. SQL constant/integer refinement is Python-specific; JS-family coercion remains unresolved. No independent reevaluation metrics are claimed.')
    if r.id in CORRECTIONS else r for r in REGISTRY)
# Information-preservation correction: no new rules, parameters or severities.
SEMANTIC_CORRECTIONS={'ARGUS-AI-001','ARGUS-AI-002','ARGUS-COST-001','ARGUS-REL-003','ARGUS-SEC-004','ARGUS-SEC-001','ARGUS-CRED-001'}
REGISTRY=tuple(replace(r,version='1.4.0',
    methodology=(r.methodology+' Occurrence-level recognized token spans take precedence over enclosing placeholder hints; exact placeholders alone remain filtered.' if r.id=='ARGUS-CRED-001' else r.methodology),
    contextual_analysis=(r.contextual_analysis+' Milestone 6.3B separates raised exits from successful returns, preserves source-qualified caller/actual/formal/result linkage, reconciles computed receiver targets before graph assessment, and scopes unsupported-control evidence. Unknown returns and external entries remain uncertain; handlers/finally, predicate refinement and exceptional call continuations remain unsupported.'),
    contextual_tests='tests/integration/test_semantic_cli.py')
    if r.id in SEMANTIC_CORRECTIONS else r for r in REGISTRY)
CONTROL_FLOW_RULES={'ARGUS-AI-001','ARGUS-AI-002','ARGUS-COST-001','ARGUS-REL-003','ARGUS-SEC-001','ARGUS-SEC-004'}
REGISTRY=tuple(replace(r,version='1.5.0',
    contextual_analysis=r.contextual_analysis+' Milestone 6.3C replaces structured execution with a bounded CFG worklist: Python builtin numeric/length/membership predicates, loop widening, break/continue, builtin exception handlers and finally overrides. Only abstract-reachable operations contribute contextual candidates; zero-iteration/terminated paths retain syntax relationships without reachable risk candidates. Unknown protocols/effects remain conservative; unverified unknown-receiver slice parameters do not establish loop or operation bounds. Only computed simple-constructor/read-only-method effects and qualified library operations receive narrow effect treatment, never suffix-based purity. Decorated and async body facts are distinct from effective invocation guarantees. No general heap, recursive summaries or JS predicate/handler parity.',
    contextual_tests='tests/integration/test_control_flow_cli.py') if r.id in CONTROL_FLOW_RULES else r for r in REGISTRY)
BY_ID = {r.id: r for r in REGISTRY}


def evaluate(rule, value, scope, location, evidence, threshold, relationships=(), parameter=None, affected=()):
    eid = identity('evidence', rule.id + ':' + scope)
    evidence.append(Evidence(id=eid, observation=f'{parameter or rule.parameter}={value}; threshold={threshold}; structural observation only.',
        producer=rule.id, producer_version=rule.version, provenance=Provenance.OBSERVED,
        confidence=Confidence.HIGH, locations=(location,)))
    return Finding(id=identity('finding', rule.id + ':' + scope), rule_id=rule.id, rule_version=rule.version,
        category=rule.category, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
        provenance=Provenance.HEURISTIC, title=rule.name, explanation=rule.methodology + ' This may increase maintenance or change coordination risk.',
        remediation=rule.remediation, evidence_ids=(eid,), affected_ids=affected or (scope,), locations=(location,),
        corrective_actions=(rule.remediation,), acceptance_criteria=(rule.validation,),
        relationship_ids=relationships, limitations=(rule.limitations,))
