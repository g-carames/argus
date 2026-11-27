"""Bounded abstract interpretation over a restricted, source-free syntax IR.

Unknown is absorbing at joins. Bounds describe a single iteration domain, not cost.
Only positive evidence can establish a safeguard; naming is never validation.
"""
import ast
import copy
import re
import math
from dataclasses import dataclass, field, replace
from .semantic_contracts import Point, Outcomes, ExitKind, FactState, SiteLedger, join_returns
from ..privacy import identity
from .parsing import PRIMARY
from .operations import resolve_operation, MODEL_SUFFIXES, EMBEDDING_SUFFIXES, HTTP_TARGETS


@dataclass(frozen=True)
class Budgets:
    depth: int = 4
    contexts: int = 128
    cfg_nodes: int = 2048
    iterations: int = 4096
    paths: int = 64
    summary_expansions: int = 256
    modules: int = 128
    receiver_depth: int = 8

    def __post_init__(self):
        if any(type(v) is not int or not 1 <= v <= 100000 for v in vars(self).values()):
            raise ValueError('Invalid semantic budget')


@dataclass(frozen=True)
class Value:
    state: str = 'unknown'  # definite, possible, conflicting, unknown
    number: int | float | None = None
    size: int | None = None
    size_verified: bool = False
    taint: bool = False
    dynamic_sql: bool = False
    receiver: str | None = None
    constructed: bool = False
    timeout: int | float | None = None
    timeout_state: str = "unknown"
    literal_string: bool = False
    sql_identifier: bool = False
    sql_value: str = "unknown"  # constant, integer, unknown; never stores query text
    origins: tuple = ()
    attributes: tuple = ()
    sensitive: bool = False
    minimum: int | float | None = None
    maximum: int | float | None = None
    object_id: tuple = ()
    provenance_truncated: bool = False
    receiver_options: tuple[str, ...] = ()
    value_id: str | None = None
    result_id: str | None = None
    boolean: bool = False
    truth: bool | None = None
    numeric: bool = False
    integer: bool = False
    collection_kind: str | None = None
    size_lower: int | None = None
    finite: bool = False
    constraint_origins: tuple = ()
    constraint_must: bool = False
    constraint_value_id: str | None = None
    normal_result: bool = True
    exception_types: tuple[str, ...] = ()
    incomplete_result: bool = False
    effects_may_mutate: bool = True

    def join(self, other):
        if self == other: return self
        same_facts=replace(self,origins=(),provenance_truncated=False,value_id=None,result_id=None)==replace(other,origins=(),provenance_truncated=False,value_id=None,result_id=None)
        return Value(state=self.state if same_facts else 'unknown' if 'unknown' in (self.state, other.state) else 'conflicting',
                     boolean=self.boolean and other.boolean,truth=self.truth if self.truth==other.truth else None,
                     size_verified=self.size_verified and other.size_verified,
                     numeric=self.numeric and other.numeric,integer=self.integer and other.integer,
                     collection_kind=self.collection_kind if self.collection_kind==other.collection_kind else None,
                     size_lower=min(self.size_lower,other.size_lower) if self.size_lower is not None and other.size_lower is not None else None,
                     finite=self.finite and other.finite,
                     constraint_origins=tuple(sorted(set(self.constraint_origins)|set(other.constraint_origins))),
                     constraint_must=self.constraint_must and other.constraint_must,
                     constraint_value_id=self.constraint_value_id if self.constraint_value_id==other.constraint_value_id else None,
                     normal_result=self.normal_result or other.normal_result,
                     exception_types=tuple(sorted(set(self.exception_types+other.exception_types))),
                     incomplete_result=self.incomplete_result or other.incomplete_result,effects_may_mutate=self.effects_may_mutate or other.effects_may_mutate,
                     size=max(self.size, other.size) if self.size is not None and other.size is not None else None,
                     number=self.number if self.number == other.number else None,
                     taint=self.taint or other.taint, dynamic_sql=self.dynamic_sql or other.dynamic_sql,
                     receiver=self.receiver if self.receiver == other.receiver else None,
                     value_id=self.value_id if self.value_id==other.value_id else None,
                     result_id=self.result_id if self.result_id==other.result_id else None,
                     receiver_options=tuple(sorted(set(self.receiver_options+other.receiver_options+tuple(x for x in (self.receiver,other.receiver) if x)))),
                     constructed=self.constructed and other.constructed,
                     timeout=self.timeout if self.timeout == other.timeout else None,
                     timeout_state=self.timeout_state if self.timeout_state == other.timeout_state else "unknown",
                     sql_value=self.sql_value if self.sql_value == other.sql_value else "unknown",
                     literal_string=self.literal_string and other.literal_string, sql_identifier=self.sql_identifier or other.sql_identifier,
                     origins=tuple(sorted(set(self.origins + other.origins)))[:32],
                     provenance_truncated=self.provenance_truncated or other.provenance_truncated or len(set(self.origins+other.origins))>32,
                     attributes=self.attributes if self.attributes==other.attributes else (),
                     object_id=self.object_id if self.object_id==other.object_id else (),
                     sensitive=self.sensitive or other.sensitive,
                     minimum=min(self.minimum,other.minimum) if self.minimum is not None and other.minimum is not None else None,
                     maximum=max(self.maximum,other.maximum) if self.maximum is not None and other.maximum is not None else None)


UNKNOWN = Value()


@dataclass(frozen=True)
class Site:
    line: int
    owner: str
    operation: str
    loops: int = 0
    upper_bound: int | None = None
    limit: bool = False
    tainted: bool = False
    dynamic_sql: bool = False
    context: tuple[int, ...] = ()
    conditional: bool = False
    configuration_observed: bool = False
    expanded: bool = False
    origins: tuple = ()
    sensitive: bool = False
    receiver_resolved: bool = False
    safeguards: tuple = ()
    timeout_state: str = "unknown"
    sql_value: str = "unknown"
    parameter_binding: bool = False
    sql_identifier: bool = False
    operation_id: str | None = None
    column: int = 1
    context_id: str | None = None
    callsite_id: str | None = None
    call_path_ids: tuple[str, ...] = ()
    formal_id: str | None = None
    actual_id: str | None = None
    origin_value_id: str | None = None
    result_id: str | None = None
    value_id: str | None = None
    argument_position: int | None = None
    binding_kind: str | None = None
    target_id: str | None = None
    candidate_target_ids: tuple[str, ...] = ()
    fact_state: FactState = FactState.KNOWN
    exit_channels: tuple[ExitKind, ...] = ()
    incomplete: tuple[str, ...] = ()
    bound_supported: bool = True
    lower_bound: int | None = None
    finite: bool = False
    constraint_origins: tuple = ()
    observation_scope: str = 'effective_invocation'
    reachability: str = 'potential'
    operation_upper_bound: int | None = None
    loop_ids: tuple[int, ...] = ()
    base_loop_bounds: tuple = ()
    constrained_value_id: str | None = None
    constraint_applicability: str = 'unverified'


@dataclass
class SemanticFacts:
    sites: list = field(default_factory=list)
    cfg: tuple = ()
    incomplete: tuple = ()
    # Function summaries are source-free sets of observed operation kinds by owner.
    summaries: dict = field(default_factory=dict)
    program: object = None  # Sanitized syntax IR; never report or serialize into reports.
    language: str = 'python'
    scope_gaps: dict = field(default_factory=dict)
    statistics: dict = field(default_factory=dict)
    effects: dict = field(default_factory=dict)
    projection_accounting: dict = field(default_factory=dict)


def column(node):
    return getattr(node,'argus_column',getattr(node,'col_offset',0)+1)


def collect(file, parsed, facts, budgets=Budgets()):
    if parsed.language == 'python':
        lines=parsed.content.splitlines()
        for node in ast.walk(parsed.tree):
            if hasattr(node,'lineno') and node.lineno<=len(lines):
                node.argus_column=len(lines[node.lineno-1][:node.col_offset].decode('utf-8',errors='replace'))+1
        return PythonFlow(parsed, facts, budgets).run()
    if parsed.language not in PRIMARY: return SemanticFacts()
    from .javascript import lower
    program, gaps = lower(parsed)
    flow = PythonFlow(type('IR', (), {'tree': program})(), facts, budgets)
    flow.language = parsed.language
    flow.gaps.update(gaps)
    return flow.run()


def identifier_interpolation(node):
    if getattr(node,'argus_sql_identifier',False): return True
    if not isinstance(node,ast.JoinedStr): return False
    return any(isinstance(left,ast.Constant) and isinstance(left.value,str) and
        re.search(r'(?i)\b(?:FROM|JOIN|UPDATE|INTO|TABLE|ORDER\s+BY|GROUP\s+BY)\s*$',left.value) and
        isinstance(right,ast.FormattedValue) for left,right in zip(node.values,node.values[1:]))


def sanitized(tree):
    """Copy a bounded syntax tree, discarding all source string/byte literals."""
    tree = copy.deepcopy(tree)
    for n in ast.walk(tree):
        if identifier_interpolation(n): n.argus_sql_identifier=True
        if isinstance(n,ast.Dict):
            n.keys=[ast.Name(id=k.value,ctx=ast.Load(),argus_literal_key=True) if isinstance(k,ast.Constant) and k.value in ('timeout','max_tokens','max_completion_tokens','max_output_tokens','config','generationConfig','maxOutputTokens','auto_error') else k for k in n.keys]
        if isinstance(n, ast.Constant) and type(n.value) not in (int, float, bool, type(None)):
            n.argus_string = isinstance(n.value,str)
            n.value = None
            n.argus_literal = True
    tree.argus_sanitized=True
    return tree


class PythonFlow:
    def __init__(self, parsed, facts, budgets):
        self.tree, self.facts, self.b = parsed.tree if getattr(parsed.tree,'argus_sanitized',False) else sanitized(parsed.tree), facts, budgets
        self.language = 'python'
        self.workspace = None
        self.imported = {}
        self.globals = {}
        self.classes = {}
        self.result = SemanticFacts()
        self.call_path = ()
        self.active_call = None
        self.pending_call = None
        self.scope_gaps = {}
        self.result.sites = SiteLedger(self)
        self.aliases, self.functions = {}, {}
        self.counts = dict(contexts=0, iterations=0, paths=0, summary_expansions=0)
        self.gaps = set()
        self.owner = facts.module.id
        self.context = ()
        self.active = ()
        self.loop_bounds = ()
        self.loop_origins = ()
        self.conditional = False
        self.guards = ()
        self.owners = {(s.location.start_line,s.location.start_column):s.id for s in facts.symbols if s.kind in ('function','method','class')}
        self.nodes = []
        self.cfg_cache={}
        self.cfg_nodes_used=0
        self.solver_stats=dict(worklist_steps=0,widenings=0,reachable_blocks=0,cfg_blocks=0)
        self.current_loop_ids=()
        self.current_base_loops=()
        self.current_constraint_value_id=None
        self.current_constraint_applicability="unverified"
        self.current_constraints=()
        self.current_incomplete=False
        self.expression_exceptions=()
        self.expression_normal=True
        self.last_exceptions=()
        self.last_normal=True
        self.body_only=False
        self.fresh_receiver_scope=False
        for n in self.tree.body:
            if isinstance(n,ast.Import):
                for a in n.names: self.aliases[a.asname or a.name.split('.')[0]] = a.name
            elif isinstance(n,ast.ImportFrom) and n.module:
                for a in n.names: self.aliases[a.asname or a.name] = n.module+'.'+a.name
            elif isinstance(n,ast.ClassDef):
                self.classes.setdefault(n.name, []).append(n)
            elif isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):
                self.functions.setdefault(n.name,[]).append(n)
        self.provider = any(v.split('.')[0] in ('openai','anthropic','google','langchain','langgraph') for v in self.aliases.values())

    def gap(self, reason, owner=None):
        self.gaps.add(reason)
        self.scope_gaps.setdefault(owner or self.owner,set()).add(reason)

    def spend(self, key):
        self.counts[key] += 1
        if self.counts[key] > getattr(self.b,key):
            self.gap('semantic_'+key+'_limit')
            return False
        return True

    def name(self,n):
        if isinstance(n,ast.Name): return self.aliases.get(n.id,n.id)
        if isinstance(n,ast.Attribute): return self.name(n.value)+'.'+n.attr
        return ''

    def evaluate(self,n,env):
        previous=self.active_call
        if isinstance(n,ast.Call) and not getattr(n,'argus_synthetic',False):
            self.active_call=Point(self.facts.module.id,self.owner,n.lineno,column(n))
        try: value=self._evaluate(n,env)
        finally: self.active_call=previous
        if n is not None:
            self.expression_normal=self.expression_normal and value.normal_result
            self.expression_exceptions=tuple(sorted(set(self.expression_exceptions+value.exception_types)))
        if n is not None and not getattr(n,'argus_synthetic',False):
            origin=(self.facts.module.id,getattr(n,'lineno',1))
            origins=tuple(sorted(set(value.origins+(origin,))))
            if value.provenance_truncated or len(origins)>32: self.gap('semantic_provenance_limit')
            point=Point(self.facts.module.id,self.owner,getattr(n,'lineno',1),column(n))
            value=replace(value,value_id=value.value_id or point.key('value'),origins=origins[:32],provenance_truncated=value.provenance_truncated or len(origins)>32)
        return value

    def _evaluate(self,n,env):
        if n is None: return UNKNOWN
        if not self.spend('iterations'): return UNKNOWN
        if isinstance(n,ast.Constant):
            if type(n.value) is bool:return Value('definite',boolean=True,truth=n.value,sql_value='constant')
            if n.value is None: return Value('definite', timeout_state='unknown' if getattr(n,'argus_literal',False) else 'disabled', sql_value='constant',literal_string=getattr(n,'argus_string',False))
            if type(n.value) is float:
                if not math.isfinite(n.value): return Value('definite',timeout_state='invalid',sql_value='constant')
                return Value('definite', number=n.value,minimum=n.value,maximum=n.value,numeric=True, timeout_state='explicit' if n.value>0 else 'invalid', sql_value='constant')
            # Never retain strings, booleans or credential-derived numerical values.
            return Value('definite',number=n.value,minimum=n.value,maximum=n.value,sql_value='integer',numeric=True,integer=True) if type(n.value) is int and abs(n.value)<=10**9 else Value('definite', sql_value='constant',literal_string=isinstance(n.value,str))
        if isinstance(n,ast.Name):
            if n.id in env: return env[n.id]
            if n.id in self.imported: return self.imported[n.id]
            if n.id in self.functions and len(self.functions[n.id])==1:
                return Value('definite',receiver='function:'+n.id)
            if n.id in self.aliases: return Value('definite',receiver=self.aliases[n.id])
            return UNKNOWN
        if isinstance(n,ast.Attribute):
            current=n; depth=0
            while isinstance(current,ast.Attribute):
                depth+=1; current=current.value
            if depth>self.b.receiver_depth:
                self.gap('semantic_receiver_depth_limit'); return UNKNOWN
            base = self.evaluate(n.value, env)
            if base.receiver and base.receiver.startswith('module:') and self.workspace:
                binding=self.workspace.export(base.receiver[7:],n.attr,())
                if binding:
                    mid,key=binding
                    self.workspace.initialize(mid)
                    other=self.workspace.flows[mid]
                    if key in other.functions: return Value('definite',receiver='function@'+mid+':'+key)
                    if key in other.classes: return Value('definite',receiver='constructor@'+mid+':'+key)
                    return other.globals.get(key,UNKNOWN)
                return UNKNOWN
            direct = dict(base.attributes).get(n.attr,env.get(self.raw_name(n)))
            if direct is not None: return direct
            if self.name(n).startswith(('flask.request.args','flask.request.form','flask.request.json','flask.request.data','flask.request.values')): return Value('possible',taint=True)
            if base.receiver and not base.receiver.startswith(('class:','class@','function:','function@')): return replace(base, receiver=base.receiver+'.'+n.attr, number=None, size=None,attributes=())
            if not base.receiver or base.receiver.startswith(('class:','class@')):self.protocol_effect(env,getattr(n,'lineno',1))
            return Value(taint=base.taint, sensitive=base.sensitive, origins=base.origins)
        if isinstance(n,ast.Dict):
            items=[]
            for k,v in zip(n.keys,n.values):
                if self.language=='python' and not getattr(k,'argus_literal_key',False):
                    key_value=self.evaluate(k,env)
                    if k is None or not (key_value.numeric or key_value.boolean or key_value.literal_string):self.protocol_effect(env,n.lineno)
                key=k.id if isinstance(k,ast.Name) and (self.language!='python' or getattr(k,'argus_literal_key',False)) else k.value if isinstance(k,ast.Constant) and isinstance(k.value,str) else None
                value=self.evaluate(v,env)
                if key is not None: items.append((key,value))
            return Value('definite',attributes=tuple(items),taint=any(v.taint for _,v in items),sensitive=any(v.sensitive for _,v in items))
        if isinstance(n,(ast.List,ast.Tuple,ast.Set)):
            values=[self.evaluate(x,env) for x in n.elts]
            if isinstance(n,ast.Set) and any(not v.numeric and not v.literal_string for v in values):
                self.protocol_effect(env,n.lineno)
                self.gap('semantic_container_protocol_incomplete')
            return Value('definite',timeout_state='requests_pair' if isinstance(n,ast.Tuple) and len(values)==2 and all(v.number is not None and v.number>0 for v in values) else 'unknown',sql_value='constant' if all(v.sql_value in ('constant','integer') for v in values) else 'unknown',size=None if any(isinstance(x,ast.Starred) for x in n.elts) else len(values),size_verified=not any(isinstance(x,ast.Starred) for x in n.elts),size_lower=0 if any(isinstance(x,ast.Starred) for x in n.elts) or not values else 1 if isinstance(n,ast.Set) else len(values),collection_kind='tuple' if isinstance(n,ast.Tuple) else 'list' if isinstance(n,ast.List) else 'set',finite=not any(isinstance(x,ast.Starred) for x in n.elts),taint=any(v.taint for v in values),sensitive=any(v.sensitive for v in values))
        if isinstance(n,(ast.JoinedStr,ast.BinOp)):
            children=[self.evaluate(x,env) for x in ast.iter_child_nodes(n) if not isinstance(x,ast.operator)]
            if isinstance(n,ast.BinOp) and isinstance(n.op,ast.Add) and len(children)==2:
                a,b=children
                if a.size is not None and b.size is not None:
                    return Value('definite',size=a.size+b.size,size_verified=a.size_verified and b.size_verified,size_lower=0,collection_kind=a.collection_kind,finite=a.finite and b.finite,taint=a.taint or b.taint)
                if a.number is not None and b.number is not None and abs(a.number+b.number)<=10**9:
                    return Value('definite',number=a.number+b.number,minimum=a.number+b.number,maximum=a.number+b.number,numeric=True,integer=a.integer and b.integer,sql_value='integer' if type(a.number) is int and type(b.number) is int else 'constant',taint=a.taint or b.taint)
            if isinstance(n,ast.BinOp) and not all(v.numeric or v.literal_string or v.collection_kind for v in children):self.protocol_effect(env,n.lineno)
            return Value('possible',sql_identifier=identifier_interpolation(n) or any(v.sql_identifier for v in children),sql_value='constant' if all(v.sql_value in ('constant','integer') for v in children) else 'unknown',taint=any(v.taint for v in children),dynamic_sql=True,sensitive=any(v.sensitive for v in children),origins=tuple(sorted({o for v in children for o in v.origins}))[:32])
        if isinstance(n,ast.FormattedValue):
            value=self.evaluate(n.value,env)
            if not (value.numeric or value.boolean or value.literal_string):self.protocol_effect(env,n.lineno)
            if n.format_spec is not None:
                spec=self.evaluate(n.format_spec,env)
                if spec.sql_value not in ('constant','integer'): return replace(value,sql_value='unknown',taint=value.taint or spec.taint)
            return value
        if isinstance(n,ast.Subscript):
            base=self.evaluate(n.value,env)
            if not base.collection_kind:self.protocol_effect(env,n.lineno)
            if self.name(n.value)=='os.environ': return Value('possible',sensitive=True)
            if isinstance(n.slice,ast.Slice) and n.slice.lower is None and n.slice.step is None:
                high=self.evaluate(n.slice.upper,env).number
                if type(high) is int and high>=0:
                    return Value('definite',size=min(base.size,high) if base.size is not None and base.size_verified else high,size_verified=base.collection_kind in ('list','tuple','range'),size_lower=0,finite=base.collection_kind in ('list','tuple','range'),collection_kind=base.collection_kind if base.collection_kind in ('list','tuple','range') else None,taint=base.taint,origins=base.origins,constraint_origins=base.constraint_origins)
            if not isinstance(n.slice,ast.Slice):self.evaluate(n.slice,env)
            self.protocol_effect(env,n.lineno)
            return Value(taint=base.taint,exception_types=('?',))
        if isinstance(n,ast.Await):
            value=self.evaluate(n.value,env)
            self.protocol_effect(env,n.lineno)
            self.gap('semantic_async_scheduling_unresolved')
            return replace(value,size=None,attributes=(),timeout=None,timeout_state='unknown')
        if isinstance(n,ast.Compare):
            values=[self.evaluate(x,env) for x in [n.left]+n.comparators]
            safe=self.language=='python' and (all(v.numeric for v in values) or len(n.ops)==1 and isinstance(n.ops[0],(ast.In,ast.NotIn)) and values[0].numeric and values[1].collection_kind in ('list','tuple','set') and isinstance(n.comparators[0],(ast.List,ast.Tuple,ast.Set)) and all(isinstance(x,ast.Constant) and type(x.value) is int for x in n.comparators[0].elts))
            if not safe:self.protocol_effect(env,n.lineno)
            return Value(boolean=safe,exception_types=() if safe else ('?',))
        if isinstance(n,ast.BoolOp):
            exceptions=set();all_boolean=True
            for child in n.values:
                if self.counts['iterations']>=self.b.iterations:
                    self.gap('semantic_iterations_limit');return Value(exception_types=('?',))
                if isinstance(child,ast.Constant) and type(child.value) is bool and (isinstance(n.op,ast.And) and not child.value or isinstance(n.op,ast.Or) and child.value):
                    return Value(boolean=all_boolean,truth=child.value if all_boolean else None,exception_types=tuple(sorted(exceptions)))
                before=(self.expression_normal,self.expression_exceptions)
                value=self.evaluate(child,env)
                all_boolean=all_boolean and value.boolean
                exceptions.update(self.truth_effect(value,env,getattr(child,'lineno',1)))
                exceptions.update(value.exception_types)
                self.expression_normal,self.expression_exceptions=before
            return Value(boolean=all_boolean,exception_types=tuple(sorted(exceptions)))
        if isinstance(n,ast.UnaryOp) and isinstance(n.op,ast.Not):
            value=self.evaluate(n.operand,env)
            exceptions=self.truth_effect(value,env,n.lineno)
            return Value(boolean=True,exception_types=exceptions)
        if isinstance(n,ast.UnaryOp) and isinstance(n.op,(ast.UAdd,ast.USub)):
            value=self.evaluate(n.operand,env)
            if value.numeric:
                sign=-1 if isinstance(n.op,ast.USub) else 1
                return replace(value,number=value.number*sign if value.number is not None else None,
                    minimum=value.minimum if sign==1 else -value.maximum if value.maximum is not None else None,
                    maximum=value.maximum if sign==1 else -value.minimum if value.minimum is not None else None)
        if isinstance(n,ast.IfExp):
            if not self.spend('paths'): return UNKNOWN
            return self.evaluate(n.body,env.copy()).join(self.evaluate(n.orelse,env.copy()))
        if not isinstance(n,ast.Call):
            self.gap('semantic_unsupported_expression')
            self.protocol_effect(env,getattr(n,'lineno',1))
            old_incomplete,old_loops=self.current_incomplete,self.loop_bounds
            self.current_incomplete=True
            if isinstance(n,(ast.ListComp,ast.SetComp,ast.DictComp,ast.GeneratorExp)):self.loop_bounds=old_loops+(None,)
            def discover(node):
                for child in ast.iter_child_nodes(node):
                    if isinstance(child,ast.Lambda):continue
                    if isinstance(child,ast.expr):self.evaluate(child,env)
                    elif not isinstance(child,(ast.operator,ast.cmpop,ast.boolop,ast.expr_context)):discover(child)
            try:
                if not isinstance(n,ast.Lambda):discover(n)
            finally:self.current_incomplete,self.loop_bounds=old_incomplete,old_loops
            return Value(incomplete_result=True,exception_types=('?',))
        target=self.name(n.func)
        function_value=self.evaluate(n.func,env) if isinstance(n.func,ast.Name) else UNKNOWN
        receiver = self.evaluate(n.func.value,env) if isinstance(n.func,ast.Attribute) else UNKNOWN
        if receiver.receiver:
            target = receiver.receiver+'.'+n.func.attr
        else:
            root=n.func
            while isinstance(root,ast.Attribute): root=root.value
            if isinstance(root,ast.Name) and root.id in env:
                target='@unresolved.'+self.raw_name(n.func)
        if function_value.receiver and not function_value.receiver.startswith(('function:','function@')):
            target=function_value.receiver
        bound=1
        for size in self.loop_bounds:
            if size is None: bound=None; break
            bound=bound*size
        if not getattr(n,'argus_synthetic',False):
            self.result.sites.append(Site(n.lineno,self.owner,'call',len(self.loop_bounds),bound if self.loop_bounds else None,context=self.context,conditional=self.conditional,column=column(n)))
        args=[self.evaluate(a,env) for a in n.args]
        kwargs={k.arg:self.evaluate(k.value,env) for k in n.keywords}
        if self.language=='python' and target in ('range','builtins.range') and target not in env and target not in self.functions and not kwargs and 1<=len(args)<=3 and all(type(v.number) is int for v in args):
            try: return Value('definite',size=len(range(*(v.number for v in args))),size_verified=True,size_lower=len(range(*(v.number for v in args))),collection_kind='range',finite=True)
            except (ValueError,OverflowError): return UNKNOWN
        if target in ('range','builtins.range') and self.language=='python' and target not in env and target not in self.functions and len(args)==1 and not kwargs and type(args[0].maximum) is int:
            return Value('possible',size=max(0,args[0].maximum),size_verified=args[0].numeric and args[0].integer,size_lower=0,finite=True,collection_kind='range',taint=args[0].taint,constraint_origins=args[0].constraint_origins)
        if self.language=='python' and target=='len' and target not in env and target not in self.functions and len(args)==1:
            if not args[0].collection_kind:self.protocol_effect(env,n.lineno)
            return Value('definite',number=args[0].size if args[0].size_verified and args[0].size_lower==args[0].size else None,minimum=args[0].size_lower,maximum=args[0].size if args[0].size_verified else None,numeric=bool(args[0].collection_kind),integer=True,exception_types=() if args[0].collection_kind else ('?',))
        if self.language=='python' and target in ('list','tuple','set') and target not in env and target not in self.functions and target not in self.aliases and len(args)<=1 and not kwargs:
            protocol=bool(args) and (not args[0].collection_kind or target=='set')
            if protocol:self.protocol_effect(env,n.lineno)
            return Value('definite',size=args[0].size if args else 0,size_verified=args[0].size_verified if args else True,size_lower=0,collection_kind=target,finite=True,taint=any(v.taint for v in args),exception_types=('?',) if protocol else ())
        if self.language=='python' and target=='bool' and target not in env and target not in self.functions and target not in self.aliases and len(args)<=1 and not kwargs:
            exceptions=self.truth_effect(args[0],env,n.lineno) if args else ()
            return Value('definite',boolean=True,truth=False if not args else None,exception_types=exceptions)
        if self.language=='python' and target in ('input','builtins.input') and target not in env and target not in self.functions: return Value('possible',taint=True)
        if self.language=='python' and target in ('int','builtins.int') and target not in env and target not in self.functions and target not in self.classes and len(args)==1 and not kwargs:
            protocol=not (args[0].numeric or args[0].boolean or args[0].literal_string)
            if protocol:self.protocol_effect(env,n.lineno)
            return Value('definite',sql_value='integer',origins=args[0].origins,numeric=True,integer=True,exception_types=('?',) if protocol or args[0].literal_string else ())
        if isinstance(n.func,ast.Attribute) and n.func.attr=='format' and receiver.literal_string:
            if any(not (v.numeric or v.boolean or v.literal_string) for v in args+list(kwargs.values())):self.protocol_effect(env,n.lineno)
            return Value('possible',dynamic_sql=True,literal_string=True,
                sql_value='constant' if all(v.sql_value in ('constant','integer') for v in args+list(kwargs.values())) else 'unknown',
                taint=any(v.taint for v in args+list(kwargs.values())),origins=receiver.origins,
                sql_identifier=receiver.sql_identifier)
        if target in ('unittest.mock.Mock','unittest.mock.MagicMock','unittest.mock.AsyncMock'):
            return Value('definite',receiver='known_mock',constructed=True)
        if target in ('sqlite3.connect','psycopg.connect','psycopg2.connect'):
            return Value('definite',receiver=target)
        if target in ('sqlite3.connect.cursor','psycopg.connect.cursor','psycopg2.connect.cursor'):
            return Value('definite',receiver=target)
        if target=='httpx.Timeout':
            default=args[0] if args else kwargs.get('timeout',UNKNOWN)
            phases=[kwargs.get(k,default) for k in ('connect','read','write','pool')]
            valid=all(v.number is not None and v.number>0 for v in phases)
            return Value('definite',timeout_state='explicit' if valid else 'disabled' if all(v.timeout_state=='disabled' for v in phases) else 'partial')
        if target in ('os.getenv','os.environ.get'): return Value('possible',sensitive=True)
        if target in ('min','max') and target not in env and target not in self.functions and self.language=='python' and len(args)>=2:
            if all(v.number is not None for v in args):
                number=(min if target=='min' else max)(v.number for v in args)
                return Value('definite',number=number,minimum=number,maximum=number,numeric=True,integer=all(v.integer for v in args))
            lowers=[v.minimum for v in args if v.minimum is not None]
            uppers=[v.maximum for v in args if v.maximum is not None]
            return Value('possible',numeric=True,integer=all(v.integer for v in args),minimum=max(lowers) if target=='max' and lowers else None,
                         maximum=min(uppers) if target=='min' and uppers else None,
                         taint=any(v.taint for v in args))
        if function_value.receiver and function_value.receiver.startswith('constructor@') and self.workspace:
            mid,name=function_value.receiver[12:].split(':',1)
            result=self.workspace.invoke(self,(mid,name),args,kwargs,n.lineno)
            if result.effects_may_mutate:self.invalidate(env,n.lineno)
            return result
        if function_value.receiver and function_value.receiver.startswith('function@') and self.workspace:
            mid,name=function_value.receiver[9:].split(':',1)
            result=self.workspace.invoke(self,(mid,name),args,kwargs,n.lineno)
            self.invalidate(env,n.lineno)
            return result
        if function_value.receiver and function_value.receiver.startswith('function:') and isinstance(n.func,ast.Name) and n.func.id not in self.functions:
            name=function_value.receiver[9:]
            if name in self.functions and len(self.functions[name])==1:
                result=self.invoke(self.functions[name][0],args,kwargs,env,n.lineno)
                self.invalidate(env,n.lineno)
                return result
        if isinstance(n.func, ast.Name) and n.func.id in self.imported and n.func.id not in env and self.workspace:
            binding = self.workspace.bindings.get((self.facts.module.id, n.func.id))
            if binding:
                result=self.workspace.invoke(self, binding, args, kwargs, n.lineno)
                self.invalidate(env,n.lineno)
                return result
        if receiver.receiver and receiver.receiver.startswith('module:') and self.workspace:
            binding = self.workspace.export(receiver.receiver[7:], n.func.attr, ())
            if binding:
                result=self.workspace.invoke(self, binding, args, kwargs, n.lineno)
                self.invalidate(env,n.lineno)
                return result
        if self.language!='python':
            if args and args[-1].attributes: kwargs.update(dict(args[-1].attributes))
            target={'openai.default':'openai.OpenAI','@anthropic-ai/sdk.default':'anthropic.Anthropic'}.get(target,target)
        if isinstance(n.func,ast.Name) and n.func.id in self.functions: target=n.func.id
        if target in ('openai.OpenAI','openai.AsyncOpenAI','anthropic.Anthropic','anthropic.AsyncAnthropic',
                      'httpx.Client','httpx.AsyncClient','requests.Session','fastapi.security.HTTPBearer','fastapi.FastAPI','flask.Flask'):
            timeout=kwargs.get('timeout',UNKNOWN)
            timeout_state=('unknown' if None in kwargs else 'sdk_default') if target.startswith('httpx.') and 'timeout' not in kwargs else ('explicit' if timeout.number is not None and timeout.number>0 else timeout.timeout_state)
            if target=='requests.Session': timeout=UNKNOWN; timeout_state='library_no_default'
            return Value('definite', receiver=target, constructed=True, timeout=timeout.number,timeout_state=timeout_state,attributes=(('auto_error',kwargs.get('auto_error',Value('definite',number=1))),) if target=='fastapi.security.HTTPBearer' else ())
        if isinstance(n.func,ast.Name) and n.func.id in self.classes and n.func.id not in env:
            classes=self.classes[n.func.id]
            if len(classes)!=1: return UNKNOWN
            cls=classes[0]
            if cls.bases: self.gap('semantic_inherited_receiver_unresolved')
            complex_protocol=bool(cls.bases or cls.keywords or cls.decorator_list or any(isinstance(x,(ast.Assign,ast.AnnAssign)) and x.value is not None and not isinstance(x.value,(ast.Constant,ast.List,ast.Tuple,ast.Set,ast.Dict)) for x in cls.body) or any(isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef)) and (x.name in ('__new__','__setattr__','__getattribute__','__getattr__') or x.decorator_list) for x in cls.body))
            value=Value('definite',receiver='class:'+n.func.id,object_id=((self.pending_call or self.active_call or Point(self.facts.module.id,self.owner,n.lineno)).key('allocation'),self.call_path))
            init=next((x for x in cls.body if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef)) and x.name=='__init__'),None)
            initial_effects=self.result.effects.copy()
            init_result=Value(effects_may_mutate=False)
            if init:
                # Constructor attributes are copied to the returned receiver's local identity.
                attrs={}
                init_result=self.invoke(init,[value]+args,kwargs,attrs,n.lineno, capture=attrs,fresh_receiver=not complex_protocol,binding_unverified=complex_protocol)
                value=replace(value,attributes=tuple(sorted((key[5:],v) for key,v in attrs.items() if key.startswith('self.'))))
            from .abstract import EffectKind
            safe_effects={EffectKind.SCALAR.value,EffectKind.REPLACE.value,EffectKind.FRESH.value}
            mutates=complex_protocol or init_result.incomplete_result or any(count>initial_effects.get(kind,0) for kind,count in self.result.effects.items() if kind not in safe_effects)
            value=replace(value,normal_result=init_result.normal_result,exception_types=init_result.exception_types,incomplete_result=init_result.incomplete_result or complex_protocol,effects_may_mutate=mutates,attributes=() if mutates else value.attributes)
            if complex_protocol:
                self.gap('semantic_constructor_protocol_unresolved')
                reference='class@'+self.facts.module.id+':'+n.func.id if self.workspace else 'class:'+n.func.id
                value=replace(value,receiver=None,receiver_options=(reference,),normal_result=True,exception_types=tuple(sorted(set(value.exception_types+('?',)))))
            if mutates:self.invalidate(env,n.lineno)
            if self.workspace and not complex_protocol: value=replace(value,receiver='class@'+self.facts.module.id+':'+n.func.id)
            return value
        if not receiver.receiver and receiver.receiver_options and self.workspace and isinstance(n.func,ast.Attribute):
            candidates=tuple(sorted({target for option in receiver.receiver_options
                for target in self.workspace.method_targets(option,n.func.attr)}))
            if candidates:
                self.result.sites.append(Site(n.lineno,self.owner,'receiver_resolution',
                    column=column(n),candidate_target_ids=candidates,
                    fact_state=FactState.POSSIBLE))
        if receiver.receiver and receiver.receiver.startswith('class@') and self.workspace:
            result=self.workspace.method(self,receiver,n.func.attr,args,kwargs,n.lineno)
            self.invalidate_receiver(receiver,env)
            if result.effects_may_mutate:self.invalidate(env,n.lineno)
            return result
        if receiver.receiver and receiver.receiver.startswith('class:'):
            clsname=receiver.receiver[6:]
            cls=self.classes.get(clsname,[])
            methods=[m for c in cls for m in c.body if isinstance(m,(ast.FunctionDef,ast.AsyncFunctionDef)) and m.name==n.func.attr]
            if len(methods)==1:
                attrs={'self.'+k:v for k,v in receiver.attributes}
                result=self.invoke(methods[0],[receiver]+args,kwargs,attrs,n.lineno)
                self.invalidate_receiver(receiver,env)
                if result.effects_may_mutate:self.invalidate(env,n.lineno)
                return result

        if isinstance(n.func,ast.Name) and n.func.id in self.functions and len(self.functions[n.func.id])==1 and n.func.id not in env:
            result=self.invoke(self.functions[n.func.id][0],args,kwargs,env,n.lineno)
            self.invalidate(env,n.lineno)
            return result
        if isinstance(n.func,ast.Attribute) and not receiver.receiver and self.raw_name(n.func).startswith('self.'):
            self.gap('semantic_unresolved_instance_receiver')
        query=target.rsplit('.',1)[-1] in ('execute','executemany','query')
        sdk_operation=resolve_operation(target) if receiver.constructed or function_value.constructed else None
        if target.startswith('known_mock.') and target.endswith(MODEL_SUFFIXES+EMBEDDING_SUFFIXES):
            self.result.sites.append(Site(n.lineno,self.owner,'mock_operation',context=self.context,column=column(n)))
        possible_receiver=self.provider and (receiver.receiver is None or not receiver.constructed and target.startswith(('openai.','anthropic.')))
        model=bool(sdk_operation and sdk_operation.kind=='model') or possible_receiver and target.endswith(MODEL_SUFFIXES)
        embedding=bool(sdk_operation and sdk_operation.kind=='embedding') or possible_receiver and target.endswith(EMBEDDING_SUFFIXES)
        request=target in HTTP_TARGETS
        op='model' if model else 'embedding' if embedding else 'database' if query else 'http' if request else 'execution' if target in ('eval','exec','os.system','os.popen') else ''
        if op:
            keys=sdk_operation.limit_keys if sdk_operation else ('max_tokens','max_completion_tokens','max_output_tokens') if model else ('timeout',) if request else ()
            timeout=kwargs.get('timeout', Value(number=receiver.timeout,timeout_state=receiver.timeout_state))
            timeout_state=('explicit' if timeout.number is not None and timeout.number>0 else timeout.timeout_state)
            if request and 'timeout' not in kwargs and target.startswith('httpx.') and target.count('.')==1: timeout_state='sdk_default'
            if request and target.startswith('requests.') and timeout_state=='requests_pair': timeout_state='explicit'
            if request and target.startswith('requests.') and 'timeout' not in kwargs: timeout_state='library_no_default'
            if timeout_state=='requests_pair': timeout_state='unknown'
            if None in kwargs: timeout_state='unknown'
            limited=(timeout_state in ('explicit','sdk_default')) if request else any(k in kwargs and kwargs[k].number is not None and kwargs[k].number>0 for k in keys)
            bound=1
            for size in self.loop_bounds:
                if size is None: bound=None; break
                bound=bound*size
            self.result.sites.append(Site(n.lineno,self.owner,op,len(self.loop_bounds),bound if self.loop_bounds else None,
                limited,any(v.taint for v in args),bool(args and args[0].dynamic_sql),self.context,self.conditional,
                any(k in kwargs for k in keys) or model and any(k in kwargs for k in ('config','generationConfig')),None in kwargs,
                origins=tuple(sorted(set(self.loop_origins)|{origin for v in args+list(kwargs.values()) for origin in v.origins}))[:32],
                sensitive=any(v.sensitive for v in args+list(kwargs.values())),
                receiver_resolved=bool(sdk_operation) if model or embedding else bool(receiver.receiver),safeguards=self.guards,
                timeout_state=timeout_state if request else 'unknown',sql_value=('untrusted_string' if args[0].taint and args[0].sql_value=='unknown' else args[0].sql_value) if args else 'unknown',
                sql_identifier=bool(args and args[0].sql_identifier),
                parameter_binding=query and len(args)>1 and receiver.receiver in ('sqlite3.connect.cursor','psycopg.connect.cursor','psycopg2.connect.cursor'),
                operation_id=sdk_operation.receiver+'.'+sdk_operation.suffix if sdk_operation else None,column=column(n),
                constraint_origins=tuple(sorted(set(self.current_constraints)|{o for v in args+list(kwargs.values()) for o in v.constraint_origins}))))
            self.result.summaries.setdefault(self.owner,set()).add(op)
        # Unknown calls may mutate any aliased collection. Invalidate all bounds,
        # because alias identities are intentionally not modeled in this subset.
        if (not op or (model or embedding) and not sdk_operation or query and not receiver.receiver) and target not in ('len','range'):
            self.invalidate(env,n.lineno)
        return Value(exception_types=('?',),taint=bool(model) or receiver.taint or any(v.taint for v in args+list(kwargs.values())),dynamic_sql=any(v.dynamic_sql for v in args+list(kwargs.values())),sensitive=receiver.sensitive or any(v.sensitive for v in args+list(kwargs.values())))

    def invalidate_receiver(self,receiver,env):
        # A method may change instance state. Without a heap-effect summary, no
        # later call through an object alias may reuse constructor attributes.
        if not receiver.object_id: return
        for key,value in list(env.items()):
            if value.object_id==receiver.object_id:
                env[key]=replace(value,attributes=(),timeout=None,timeout_state="unknown",state='unknown')

    def truth_effect(self,value,env,line):
        if self.language!='python' or value.boolean or value.numeric or value.collection_kind or value.literal_string:return ()
        # Unknown __bool__/__len__ can mutate aliased state or raise. This is a
        # conservative unknown effect, never an assumption of predicate purity.
        self.invalidate(env,line)
        return ('?',)

    def protocol_effect(self,env,line):
        # Unknown object protocols may mutate state and transfer to a handler.
        if self.language=='python':self.expression_exceptions=tuple(sorted(set(self.expression_exceptions+('?',))))
        self.invalidate(env,line)

    def invalidate(self,env,line=1):
        from .abstract import Effect,EffectKind
        self.apply_effect(Effect(EffectKind.CALL,line=line),env)

    def apply_effect(self,effect,env):
        from .abstract import EffectKind
        self.result.effects[effect.kind.value]=self.result.effects.get(effect.kind.value,0)+1
        if effect.kind in (EffectKind.SCALAR,EffectKind.REPLACE,EffectKind.FRESH):return
        if any(v.size is not None or v.timeout is not None or v.attributes or v.constraint_origins for v in env.values()):
            self.result.sites.append(Site(effect.line,self.owner,'invalidation',context=self.context))
        for key,value in list(env.items()):
            if key.startswith('@loop:') and value.collection_kind in ('range','tuple') and effect.kind!=EffectKind.UNSUPPORTED:continue
            if value.size is not None or value.attributes or value.timeout is not None or value.timeout_state!='unknown' or value.collection_kind or value.constraint_origins:
                env[key]=replace(value,size=None,size_verified=False,size_lower=0 if value.collection_kind else None,attributes=(),timeout=None,
                    timeout_state='unknown',state='unknown',constraint_origins=(),constraint_must=False,constraint_value_id=None,finite=False)

    def static_receiver(self,node,env):
        if isinstance(node,ast.Name):return env.get(node.id,self.imported.get(node.id,UNKNOWN))
        if isinstance(node,ast.Attribute):
            direct=env.get(self.raw_name(node))
            if direct is not None:return direct
            base=self.static_receiver(node.value,env)
            attribute=dict(base.attributes).get(node.attr)
            if attribute is not None:return attribute
            if base.receiver:return replace(base,receiver=base.receiver+'.'+node.attr)
        return UNKNOWN

    def call_may_mutate(self,call,env):
        target=self.name(call.func)
        if self.language=='python' and target in ('range','len','str','int','float','bool','list','tuple','set') and target not in env and target not in self.functions and target not in self.aliases:
            values=[self.static_receiver(a,env) for a in call.args]
            if target in ('list','tuple','len'):return any(not v.collection_kind for v in values)
            if target=='set':return bool(values)
            return any(not (v.numeric or v.boolean or v.literal_string) and not isinstance(a,ast.Constant) for a,v in zip(call.args,values))
        if isinstance(call.func,ast.Attribute):
            receiver=self.static_receiver(call.func.value,env)
            if receiver.constructed and receiver.receiver and resolve_operation(receiver.receiver+'.'+call.func.attr):return False
            if receiver.receiver in ('sqlite3.connect.cursor','psycopg.connect.cursor','psycopg2.connect.cursor') and call.func.attr in ('execute','executemany'):return False
        if target in tuple('requests.'+v for v in ('get','post','put','delete','patch','head','options','request')):
            root=call.func
            while isinstance(root,ast.Attribute):root=root.value
            return isinstance(root,ast.Name) and root.id in env
        return True

    def merge_visits(self,start,incomplete):
        # A solver revisits source operations, not additional executions to report.
        merged={}
        for site in self.result.sites[start:]:
            key=(site.owner,site.line,site.column,site.operation,site.context_id,site.callsite_id,site.formal_id,site.actual_id,site.result_id,site.observation_scope)
            old=merged.get(key)
            if old is None:merged[key]=site;continue
            bound=max(old.upper_bound,site.upper_bound) if old.upper_bound is not None and site.upper_bound is not None else None
            operation_bound=max(old.operation_upper_bound,site.operation_upper_bound) if old.operation_upper_bound is not None and site.operation_upper_bound is not None else None
            predicates=tuple(sorted(set(old.constraint_origins+site.constraint_origins)))
            same_value=old.constrained_value_id==site.constrained_value_id
            applicability='all_reaching_states' if same_value and old.constrained_value_id and old.constraint_applicability==site.constraint_applicability=='all_reaching_states' and bound is not None else 'some_reaching_states' if predicates else 'unverified'
            merged[key]=replace(old,upper_bound=bound,operation_upper_bound=operation_bound,
                lower_bound=min(old.lower_bound,site.lower_bound) if old.lower_bound is not None and site.lower_bound is not None else None,
                finite=old.finite and site.finite,exit_channels=tuple(sorted(set(old.exit_channels+site.exit_channels))),
                constrained_value_id=old.constrained_value_id if same_value else None,constraint_applicability=applicability,
                reachability='potential' if 'potential' in (old.reachability,site.reachability) else old.reachability,
                limit=old.limit and site.limit,conditional=old.conditional or site.conditional,
                receiver_resolved=old.receiver_resolved and site.receiver_resolved,bound_supported=old.bound_supported and site.bound_supported,
                origins=tuple(sorted(set(old.origins+site.origins)))[:32],constraint_origins=predicates,
                incomplete=tuple(sorted(set(old.incomplete+site.incomplete))),
                candidate_target_ids=tuple(sorted(set(old.candidate_target_ids+site.candidate_target_ids))),
                target_id=old.target_id if old.target_id==site.target_id else None,
                fact_state=FactState.INCOMPLETE if FactState.INCOMPLETE in (old.fact_state,site.fact_state) else FactState.KNOWN if bound is not None else FactState.UNKNOWN if old.fact_state!=site.fact_state else old.fact_state)
        self.result.sites[start:]=[replace(s,upper_bound=None,operation_upper_bound=None,limit=False,fact_state=FactState.INCOMPLETE,reachability='potential',constraint_applicability='unverified',
            incomplete=tuple(sorted(set(s.incomplete+('semantic_solver_incomplete',))))) if incomplete else s for s in merged.values()]

    def raw_name(self,n):
        if isinstance(n,ast.Name): return n.id
        if isinstance(n,ast.Attribute): return self.raw_name(n.value)+'.'+n.attr
        return ''

    def invoke(self,fn,args,kwargs,env,line,capture=None,external=False,fresh_receiver=False,binding_unverified=False):
        if fn.lineno in self.active or len(self.active)>=self.b.depth:
            self.gap('semantic_recursion_or_depth_limit'); return UNKNOWN
        if not self.spend('contexts') or not self.spend('summary_expansions'): return UNKNOWN
        if fn.args.vararg or fn.args.kwarg or None in kwargs:
            self.gap('semantic_dynamic_function_binding'); return UNKNOWN
        from .safeguards import function_guards
        guards=function_guards(fn,self.aliases,self.globals)
        def route_decorator(dec):
            if not isinstance(dec,ast.Call) or not isinstance(dec.func,ast.Attribute) or not isinstance(dec.func.value,ast.Name): return False
            value=self.globals.get(dec.func.value.id,UNKNOWN)
            return value.receiver in ('fastapi.FastAPI','flask.Flask') and dec.func.attr in ('route','get','post','put','patch','delete','head','options','api_route')
        route=any(route_decorator(d) for d in fn.decorator_list)
        def identity_decorator(dec):
            if not isinstance(dec,ast.Name) or dec.id in self.globals:return False
            definitions=self.functions.get(dec.id,())
            if len(definitions)!=1:return False
            decorator=definitions[0]
            parameters=decorator.args.posonlyargs+decorator.args.args
            return (not isinstance(decorator,ast.AsyncFunctionDef) and len(parameters)==1 and not decorator.decorator_list
                and not decorator.args.vararg and not decorator.args.kwarg and not decorator.args.kwonlyargs and not decorator.args.defaults
                and len(decorator.body)==1 and isinstance(decorator.body[0],ast.Return)
                and isinstance(decorator.body[0].value,ast.Name) and decorator.body[0].value.id==parameters[0].arg)
        dynamic_decorator=any(not identity_decorator(dec) for dec in fn.decorator_list)
        if dynamic_decorator:
            self.gap('semantic_decorated_function_binding_unverified',self.owners.get((fn.lineno,column(fn)),self.owner))
        params=fn.args.posonlyargs+fn.args.args
        allowed={p.arg for p in fn.args.args+fn.args.kwonlyargs}
        supplied={p.arg for p in params[:len(args)]}
        required={p.arg for p in params[:len(params)-len(fn.args.defaults)]} | {p.arg for p,d in zip(fn.args.kwonlyargs,fn.args.kw_defaults) if d is None}
        missing=bool(required-supplied-set(kwargs))
        if len(args)>len(params) or any(k not in allowed or k in supplied for k in kwargs) or missing and self.language=='python':
            self.gap('semantic_invalid_or_unsupported_argument_binding')
            return UNKNOWN
        local=dict(self.globals)
        local.update(env if capture is not None or any(k.startswith('self.') for k in env) else {})
        for p in params+fn.args.kwonlyargs: local.pop(p.arg,None)
        for p,v in zip(params,args): local[p.arg]=replace(v,normal_result=True,exception_types=())
        defaults=dict(zip([p.arg for p in params[-len(fn.args.defaults):]],fn.args.defaults)) if fn.args.defaults else {}
        defaults.update({p.arg:d for p,d in zip(fn.args.kwonlyargs,fn.args.kw_defaults) if d is not None})
        for p in params+fn.args.kwonlyargs:
            if p.arg in kwargs: local[p.arg]=replace(kwargs[p.arg],normal_result=True,exception_types=())
            elif p.arg not in local:
                local[p.arg]=self.evaluate(defaults.get(p.arg),self.globals.copy())
                if route and p.arg not in defaults: local[p.arg]=replace(local[p.arg],taint=True)
                if p.annotation and self.name(p.annotation)=='fastapi.Request': local[p.arg]=replace(local[p.arg],taint=True)
        if external and route:
            for p in params+fn.args.kwonlyargs: local[p.arg]=replace(local[p.arg],taint=True)
        saved=(self.owner,self.context,self.active,self.loop_bounds,self.conditional,self.guards,self.call_path)
        call=self.pending_call or self.active_call or Point(self.facts.module.id,self.owner,line)
        self.pending_call=None
        target=self.owners.get((fn.lineno,column(fn)),self.owner)
        callsite=call.key('callsite')
        context_path=self.call_path+(identity('external_entry',target) if external else callsite,)
        result_id=identity('result',repr((target,context_path)))
        if not external:
            # The caller owns this record even when the callee is in another file.
            producer=self.workspace.flows.get(call.module_id,self) if self.workspace else self
            producer.result.sites.append(Site(call.line,call.owner_id,'receiver_resolution',column=call.column,
                callsite_id=callsite,target_id=None if dynamic_decorator or binding_unverified else target,candidate_target_ids=(target,),fact_state=FactState.POSSIBLE if dynamic_decorator or binding_unverified else FactState.KNOWN,
                context_id=identity('context',repr((call.owner_id,context_path[:-1]))),
                call_path_ids=context_path[:-1]))
        self.call_path=context_path
        self.guards=guards
        self.owner=self.owners.get((fn.lineno,column(fn)),self.owner)
        self.context=self.context+((call.line,) if not external and call.module_id==self.facts.module.id else ())
        self.active=self.active+(fn.lineno,)
        # Caller loop domains remain relevant to callee operations.
        for index,p in enumerate(params+fn.args.kwonlyargs):
            v=local.get(p.arg,UNKNOWN)
            positional=index<len(args) and index<len(params)
            binding='external_unknown' if external else 'positional' if positional else 'keyword' if p.arg in kwargs else 'default'
            formal=identity('formal',repr((target,index)))
            actual=identity('actual',repr((callsite,index,binding,context_path)))
            self.result.sites.append(Site(fn.lineno,self.owner,'argument_bound',upper_bound=v.size,bound_supported=v.size_verified,column=column(fn),
                context=self.context,origins=v.origins,formal_id=formal,actual_id=actual,result_id=result_id,origin_value_id=v.value_id,
                callsite_id=None if external else callsite,argument_position=index,binding_kind=binding,
                value_id=actual,fact_state=FactState.KNOWN if v.size is not None else FactState.UNKNOWN))
        if guards:
            self.result.sites.append(Site(fn.lineno,self.owner,'authentication',context=self.context,safeguards=guards))
        expression_saved=(self.expression_normal,self.expression_exceptions,self.current_constraints,self.current_incomplete,self.current_loop_ids,self.current_base_loops,self.current_constraint_value_id,self.current_constraint_applicability)
        initial_function_effects=self.result.effects.copy()
        saved_fresh_receiver=self.fresh_receiver_scope
        self.fresh_receiver_scope=fresh_receiver
        saved_body_only=self.body_only
        self.body_only=dynamic_decorator or binding_unverified or isinstance(fn,ast.AsyncFunctionDef)
        outcome=self.block(fn.body,local)
        self.expression_normal,self.expression_exceptions,self.current_constraints,self.current_incomplete,self.current_loop_ids,self.current_base_loops,self.current_constraint_value_id,self.current_constraint_applicability=expression_saved
        self.body_only=saved_body_only
        self.fresh_receiver_scope=saved_fresh_receiver
        value=outcome.returned
        if outcome.normal: value=join_returns(value,UNKNOWN)
        if outcome.incomplete: value=UNKNOWN
        if value is None:value=UNKNOWN
        body_value=value
        body_exits=outcome.channels
        # An unresolved wrapper can replace the result or control flow. Body facts
        # remain available under a distinct scope, never invocation guarantees.
        if dynamic_decorator or binding_unverified or isinstance(fn,ast.AsyncFunctionDef):
            self.result.sites.append(Site(fn.lineno,self.owner,'return_bound',upper_bound=body_value.size,bound_supported=body_value.size_verified,context=self.context,column=column(fn),
                origins=body_value.origins,result_id=result_id,value_id=result_id,observation_scope='function_body',
                fact_state=FactState.KNOWN if body_value.size is not None else FactState.UNKNOWN,exit_channels=body_exits))
            value=Value(taint=value.taint or any(v.taint for v in args+list(kwargs.values())),dynamic_sql=value.dynamic_sql,sensitive=value.sensitive,exception_types=('?',))
        else:value=replace(value,normal_result=self.last_normal,exception_types=self.last_exceptions)
        self.result.sites.append(Site(fn.lineno,self.owner,'return_bound',upper_bound=value.size,bound_supported=value.size_verified,context=self.context,column=column(fn),
            origins=value.origins,result_id=result_id,value_id=result_id,callsite_id=None if external else callsite,
            observation_scope='effective_invocation',fact_state=FactState.INCOMPLETE if outcome.incomplete or dynamic_decorator or binding_unverified or isinstance(fn,ast.AsyncFunctionDef) else FactState.KNOWN if value.size is not None else FactState.UNKNOWN,
            exit_channels=body_exits if not dynamic_decorator and not binding_unverified and not isinstance(fn,ast.AsyncFunctionDef) else (),incomplete=tuple(sorted(self.scope_gaps.get(self.owner,())))))
        if capture is not None: capture.update(local)
        self.owner,self.context,self.active,self.loop_bounds,self.conditional,self.guards,self.call_path=saved
        from .abstract import EffectKind
        safe_effects={EffectKind.SCALAR.value,EffectKind.REPLACE.value,EffectKind.FRESH.value}
        effects_unknown=any(count>initial_function_effects.get(kind,0) for kind,count in self.result.effects.items() if kind not in safe_effects)
        return replace(value,result_id=result_id,value_id=result_id,effects_may_mutate=effects_unknown or outcome.incomplete or dynamic_decorator or binding_unverified,incomplete_result=outcome.incomplete or dynamic_decorator or binding_unverified or isinstance(fn,ast.AsyncFunctionDef))

    def counter_bound(self,node,env):
        """Only a local monotonic counter with one unconditional final increment."""
        test=node.test
        if self.language!='python' or not isinstance(test,ast.Compare) or len(test.ops)!=1 or not isinstance(test.ops[0],(ast.Lt,ast.LtE)) or not isinstance(test.left,ast.Name) or not node.body: return None
        key=test.left.id
        start=env.get(key,UNKNOWN).number
        if not isinstance(test.comparators[0],(ast.Name,ast.Constant)):return None
        stop=self.evaluate(test.comparators[0],env).number
        last=node.body[-1]
        if type(start) is not int or type(stop) is not int or not isinstance(last,ast.AugAssign) or not isinstance(last.target,ast.Name) or last.target.id!=key or not isinstance(last.op,ast.Add): return None
        if not isinstance(last.value,(ast.Name,ast.Constant)):return None
        step=self.evaluate(last.value,env).number
        if type(step) is not int or step<=0: return None
        writes=[n for stmt in node.body for n in ast.walk(stmt) if isinstance(n,ast.Name) and n.id==key and isinstance(n.ctx,ast.Store)]
        if len(writes)!=1 or any(isinstance(n,(ast.Continue,ast.Break,ast.Global,ast.Nonlocal,ast.Await,ast.Yield,ast.FunctionDef,ast.ClassDef)) for stmt in node.body for n in ast.walk(stmt)): return None
        return max(0,(stop-start+int(isinstance(test.ops[0],ast.LtE))+step-1)//step)

    def block(self,body,env):
        from .solver import solve
        return solve(self,body,env)

    def run(self):
        module_env=dict(self.imported)
        self.block(self.tree.body,module_env)
        # Mutable exported collections cannot be treated as immutable snapshots.
        self.globals={k:v for k,v in module_env.items() if v.size is None}
        self.exports=module_env
        for fns in self.functions.values():
            if len(fns)==1:
                fn=fns[0]
                # Analyze public entry scope with unknown arguments, independently
                # of callers. Never let one constrained caller protect another.
                self.invoke(fn,[UNKNOWN for _ in fn.args.posonlyargs+fn.args.args],{p.arg:UNKNOWN for p in fn.args.kwonlyargs}, {},fn.lineno,external=True)
        if sum(1 for _ in ast.walk(self.tree))>self.b.cfg_nodes*4:
            self.gap('semantic_intermediate_representation_limit')
        else:
            self.result.program=self.tree
        self.result.sites=list(self.result.sites)
        self.result.language=self.language
        self.result.cfg=tuple(self.cfg_cache.values())
        self.result.statistics=dict(self.solver_stats,contexts=self.counts["contexts"],transfer_steps=self.counts["iterations"],prepared_cfg_nodes=self.cfg_nodes_used)
        self.result.incomplete=tuple(sorted(self.gaps))
        self.result.scope_gaps={k:tuple(sorted(v)) for k,v in self.scope_gaps.items()}
        return self.result
