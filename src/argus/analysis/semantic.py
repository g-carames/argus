"""Bounded abstract interpretation over a restricted, source-free syntax IR.

Unknown is absorbing at joins. Bounds describe a single iteration domain, not cost.
Only positive evidence can establish a safeguard; naming is never validation.
"""
import ast
import copy
import re
import math
from dataclasses import dataclass, field, replace
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

    def join(self, other):
        if self == other: return self
        same_facts=replace(self,origins=(),provenance_truncated=False)==replace(other,origins=(),provenance_truncated=False)
        return Value(state=self.state if same_facts else 'unknown' if 'unknown' in (self.state, other.state) else 'conflicting',
                     size=max(self.size, other.size) if self.size is not None and other.size is not None else None,
                     number=self.number if self.number == other.number else None,
                     taint=self.taint or other.taint, dynamic_sql=self.dynamic_sql or other.dynamic_sql,
                     receiver=self.receiver if self.receiver == other.receiver else None,
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
class FlowNode:
    index: int
    line: int
    kind: str
    successors: tuple[int, ...] = ()


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


@dataclass
class SemanticFacts:
    sites: list = field(default_factory=list)
    cfg: tuple = ()
    incomplete: tuple = ()
    # Function summaries are source-free sets of observed operation kinds by owner.
    summaries: dict = field(default_factory=dict)
    program: object = None  # Sanitized syntax IR; never report or serialize into reports.
    language: str = 'python'


def collect(file, parsed, facts, budgets=Budgets()):
    if parsed.language == 'python':
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
            n.keys=[ast.Name(id=k.value,ctx=ast.Load()) if isinstance(k,ast.Constant) and k.value in ('timeout','max_tokens','max_completion_tokens','max_output_tokens','config','generationConfig','maxOutputTokens','auto_error') else k for k in n.keys]
        if isinstance(n, ast.Constant) and type(n.value) not in (int, float, bool, type(None)):
            n.argus_string = isinstance(n.value,str)
            n.value = None
            n.argus_literal = True
    return tree


class PythonFlow:
    def __init__(self, parsed, facts, budgets):
        self.tree, self.facts, self.b = parsed.tree, facts, budgets
        self.language = 'python'
        self.workspace = None
        self.imported = {}
        self.globals = {}
        self.classes = {}
        self.result = SemanticFacts()
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
        self.owners = {(s.location.start_line,s.location.start_column):s.id for s in facts.symbols}
        self.nodes = []
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

    def spend(self, key):
        self.counts[key] += 1
        if self.counts[key] > getattr(self.b,key):
            self.gaps.add('semantic_'+key+'_limit')
            return False
        return True

    def name(self,n):
        if isinstance(n,ast.Name): return self.aliases.get(n.id,n.id)
        if isinstance(n,ast.Attribute): return self.name(n.value)+'.'+n.attr
        return ''

    def evaluate(self,n,env):
        value=self._evaluate(n,env)
        if n is not None:
            origin=(self.facts.module.id,getattr(n,'lineno',1))
            origins=tuple(sorted(set(value.origins+(origin,))))
            if value.provenance_truncated or len(origins)>32: self.gaps.add('semantic_provenance_limit')
            value=replace(value,origins=origins[:32],provenance_truncated=value.provenance_truncated or len(origins)>32)
        return value

    def _evaluate(self,n,env):
        if n is None: return UNKNOWN
        if not self.spend('iterations'): return UNKNOWN
        if isinstance(n,ast.Constant):
            if n.value is None: return Value('definite', timeout_state='unknown' if getattr(n,'argus_literal',False) else 'disabled', sql_value='constant',literal_string=getattr(n,'argus_string',False))
            if type(n.value) is float:
                if not math.isfinite(n.value): return Value('definite',timeout_state='invalid',sql_value='constant')
                return Value('definite', number=n.value, timeout_state='explicit' if n.value>0 else 'invalid', sql_value='constant')
            # Never retain strings, booleans or credential-derived numerical values.
            return Value('definite',number=n.value,minimum=n.value,maximum=n.value,sql_value='integer') if type(n.value) is int and abs(n.value)<=10**9 else Value('definite', sql_value='constant',literal_string=isinstance(n.value,str))
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
                self.gaps.add('semantic_receiver_depth_limit'); return UNKNOWN
            base = self.evaluate(n.value, env)
            if base.receiver and base.receiver.startswith('module:') and self.workspace:
                binding=self.workspace.export(base.receiver[7:],n.attr,())
                if binding:
                    mid,key=binding
                    self.workspace.initialize(mid)
                    other=self.workspace.flows[mid]
                    if key in other.functions: return Value('definite',receiver='function@'+mid+':'+key)
                    return other.globals.get(key,UNKNOWN)
                return UNKNOWN
            direct = dict(base.attributes).get(n.attr,env.get(self.raw_name(n)))
            if direct is not None: return direct
            if self.name(n).startswith(('flask.request.args','flask.request.form','flask.request.json','flask.request.data','flask.request.values')): return Value('possible',taint=True)
            if base.receiver and not base.receiver.startswith(('class:','class@','function:','function@')): return replace(base, receiver=base.receiver+'.'+n.attr, number=None, size=None,attributes=())
            return Value(taint=base.taint, sensitive=base.sensitive, origins=base.origins)
        if isinstance(n,ast.Dict):
            items=[]
            for k,v in zip(n.keys,n.values):
                key=k.id if isinstance(k,ast.Name) else k.value if isinstance(k,ast.Constant) and isinstance(k.value,str) else None
                value=self.evaluate(v,env)
                if key is not None: items.append((key,value))
            return Value('definite',attributes=tuple(items),taint=any(v.taint for _,v in items),sensitive=any(v.sensitive for _,v in items))
        if isinstance(n,(ast.List,ast.Tuple,ast.Set)):
            values=[self.evaluate(x,env) for x in n.elts]
            return Value('definite',timeout_state='requests_pair' if isinstance(n,ast.Tuple) and len(values)==2 and all(v.number is not None and v.number>0 for v in values) else 'unknown',sql_value='constant' if all(v.sql_value in ('constant','integer') for v in values) else 'unknown',size=None if any(isinstance(x,ast.Starred) for x in n.elts) else len(values),taint=any(v.taint for v in values),sensitive=any(v.sensitive for v in values))
        if isinstance(n,(ast.JoinedStr,ast.BinOp)):
            children=[self.evaluate(x,env) for x in ast.iter_child_nodes(n) if not isinstance(x,ast.operator)]
            if isinstance(n,ast.BinOp) and isinstance(n.op,ast.Add) and len(children)==2:
                a,b=children
                if a.size is not None and b.size is not None:
                    return Value('definite',size=a.size+b.size,taint=a.taint or b.taint)
                if a.number is not None and b.number is not None and abs(a.number+b.number)<=10**9:
                    return Value('definite',number=a.number+b.number,sql_value='integer' if type(a.number) is int and type(b.number) is int else 'constant',taint=a.taint or b.taint)
            return Value('possible',sql_identifier=identifier_interpolation(n) or any(v.sql_identifier for v in children),sql_value='constant' if all(v.sql_value in ('constant','integer') for v in children) else 'unknown',taint=any(v.taint for v in children),dynamic_sql=True,sensitive=any(v.sensitive for v in children),origins=tuple(sorted({o for v in children for o in v.origins}))[:32])
        if isinstance(n,ast.FormattedValue):
            value=self.evaluate(n.value,env)
            if n.format_spec is not None:
                spec=self.evaluate(n.format_spec,env)
                if spec.sql_value not in ('constant','integer'): return replace(value,sql_value='unknown',taint=value.taint or spec.taint)
            return value
        if isinstance(n,ast.Subscript):
            base=self.evaluate(n.value,env)
            if self.name(n.value)=='os.environ': return Value('possible',sensitive=True)
            if isinstance(n.slice,ast.Slice) and n.slice.lower is None and n.slice.step is None:
                high=self.evaluate(n.slice.upper,env).number
                if type(high) is int and high>=0:
                    return Value('definite',size=min(base.size,high) if base.size is not None else high,taint=base.taint)
            return Value(taint=base.taint)
        if isinstance(n,ast.Await):
            value=self.evaluate(n.value,env)
            self.invalidate(env,n.lineno)
            self.gaps.add('semantic_async_scheduling_unresolved')
            return replace(value,size=None,attributes=(),timeout=None,timeout_state='unknown')
        if isinstance(n,ast.IfExp):
            if not self.spend('paths'): return UNKNOWN
            return self.evaluate(n.body,env.copy()).join(self.evaluate(n.orelse,env.copy()))
        if not isinstance(n,ast.Call): return UNKNOWN
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
        self.result.sites.append(Site(n.lineno,self.owner,'call',len(self.loop_bounds),bound if self.loop_bounds else None,context=self.context,conditional=self.conditional))
        args=[self.evaluate(a,env) for a in n.args]
        kwargs={k.arg:self.evaluate(k.value,env) for k in n.keywords}
        if self.language=='python' and target in ('range','builtins.range') and target not in env and target not in self.functions and not kwargs and 1<=len(args)<=3 and all(type(v.number) is int for v in args):
            try: return Value('definite',size=len(range(*(v.number for v in args))))
            except (ValueError,OverflowError): return UNKNOWN
        if target in ('range','builtins.range') and self.language=='python' and target not in env and target not in self.functions and len(args)==1 and not kwargs and type(args[0].maximum) is int:
            return Value('possible',size=max(0,args[0].maximum),taint=args[0].taint)
        if self.language=='python' and target=='len' and target not in env and target not in self.functions and len(args)==1: return Value('definite',number=args[0].size)
        if self.language=='python' and target in ('input','builtins.input') and target not in env and target not in self.functions: return Value('possible',taint=True)
        if self.language=='python' and target in ('int','builtins.int') and target not in env and target not in self.functions and target not in self.classes and len(args)==1 and not kwargs:
            return Value('definite',sql_value='integer',origins=args[0].origins)
        if isinstance(n.func,ast.Attribute) and n.func.attr=='format' and receiver.literal_string:
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
                return Value('definite',number=number,minimum=number,maximum=number)
            lowers=[v.minimum for v in args if v.minimum is not None]
            uppers=[v.maximum for v in args if v.maximum is not None]
            return Value('possible',minimum=max(lowers) if target=='max' and lowers else None,
                         maximum=min(uppers) if target=='min' and uppers else None,
                         taint=any(v.taint for v in args))
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
        if isinstance(n.func, ast.Name) and n.func.id in self.imported and self.workspace:
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
            if cls.bases: self.gaps.add('semantic_inherited_receiver_unresolved')
            value=Value('definite',receiver='class:'+n.func.id,object_id=(self.facts.module.id,n.lineno,self.context))
            init=next((x for x in cls.body if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef)) and x.name=='__init__'),None)
            if init:
                # Constructor attributes are copied to the returned receiver's local identity.
                attrs={}
                self.invoke(init,[value]+args,kwargs,attrs,n.lineno, capture=attrs)
                value=replace(value,attributes=tuple(sorted((key[5:],v) for key,v in attrs.items() if key.startswith('self.'))))
            if self.workspace: value=replace(value,receiver='class@'+self.facts.module.id+':'+n.func.id)
            return value
        if receiver.receiver and receiver.receiver.startswith('class@') and self.workspace:
            result=self.workspace.method(self,receiver,n.func.attr,args,kwargs,n.lineno)
            self.invalidate_receiver(receiver,env)
            return result
        if receiver.receiver and receiver.receiver.startswith('class:'):
            clsname=receiver.receiver[6:]
            cls=self.classes.get(clsname,[])
            methods=[m for c in cls for m in c.body if isinstance(m,(ast.FunctionDef,ast.AsyncFunctionDef)) and m.name==n.func.attr]
            if len(methods)==1:
                attrs={'self.'+k:v for k,v in receiver.attributes}
                result=self.invoke(methods[0],[receiver]+args,kwargs,attrs,n.lineno)
                self.invalidate_receiver(receiver,env)
                return result

        if isinstance(n.func,ast.Name) and n.func.id in self.functions and len(self.functions[n.func.id])==1 and n.func.id not in env:
            result=self.invoke(self.functions[n.func.id][0],args,kwargs,env,n.lineno)
            self.invalidate(env,n.lineno)
            return result
        if isinstance(n.func,ast.Attribute) and not receiver.receiver and self.raw_name(n.func).startswith('self.'):
            self.gaps.add('semantic_unresolved_instance_receiver')
        query=target.rsplit('.',1)[-1] in ('execute','executemany','query')
        sdk_operation=resolve_operation(target) if receiver.constructed or function_value.constructed else None
        if target.startswith('known_mock.') and target.endswith(MODEL_SUFFIXES+EMBEDDING_SUFFIXES):
            self.result.sites.append(Site(n.lineno,self.owner,'mock_operation',context=self.context))
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
                operation_id=sdk_operation.receiver+'.'+sdk_operation.suffix if sdk_operation else None))
            self.result.summaries.setdefault(self.owner,set()).add(op)
        # Unknown calls may mutate any aliased collection. Invalidate all bounds,
        # because alias identities are intentionally not modeled in this subset.
        if not op and target not in ('len','range'):
            self.invalidate(env,n.lineno)
        return Value(taint=bool(model) or receiver.taint or any(v.taint for v in args+list(kwargs.values())),dynamic_sql=any(v.dynamic_sql for v in args+list(kwargs.values())),sensitive=receiver.sensitive or any(v.sensitive for v in args+list(kwargs.values())))

    def invalidate_receiver(self,receiver,env):
        # A method may change instance state. Without a heap-effect summary, no
        # later call through an object alias may reuse constructor attributes.
        if not receiver.object_id: return
        for key,value in list(env.items()):
            if value.object_id==receiver.object_id:
                env[key]=replace(value,attributes=(),timeout=None,timeout_state="unknown",state='unknown')

    def invalidate(self,env,line=1):
        if any(v.size is not None or v.timeout is not None or v.attributes for v in env.values()):
            self.result.sites.append(Site(line,self.owner,'invalidation',context=self.context))
        for key,value in list(env.items()):
            if value.size is not None or value.attributes or value.timeout is not None or value.timeout_state!='unknown':
                env[key]=replace(value,size=None,attributes=(),timeout=None,timeout_state="unknown",state='unknown')

    def raw_name(self,n):
        if isinstance(n,ast.Name): return n.id
        if isinstance(n,ast.Attribute): return self.raw_name(n.value)+'.'+n.attr
        return ''

    def invoke(self,fn,args,kwargs,env,line,capture=None,external=False):
        if fn.lineno in self.active or len(self.active)>=self.b.depth:
            self.gaps.add('semantic_recursion_or_depth_limit'); return UNKNOWN
        if not self.spend('contexts') or not self.spend('summary_expansions'): return UNKNOWN
        if fn.args.vararg or fn.args.kwarg or None in kwargs:
            self.gaps.add('semantic_dynamic_function_binding'); return UNKNOWN
        from .safeguards import function_guards
        guards=function_guards(fn,self.aliases,self.globals)
        def route_decorator(dec):
            if not isinstance(dec,ast.Call) or not isinstance(dec.func,ast.Attribute) or not isinstance(dec.func.value,ast.Name): return False
            value=self.globals.get(dec.func.value.id,UNKNOWN)
            return value.receiver in ('fastapi.FastAPI','flask.Flask') and dec.func.attr in ('route','get','post','put','patch','delete','head','options','api_route')
        route=any(route_decorator(d) for d in fn.decorator_list)
        dynamic_decorator=bool(fn.decorator_list) and not guards and not route
        if dynamic_decorator:
            self.gaps.add('semantic_decorated_function_binding_unverified')
        params=fn.args.posonlyargs+fn.args.args
        local=dict(self.globals)
        local.update(env if capture is not None or any(k.startswith('self.') for k in env) else {})
        for p in params+fn.args.kwonlyargs: local.pop(p.arg,None)
        for p,v in zip(params,args): local[p.arg]=v
        defaults=dict(zip([p.arg for p in params[-len(fn.args.defaults):]],fn.args.defaults)) if fn.args.defaults else {}
        defaults.update({p.arg:d for p,d in zip(fn.args.kwonlyargs,fn.args.kw_defaults) if d is not None})
        for p in params+fn.args.kwonlyargs:
            if p.arg in kwargs: local[p.arg]=kwargs[p.arg]
            elif p.arg not in local:
                local[p.arg]=self.evaluate(defaults.get(p.arg),self.globals.copy())
                if route and p.arg not in defaults: local[p.arg]=replace(local[p.arg],taint=True)
                if p.annotation and self.name(p.annotation)=='fastapi.Request': local[p.arg]=replace(local[p.arg],taint=True)
        if external and route:
            for p in params+fn.args.kwonlyargs: local[p.arg]=replace(local[p.arg],taint=True)
        saved=(self.owner,self.context,self.active,self.loop_bounds,self.conditional,self.guards)
        self.guards=guards
        self.owner=self.owners.get((fn.lineno,fn.col_offset+1),self.owner)
        self.context=self.context+(line,)
        self.active=self.active+(fn.lineno,)
        # Caller loop domains remain relevant to callee operations.
        for v in args+list(kwargs.values()):
            if v.size is not None:
                self.result.sites.append(Site(fn.lineno,self.owner,'argument_bound',upper_bound=v.size,context=self.context))
        if guards:
            self.result.sites.append(Site(fn.lineno,self.owner,'authentication',context=self.context,safeguards=guards))
        value,_=self.block(fn.body,local)
        if value.size is not None:
            self.result.sites.append(Site(fn.lineno,self.owner,'return_bound',upper_bound=value.size,context=self.context))
        if dynamic_decorator:
            value=Value(taint=value.taint or any(v.taint for v in args+list(kwargs.values())),dynamic_sql=value.dynamic_sql,sensitive=value.sensitive)
        if capture is not None: capture.update(local)
        self.owner,self.context,self.active,self.loop_bounds,self.conditional,self.guards=saved
        return value

    def counter_bound(self,node,env):
        """Only a local monotonic counter with one unconditional final increment."""
        test=node.test
        if self.language!='python' or not isinstance(test,ast.Compare) or len(test.ops)!=1 or not isinstance(test.ops[0],(ast.Lt,ast.LtE)) or not isinstance(test.left,ast.Name) or not node.body: return None
        key=test.left.id
        start=env.get(key,UNKNOWN).number
        stop=self.evaluate(test.comparators[0],env).number
        last=node.body[-1]
        if type(start) is not int or type(stop) is not int or not isinstance(last,ast.AugAssign) or not isinstance(last.target,ast.Name) or last.target.id!=key or not isinstance(last.op,ast.Add): return None
        step=self.evaluate(last.value,env).number
        if type(step) is not int or step<=0: return None
        writes=[n for stmt in node.body for n in ast.walk(stmt) if isinstance(n,ast.Name) and n.id==key and isinstance(n.ctx,ast.Store)]
        if len(writes)!=1 or any(isinstance(n,(ast.Continue,ast.Break,ast.Global,ast.Nonlocal,ast.Await,ast.Yield,ast.FunctionDef,ast.ClassDef)) for stmt in node.body for n in ast.walk(stmt)): return None
        return max(0,(stop-start+int(isinstance(test.ops[0],ast.LtE))+step-1)//step)

    def block(self,body,env):
        pending=None
        def returned(value): return value if pending is None else pending.join(value)
        for n in body:
            if not self.spend('iterations'): return UNKNOWN,False
            if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Import,ast.ImportFrom)): continue
            if isinstance(n,(ast.Assign,ast.AnnAssign)):
                value=self.evaluate(n.value,env)
                targets=n.targets if isinstance(n,ast.Assign) else [n.target]
                for t in targets:
                    if isinstance(t,ast.Name): env[t.id]=value
                    elif isinstance(t,ast.Attribute) and self.raw_name(t).startswith('self.'):
                        env[self.raw_name(t)]=value
                    else:
                        self.invalidate(env,n.lineno)
            elif isinstance(n,ast.AugAssign):
                self.evaluate(n.value,env)
                for k,v in list(env.items()):
                    if v.size is not None or isinstance(n.target,ast.Name) and k==n.target.id: env[k]=UNKNOWN
            elif isinstance(n,ast.Expr): self.evaluate(n.value,env)
            elif isinstance(n,ast.Return): return returned(self.evaluate(n.value,env)),True
            elif isinstance(n,ast.Raise): self.evaluate(n.exc,env); return returned(UNKNOWN),True
            elif isinstance(n,ast.If):
                self.evaluate(n.test,env)
                if not self.spend('paths'): return UNKNOWN,False
                left,right=env.copy(),env.copy()
                old=self.conditional; self.conditional=True
                lv,lr=self.block(n.body,left); rv,rr=self.block(n.orelse,right)
                self.conditional=old
                for k in left.keys()|right.keys():
                    env[k]=right.get(k,UNKNOWN) if lr and not rr else left.get(k,UNKNOWN) if rr and not lr else left.get(k,UNKNOWN).join(right.get(k,UNKNOWN))
                if lr and rr: return returned(lv.join(rv)),True
                if lr: pending=returned(lv)
                elif rr: pending=returned(rv)
            elif isinstance(n,(ast.For,ast.AsyncFor,ast.While)):
                domain=self.evaluate(n.iter,env) if isinstance(n,(ast.For,ast.AsyncFor)) else UNKNOWN
                if isinstance(n,ast.While):
                    self.evaluate(n.test,env)
                    domain=Value('possible',size=self.counter_bound(n,env))
                old=self.loop_bounds
                old_origins=self.loop_origins
                self.loop_origins=tuple(sorted(set(old_origins+domain.origins)))[:32]
                self.loop_bounds=old+(domain.size,)
                local=env.copy()
                # All loop-carried assignments and mutations are widened before
                # observing operations; a single unrolling cannot prove invariants.
                stores={x.id for statement in n.body for x in ast.walk(statement) if isinstance(x,ast.Name) and isinstance(x.ctx,ast.Store)}
                def may_mutate(call):
                    target=self.name(call.func)
                    if target in ('range','len','str','int','float','bool') and target not in env and target not in self.functions:
                        return False
                    if self.provider and target.endswith(MODEL_SUFFIXES+EMBEDDING_SUFFIXES):
                        return False
                    if target in tuple('requests.'+v for v in ('get','post','put','delete','patch','head','options','request')):
                        return False
                    if target.rsplit('.',1)[-1] in ('execute','executemany','query'):
                        return False
                    return True
                mutates=any(isinstance(x,ast.Call) and may_mutate(x) for statement in n.body for x in ast.walk(statement))
                if mutates or isinstance(n,ast.AsyncFor) or any(isinstance(x,ast.Await) for stmt in n.body for x in ast.walk(stmt)):
                    self.loop_bounds=old+(None,)
                for k in stores: local[k]=UNKNOWN
                if isinstance(n,(ast.For,ast.AsyncFor)) and isinstance(n.target,ast.Name): local[n.target.id]=Value(taint=domain.taint)
                loop_return,loop_exits=self.block(n.body,local)
                if any(isinstance(x,ast.Return) for statement in n.body for x in ast.walk(statement)):
                    # A loop may execute zero times. Retain possible return values
                    # without proving iteration feasibility or dropping taint.
                    pending=returned(loop_return)
                self.loop_bounds=old
                self.loop_origins=old_origins
                for k in env.keys()|local.keys(): env[k]=env.get(k,UNKNOWN).join(local.get(k,UNKNOWN))
                self.block(n.orelse,env)
            else:
                # Do not infer enforcement through unmodeled try/with/match,
                # comprehensions, break/continue or destructuring semantics.
                self.gaps.add('semantic_unsupported_control_or_statement')
                for child in ast.iter_child_nodes(n):
                    if isinstance(child,ast.expr): self.evaluate(child,env)
                for k in list(env): env[k]=UNKNOWN
        return returned(UNKNOWN),False

    def run(self):
        # A bounded structured CFG for straight-line/if/for/while/return blocks.
        # Exception edges and unsupported controls are explicitly absent.
        def cfg(body,follow=()):
            nexts=follow
            for n in reversed(body):
                if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)): continue
                if len(self.nodes)>=self.b.cfg_nodes:
                    self.gaps.add('semantic_cfg_nodes_limit'); return nexts
                i=len(self.nodes); self.nodes.append(FlowNode(i,n.lineno,type(n).__name__))
                if isinstance(n,ast.If): successors=cfg(n.body,nexts)+cfg(n.orelse,nexts)
                elif isinstance(n,(ast.For,ast.AsyncFor,ast.While)): successors=cfg(n.body,(i,))+nexts
                else: successors=() if isinstance(n,(ast.Return,ast.Raise)) else nexts
                self.nodes[i]=FlowNode(i,n.lineno,type(n).__name__,tuple(dict.fromkeys(successors)))
                nexts=(i,)
            return nexts
        cfg(self.tree.body)
        for fns in self.functions.values():
            for fn in fns: cfg(fn.body)
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
            self.gaps.add('semantic_intermediate_representation_limit')
        else:
            self.result.program=sanitized(self.tree)
        self.result.language=self.language
        self.result.cfg=tuple(self.nodes)
        self.result.incomplete=tuple(sorted(self.gaps))
        return self.result
