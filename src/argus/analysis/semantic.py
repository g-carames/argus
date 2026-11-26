"""Bounded abstract interpretation. Parser objects and names never leave extraction.

Unknown is absorbing at joins. Bounds describe a single iteration domain, not cost.
Only positive evidence can establish a safeguard; naming is never validation.
"""
import ast
from dataclasses import dataclass, field, replace
from .parsing import PRIMARY, walk


@dataclass(frozen=True)
class Budgets:
    depth: int = 4
    contexts: int = 128
    cfg_nodes: int = 2048
    iterations: int = 4096
    paths: int = 64
    summary_expansions: int = 256

    def __post_init__(self):
        if any(type(v) is not int or not 1 <= v <= 100000 for v in vars(self).values()):
            raise ValueError('Invalid semantic budget')


@dataclass(frozen=True)
class Value:
    state: str = 'unknown'  # definite, possible, conflicting, unknown
    number: int | None = None
    size: int | None = None
    taint: bool = False
    dynamic_sql: bool = False

    def join(self, other):
        if self == other: return self
        return Value(state='unknown' if 'unknown' in (self.state, other.state) else 'conflicting',
                     size=max(self.size, other.size) if self.size is not None and other.size is not None else None,
                     taint=self.taint or other.taint, dynamic_sql=self.dynamic_sql or other.dynamic_sql)


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


@dataclass
class SemanticFacts:
    sites: list = field(default_factory=list)
    cfg: tuple = ()
    incomplete: tuple = ()
    # Function summaries are source-free sets of observed operation kinds by owner.
    summaries: dict = field(default_factory=dict)


def collect(file, parsed, facts, budgets=Budgets()):
    if parsed.language == 'python':
        return PythonFlow(parsed, facts, budgets).run()
    result = SemanticFacts()
    if parsed.language not in PRIMARY: return result
    result.incomplete=('JavaScript-family value flow, CFG and safeguard applicability unavailable.',)
    data = parsed.content
    def text(n): return data[n.start_byte:n.end_byte].decode('utf-8') if n else ''
    owners = {(s.location.start_line, s.location.start_column): s.id for s in facts.symbols}
    provider = any(n.type == 'import_statement' and text(n.child_by_field_name('source')).strip('\"\'') in
                   ('openai','@anthropic-ai/sdk','@google/generative-ai','@google/genai','langchain','@langchain/openai','@langchain/langgraph')
                   for n in parsed.tree.root_node.named_children)
    def visit(n, owner=facts.module.id, loops=0):
        if len(result.sites)>=budgets.cfg_nodes:
            result.incomplete=tuple(sorted(set(result.incomplete+('semantic_sites_limit',))))
            return
        if n.type in ('function_declaration','function_expression','arrow_function','method_definition','generator_function_declaration'):
            owner = owners.get((n.start_point.row+1,n.start_point.column+1), owner)
            loops = 0
        loops += n.type in ('for_statement','for_in_statement','while_statement','do_statement')
        if n.type == 'call_expression':
            target = text(n.child_by_field_name('function'))
            op = 'model' if provider and target.endswith(('.chat.completions.create','.completions.create','.messages.create','.generateContent','.generate_content')) else 'embedding' if provider and target.endswith(('.embeddings.create','.embedContent','.embed_content')) else ''
            result.sites.append(Site(n.start_point.row+1,owner,'call',loops))
            if op:
                result.sites.append(Site(n.start_point.row+1,owner,op,loops))
                result.summaries.setdefault(owner,set()).add(op)
        for c in n.named_children: visit(c,owner,loops)
    visit(parsed.tree.root_node)
    return result


class PythonFlow:
    def __init__(self, parsed, facts, budgets):
        self.tree, self.facts, self.b = parsed.tree, facts, budgets
        self.result = SemanticFacts()
        self.aliases, self.functions = {}, {}
        self.counts = dict(contexts=0, iterations=0, paths=0, summary_expansions=0)
        self.gaps = set()
        self.owner = facts.module.id
        self.context = ()
        self.active = ()
        self.loop_bounds = ()
        self.conditional = False
        self.owners = {(s.location.start_line,s.location.start_column):s.id for s in facts.symbols}
        self.nodes = []
        for n in self.tree.body:
            if isinstance(n,ast.Import):
                for a in n.names: self.aliases[a.asname or a.name.split('.')[0]] = a.name
            elif isinstance(n,ast.ImportFrom) and n.module:
                for a in n.names: self.aliases[a.asname or a.name] = n.module+'.'+a.name
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
        if n is None: return UNKNOWN
        if not self.spend('iterations'): return UNKNOWN
        if isinstance(n,ast.Constant):
            # Never retain strings, booleans or credential-derived numerical values.
            return Value('definite',number=n.value) if type(n.value) is int and abs(n.value)<=10**9 else Value('definite')
        if isinstance(n,ast.Name): return env.get(n.id,UNKNOWN)
        if isinstance(n,(ast.List,ast.Tuple,ast.Set)):
            values=[self.evaluate(x,env) for x in n.elts]
            return Value('definite',size=len(values),taint=any(v.taint for v in values))
        if isinstance(n,(ast.JoinedStr,ast.BinOp)):
            children=[self.evaluate(x,env) for x in ast.iter_child_nodes(n) if not isinstance(x,ast.operator)]
            if isinstance(n,ast.BinOp) and isinstance(n.op,ast.Add) and len(children)==2:
                a,b=children
                if a.size is not None and b.size is not None:
                    return Value('definite',size=a.size+b.size,taint=a.taint or b.taint)
                if a.number is not None and b.number is not None and abs(a.number+b.number)<=10**9:
                    return Value('definite',number=a.number+b.number,taint=a.taint or b.taint)
            return Value('possible',taint=any(v.taint for v in children),dynamic_sql=True)
        if isinstance(n,ast.FormattedValue): return self.evaluate(n.value,env)
        if isinstance(n,ast.Subscript):
            base=self.evaluate(n.value,env)
            if isinstance(n.slice,ast.Slice) and n.slice.lower is None and n.slice.step is None:
                high=self.evaluate(n.slice.upper,env).number
                if high is not None and high>=0:
                    return Value('definite',size=min(base.size,high) if base.size is not None else high,taint=base.taint)
            return Value(taint=base.taint)
        if isinstance(n,ast.Await): return self.evaluate(n.value,env)
        if isinstance(n,ast.IfExp):
            if not self.spend('paths'): return UNKNOWN
            return self.evaluate(n.body,env.copy()).join(self.evaluate(n.orelse,env.copy()))
        if not isinstance(n,ast.Call): return UNKNOWN
        target=self.name(n.func)
        bound=1
        for size in self.loop_bounds:
            if size is None: bound=None; break
            bound=bound*size
        self.result.sites.append(Site(n.lineno,self.owner,'call',len(self.loop_bounds),bound if self.loop_bounds else None,context=self.context,conditional=self.conditional))
        args=[self.evaluate(a,env) for a in n.args]
        kwargs={k.arg:self.evaluate(k.value,env) for k in n.keywords}
        if target in ('range','builtins.range') and target not in env and target not in self.functions and not kwargs and 1<=len(args)<=3 and all(v.number is not None for v in args):
            try: return Value('definite',size=len(range(*(v.number for v in args))))
            except (ValueError,OverflowError): return UNKNOWN
        if target=='len' and target not in env and target not in self.functions and len(args)==1: return Value('definite',number=args[0].size)
        if target in ('input','builtins.input'): return Value('possible',taint=True)
        if isinstance(n.func,ast.Name) and n.func.id in self.functions and len(self.functions[n.func.id])==1 and n.func.id not in env:
            result=self.invoke(self.functions[n.func.id][0],args,kwargs,env,n.lineno)
            for key,value in list(env.items()):
                if value.size is not None: env[key]=replace(value,size=None,state='unknown')
            return result
        query=target.rsplit('.',1)[-1] in ('execute','executemany','query')
        model=self.provider and target.endswith(('.chat.completions.create','.completions.create','.messages.create','.generate_content','.generateContent'))
        embedding=self.provider and target.endswith(('.embeddings.create','.embed_content','.embedContent'))
        request=target in tuple('requests.'+v for v in ('get','post','put','delete','patch','head','options','request'))
        op='model' if model else 'embedding' if embedding else 'database' if query else 'http' if request else 'execution' if target in ('eval','exec','os.system','os.popen') else ''
        if op:
            keys=('max_tokens','max_completion_tokens','max_output_tokens') if model else ('timeout',) if request else ()
            limited=any(k in kwargs and kwargs[k].number is not None and kwargs[k].number>0 for k in keys)
            bound=1
            for size in self.loop_bounds:
                if size is None: bound=None; break
                bound=bound*size
            self.result.sites.append(Site(n.lineno,self.owner,op,len(self.loop_bounds),bound if self.loop_bounds else None,
                limited,any(v.taint for v in args),bool(args and args[0].dynamic_sql),self.context,self.conditional,
                any(k in kwargs for k in keys) or model and any(k in kwargs for k in ('config','generationConfig')),None in kwargs))
            self.result.summaries.setdefault(self.owner,set()).add(op)
        # Unknown calls may mutate any aliased collection. Invalidate all bounds,
        # because alias identities are intentionally not modeled in this subset.
        if not op and target not in ('len','range'):
            for key,value in list(env.items()):
                if value.size is not None: env[key]=replace(value,size=None,state='unknown')
        return Value(taint=any(v.taint for v in args),dynamic_sql=any(v.dynamic_sql for v in args))

    def invoke(self,fn,args,kwargs,env,line):
        if fn.lineno in self.active or len(self.active)>=self.b.depth:
            self.gaps.add('semantic_recursion_or_depth_limit'); return UNKNOWN
        if not self.spend('contexts') or not self.spend('summary_expansions'): return UNKNOWN
        if fn.decorator_list or fn.args.vararg or fn.args.kwarg or None in kwargs:
            self.gaps.add('semantic_dynamic_function_binding'); return UNKNOWN
        params=fn.args.posonlyargs+fn.args.args
        local={}  # Mutable globals/closures are not assumed stable.
        for p,v in zip(params,args): local[p.arg]=v
        defaults=dict(zip([p.arg for p in params[-len(fn.args.defaults):]],fn.args.defaults)) if fn.args.defaults else {}
        for p in params+fn.args.kwonlyargs:
            if p.arg in kwargs: local[p.arg]=kwargs[p.arg]
            elif p.arg not in local: local[p.arg]=self.evaluate(defaults.get(p.arg),{})
        saved=(self.owner,self.context,self.active,self.loop_bounds,self.conditional)
        self.owner=self.owners.get((fn.lineno,fn.col_offset+1),self.owner)
        self.context=self.context+(line,)
        self.active=self.active+(fn.lineno,)
        # Caller loop domains remain relevant to callee operations.
        value,_=self.block(fn.body,local)
        self.owner,self.context,self.active,self.loop_bounds,self.conditional=saved
        return value

    def block(self,body,env):
        for n in body:
            if not self.spend('iterations'): return UNKNOWN,False
            if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Import,ast.ImportFrom)): continue
            if isinstance(n,(ast.Assign,ast.AnnAssign)):
                value=self.evaluate(n.value,env)
                targets=n.targets if isinstance(n,ast.Assign) else [n.target]
                for t in targets:
                    if isinstance(t,ast.Name): env[t.id]=value
                    else:
                        for k,v in list(env.items()):
                            if v.size is not None: env[k]=replace(v,size=None,state='unknown')
            elif isinstance(n,ast.AugAssign):
                self.evaluate(n.value,env)
                for k,v in list(env.items()):
                    if v.size is not None or isinstance(n.target,ast.Name) and k==n.target.id: env[k]=UNKNOWN
            elif isinstance(n,ast.Expr): self.evaluate(n.value,env)
            elif isinstance(n,ast.Return): return self.evaluate(n.value,env),True
            elif isinstance(n,ast.Raise): self.evaluate(n.exc,env); return UNKNOWN,True
            elif isinstance(n,ast.If):
                self.evaluate(n.test,env)
                if not self.spend('paths'): return UNKNOWN,False
                left,right=env.copy(),env.copy()
                old=self.conditional; self.conditional=True
                lv,lr=self.block(n.body,left); rv,rr=self.block(n.orelse,right)
                self.conditional=old
                for k in left.keys()|right.keys():
                    env[k]=right.get(k,UNKNOWN) if lr and not rr else left.get(k,UNKNOWN) if rr and not lr else left.get(k,UNKNOWN).join(right.get(k,UNKNOWN))
                if lr and rr: return lv.join(rv),True
            elif isinstance(n,(ast.For,ast.AsyncFor,ast.While)):
                domain=self.evaluate(n.iter,env) if isinstance(n,(ast.For,ast.AsyncFor)) else UNKNOWN
                if isinstance(n,ast.While): self.evaluate(n.test,env)
                old=self.loop_bounds
                self.loop_bounds=old+(domain.size,)
                local=env.copy()
                # All loop-carried assignments and mutations are widened before
                # observing operations; a single unrolling cannot prove invariants.
                stores={x.id for statement in n.body for x in ast.walk(statement) if isinstance(x,ast.Name) and isinstance(x.ctx,ast.Store)}
                def may_mutate(call):
                    target=self.name(call.func)
                    if target in ('range','len','str','int','float','bool') and target not in env and target not in self.functions:
                        return False
                    if self.provider and target.endswith(('.chat.completions.create','.completions.create','.messages.create','.generate_content','.generateContent','.embeddings.create','.embed_content','.embedContent')):
                        return False
                    if target.rsplit('.',1)[-1] in ('execute','executemany','query'):
                        return False
                    return True
                mutates=any(isinstance(x,ast.Call) and may_mutate(x) for statement in n.body for x in ast.walk(statement))
                if mutates:
                    self.loop_bounds=old+(None,)
                for k in stores: local[k]=UNKNOWN
                if isinstance(n,(ast.For,ast.AsyncFor)) and isinstance(n.target,ast.Name): local[n.target.id]=Value(taint=domain.taint)
                self.block(n.body,local)
                self.loop_bounds=old
                for k in env.keys()|local.keys(): env[k]=env.get(k,UNKNOWN).join(local.get(k,UNKNOWN))
                self.block(n.orelse,env)
            else:
                # Do not infer enforcement through unmodeled try/with/match,
                # comprehensions, break/continue or destructuring semantics.
                self.gaps.add('semantic_unsupported_control_or_statement')
                for child in ast.iter_child_nodes(n):
                    if isinstance(child,ast.expr): self.evaluate(child,env)
                for k in list(env): env[k]=UNKNOWN
        return UNKNOWN,False

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
        self.block(self.tree.body,{})
        for fns in self.functions.values():
            if len(fns)==1:
                fn=fns[0]
                # Analyze public entry scope with unknown arguments, independently
                # of callers. Never let one constrained caller protect another.
                self.invoke(fn,[],{}, {},fn.lineno)
        self.result.cfg=tuple(self.nodes)
        self.result.incomplete=tuple(sorted(self.gaps))
        return self.result
