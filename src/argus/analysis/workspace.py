"""Bounded cross-file flow over already extracted, source-free programs.

Never opens target files. The existing resolver is the sole authority for module
identity. Cycles and ambiguous exports remain unknown, including re-export cycles.
"""
import ast
from types import SimpleNamespace
from .semantic import PythonFlow, Budgets, Value, UNKNOWN, column
from .extraction import ImportFact
from ..models.analysis import Resolution


class WorkspaceFlow:
    def __init__(self, facts, files, resolver, budgets=Budgets()):
        self.flows={}
        self.paths={}
        self.bindings={}
        self.resolver=resolver
        self.b=budgets
        self.active=[]
        self.contexts=0
        self.initializing=set()
        self.initialized=set()
        self.files=files
        for path,file in sorted(files.items()):
            f=facts.get(file.id)
            if not f or not f.semantic or f.semantic.program is None: continue
            if len(self.flows)>=budgets.modules:
                f.semantic.incomplete=tuple(sorted(set(f.semantic.incomplete+('semantic_cross_file_modules_limit',))))
                continue
            flow=PythonFlow(SimpleNamespace(tree=f.semantic.program),f,budgets)
            flow.language=f.semantic.language
            flow.workspace=self
            flow.gaps.update(f.semantic.incomplete)
            self.flows[f.module.id]=flow
            self.paths[f.module.id]=path
        self.by_path={p:mid for mid,p in self.paths.items()}

    def target(self,flow,node,alias):
        ref='.'*node.level+(node.module or '') if isinstance(node,ast.ImportFrom) else alias.name
        fact=ImportFact(ref,node.lineno,names=(alias.name,) if isinstance(node,ast.ImportFrom) else ())
        target=self.resolver.resolve(self.paths[flow.facts.module.id],flow.language,fact)
        if target.status!=Resolution.RESOLVED: return None
        return self.by_path.get(target.path)

    def initialize(self,mid):
        if mid in self.initialized: return
        if mid in self.initializing:
            self.flows[mid].gaps.add('semantic_cyclic_module_initialization'); return
        self.initializing.add(mid)
        flow=self.flows[mid]
        for n in flow.tree.body:
            if not isinstance(n,(ast.Import,ast.ImportFrom)): continue
            for alias in n.names:
                target=self.target(flow,n,alias)
                if target is None:
                    reference='.'*n.level+(n.module or '') if isinstance(n,ast.ImportFrom) else alias.name
                    resolution=self.resolver.resolve(self.paths[mid],flow.language,ImportFact(reference,n.lineno,names=(alias.name,) if isinstance(n,ast.ImportFrom) else ()))
                    if resolution.status!=Resolution.EXTERNAL:
                        flow.imported[alias.asname or alias.name.split('.')[0]]=UNKNOWN
                        flow.gap('semantic_unresolved_or_unavailable_import')
                    continue
                local=alias.asname or alias.name.split('.')[0]
                if isinstance(n,ast.Import) or alias.name=='*':
                    flow.imported[local]=Value('definite',receiver='module:'+target)
                else:
                    binding=self.export(target,alias.name,())
                    if binding:
                        self.bindings[mid,local]=binding
                        other,name=binding
                        self.initialize(other)
                        value=self.flows[other].globals.get(name,UNKNOWN)
                        if name in self.flows[other].functions:
                            value=Value('definite',receiver='function@'+other+':'+name)
                        elif name in self.flows[other].classes:
                            value=Value('definite',receiver='constructor@'+other+':'+name)
                        flow.imported[local]=value
                    else:
                        flow.imported[local]=UNKNOWN
                        flow.gap('semantic_unresolved_import_value')
        # Execute only abstract transfer functions, never target code.
        env=dict(flow.imported)
        flow.block(flow.tree.body,env)
        flow.globals={k:(UNKNOWN if any('limit' in g for g in flow.gaps) else v) for k,v in env.items() if v.size is None}
        flow.exports=env
        self.initializing.remove(mid)
        self.initialized.add(mid)

    def export(self,mid,name,seen):
        key=(mid,name)
        if key in seen or len(seen)>=self.b.depth:
            self.flows[mid].gaps.add('semantic_reexport_cycle_or_depth_limit'); return None
        flow=self.flows[mid]
        definitions=[]
        for n in flow.tree.body:
            if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and n.name==name: definitions.append((mid,name))
            elif isinstance(n,(ast.Assign,ast.AnnAssign)):
                targets=n.targets if isinstance(n,ast.Assign) else [n.target]
                if any(isinstance(t,ast.Name) and t.id==name for t in targets): definitions.append((mid,name))
            elif isinstance(n,ast.ImportFrom):
                for alias in n.names:
                    if (alias.asname or alias.name)==name:
                        target=self.target(flow,n,alias)
                        if target:
                            binding=self.export(target,alias.name,seen+(key,))
                            if binding: definitions.append(binding)
        return definitions[0] if len(definitions)==1 else None

    def invoke(self,caller,binding,args,kwargs,line):
        mid,name=binding
        callee=self.flows[mid]
        key=(mid,name)
        self.contexts+=1
        if key in self.active or len(self.active)>=self.b.depth or self.contexts>self.b.contexts:
            caller.gap('semantic_cross_file_context_or_recursion_limit')
            callee.gap('semantic_cross_file_context_or_recursion_limit')
            return UNKNOWN
        functions=callee.functions.get(name,[])
        if len(functions)!=1 and name in callee.classes:
            env={'@arg'+str(i):v for i,v in enumerate(args)}
            keys={k:'@kw'+str(i) for i,k in enumerate(kwargs)}
            env.update({keys[k]:v for k,v in kwargs.items()})
            call=ast.Call(func=ast.Name(id=name,ctx=ast.Load()),args=[ast.Name(id='@arg'+str(i),ctx=ast.Load()) for i in range(len(args))],keywords=[ast.keyword(arg=k,value=ast.Name(id=v,ctx=ast.Load())) for k,v in keys.items()])
            call.lineno=line
            for node in ast.walk(call): node.argus_synthetic=True
            saved=(callee.context,callee.loop_bounds,callee.conditional,callee.loop_origins,callee.call_path,callee.pending_call,callee.active_call)
            callee.context=caller.context if callee is caller else ()
            callee.call_path=caller.call_path
            callee.pending_call=caller.active_call
            callee.active_call=caller.active_call
            callee.loop_bounds=caller.loop_bounds
            callee.loop_origins=caller.loop_origins
            callee.conditional=caller.conditional
            self.active.append(key)
            try: return callee.evaluate(call,env)
            finally:
                callee.context,callee.loop_bounds,callee.conditional,callee.loop_origins,callee.call_path,callee.pending_call,callee.active_call=saved
                self.active.pop()
        if len(functions)!=1:
            caller.gap('semantic_imported_callable_unavailable'); return UNKNOWN
        self.active.append(key)
        saved=(callee.context,callee.loop_bounds,callee.conditional,callee.loop_origins,callee.call_path,callee.pending_call)
        # Context line numbers belong to their source module; do not invent
        # same-file call paths from foreign line numbers.
        callee.context=()
        callee.call_path=caller.call_path
        callee.pending_call=caller.active_call
        callee.loop_bounds=caller.loop_bounds
        callee.loop_origins=caller.loop_origins
        callee.conditional=caller.conditional
        try: return callee.invoke(functions[0],args,kwargs,callee.globals,functions[0].lineno if callee is not caller else line)
        finally:
            callee.context,callee.loop_bounds,callee.conditional,callee.loop_origins,callee.call_path,callee.pending_call=saved
            self.active.pop()

    def method_targets(self,receiver,name):
        if not receiver.startswith('class@'): return ()
        mid,clsname=receiver[6:].split(':',1)
        flow=self.flows.get(mid)
        if flow is None: return ()
        return tuple(flow.owners[(m.lineno,column(m))]
            for cls in flow.classes.get(clsname,()) for m in cls.body
            if isinstance(m,(ast.FunctionDef,ast.AsyncFunctionDef)) and m.name==name
            and (m.lineno,column(m)) in flow.owners)

    def method(self,caller,receiver,name,args,kwargs,line):
        mid,clsname=receiver.receiver[6:].split(':',1)
        callee=self.flows.get(mid)
        if callee is None: return UNKNOWN
        methods=[m for c in callee.classes.get(clsname,[]) for m in c.body if isinstance(m,(ast.FunctionDef,ast.AsyncFunctionDef)) and m.name==name]
        key=(mid,clsname+'.'+name)
        self.contexts+=1
        if len(methods)!=1 or key in self.active or len(self.active)>=self.b.depth or self.contexts>self.b.contexts:
            caller.gap('semantic_method_resolution_or_context_limit'); return UNKNOWN
        self.active.append(key)
        saved=(callee.context,callee.loop_bounds,callee.conditional,callee.loop_origins,callee.call_path,callee.pending_call)
        callee.context=()
        callee.call_path=caller.call_path
        callee.pending_call=caller.active_call
        callee.loop_bounds=caller.loop_bounds
        callee.loop_origins=caller.loop_origins
        callee.conditional=caller.conditional
        try:
            return callee.invoke(methods[0],[receiver]+args,kwargs,{'self.'+k:v for k,v in receiver.attributes},methods[0].lineno if callee is not caller else line)
        finally:
            callee.context,callee.loop_bounds,callee.conditional,callee.loop_origins,callee.call_path,callee.pending_call=saved
            self.active.pop()

    def run(self):
        for mid in self.flows: self.initialize(mid)
        for flow in self.flows.values():
            for funcs in flow.functions.values():
                if len(funcs)==1:
                    fn=funcs[0]
                    flow.invoke(fn,[UNKNOWN for _ in fn.args.posonlyargs+fn.args.args],{p.arg:UNKNOWN for p in fn.args.kwonlyargs},flow.globals,fn.lineno,external=True)
        for flow in self.flows.values():
            flow.facts.semantic.sites=list(flow.result.sites)
            flow.facts.semantic.summaries=flow.result.summaries
            flow.facts.semantic.incomplete=tuple(sorted(flow.gaps))
            flow.facts.semantic.scope_gaps={k:tuple(sorted(v)) for k,v in flow.scope_gaps.items()}
