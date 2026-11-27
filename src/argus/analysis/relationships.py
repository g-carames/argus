"""Conservative source declarations for calls and HTTP; no runtime communication claim."""
import ast
import re
from dataclasses import dataclass, field
from ..privacy import identity
from ..models.analysis import GraphNode, Relationship, RelationshipKind, Resolution
from ..models.base import Confidence, Provenance
from ..models.source import Evidence, SourceLocation
from .extraction import ImportFact
from .parsing import PRIMARY, walk
from .semantic_contracts import Point


@dataclass
class Links:
    declarations: list = field(default_factory=list)  # hashed name, symbol id, lexical parent
    calls: list = field(default_factory=list)  # owner, hashed name, import reference, imported name, line, Unicode column
    endpoints: list = field(default_factory=list)  # method, normalized path, line
    requests: list = field(default_factory=list)


def literal(n):
    return n.value if isinstance(n, ast.Constant) and isinstance(n.value, str) else None


def route(value):
    # Keep only bounded path syntax; query strings/credentials/hostnames are not route evidence.
    if not isinstance(value,str) or len(value)>512 or not re.fullmatch(r'/[A-Za-z0-9_./:{}<>-]*',value): return None
    return value.rstrip('/') or '/'


def collect(file, parsed, facts):
    result=Links()
    if file.language not in PRIMARY: return result
    mid=facts.module.id
    source_lines=parsed.content.splitlines()
    symbols={(s.location.start_line,s.location.start_column,s.kind):s for s in facts.symbols}
    bindings={}
    known_apps={}
    constants={}
    if file.language == 'python':
        def qualified(n):
            if isinstance(n,ast.Name): return n.id
            if isinstance(n,ast.Attribute): return qualified(n.value)+'.'+n.attr
            return ''
        for n in parsed.tree.body:
            if isinstance(n,ast.Import):
                for a in n.names: bindings[a.asname or a.name.split('.')[0]]=(a.name,None)
            elif isinstance(n,ast.ImportFrom) and n.module:
                for a in n.names: bindings[a.asname or a.name]=('.'*n.level+n.module,a.name)
            elif isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
                name=n.targets[0].id
                value=literal(n.value)
                if value is not None: constants[name]=value
                if isinstance(n.value,ast.Call):
                    target=qualified(n.value.func)
                    module,member=bindings.get(target,('',None))
                    if (module,member) in (('fastapi','FastAPI'),('fastapi','APIRouter'),('flask','Flask'),('flask','Blueprint')):
                        prefix=next((literal(k.value) for k in n.value.keywords if k.arg in ('prefix','url_prefix')), '')
                        if prefix is not None: known_apps[name]=prefix
        # Includes same-module APIRouter mounts with a literal prefix only.
        for n in parsed.tree.body:
            if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call):
                c=n.value
                target=qualified(c.func)
                if target.endswith('.include_router') and target.split('.')[0] in known_apps and c.args and isinstance(c.args[0],ast.Name):
                    router=c.args[0].id
                    prefix=next((literal(k.value) for k in c.keywords if k.arg=='prefix'),'')
                    if router in known_apps and prefix is not None: known_apps[router]=prefix+known_apps[router]
        def stores(nodes):
            names=set()
            stack=list(nodes)
            while stack:
                item=stack.pop()
                if isinstance(item,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda)): continue
                if isinstance(item,ast.Name) and isinstance(item.ctx,ast.Store): names.add(item.id)
                stack.extend(ast.iter_child_nodes(item))
            return names
        def visit(n, owner=mid, blocked=frozenset()):
            if isinstance(n,ast.Module): blocked=blocked | (stores(n.body)-known_apps.keys())
            if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                kind='class' if isinstance(n,ast.ClassDef) else 'function'
                sym=symbols.get((n.lineno,n.col_offset+1,kind)) or symbols.get((n.lineno,n.col_offset+1,'method'))
                if sym:
                    result.declarations.append((identity('binding',n.name),sym.id,owner))
                    owner=sym.id
                if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):
                    blocked=blocked | frozenset(a.arg for a in n.args.posonlyargs+n.args.args+n.args.kwonlyargs) | stores(n.body)
                    if n.args.vararg: blocked=blocked | {n.args.vararg.arg}
                    if n.args.kwarg: blocked=blocked | {n.args.kwarg.arg}
                    for dec in n.decorator_list:
                        if not isinstance(dec,ast.Call) or not isinstance(dec.func,ast.Attribute): continue
                        app=qualified(dec.func.value)
                        verb=dec.func.attr
                        if app not in known_apps or app in blocked or not dec.args: continue
                        declared=literal(dec.args[0])
                        path=route(known_apps[app]+declared) if declared is not None else None
                        methods=[verb.upper()] if verb in ('get','post','put','delete','patch','head','options') else []
                        if verb=='route':
                            methods=['GET']
                            for k in dec.keywords:
                                if k.arg=='methods':
                                    methods=[literal(x) for x in k.value.elts] if isinstance(k.value,(ast.List,ast.Tuple)) else []
                        if path:
                            result.endpoints.extend((m.upper(),path,dec.lineno) for m in methods if isinstance(m,str) and m.upper() in ('GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'))
            if isinstance(n,ast.Call):
                target=qualified(n.func)
                head,*tail=target.split('.')
                ref,member=bindings.get(head,(None,None)) if head not in blocked else (None,None)
                if head in blocked: ref=None
                imported=tail[0] if len(tail)==1 else member if not tail else None
                if target:
                    key=identity('blocked' if head in blocked else 'binding',target if tail and not ref else head)
                    result.calls.append((owner,key,ref,identity('binding',imported) if imported else None,n.lineno,len(source_lines[n.lineno-1][:n.col_offset].decode('utf-8',errors='replace'))+1))
            for child in ast.iter_child_nodes(n): visit(child,owner,blocked)
        visit(parsed.tree)
    else:
        data=parsed.content
        def text(n): return data[n.start_byte:n.end_byte].decode('utf-8') if n else ''
        def string(n):
            if n is None or n.type not in ('string','template_string'): return None
            value=text(n)
            if '${' in value or '\\' in value: return None
            return value[1:-1]
        root=parsed.tree.root_node
        axios=set()
        express=set()
        for n in root.named_children:
            if n.type=='import_statement':
                ref=string(n.child_by_field_name('source'))
                for c in walk(n):
                    if c.type=='import_specifier':
                        name=text(c.child_by_field_name('name'))
                        alias=text(c.child_by_field_name('alias')) or name
                        bindings[alias]=(ref,name)
                    elif c.type=='import_clause':
                        for child in c.named_children:
                            if child.type=='identifier': bindings[text(child)]=(ref,'default')
                    elif c.type=='namespace_import':
                        for child in c.named_children:
                            if child.type=='identifier': bindings[text(child)]=(ref,None)
                if ref=='axios': axios.update(k for k,v in bindings.items() if v[0]==ref)
                if ref=='express': express.update(k for k,v in bindings.items() if v[0]==ref)
        # Only module const strings, not mutable identifiers or computed configuration.
        for n in root.named_children:
            if n.type!='lexical_declaration' or not text(n).lstrip().startswith('const '): continue
            for c in n.named_children:
                if c.type!='variable_declarator': continue
                name=text(c.child_by_field_name('name'))
                value=c.child_by_field_name('value')
                if string(value) is not None: constants[name]=string(value)
                if value and value.type=='call_expression':
                    target=text(value.child_by_field_name('function'))
                    if target in express or any(target==e+'.Router' for e in express): known_apps[name]=''
        funcs={'function_declaration','generator_function_declaration','function_expression','arrow_function','method_definition'}
        next_evidence=any(ref=='next/server' for ref,_ in bindings.values())
        next_path=None
        if next_evidence and file.path.endswith(('/route.ts','/route.js','/route.tsx')):
            parts=file.path.split('/')
            for i in range(len(parts)-2):
                if parts[i:i+2]==['app','api']:
                    segments=parts[i+1:-1]
                    if all(not s.startswith('(') and not s.startswith('@') and not s.startswith('[...') and not s.startswith('[[...') for s in segments):
                        next_path=route('/'+'/'.join('{'+s[1:-1]+'}' if s.startswith('[') and s.endswith(']') else s for s in segments))
                    break
        def local_bindings(node):
            names=set()
            stack=[node]
            while stack:
                item=stack.pop()
                if item!=node and item.type in funcs: continue
                if item.type in ('formal_parameters','variable_declarator'):
                    if item.type=='variable_declarator':
                        target=item.child_by_field_name('name')
                        if target and target.type=='identifier': names.add(text(target))
                    else:
                        for p in walk(item):
                            if p.type=='identifier': names.add(text(p))
                stack.extend(item.named_children)
            return names
        def visit(n,owner=mid,blocked=frozenset()):
            if n.type in funcs | {'class_declaration'}:
                kind='class' if n.type=='class_declaration' else 'method' if n.type=='method_definition' else 'function'
                sym=symbols.get((n.start_point.row+1,n.start_point.column+1,kind))
                name=text(n.child_by_field_name('name'))
                if next_path and name in ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS') and n.parent and n.parent.type=='export_statement':
                    result.endpoints.append((name,next_path,n.start_point.row+1))
                blocked=blocked | local_bindings(n)
                if sym:
                    if name: result.declarations.append((identity('binding',name),sym.id,owner))
                    owner=sym.id
            if n.type in ('call_expression','new_expression'):
                fn=n.child_by_field_name('function') or n.child_by_field_name('constructor')
                target=text(fn)
                args=n.child_by_field_name('arguments')
                children=args.named_children if args else []
                line=n.start_point.row+1
                head,*tail=target.split('.')
                ref,member=bindings.get(head,(None,None)) if head not in blocked else (None,None)
                if re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)?',target):
                    result.calls.append((owner,identity('blocked' if head in blocked else 'binding',target if tail and not ref else head),ref,identity('binding',tail[-1] if tail else member) if tail or member else None,line,len(source_lines[n.start_point.row][:n.start_point.column].decode('utf-8',errors='replace'))+1))
                if children:
                    first=string(children[0]) or (constants.get(text(children[0])) if text(children[0]) not in blocked else None)
                    verb='GET'
                    request=head not in blocked and (target=='fetch' or head in axios and (not tail or tail[-1] in ('get','post','put','patch','delete','head','options')))
                    if head in axios and tail: verb=tail[-1].upper()
                    if target=='fetch' and len(children)>1:
                        if children[1].type!='object': verb=None
                        else:
                            for pair in children[1].named_children:
                                if pair.type=='spread_element': verb=None
                                elif pair.type=='pair' and text(pair.child_by_field_name('key')).strip('\"\'')=='method':
                                    method=string(pair.child_by_field_name('value'))
                                    verb=method.upper() if method else None
                    if request:
                        if first and first.startswith(('https://','http://')): result.requests.append((verb, None,line,'external'))
                        else: result.requests.append((verb,route(first),line,'local'))
                    if head not in blocked and head in known_apps and tail and tail[-1] in ('get','post','put','patch','delete','head','options'):
                        path=route(first)
                        if path: result.endpoints.append((tail[-1].upper(),path,line))
            for c in n.named_children: visit(c,owner,blocked)
        visit(root)
    if len(result.calls)+len(result.endpoints)+len(result.requests)>100000:
        from .parsing import ParseFailure
        raise ParseFailure()
    return result


def assemble(facts_by_file, file_by_id, resolver, evidence):
    nodes=[]
    edges=[]
    endpoints=[]
    diagnostics=[]
    comparisons=0
    class_ids={s.id for facts in facts_by_file.values() for s in facts.symbols if s.kind=="class"}
    declarations={}
    parents={}
    for fid,facts in facts_by_file.items():
        for key,sid,parent in facts.links.declarations:
            declarations.setdefault((parent,key),[]).append(sid)
            parents[sid]=parent
        file=file_by_id[fid]
        for ordinal,(method,path,line) in enumerate(facts.links.endpoints):
            eid=identity('evidence',fid+':endpoint:'+str(ordinal)+':'+method)
            nid=identity('endpoint',eid)
            loc=SourceLocation(path=file.path,start_line=line,start_column=1)
            evidence.append(Evidence(id=eid,observation='Observed framework route declaration; route text withheld.',producer='argus.http',producer_version='1',provenance=Provenance.OBSERVED,confidence=Confidence.HIGH,locations=(loc,)))
            nodes.append(GraphNode(id=nid,kind='http_endpoint',label=method+' endpoint',file_id=fid,language=file.language,parent_id=facts.module.id,evidence_ids=(eid,),grouping_provenance=Provenance.OBSERVED))
            endpoints.append((method,path,nid))
    def add(file,source,target,kind,status,line,key,observation,provenance=Provenance.INFERRED,column=1,callsite=None):
        rid=identity('relationship',source+':'+key+':'+str(line))
        eid=identity('evidence',rid)
        loc=SourceLocation(path=file.path,start_line=line,start_column=column)
        evidence.append(Evidence(id=eid,observation=observation,producer='argus.links',producer_version='1',provenance=Provenance.OBSERVED,confidence=Confidence.HIGH,locations=(loc,)))
        edges.append(Relationship(id=rid,source_id=source,target_id=target,kind=kind,language=file.language,resolution=status,
            target_reference=identity('reference',key),callsite_id=callsite,provenance=provenance,confidence=Confidence.MEDIUM,evidence_ids=(eid,),
            limitations=('Syntactic declarations only; shadowing, wrappers, re-exports, deployment, service identity and runtime reachability unverified. Route matches are candidates, never proof of communication.',)))
    paths={f.id:p for p,f in resolver.files.items()}
    for fid,facts in facts_by_file.items():
        file=file_by_id[fid]
        for index,(owner,key,ref,member,line,column) in enumerate(facts.links.calls):
            candidates=[]
            status=Resolution.UNRESOLVED
            if ref:
                target=resolver.resolve(paths[fid],file.language,ImportFact(ref,line))
                status=target.status
                tf=resolver.files.get(target.path)
                targetfacts=facts_by_file.get(tf.id) if tf else None
                if targetfacts and member:
                    candidates=declarations.get((targetfacts.module.id,member),[])
                    status=Resolution.RESOLVED if len(candidates)==1 else Resolution.AMBIGUOUS if candidates else Resolution.UNRESOLVED
                elif status==Resolution.RESOLVED: status=Resolution.UNRESOLVED
            else:
                scope=owner
                while scope:
                    is_class = scope in class_ids
                    candidates=[] if is_class else declarations.get((scope,key),[])
                    if candidates: break
                    scope=parents.get(scope,facts.module.id if scope!=facts.module.id else None)
                status=Resolution.RESOLVED if len(candidates)==1 else Resolution.AMBIGUOUS if candidates else Resolution.UNRESOLVED
            add(file,owner,candidates[0] if len(candidates)==1 else None,RelationshipKind.CALL,status,line,'call:'+str(index),
                'Observed call syntax; static binding target inferred when unique.',column=column,callsite=Point(facts.module.id,owner,line,column).key('callsite'))
        for index,(method,path,line,context) in enumerate(facts.links.requests):
            matches=[]
            budget_exceeded=context=='local' and path and method and comparisons+len(endpoints)>1000000
            if budget_exceeded:
                from ..models.scan import Diagnostic
                diagnostics.append(Diagnostic(code='http_matching_resource_limit',stage='analysis',message='HTTP candidate matching budget exceeded; request declaration retained unresolved.',location=SourceLocation(path=file.path,start_line=line,start_column=1)))
            if context=='local' and path and method and not budget_exceeded:
                comparisons+=len(endpoints)
                for verb,pattern,nid in endpoints:
                    regex=re.sub(r'\\\{[^}]+\\\}|:[A-Za-z_][A-Za-z0-9_]*|<[^>]+>',r'[^/]+',re.escape(pattern))
                    if verb==method and re.fullmatch(regex,path): matches.append(nid)
            status=Resolution.EXTERNAL if context=='external' else Resolution.RESOLVED if len(matches)==1 else Resolution.AMBIGUOUS if matches else Resolution.UNRESOLVED
            add(file,facts.module.id,matches[0] if len(matches)==1 else None,RelationshipKind.HTTP,status,line,'http:'+str(index),
                'Observed frontend request declaration. Method/path compatibility only; no verified service or deployment identity.' + (' Matching not evaluated: resource budget exhausted.' if budget_exceeded else ''))
    # Repeated syntax on one physical line remains distinct by ordinal.
    return nodes,edges,diagnostics


def reconcile(graph,facts_by_file,files,evidence):
    """One bounded pass over computed call facts; preserve observed syntax evidence.

    Alternatives and unknown contexts prevent definite edges. No receiver solving
    occurs here, and inferred deployment relationships are never rewritten.
    """
    from dataclasses import replace
    from .semantic_contracts import FactState
    grouped={}
    for fid,facts in sorted(facts_by_file.items()):
        if not facts.semantic: continue
        for site in facts.semantic.sites:
            if site.operation=='receiver_resolution' and site.callsite_id:
                grouped.setdefault((fid,site.callsite_id),[]).append(site)
    edges=list(graph.relationships)
    syntax_index={}
    for index,edge in enumerate(edges):
        if edge.kind==RelationshipKind.CALL and edge.callsite_id:
            syntax_index.setdefault(edge.callsite_id,[]).append(index)
    reconciled=0
    for (fid,callsite),sites in sorted(grouped.items()):
        fact=facts_by_file[fid]
        if reconciled >= 4096:
            fact.semantic.incomplete=tuple(sorted(set(fact.semantic.incomplete+('semantic_graph_reconciliation_limit',))))
            continue
        reconciled+=1
        targets=tuple(sorted({t for s in sites for t in s.candidate_target_ids}))
        definite=len(targets)==1 and all(s.target_id==targets[0] and s.fact_state==FactState.KNOWN for s in sites)
        resolution=Resolution.RESOLVED if definite else Resolution.AMBIGUOUS if targets else Resolution.UNRESOLVED
        site=sites[0]
        rid=identity('relationship','semantic:'+callsite)
        eid=identity('evidence',rid)
        evidence.append(Evidence(id=eid,observation='Semantic static call binding: '+resolution.value+'; alternatives retained, runtime dispatch unverified.',
            producer='argus.semantic.links',producer_version='1',provenance=Provenance.INFERRED,
            confidence=Confidence.MEDIUM,locations=(SourceLocation(path=files[fid].path,start_line=site.line,start_column=site.column),)))
        resolved=Relationship(id=rid,source_id=site.owner,target_id=targets[0] if definite else None,
            target_reference=callsite,kind=RelationshipKind.CALL,language=files[fid].language,
            resolution=resolution,provenance=Provenance.INFERRED,confidence=Confidence.MEDIUM,evidence_ids=(eid,),
            callsite_id=callsite,context_ids=tuple(sorted({s.context_id for s in sites})),candidate_target_ids=targets,
            limitations=('Bounded nonrecursive static contexts only; external callers and dynamic receiver behavior remain unknown. Syntax evidence is retained.',))
        # Exact shared callsite identity avoids line-only attribution and an
        # O(computed_calls * all_edges) reconciliation scan. Constructor syntax
        # may resolve to a class while its implicit initializer is a distinct edge.
        matching=[(i,edges[i]) for i in syntax_index.get(callsite,())
            if edges[i].target_id==resolved.target_id or edges[i].resolution!=Resolution.RESOLVED]
        if len(matching)==1:
            index,syntax=matching[0]
            edges[index]=replace(resolved,id=syntax.id,evidence_ids=syntax.evidence_ids+resolved.evidence_ids)
        else:
            edges.append(resolved)
    return replace(graph,relationships=tuple(sorted(edges,key=lambda r:r.id)))
