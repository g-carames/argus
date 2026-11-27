"""Tree-sitter to bounded flow IR. No evaluation, transpilation or source retention.

Only the enumerated syntax is lowered. Unsupported control invalidates the environment
in the interpreter; JS coercion, prototypes, getters and scheduling are never Pythonized.
"""
import ast


def lower(parsed):
    data=parsed.content
    source_lines=data.splitlines()
    gaps={'JavaScript closures, prototypes, getters, promise scheduling and external mutation are unresolved.'}
    def text(n): return data[n.start_byte:n.end_byte].decode() if n else ''
    def field(n,k): return n.child_by_field_name(k)
    def at(n,out):
        out.lineno=n.start_point.row+1
        out.col_offset=n.start_point.column
        out.argus_column=len(source_lines[n.start_point.row][:n.start_point.column].decode("utf-8",errors="replace"))+1
        return out
    def unknown(n): return at(n,ast.Name(id='@unknown',ctx=ast.Load()))
    def expr(n):
        if n is None: return ast.Constant(value=None)
        t=n.type
        if t in ('identifier','property_identifier','shorthand_property_identifier'): return at(n,ast.Name(id=text(n),ctx=ast.Load()))
        if t=='this': return at(n,ast.Name(id='self',ctx=ast.Load()))
        if t=='number':
            try: value=int(text(n),0) if text(n).startswith(('0x','0o','0b')) else int(text(n))
            except ValueError: return unknown(n)
            return at(n,ast.Constant(value=value if abs(value)<=10**9 else None))
        if t in ('string','null','true','false'): return at(n,ast.Constant(value=None))
        if t=='object':
            pairs=[c for c in n.named_children if c.type=='pair']
            if len(pairs)!=len(n.named_children): gaps.add('semantic_js_object_spread_or_method_unavailable')
            return at(n,ast.Dict(keys=[ast.Name(id=text(field(c,'key')).strip('\"\''),ctx=ast.Load()) for c in pairs],values=[expr(field(c,'value')) for c in pairs]))
        if t=='array':
            expecting=True
            for child in n.children[1:-1]:
                if child.type=='comment': continue
                if child.type==',':
                    if expecting:
                        gaps.add('semantic_js_sparse_array_unavailable'); return unknown(n)
                    expecting=True
                else: expecting=False
            if any(c.type=='spread_element' for c in n.named_children): return unknown(n)
            return at(n,ast.List(elts=[expr(c) for c in n.named_children],ctx=ast.Load()))
        if t=='await_expression': return at(n,ast.Await(value=expr(n.named_children[0])))
        if t in ('parenthesized_expression','as_expression','non_null_expression'):
            return expr(n.named_children[0])
        if t=='member_expression': return at(n,ast.Attribute(value=expr(field(n,'object')),attr=text(field(n,'property')),ctx=ast.Load()))
        if t=='template_string':
            return at(n,ast.JoinedStr(values=[at(c,ast.FormattedValue(value=expr(c.named_children[0]),conversion=-1)) for c in n.named_children if c.type=='template_substitution']))
        if t=='binary_expression':
            # Numeric addition/coercion is intentionally unknown in JS. Preserve influence.
            return at(n,ast.JoinedStr(values=[expr(field(n,'left')),expr(field(n,'right'))]))
        if t=='ternary_expression': return at(n,ast.IfExp(test=expr(field(n,'condition')),body=expr(field(n,'consequence')),orelse=expr(field(n,'alternative'))))
        if t in ('call_expression','new_expression'):
            target=field(n,'function') or field(n,'constructor')
            args=field(n,'arguments')
            args=list(args.named_children) if args else []
            keywords=[]
            if target and target.type=='member_expression' and text(field(target,'property'))=='slice' and 1<=len(args)<=2 and text(args[0])=='0':
                return at(n,ast.Subscript(value=expr(field(target,'object')),slice=ast.Slice(lower=None,upper=expr(args[1]) if len(args)==2 else None,step=None),ctx=ast.Load()))
            return at(n,ast.Call(func=expr(target),args=[expr(c) for c in args],keywords=keywords))
        gaps.add('semantic_js_unsupported_expression')
        # Traverse influence through unsupported expressions, never prove a bound.
        return at(n,ast.JoinedStr(values=[expr(c) for c in n.named_children])) if n.named_children else unknown(n)
    def function(n,name=None):
        params=field(n,'parameters')
        params=list(params.named_children) if params else [field(n,'parameter')] if field(n,'parameter') else []
        names=[]; defaults=[]
        for p in params:
            node=field(p,'pattern') if p.type in ('required_parameter','optional_parameter') else p
            if node is None: node=p
            if node.type=='assignment_pattern':
                names.append(ast.arg(arg=text(field(node,'left')))); defaults.append(expr(field(node,'right')))
            elif node.type=='identifier':
                if defaults:
                    gaps.add('semantic_js_default_binding_unavailable'); return at(n,ast.Pass())
                names.append(ast.arg(arg=text(node)))
            else:
                gaps.add('semantic_js_destructured_or_rest_parameters')
                return at(n,ast.Pass())
        body=field(n,'body')
        body=stmts(body) if body and body.type=='statement_block' else [at(n,ast.Return(value=expr(body)))]
        return at(n,ast.FunctionDef(name=name or text(field(n,'name')),args=ast.arguments(posonlyargs=[],args=names,kwonlyargs=[],kw_defaults=[],defaults=defaults),body=body,decorator_list=[]))
    def stmt(n):
        t=n.type
        if t in ('comment','empty_statement'): return []
        if t=='export_statement':
            declaration=field(n,'declaration')
            if declaration: return stmt(declaration)
            gaps.add('semantic_js_reexport_unavailable'); return []
        if t=='import_statement':
            source=text(field(n,'source')).strip('\"\'')
            aliases=[]
            for c in n.named_children:
                if c.type!='import_clause': continue
                for spec in c.named_children:
                    if spec.type=='identifier': aliases.append(ast.alias(name='default',asname=text(spec)))
                    elif spec.type=='namespace_import': aliases.append(ast.alias(name='*',asname=text(spec.named_children[0])))
                    elif spec.type=='named_imports':
                        for item in spec.named_children:
                            aliases.append(ast.alias(name=text(field(item,'name')),asname=text(field(item,'alias')) or None))
            return [at(n,ast.ImportFrom(module=source,names=aliases,level=0))]
        if t in ('lexical_declaration','variable_declaration'):
            out=[]
            if text(n).startswith('var '): gaps.add('semantic_js_var_hoisting_unavailable')
            for c in n.named_children:
                name=field(c,'name'); value=field(c,'value')
                if name is None or name.type!='identifier':
                    out.append(at(n,ast.Pass())); gaps.add('semantic_js_destructuring_unavailable'); continue
                if value and value.type in ('arrow_function','function_expression'):
                    out.append(function(value,text(name)))
                else: out.append(at(c,ast.Assign(targets=[expr(name)],value=expr(value))))
            return out
        if t in ('function_declaration','generator_function_declaration'): return [function(n)]
        if t=='expression_statement':
            e=n.named_children[0]
            if e.type=='assignment_expression': return [at(n,ast.Assign(targets=[expr(field(e,'left'))],value=expr(field(e,'right'))))]
            return [at(n,ast.Expr(value=expr(e)))]
        if t=='return_statement': return [at(n,ast.Return(value=expr(n.named_children[0]) if n.named_children else None))]
        if t=='throw_statement': return [at(n,ast.Raise(exc=expr(n.named_children[0]),cause=None))]
        if t=='if_statement':
            alt=field(n,'alternative')
            if alt and alt.type=='else_clause': alt=alt.named_children[0]
            return [at(n,ast.If(test=expr(field(n,'condition')),body=stmts(field(n,'consequence')),orelse=stmts(alt)))]
        if t=='for_in_statement' and ' of ' in text(n):
            return [at(n,ast.For(target=expr(field(n,'left')),iter=expr(field(n,'right')),body=stmts(field(n,'body')),orelse=[]))]
        if t in ('for_statement','while_statement','do_statement'):
            gaps.add('semantic_js_counter_loop_bound_unavailable')
            return [at(n,ast.While(test=unknown(n),body=stmts(field(n,'body')),orelse=[]))]
        if t=='statement_block': return stmts(n)
        gaps.add('semantic_js_unsupported_control_or_statement')
        return [at(n,ast.Pass())]
    def stmts(n):
        if n is None: return []
        if n.type in ('program','statement_block'): return [s for c in n.named_children for s in stmt(c)]
        return stmt(n)
    return ast.Module(body=stmts(parsed.tree.root_node),type_ignores=[]),gaps
