"""Language-aware extraction into source-free facts, separate from resolution."""
import ast
import re
from dataclasses import dataclass, field

from .parsing import PRIMARY, GRAMMARS, walk, grammar
from ..models.source import Module, Symbol, SourceLocation
from ..privacy import identity

@dataclass
class ImportFact:
    reference: str | None
    line: int
    phase: str = 'runtime'
    conditional: bool = False
    names: tuple[str, ...] = ()

@dataclass
class Facts:
    module: Module
    symbols: list = field(default_factory=list)
    imports: list = field(default_factory=list)
    measurements: list = field(default_factory=list)
    declarations: dict = field(default_factory=dict)
    limitations: tuple = ()
    links: object = None
    semantic: object = None


def extract(file, parsed):
    mid = identity('module', file.id)
    facts = Facts(Module(id=mid, file_id=file.id, qualified_name=identity('name', file.id), language=file.language))
    data = parsed.content
    lines = data.splitlines()

    def loc(node):
        if isinstance(node, ast.AST):
            row, col = node.lineno - 1, node.col_offset
            endrow, endcol = node.end_lineno - 1, node.end_col_offset
        else:
            row, col = node.start_point
            endrow, endcol = node.end_point
        def column(r, c):
            return len(lines[r][:c].decode('utf-8', errors='replace')) + 1 if r < len(lines) else 1
        return SourceLocation(path=file.path, start_line=row + 1, start_column=column(row, col),
                              end_line=endrow + 1, end_column=column(endrow, endcol))

    def symbol(node, kind, parent, key):
        sid = identity('symbol', mid + ':' + key)
        # Source identifiers are deliberately opaque, including strings used as method names.
        facts.symbols.append(Symbol(id=sid, module_id=mid, name=identity('name', key),
                                    kind=kind, location=loc(node), parent_id=parent))
        return sid

    def measure(scope, node, children, decision, nesting, is_scope):
        stack = [(child, 0) for child in children(node)]
        complexity, deepest, conditions, loops = 1, 0, 0, 0
        while stack:
            child, depth = stack.pop()
            if is_scope(child):
                continue
            inc, is_loop = decision(child)
            complexity += inc
            conditions += int(inc > 0 and not is_loop)
            loops += int(is_loop)
            depth += int(nesting(child))
            deepest = max(deepest, depth)
            stack.extend((c, depth) for c in children(child))
        location = loc(node)
        facts.measurements.append((scope, location, {'function_length': location.end_line - location.start_line + 1,
                                  'nesting_depth': deepest, 'cyclomatic_complexity': complexity,
                                  'conditional_count': conditions, 'loop_count': loops}))

    if file.language == 'python':
        scopes = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        controls = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.Match)
        def decisions(n):
            inc = (len(n.values) - 1 if isinstance(n, ast.BoolOp) else
                   int(isinstance(n, (ast.If, ast.IfExp, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.comprehension)))
                   + (len(n.cases) if isinstance(n, ast.Match) else 0))
            return inc, isinstance(n, (ast.For, ast.AsyncFor, ast.While, ast.comprehension))
        stack = [(parsed.tree, None, '', False, False)]
        counts = {}
        while stack:
            n, parent, prefix, conditional, type_only = stack.pop()
            if isinstance(n, scopes):
                kind = 'class' if isinstance(n, ast.ClassDef) else 'method' if parent and prefix.endswith('#class') else 'function'
                key = prefix + '/' + getattr(n, 'name', 'lambda')
                counts[key] = counts.get(key, 0) + 1
                key += ':' + str(counts[key])
                sid = symbol(n, kind, parent, key)
                if kind != 'class':
                    measure(sid, n, ast.iter_child_nodes, decisions, lambda x: isinstance(x, controls), lambda x: isinstance(x, scopes))
                parent, prefix = sid, key + ('#class' if kind == 'class' else '')
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                if isinstance(n, ast.Import):
                    for alias in n.names:
                        facts.imports.append(ImportFact(alias.name, n.lineno, 'type_only' if type_only else 'runtime', conditional))
                else:
                    for alias in n.names:
                        facts.imports.append(ImportFact('.' * n.level + (n.module or ''), n.lineno,
                                                       'type_only' if type_only else 'runtime', conditional,
                                                       (alias.name,)))
            elif isinstance(n, ast.Call) and ((isinstance(n.func, ast.Name) and n.func.id == '__import__') or
                    (isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
                     and n.func.value.id == 'importlib' and n.func.attr == 'import_module')):
                ref = n.args[0].value if n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str) else None
                facts.imports.append(ImportFact(ref, n.lineno, 'dynamic', conditional))
            elif isinstance(n, (ast.Assign, ast.AnnAssign)):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        key = prefix + '/declaration/' + target.id
                        counts[key] = counts.get(key, 0) + 1
                        symbol(target, 'declaration', parent, key + ':' + str(counts[key]))
            is_type = isinstance(n, ast.If) and ((isinstance(n.test, ast.Name) and n.test.id == 'TYPE_CHECKING') or
                       (isinstance(n.test, ast.Attribute) and n.test.attr == 'TYPE_CHECKING'))
            stack.extend((c, parent, prefix, conditional or isinstance(n, controls + (ast.FunctionDef, ast.AsyncFunctionDef)),
                          type_only or (is_type and c in n.body)) for c in reversed(list(ast.iter_child_nodes(n))))
    elif file.language in GRAMMARS:
        from tree_sitter import Query, QueryCursor
        root = parsed.tree.root_node
        text = lambda n: data[n.start_byte:n.end_byte].decode('utf-8', errors='replace')
        functions = {'function_declaration', 'function_expression', 'generator_function_declaration',
                     'generator_function', 'arrow_function', 'method_definition', 'function_definition'}
        classes = {'class_declaration', 'class', 'interface_declaration', 'type_alias_declaration', 'enum_declaration'}
        controls = {'if_statement', 'for_statement', 'for_in_statement', 'while_statement', 'do_statement',
                    'switch_statement', 'try_statement', 'catch_clause', 'conditional_expression', 'elif_clause', 'case_statement', 'switch_case'}
        loops = {'for_statement', 'for_in_statement', 'while_statement', 'do_statement'}
        def decisions(n):
            return int(n.type in controls - {'try_statement', 'switch_statement'} or
                       (n.type == 'binary_expression' and any(c.type in ('&&', '||', '??') for c in n.children))), n.type in loops
        if file.language in PRIMARY:
            # Shared declarative import/export query across JS/TS/JSX/TSX.
            query = Query(grammar(file.language), '(import_statement) @dependency\n(export_statement source: (string)) @dependency')
            for n in QueryCursor(query).captures(root).get('dependency', []):
                source = n.child_by_field_name('source')
                ref = text(source)[1:-1] if source else None
                phases = ['type_only'] if any(c.type == 'type' for c in n.children) else ['runtime']
                specs = [c for c in walk(n) if c.type == 'import_specifier']
                if specs and all(any(c.type == 'type' for c in s.children) for s in specs):
                    phases = ['type_only']
                elif any(any(c.type == 'type' for c in s.children) for s in specs):
                    phases.append('type_only')
                for phase in phases:
                    facts.imports.append(ImportFact(ref, n.start_point.row + 1, phase))
        stack = [(root, None, '', False)]
        counts = {}
        while stack:
            n, parent, prefix, conditional = stack.pop()
            if n.type in functions | classes | {'variable_declarator'}:
                name = n.child_by_field_name('name')
                key = prefix + '/' + n.type + '/' + (text(name) if name else 'anonymous')
                counts[key] = counts.get(key, 0) + 1
                key += ':' + str(counts[key])
                kind = 'method' if n.type == 'method_definition' else 'function' if n.type in functions else 'class' if n.type in classes else 'declaration'
                sid = symbol(n, kind, parent, key)
                if n.type in functions and file.language in PRIMARY + ('bash', 'shell'):
                    measure(sid, n, lambda x: x.named_children, decisions, lambda x: x.type in controls,
                            lambda x: x.type in functions | classes)
                if n.type != 'variable_declarator':
                    parent, prefix = sid, key
            if n.type == 'export_statement':
                symbol(n, 'export', parent, prefix + '/export/' + str(n.start_byte))
            if n.type == 'call_expression' and file.language in PRIMARY:
                fn = n.child_by_field_name('function')
                if fn and text(fn) in ('require', 'import'):
                    args = n.child_by_field_name('arguments')
                    first = args.named_children[0] if args and args.named_children else None
                    ref = text(first)[1:-1] if first and first.type == 'string' else None
                    facts.imports.append(ImportFact(ref, n.start_point.row + 1,
                                                   'dynamic' if text(fn) == 'import' else 'commonjs', conditional))
            if file.language in ('html', 'css', 'yaml'):
                kinds = {'element', 'rule_set', 'block_mapping_pair'}
                if n.type in kinds:
                    symbol(n, {'element': 'element', 'rule_set': 'style_rule', 'block_mapping_pair': 'configuration_entry'}[n.type], parent, str(n.start_byte))
            stack.extend((c, parent, prefix, conditional or n.type in controls | functions) for c in reversed(n.named_children))
    elif file.language in ('json', 'toml'):
        stack = [(parsed.tree, '')]
        while stack:
            value, key = stack.pop()
            if isinstance(value, dict):
                for index, child in enumerate(value.values()):
                    # Values and key names never enter reports; key counts and nesting only.
                    stack.append((child, key + '/' + str(index)))
                facts.declarations['configuration_entries'] = facts.declarations.get('configuration_entries', 0) + len(value)
            elif isinstance(value, list):
                stack.extend((child, key + '/' + str(i)) for i, child in enumerate(value))
    elif file.language == 'sql':
        facts.declarations['sql_statement_count'] = len(parsed.tree)
        facts.limitations = ('SQL tokenization only; dialect syntax, tables, relationships and query security are not validated.',)
    elif file.language == 'dockerfile':
        allowed = {'FROM', 'RUN', 'CMD', 'LABEL', 'MAINTAINER', 'EXPOSE', 'ENV', 'ADD', 'COPY', 'ENTRYPOINT', 'VOLUME', 'USER', 'WORKDIR', 'ARG', 'ONBUILD', 'STOPSIGNAL', 'HEALTHCHECK', 'SHELL'}
        continuation = False
        count = 0
        for line in parsed.tree:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if not continuation:
                if stripped.split()[0].upper() not in allowed:
                    from .parsing import ParseFailure
                    raise ParseFailure()
                count += 1
            continuation = stripped.endswith('\\')
        if continuation:
            from .parsing import ParseFailure
            raise ParseFailure()
        facts.declarations['docker_instruction_count'] = count
        facts.limitations = ('Dockerfile instruction recognition only; arguments, heredocs, stages and embedded shell are not semantically validated.',)
    from .relationships import collect
    facts.links = collect(file, parsed, facts)
    from .semantic import collect as collect_semantic
    facts.semantic = collect_semantic(file, parsed, facts)
    return facts
