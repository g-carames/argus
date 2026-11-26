"""Source-free syntactic risk observations. Never retains snippets or literal values."""
import ast
import re
from .parsing import PRIMARY, walk

# Quoted values only: environment lookups and identifiers are not secrets.
ASSIGNMENT = re.compile(r'''(?i)["']?\b(?:[a-z_][a-z0-9_]*_)?(?:password|passwd|api_key|apikey|secret|secret_key|access_token|auth_token|token)\b["']?\s*[:=]\s*["']([^"'\r\n]{8,})["']''')
PLACEHOLDER = re.compile(r'(?i)^(?:\$\{|<|your[_ -]|example|placeholder|changeme|test[_-]|dummy|\*{3}|\[redacted\])')
TOKEN = re.compile(r'(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{30,}|(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})')


def credentials(content, path=""):
    try:
        text = content.decode('utf-8-sig')
    except UnicodeError:
        return []
    if '\x00' in text:
        return []
    hits = []
    # Generic browser keys require value semantics AND request-use context.
    # No inference from a generic variable name or a source comment alone.
    browser_context = path.endswith(('.js','.jsx','.ts','.tsx')) and bool(re.search(r'\bfetch\s*\(', text)) and bool(re.search(r'JSON\.stringify\s*\([^;]*\bkey\b',text))
    generic = re.compile(r'''\b(?:const|let|var)\s+key\s*=\s*["']([^"'\r\n]{16,})["']''')
    for line, value in enumerate(text.splitlines(), 1):
        assignments = ASSIGNMENT.finditer(value)
        env = path.rsplit('/',1)[-1].startswith('.env') and re.fullmatch(r'\s*[A-Za-z_][A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD)\s*=\s*([^\s#\"\']{8,})\s*', value)
        env_secret = bool(env) and not PLACEHOLDER.search(env[1])
        browser_secret = browser_context and any(not PLACEHOLDER.search(m[1]) and re.search(r'(?i)(?:secret|api[-_]?key|access[-_]?token|browser[-_]?key)',m[1]) for m in generic.finditer(value))
        if (browser_secret or env_secret or TOKEN.search(value) or re.search(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----', value)
            or any(not PLACEHOLDER.search(m[1]) for m in assignments)):
            hits.append(('ARGUS-CRED-001', line))
    return hits


def detect(parsed):
    if parsed.language not in PRIMARY:
        return []
    hits = set()
    def hit(key, line):
        hits.add(('ARGUS-' + key, line))
    provider = False
    aliases = {}
    if parsed.language == 'python':
        for n in walk(parsed.tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    aliases[a.asname or a.name.split('.')[0]] = a.name if a.asname else a.name.split('.')[0]
                    provider |= a.name.split('.')[0] in ('openai','anthropic','google','langchain','langgraph')
            elif isinstance(n, ast.ImportFrom) and n.module:
                for a in n.names:
                    aliases[a.asname or a.name] = n.module + '.' + a.name
                provider |= n.module.split('.')[0] in ('openai','anthropic','google','langchain','langgraph')
        def name(n):
            if isinstance(n, ast.Name):
                return aliases.get(n.id, n.id)
            if isinstance(n, ast.Attribute):
                return name(n.value) + '.' + n.attr
            return ''
        def visit(n, loops=0, asynchronous=False):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                loops, asynchronous = 0, isinstance(n, ast.AsyncFunctionDef)
            loops += isinstance(n, (ast.For, ast.AsyncFor, ast.While))
            if isinstance(n, ast.ExceptHandler):
                silent = all(isinstance(x, ast.Pass) or isinstance(x, ast.Expr) and isinstance(x.value, ast.Constant) for x in n.body)
                broad = n.type is None or any(isinstance(x, ast.Name) and x.id in ('Exception','BaseException') for x in ast.walk(n.type))
                if silent: hit('REL-002', n.lineno)
                elif broad: hit('REL-001', n.lineno)
            if isinstance(n, ast.Call):
                target = name(n.func)
                kwargs = {k.arg:k.value for k in n.keywords}
                expanded = None in kwargs
                if target in ('eval','exec'): hit('SEC-001', n.lineno)
                if target in ('os.system','os.popen') or target.startswith('subprocess.') and isinstance(kwargs.get('shell'), ast.Constant) and kwargs['shell'].value is True:
                    hit('SEC-002', n.lineno)
                if target in ('pickle.load','pickle.loads','dill.load','dill.loads','yaml.unsafe_load') or target == 'yaml.load' and not any(name(k.value) in ('yaml.SafeLoader','yaml.CSafeLoader') for k in n.keywords if k.arg == 'Loader'):
                    hit('SEC-003', n.lineno)
                if target in ('hashlib.md5','hashlib.sha1'): hit('SEC-005', n.lineno)
                request = target in tuple('requests.' + v for v in ('get','post','put','delete','patch','head','options','request'))
                if request and isinstance(kwargs.get('verify'), ast.Constant) and kwargs['verify'].value is False: hit('SEC-006',n.lineno)
                if target.endswith('.add_middleware') and n.args and name(n.args[0]) in ('fastapi.middleware.cors.CORSMiddleware','starlette.middleware.cors.CORSMiddleware'):
                    origins=kwargs.get('allow_origins')
                    allow=kwargs.get('allow_credentials')
                    if isinstance(origins,(ast.List,ast.Tuple)) and any(isinstance(x,ast.Constant) and x.value=='*' for x in origins.elts) and isinstance(allow,ast.Constant) and allow.value is True: hit('SEC-007',n.lineno)
                if request and 'timeout' not in kwargs and not expanded: hit('REL-003', n.lineno)
                if asynchronous and (request or target == 'time.sleep'): hit('REL-004', n.lineno)
                query = target.rsplit('.',1)[-1] in ('execute','executemany','query')
                if query and n.args and isinstance(n.args[0], (ast.JoinedStr, ast.BinOp)): hit('SEC-004', n.lineno)
                if query and loops: hit('COST-001', n.lineno)
                model = provider and target.endswith(('.chat.completions.create','.completions.create','.messages.create','.generate_content','.generateContent'))
                embedding = provider and target.endswith(('.embeddings.create','.embed_content','.embedContent'))
                if model and not expanded and not {'max_tokens','max_completion_tokens','max_output_tokens','generationConfig','config'} & kwargs.keys(): hit('AI-001', n.lineno)
                if (model or embedding) and loops: hit('AI-002', n.lineno)
            for child in ast.iter_child_nodes(n): visit(child, loops, asynchronous)
        visit(parsed.tree)
    else:
        data = parsed.content
        def text(n): return data[n.start_byte:n.end_byte].decode('utf-8') if n else ''
        cors=set()
        for n in walk(parsed.tree.root_node):
            if n.type == 'import_statement':
                source = text(n.child_by_field_name('source')).strip('\"\'')
                provider |= source in ('openai','@anthropic-ai/sdk','@google/generative-ai','@google/genai','langchain','@langchain/openai','@langchain/langgraph')
                if source=='cors':
                    for c in walk(n):
                        if c.type=='import_clause':
                            cors.update(text(x) for x in c.named_children if x.type=='identifier')
                if source in ('child_process','node:child_process'):
                    for spec in walk(n):
                        if spec.type == 'import_specifier':
                            original = text(spec.child_by_field_name('name'))
                            aliases[text(spec.child_by_field_name('alias')) or original] = 'child_process.' + original
                        elif spec.type in ('namespace_import','import_clause') and len(spec.named_children) == 1 and spec.named_children[0].type == 'identifier':
                            aliases[text(spec.named_children[0])] = 'child_process'
        def visit(n, loops=0):
            if n.type in ('function_declaration','function_expression','arrow_function','method_definition','generator_function_declaration','generator_function'): loops=0
            loops += n.type in ('for_statement','for_in_statement','while_statement','do_statement')
            if n.type=='pair' and text(n.child_by_field_name('key')).strip('\"\'')=='rejectUnauthorized' and text(n.child_by_field_name('value'))=='false': hit('SEC-006',n.start_point.row+1)
            if n.type == 'call_expression' or n.type == 'new_expression':
                f = n.child_by_field_name('function') or n.child_by_field_name('constructor')
                target = text(f)
                head, *tail = target.split('.')
                target = '.'.join([aliases.get(head, head)] + tail)
                line = n.start_point.row + 1
                args = n.child_by_field_name('arguments')
                children = args.named_children if args else []
                if target in cors and children and children[0].type=='object':
                    options={text(c.child_by_field_name('key')).strip('\"\''):text(c.child_by_field_name('value')) for c in children[0].named_children if c.type=='pair'}
                    if options.get('credentials')=='true' and options.get('origin') in ('true','\"*\"',"'*'"): hit('SEC-007',line)
                if target in ('eval','Function'): hit('SEC-001',line)
                if target in ('child_process.exec','child_process.execSync'): hit('SEC-002',line)
                query = target.rsplit('.',1)[-1] in ('execute','executemany','query')
                if query and children:
                    arg = children[0]
                    if arg.type == 'binary_expression' or arg.type == 'template_string' and any(c.type == 'template_substitution' for c in arg.named_children): hit('SEC-004',line)
                if query and loops: hit('COST-001',line)
                if target == 'crypto.createHash' and children and text(children[0]).strip('\"\'').lower() in ('md5','sha1'): hit('SEC-005',line)
                model = provider and target.endswith(('.chat.completions.create','.completions.create','.messages.create','.generateContent','.generate_content'))
                embedding = provider and target.endswith(('.embeddings.create','.embedContent','.embed_content'))
                keys = set()
                expanded = False
                for arg in children:
                    if arg.type != 'object': expanded = True
                    for c in arg.named_children:
                        if c.type == 'spread_element': expanded = True
                        if c.type == 'pair': keys.add(text(c.child_by_field_name('key')).strip('\"\''))
                if model and not expanded and not {'max_tokens','max_completion_tokens','max_output_tokens','generationConfig','config'} & keys: hit('AI-001',line)
                if (model or embedding) and loops: hit('AI-002',line)
            for c in n.named_children: visit(c,loops)
        visit(parsed.tree.root_node)
    return sorted(hits)
