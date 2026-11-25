"""Prepared parser service. No downloads, target imports, or executable configuration."""
import ast
import importlib
import json
import tomllib
from dataclasses import dataclass
from functools import lru_cache

PRIMARY = ('python', 'javascript', 'typescript', 'jsx', 'tsx')
GRAMMARS = {'javascript': ('javascript', 'language'), 'jsx': ('javascript', 'language'),
            'typescript': ('typescript', 'language_typescript'), 'tsx': ('typescript', 'language_tsx'),
            'bash': ('bash', 'language'), 'shell': ('bash', 'language'),
            'html': ('html', 'language'), 'css': ('css', 'language'), 'yaml': ('yaml', 'language')}
CONFIG = ('json', 'toml', 'yaml')
SUPPORTED = PRIMARY + ('bash', 'shell', 'html', 'css', 'yaml', 'json', 'toml', 'sql', 'dockerfile')

class ParseUnavailable(Exception):
    """Prepared grammar unavailable."""

class ParseFailure(Exception):
    """Malformed input or parser budget exceeded; never carries source text."""

@dataclass
class Parsed:
    language: str
    tree: object
    content: bytes

@lru_cache
def grammar(language):
    try:
        from tree_sitter import Language
        package, factory = GRAMMARS[language]
        # Names originate exclusively from this trusted registry.
        return Language(getattr(importlib.import_module('tree_sitter_' + package), factory)())
    except (ImportError, AttributeError, ValueError):
        raise ParseUnavailable() from None


def walk(root, max_nodes=200000):
    stack = [(root, 0)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > max_nodes or depth > 256:
            raise ParseFailure()
        yield node
        children = list(ast.iter_child_nodes(node)) if isinstance(node, ast.AST) else node.named_children
        stack.extend((child, depth + 1) for child in reversed(children))


def parse(language, content):
    try:
        if language == 'python':
            tree = ast.parse(content.decode('utf-8-sig'))
        elif language == 'json':
            tree = json.loads(content.decode('utf-8-sig'))
        elif language == 'toml':
            tree = tomllib.loads(content.decode('utf-8-sig'))
        elif language == 'sql':
            import sqlparse
            # Tokenization is not SQL validation, explicitly disclosed by adapter.
            try:
                tree = sqlparse.parse(content.decode('utf-8-sig'))
            except sqlparse.exceptions.SQLParseError:
                raise ParseFailure() from None
        elif language == 'dockerfile':
            tree = content.decode('utf-8-sig').splitlines()
        else:
            from tree_sitter import Parser
            parser = Parser(grammar(language))
            import warnings
            # The 0.25 callback path crashes on the validated CPython/platform;
            # use its supported native timeout with bounded byte input instead.
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', DeprecationWarning)
                parser.timeout_micros = 1000000
            tree = parser.parse(content)
            if tree is None or tree.root_node.has_error:
                raise ParseFailure()
        if language == 'python':
            list(walk(tree))
        elif language in GRAMMARS:
            list(walk(tree.root_node))
        return Parsed(language, tree, content)
    except (ParseUnavailable, ImportError):
        raise ParseUnavailable() from None
    except (SyntaxError, ValueError, UnicodeError, RecursionError, MemoryError, OverflowError):
        raise ParseFailure() from None
