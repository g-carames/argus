"""Installed adapter metadata. Capability availability is independent per language."""
from importlib.metadata import version
import sys

from ..contracts import AdapterDescriptor, CapabilityDeclaration
from ..models.base import Capability
from .parsing import SUPPORTED, PRIMARY, GRAMMARS, grammar, ParseUnavailable
def supported_caps(language):
    caps = {Capability.PARSING}
    if language in PRIMARY:
        caps |= {Capability.SYMBOLS, Capability.STRUCTURE, Capability.DEPENDENCIES, Capability.RESOLUTION, Capability.COMPLEXITY, Capability.ARCHITECTURE}
    elif language in ('bash', 'shell'):
        caps |= {Capability.SYMBOLS, Capability.STRUCTURE, Capability.COMPLEXITY}
    elif language in ('html', 'css', 'yaml'):
        caps |= {Capability.SYMBOLS, Capability.STRUCTURE}
    elif language in ('json', 'toml'):
        caps |= {Capability.STRUCTURE, Capability.CONFIGURATION}
    elif language in ('sql', 'dockerfile'):
        caps = {Capability.STRUCTURE}  # no claim of syntax validation
    return caps



def descriptor(language):
    if language not in SUPPORTED:
        raise ValueError('No installed adapter for language')
    available = supported_caps(language)
    grammar_version = None
    if language in GRAMMARS:
        package, _ = GRAMMARS[language]
        parser_id, parser_version = 'tree-sitter', version('tree-sitter')
        try:
            grammar(language)
            grammar_version = version('tree-sitter-' + package)
        except ParseUnavailable:
            available = set()
    elif language == 'sql':
        parser_id, parser_version = 'sqlparse-tokenizer', version('sqlparse')
    else:
        parser_id, parser_version = ('python-ast' if language == 'python' else 'stdlib-or-instruction-reader'), sys.version.split()[0]
    return AdapterDescriptor(id='argus.' + language, version='1', language=language,
        parser_id=parser_id, parser_version=parser_version, grammar_version=grammar_version,
        capabilities=tuple(CapabilityDeclaration(capability=c, available=c in available,
            reason='Available with language-specific static limitations.' if c in available else 'No implemented capability or prepared grammar unavailable.',
            limitations=('Syntax success does not establish semantic or security completeness.',)) for c in Capability))
