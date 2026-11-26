"""Declarative recognition, independent from parser and analysis availability."""
from dataclasses import dataclass
from pathlib import PurePosixPath
import re

from .models.source import FileKind

# Public registry: downstream extensions can construct a separate registry instance.
EXTENSIONS = {
    'python': 'py pyi pyw', 'javascript': 'js mjs cjs', 'typescript': 'ts mts cts',
    'jsx': 'jsx', 'tsx': 'tsx', 'sql': 'sql', 'html': 'html htm xhtml',
    'css': 'css', 'scss': 'scss', 'json': 'json jsonl jsonc', 'yaml': 'yaml yml',
    'toml': 'toml', 'bash': 'bash', 'shell': 'sh zsh ksh', 'powershell': 'ps1 psm1 psd1',
    'go': 'go', 'rust': 'rs', 'java': 'java', 'csharp': 'cs', 'c': 'c',
    'cpp': 'cpp cc cxx c++ C hpp hxx hh', 'swift': 'swift', 'kotlin': 'kt kts',
    'dart': 'dart', 'php': 'php phtml php3 php4 php5', 'ruby': 'rb rake gemspec',
    'r': 'r R Rmd', 'lua': 'lua', 'hcl': 'hcl', 'terraform': 'tf tfvars',
    'graphql': 'graphql gql', 'vue': 'vue', 'svelte': 'svelte', 'xml': 'xml xsd xsl svg',
    'jupyter': 'ipynb', 'markdown': 'md markdown',
}
CONFIG_FORMATS = {'json', 'yaml', 'toml', 'xml', 'hcl', 'terraform', 'dockerfile', 'requirements', 'go-module', 'go-checksums'}
FILENAMES = {
    'Dockerfile': 'dockerfile', 'Containerfile': 'dockerfile',
    '.bashrc': 'bash', '.bash_profile': 'bash', '.bash_login': 'bash',
    '.zshrc': 'shell', '.zshenv': 'shell', '.zprofile': 'shell', '.profile': 'shell',
    'Gemfile': 'ruby', 'Rakefile': 'ruby', 'Vagrantfile': 'ruby',
    'Pipfile': 'toml', 'uv.lock': 'toml', 'poetry.lock': 'toml', 'Cargo.lock': 'toml',
    'go.mod': 'go-module', 'go.sum': 'go-checksums', '.gitignore': 'gitignore', '.dockerignore': 'gitignore',
    '.env': 'dotenv', '.env.example': 'dotenv', '.env.sample': 'dotenv', '.env.template': 'dotenv',
}
AMBIGUOUS = {'h': ('c', 'cpp'), 'm': ('objective-c', 'matlab'),
             'pl': ('perl', 'prolog'), 'v': ('verilog', 'v')}


@dataclass(frozen=True)
class Recognition:
    language: str | None
    kind: FileKind
    basis: str
    candidates: tuple[str, ...] = ()


class RecognitionRegistry:
    def __init__(self, extensions=None, filenames=None):
        self.extensions = {ext: lang for lang, exts in (extensions or EXTENSIONS).items()
                           for ext in exts.split()}
        self.filenames = dict(filenames or FILENAMES)

    def recognize(self, path: str, prefix: bytes = b'') -> Recognition:
        name = PurePosixPath(path).name
        ext = name.rsplit('.', 1)[-1] if '.' in name else ''
        if ext in AMBIGUOUS:
            return Recognition(None, FileKind.SOURCE, 'ambiguous_extension', AMBIGUOUS[ext])
        language = self.filenames.get(name)
        if (name.lower() in {'dockerfile', 'containerfile'}
                or name.startswith(('Dockerfile.', 'Containerfile.')) or name.endswith('.dockerfile')):
            language = 'dockerfile'
        if name.startswith('requirements') and name.endswith(('.txt', '.in')):
            language = 'requirements'
        language = language or self.extensions.get(ext)
        basis = 'filename_or_extension'
        if language is None and prefix.startswith(b'#!'):
            line = prefix.split(b'\n', 1)[0].decode('ascii', errors='ignore')
            # Match interpreter tokens, not arbitrary substrings in shebang arguments.
            match = re.match(r'^#!\s*(?:/[^\s]+/)?(python[\d.]*|bash|sh|zsh|ksh|node|ruby|php|pwsh|lua)(?:\s|$)', line)
            if not match:
                match = re.match(r'^#!\s*/usr/bin/env\s+(?:-S\s+)?(python[\d.]*|bash|sh|zsh|ksh|node|ruby|php|pwsh|lua)(?:\s|$)', line)
            if match:
                token = match[1]
                language = ('python' if token.startswith('python') else
                            {'node': 'javascript', 'sh': 'shell', 'zsh': 'shell',
                             'ksh': 'shell', 'pwsh': 'powershell'}.get(token, token))
                basis = 'bounded_shebang'
        if language is None and prefix.lstrip().startswith(b'<?php'):
            language, basis = 'php', 'bounded_signature'
        kind = (FileKind.UNKNOWN if language is None else
                FileKind.OTHER if language in {'markdown', 'gitignore'} else
                FileKind.CONFIGURATION if language in CONFIG_FORMATS or language == 'dotenv' else FileKind.SOURCE)
        return Recognition(language, kind, basis)
