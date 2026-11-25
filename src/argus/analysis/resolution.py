"""Conservative repository-index resolution. Never opens files or executes config."""
import posixpath
from pathlib import PurePosixPath
from dataclasses import dataclass

from ..models.analysis import Resolution

JS_EXTENSIONS = ('.ts', '.tsx', '.js', '.jsx', '.mts', '.cts', '.mjs', '.cjs')

@dataclass(frozen=True)
class Target:
    status: Resolution
    path: str | None = None
    reason: str = 'Static resolution cannot establish a unique target.'


def normalize(path):
    result = posixpath.normpath(path)
    return None if result == '..' or result.startswith('../') or result.startswith('/') or '\\' in result else result


class Resolver:
    def __init__(self, files, manifests=None, tsconfigs=None):
        self.files = files  # original relative paths -> source file; includes unsupported files
        self.manifests = manifests or {}
        self.tsconfigs = tsconfigs or {}
        self.python = {}
        for path, file in files.items():
            if file.language != 'python':
                continue
            parts = path.split('/')
            variants = [parts]
            if 'src' in parts:
                variants.append(parts[parts.index('src') + 1:])
            # Package roots can live below separately located applications.
            for i in range(1, len(parts)):
                if '/'.join(parts[:i] + ['__init__.py']) in files:
                    variants.append(parts[i - 1:])
                    break
            for variant in variants:
                name = '.'.join(variant)[:-3]
                if name.endswith('.__init__'):
                    name = name[:-9]
                self.python.setdefault(name, set()).add(path)

    def choose(self, candidates):
        candidates = sorted(set(candidates))
        if len(candidates) == 1:
            return Target(Resolution.RESOLVED, candidates[0], 'Unique inventoried static path candidate; runtime loading is not verified.')
        return Target(Resolution.AMBIGUOUS if candidates else Resolution.UNRESOLVED)

    def js_candidates(self, base):
        base = normalize(base)
        if base is None:
            return []
        candidates = [base] if base in self.files else []
        if not PurePosixPath(base).suffix:
            candidates += [base + ext for ext in JS_EXTENSIONS if base + ext in self.files]
            candidates += [base + '/index' + ext for ext in JS_EXTENSIONS if base + '/index' + ext in self.files]
            package = self.manifests.get(base + '/package.json', {})
            for field in ('main', 'module', 'types'):
                entry = package.get(field)
                if isinstance(entry, str):
                    candidate = normalize(base + '/' + entry)
                    if candidate in self.files:
                        candidates.append(candidate)
        elif base.endswith(('.js', '.mjs', '.cjs')) and base not in self.files:
            stem = base.rsplit('.', 1)[0]
            candidates += [stem + ext for ext in ('.ts', '.tsx', '.mts', '.cts') if stem + ext in self.files]
        return candidates

    def resolve(self, path, language, fact):
        ref = fact.reference
        if not ref or len(ref) > 4096 or '\\' in ref or any(ord(c) < 32 for c in ref):
            return Target(Resolution.UNRESOLVED)
        if language == 'python':
            if ref.startswith('.'):
                level = len(ref) - len(ref.lstrip('.'))
                parent = path.split('/')[:-1]
                if level > len(parent):
                    return Target(Resolution.UNRESOLVED)
                base = '/'.join(parent[:len(parent) - level + 1])
                tail = ref[level:].replace('.', '/')
                base = '/'.join(x for x in (base, tail) if x)
                submodules = [p for name in fact.names for p in
                              (base + '/' + name + '.py', base + '/' + name + '/__init__.py') if p in self.files]
                candidates = submodules or [p for p in (base + '.py', base + '/__init__.py') if p in self.files]
                # `from . import sibling` identifies a module only if unique.
                if not tail:
                    candidates = [p for name in fact.names for p in
                                  (base + '/' + name + '.py', base + '/' + name + '/__init__.py') if p in self.files]
                return self.choose(candidates)
            submodules = set()
            for name in fact.names:
                submodules.update(self.python.get(ref + '.' + name, set()))
            if submodules:
                return self.choose(submodules)
            candidates = self.python.get(ref, set())
            if candidates:
                return self.choose(candidates)
            top = ref.split('.')[0]
            if any(name == top or name.startswith(top + '.') for name in self.python):
                return Target(Resolution.UNRESOLVED)
            # External means outside the inventory, not proven installed.
            return Target(Resolution.EXTERNAL, reason='Absolute module reference outside inventoried Python module index; installation unverified.')
        if ref.startswith('.'):
            return self.choose(self.js_candidates(posixpath.join(posixpath.dirname(path), ref)))
        # Nearest strict JSON tsconfig only; extends and JSONC are deliberately unsupported.
        ancestors = [str(p) for p in PurePosixPath(path).parents]
        for ancestor in ancestors:
            config_path = ('' if ancestor == '.' else ancestor + '/') + 'tsconfig.json'
            config = self.tsconfigs.get(config_path)
            if config is None:
                continue
            options = config.get('compilerOptions', {})
            if not isinstance(options, dict) or 'extends' in config:
                return Target(Resolution.UNRESOLVED)
            base_url = options.get('baseUrl', '.')
            mappings = options.get('paths', {})
            if not isinstance(base_url, str) or not isinstance(mappings, dict):
                return Target(Resolution.UNRESOLVED)
            directory = '' if ancestor == '.' else ancestor + '/'
            candidates, matched = [], False
            for pattern, targets in mappings.items():
                if not isinstance(pattern, str) or pattern.count('*') > 1 or not isinstance(targets, list):
                    continue
                prefix, _, suffix = pattern.partition('*')
                match = ref == pattern if '*' not in pattern else ref.startswith(prefix) and ref.endswith(suffix) and len(ref) >= len(prefix) + len(suffix)
                if not match:
                    continue
                matched = True
                middle = ref[len(prefix):len(ref) - len(suffix) if suffix else None]
                for target in targets:
                    if isinstance(target, str) and target.count('*') <= 1:
                        candidates += self.js_candidates(directory + base_url + '/' + target.replace('*', middle))
            if matched:
                return self.choose(candidates)
            if 'baseUrl' in options:
                candidates = self.js_candidates(directory + base_url + '/' + ref)
                if candidates:
                    return self.choose(candidates)
            break
        # Local workspace package names and statically declared entry points.
        candidates = []
        for manifest, package in self.manifests.items():
            name = package.get('name')
            if not isinstance(name, str):
                continue
            base = posixpath.dirname(manifest)
            if ref == name:
                candidates += self.js_candidates(base or '.')
            elif ref.startswith(name + '/'):
                candidates += self.js_candidates(base + '/' + ref[len(name) + 1:])
        if candidates:
            return self.choose(candidates)
        return Target(Resolution.EXTERNAL, reason='Bare package reference outside statically resolved inventory; installation and exports conditions unverified.')
