"""Conservative repository-index resolution. Never opens files or executes config."""
import posixpath
import fnmatch
from functools import lru_cache


def path_match(path, pattern):
    parts=path.split("/")
    tokens=pattern.split("/")
    @lru_cache
    def match(i,j):
        if j==len(tokens): return i==len(parts)
        if tokens[j]=="**": return match(i,j+1) or i<len(parts) and match(i+1,j)
        return i<len(parts) and fnmatch.fnmatchcase(parts[i],tokens[j]) and match(i+1,j+1)
    return match(0,0)
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
    def __init__(self, files, manifests=None, tsconfigs=None, workspace_patterns=()):
        self.files = files  # original relative paths -> source file; includes unsupported files
        self.manifests = manifests or {}
        self.tsconfigs = tsconfigs or {}
        self.workspace_patterns = list(workspace_patterns)
        for manifest, package in self.manifests.items():
            patterns = package.get('workspaces', [])
            if isinstance(patterns, dict): patterns = patterns.get('packages', [])
            if isinstance(patterns, list):
                base = posixpath.dirname(manifest)
                self.workspace_patterns.extend(posixpath.join(base, p) for p in patterns if isinstance(p, str))
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
        # Nearest TS/JS project config; failed/cyclic extends prevents invented aliases.
        for ancestor in PurePosixPath(path).parents:
            directory = '' if str(ancestor) == '.' else str(ancestor) + '/'
            config_path = next((directory + name for name in ('tsconfig.json','jsconfig.json') if directory + name in self.files), None)
            if config_path is None:
                continue
            options = self.config_options(config_path)
            if options is None:
                return Target(Resolution.UNRESOLVED, reason='Project config or extends chain unavailable, cyclic or unsupported.')
            candidates, matched = [], False
            mappings, mapping_base = options.get('paths', ({}, directory))
            base_url = options.get('baseUrl', (None, directory))[0]
            if len(mappings)>1024: return Target(Resolution.UNRESOLVED,reason='Alias mapping count exceeds 1024.')
            # Exact key wins; otherwise longest literal prefix wins, as in TS paths.
            selected=[]
            for pattern in mappings:
                if not isinstance(pattern,str) or len(pattern)>4096 or pattern.count('*')>1: continue
                head,_,tail=pattern.partition('*')
                if ref==pattern or '*' in pattern and ref.startswith(head) and ref.endswith(tail) and len(ref)>=len(head)+len(tail): selected.append(pattern)
            if ref in selected: selected=[ref]
            elif selected:
                best=max(len(p.partition('*')[0]) for p in selected)
                selected=[p for p in selected if len(p.partition('*')[0])==best]
            for pattern in selected:
                targets=mappings[pattern]
                if isinstance(targets,list) and len(targets)>128: return Target(Resolution.UNRESOLVED,reason='Alias alternatives exceed 128.')
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
                        candidates += self.js_candidates(posixpath.join(base_url or mapping_base, target.replace('*', middle)))
            if matched:
                return self.choose(candidates)
            if base_url is not None:
                candidates = self.js_candidates(posixpath.join(base_url, ref))
                if candidates:
                    return self.choose(candidates)
            break
        candidates, internal = [], False
        for manifest, package in self.manifests.items():
            name = package.get('name')
            base = posixpath.dirname(manifest)
            if not isinstance(name, str) or not (ref == name or ref.startswith(name + '/')):
                continue
            if not self.workspace_member(base):
                continue
            internal = True
            subpath = '.' if ref == name else './' + ref[len(name)+1:]
            if 'exports' in package:
                entries = self.export_entries(package['exports'], subpath)
                for entry in entries:
                    if entry.startswith('./'):
                        candidate = normalize(posixpath.join(base, entry))
                        if candidate and (candidate == base or candidate.startswith(base + '/')):
                            candidates += self.js_candidates(candidate)
            elif ref == name:
                candidates += self.js_candidates(base or '.')
            else:
                candidates += self.js_candidates(posixpath.join(base, ref[len(name)+1:]))
        if internal:
            return self.choose(candidates)
        return Target(Resolution.EXTERNAL, reason='Bare package reference outside statically resolved inventory; installation and exports conditions unverified.')

    def config_options(self, path, seen=()):
        if path in seen or len(seen) >= 16:
            return None
        config = self.tsconfigs.get(path)
        if not isinstance(config, dict): return None
        directory = posixpath.dirname(path)
        merged = {}
        extended = config.get('extends')
        if extended is not None:
            if not isinstance(extended, str) or not extended.startswith('.'):
                return None
            parent = normalize(posixpath.join(directory, extended))
            if parent is None: return None
            if not parent.endswith(('.json','.jsonc')): parent += '.json'
            merged = self.config_options(parent, seen + (path,))
            if merged is None: return None
            merged = dict(merged)
        options = config.get('compilerOptions', {})
        if not isinstance(options, dict): return None
        if 'baseUrl' in options:
            if not isinstance(options['baseUrl'], str): return None
            base = normalize(posixpath.join(directory, options['baseUrl']))
            if base is None: return None
            merged['baseUrl'] = (base, directory)
        if 'paths' in options:
            if not isinstance(options['paths'], dict): return None
            merged['paths'] = (options['paths'], directory)
        return merged

    def workspace_member(self, directory):
        positive = any(path_match(directory, p) for p in self.workspace_patterns if not p.startswith('!'))
        negative = any(path_match(directory, p[1:]) for p in self.workspace_patterns if p.startswith('!'))
        return positive and not negative

    def export_entries(self, value, subpath, depth=0):
        if depth > 16: return []
        if isinstance(value, str): return [value] if subpath == '.' else []
        if isinstance(value, list):
            return [p for item in value for p in self.export_entries(item, subpath, depth+1)]
        if not isinstance(value, dict): return []
        if any(k.startswith('.') for k in value):
            if subpath in value:
                return self.export_entries(value[subpath], '.', depth+1)
            matches=[]
            for key, item in value.items():
                if key.count('*') != 1: continue
                head,tail=key.split('*')
                if subpath.startswith(head) and subpath.endswith(tail):
                    middle=subpath[len(head):len(subpath)-len(tail) if tail else None]
                    matches += [p.replace('*',middle) for p in self.export_entries(item,'.',depth+1)]
            return matches
        # No active runtime condition is assumed: multiple targets remain ambiguous.
        return [p for item in value.values() for p in self.export_entries(item,subpath,depth+1)]
