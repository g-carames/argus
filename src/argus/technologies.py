"""Bounded manifest observations. No dependency resolution or source execution."""
import json
import re
import tomllib
from pathlib import PurePosixPath

JS = {'react': 'React', 'next': 'Next.js', 'vue': 'Vue', 'svelte': 'Svelte',
      'express': 'Express', '@supabase/supabase-js': 'Supabase', 'firebase': 'Firebase',
      'firebase-admin': 'Firebase', 'pg': 'PostgreSQL', 'postgres': 'PostgreSQL',
      'openai': 'OpenAI SDK', '@anthropic-ai/sdk': 'Anthropic SDK',
      '@google/genai': 'Google Gen AI SDK', '@google/generative-ai': 'Google Gen AI SDK',
      'langchain': 'LangChain', '@langchain/core': 'LangChain',
      '@langchain/langgraph': 'LangGraph'}
PY = {'fastapi': 'FastAPI', 'flask': 'Flask', 'django': 'Django', 'supabase': 'Supabase',
      'firebase-admin': 'Firebase', 'psycopg': 'PostgreSQL', 'psycopg2': 'PostgreSQL',
      'psycopg2-binary': 'PostgreSQL', 'asyncpg': 'PostgreSQL', 'openai': 'OpenAI SDK',
      'anthropic': 'Anthropic SDK', 'google-genai': 'Google Gen AI SDK',
      'google-generativeai': 'Google Gen AI SDK', 'langchain': 'LangChain',
      'langchain-core': 'LangChain', 'langgraph': 'LangGraph'}


def inspect_manifest(path: str, text: str):
    """Return only trusted technology/basis labels plus a malformed flag."""
    name = PurePosixPath(path).name
    observations = set()
    malformed = False
    try:
        if name == 'package.json':
            data = json.loads(text)
            if type(data) is not dict:
                raise ValueError
            observations.add(('Node.js', 'manifest_present'))
            for section in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'):
                deps = data.get(section, {})
                if type(deps) is not dict or any(type(v) is not str for v in deps.values()):
                    raise ValueError
                for key in deps:
                    if key in JS:
                        observations.add((JS[key], 'declared_dependency'))
        elif name == 'pyproject.toml':
            data = tomllib.loads(text)
            project = data.get('project', {})
            deps = project.get('dependencies', [])
            if type(deps) is not list:
                raise ValueError
            deps = list(deps)
            for group in project.get('optional-dependencies', {}).values():
                if type(group) is not list:
                    raise ValueError
                deps.extend(group)
            for group in data.get('dependency-groups', {}).values():
                if type(group) is not list:
                    raise ValueError
                deps.extend(x for x in group if isinstance(x, str))
            poetry = data.get('tool', {}).get('poetry', {}).get('dependencies', {})
            if type(poetry) is not dict:
                raise ValueError
            deps.extend(poetry)
            for dep in deps:
                if type(dep) is not str:
                    raise ValueError
                match = re.match(r'\s*([A-Za-z0-9_.-]+)', dep)
                key = re.sub(r'[-_.]+', '-', match[1]).lower() if match else ''
                if key in PY:
                    observations.add((PY[key], 'declared_dependency'))
        elif name.startswith('requirements') and name.endswith(('.txt', '.in')):
            for line in text.splitlines():
                match = re.match(r'^\s*([A-Za-z0-9_.-]+)(?:\s*(?:[<>=!~;\[]|$))', line)
                if match:
                    key = re.sub(r'[-_.]+', '-', match[1]).lower()
                    if key in PY:
                        observations.add((PY[key], 'declared_dependency'))
        if (name.lower() in {'dockerfile', 'containerfile'}
                or name.startswith(('Dockerfile.', 'Containerfile.')) or name.endswith('.dockerfile')):
            observations.add(('Docker', 'configuration_filename'))
        if re.fullmatch(r'(?:docker-)?compose(?:\.[A-Za-z0-9_-]+)?\.ya?ml', name):
            observations.add(('Docker Compose', 'configuration_filename'))
        for prefix, technology in [('next.config.', 'Next.js'), ('vue.config.', 'Vue'),
                                   ('svelte.config.', 'Svelte')]:
            if name.startswith(prefix):
                observations.add((technology, 'configuration_filename'))
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError):
        # Partial malformed manifests are not promoted to dependency evidence.
        return (), True
    return tuple(sorted(observations)), malformed


def is_argus_report(path: str, text: str) -> bool:
    """Recognize our envelope without trusting arbitrary filenames."""
    from .models.scan import DISCLAIMER
    if not path.endswith(('.json', '.txt')):
        return False
    try:
        data = json.loads(text)
        return (type(data) is dict and data.get('disclaimer') == DISCLAIMER
                and isinstance(data.get('schema_version'), str)
                and 'tool_version' in data and 'not_reviewed_portions_of_the_code' in data)
    except (ValueError, RecursionError):
        return False


def suggests_application(path: str, text: str) -> bool:
    """A manifest entry point suggests, but does not confirm, an application."""
    name = PurePosixPath(path).name
    try:
        if name == 'package.json':
            scripts = json.loads(text).get('scripts', {})
            return isinstance(scripts, dict) and bool({'start', 'dev'} & scripts.keys())
        if name == 'pyproject.toml':
            return bool(tomllib.loads(text).get('project', {}).get('scripts', {}))
    except (ValueError, AttributeError, TypeError, RecursionError):
        pass
    return False
