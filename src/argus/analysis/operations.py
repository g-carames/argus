"""Offline SDK operation metadata. Exact receiver identity is required for recognition.

References: https://github.com/openai/openai-python/blob/main/src/openai/resources/responses/responses.py
https://www.python-httpx.org/advanced/timeouts/ . No runtime SDK imports.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Operation:
    receiver: str
    suffix: str
    kind: str
    limit_keys: tuple[str, ...] = ()


OPERATIONS = tuple(
    Operation(receiver, suffix, kind, keys)
    for receiver, entries in (
        ('openai.OpenAI', (
            ('responses.create', 'model', ('max_output_tokens',)),
            ('chat.completions.create', 'model', ('max_tokens', 'max_completion_tokens')),
            ('completions.create', 'model', ('max_tokens',)),
            ('embeddings.create', 'embedding', ()),
        )),
        ('openai.AsyncOpenAI', (
            ('responses.create', 'model', ('max_output_tokens',)),
            ('chat.completions.create', 'model', ('max_tokens', 'max_completion_tokens')),
            ('completions.create', 'model', ('max_tokens',)),
            ('embeddings.create', 'embedding', ()),
        )),
        ('anthropic.Anthropic', (('messages.create', 'model', ('max_tokens',)),)),
        ('anthropic.AsyncAnthropic', (('messages.create', 'model', ('max_tokens',)),)),
    ) for suffix, kind, keys in entries
)


def resolve_operation(target):
    return next((op for op in OPERATIONS if target == op.receiver + '.' + op.suffix), None)


MODEL_SUFFIXES = ('.responses.create', '.chat.completions.create', '.completions.create',
                  '.messages.create', '.generate_content', '.generateContent')
EMBEDDING_SUFFIXES = ('.embeddings.create', '.embed_content', '.embedContent')
HTTP_METHODS = ('get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'request', 'stream')
HTTP_TARGETS = tuple(prefix + '.' + method for prefix in
                     ('requests', 'requests.Session', 'httpx', 'httpx.Client', 'httpx.AsyncClient')
                     for method in HTTP_METHODS)
