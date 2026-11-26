"""Bounded caller input; remove JSONC comments and trailing commas outside strings."""
import json
import re


def loads(content):
    text=content.decode('utf-8-sig')
    out=[]
    i=0
    quoted=False
    while i < len(text):
        c=text[i]
        if quoted:
            out.append(c)
            if c == '\\' and i+1 < len(text):
                i+=1
                out.append(text[i])
            elif c == '"': quoted=False
        elif c == '"':
            quoted=True
            out.append(c)
        elif text.startswith('//',i):
            while i < len(text) and text[i] not in '\r\n':
                out.append(' ')
                i+=1
            continue
        elif text.startswith('/*',i):
            end=text.find('*/',i+2)
            if end < 0: raise ValueError('Invalid JSONC')
            out.extend('\n' if c == '\n' else ' ' for c in text[i:end+2])
            i=end+2
            continue
        elif c == ',':
            # Comments have to be removed before testing the next significant token.
            out.append(c)
        else: out.append(c)
        i+=1
    cleaned=''.join(out)
    # A second lexical pass avoids changing comma-like sequences inside strings.
    tokens=re.compile(r'"(?:[^"\\]|\\.)*"|,(\s*[}\]])')
    cleaned=tokens.sub(lambda m: m[1] if m[1] is not None else m[0],cleaned)
    return json.loads(cleaned)
