import pytest
from argus.scanner import scan
from argus.models.analysis import Resolution, RelationshipKind


def fixture(tmp_path, sources):
    for path, content in sources.items():
        p = tmp_path / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return scan(tmp_path)


def edges(result):
    files = {f.id:f.path for f in result.files}
    modules = {m.id:files[m.file_id] for m in result.modules}
    return [(modules[r.source_id], modules.get(r.target_id), r.resolution, r.dependency_phase) for r in result.graph.relationships if r.kind == RelationshipKind.IMPORT]


def test_python_relative_absolute_src_conditional_dynamic_external(tmp_path):
    r = fixture(tmp_path, {'src/pkg/__init__.py':'', 'src/pkg/a.py':
        'from . import b\nimport pkg.b\nif True:\n import pkg.b\nfrom typing import TYPE_CHECKING\nif TYPE_CHECKING:\n import pkg.b\n__import__("pkg.b")\n__import__(name)\nimport requests\n',
        'src/pkg/b.py':''})
    e = edges(r)
    assert sum(t == 'src/pkg/b.py' for _,t,_,_ in e) == 5
    assert any(phase == 'type_only_conditional' for *_,phase in e)
    assert any(phase == 'runtime_conditional' for *_,phase in e)
    assert any(status == Resolution.EXTERNAL for _,_,status,_ in e)
    assert any(status == Resolution.UNRESOLVED for _,_,status,_ in e)


def test_python_ambiguous_roots(tmp_path):
    r = fixture(tmp_path, {'app.py':'import pkg.a\n','one/src/pkg/a.py':'','two/src/pkg/a.py':''})
    assert r.graph.relationships[0].resolution == Resolution.AMBIGUOUS
    assert r.graph.relationships[0].target_id is None


def test_js_types_dynamic_require_reexports_indexes_and_external(tmp_path):
    r = fixture(tmp_path, {'a.ts': 'import type { B } from "./b";\nexport { B } from "./b";\nif (true) require("./folder");\nimport("./b");\nrequire(computed);\nimport x from "outside";',
                         'b.ts':'export type B = number;', 'folder/index.ts':'export const b = 1;'})
    e = edges(r)
    assert any(t == 'folder/index.ts' and p == 'commonjs_conditional' for _,t,_,p in e)
    assert any(p == 'type_only' for *_,p in e)
    assert any(p == 'dynamic' for *_,p in e)
    assert any(s == Resolution.EXTERNAL for _,_,s,_ in e)
    assert any(s == Resolution.UNRESOLVED for _,_,s,_ in e)


def test_aliases_ambiguous_and_package_entry(tmp_path):
    r = fixture(tmp_path, {'tsconfig.json':'{"compilerOptions":{"baseUrl":".","paths":{"@/*":["src/*"]}}}',
        'main.ts':'import x from "@/b"; import y from "./dual"; import z from "./lib";',
        'src/b.ts':'', 'dual.js':'', 'dual.ts':'', 'lib/package.json':'{"main":"entry.js"}', 'lib/entry.js':''})
    e = edges(r)
    assert any(t == 'src/b.ts' for _,t,_,_ in e)
    assert any(t == 'lib/entry.js' for _,t,_,_ in e)
    assert any(s == Resolution.AMBIGUOUS for _,_,s,_ in e)


def test_escaping_relative_and_excluded_targets(tmp_path):
    r = fixture(tmp_path, {'.gitignore':'hidden.ts\n','a.ts':'import x from "../escape"; import y from "./hidden";', 'hidden.ts':'never read'})
    refs = r.graph.relationships
    assert any(e.resolution == Resolution.UNRESOLVED for e in refs)
    target = next(e for e in refs if e.resolution == Resolution.RESOLVED)
    assert target.target_id in {f.id for f in r.files}
    assert not any(m.file_id == target.target_id for m in r.modules)
