from argus.models.analysis import RelationshipKind, Resolution
from argus.scanner import scan

def fixture(tmp_path, sources):
    for path, source in sources.items():
        p=tmp_path/path
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text(source)
    return scan(tmp_path)


def imports(result):
    files={f.id:f.path for f in result.files}
    modules={m.id:files[m.file_id] for m in result.modules}
    return [(modules[r.source_id],modules.get(r.target_id),r.resolution) for r in result.graph.relationships if r.kind == RelationshipKind.IMPORT]


def test_jsonc_jsconfig_extended_origin_and_index(tmp_path):
    result=fixture(tmp_path,{'configs/base.json':'{"compilerOptions":{"baseUrl":"..","paths":{"@/*":["shared/*"]}}}',
        'app/jsconfig.json':'{ // comment\n "extends":"../configs/base", /*ok*/ "compilerOptions":{}, }',
        'app/a.js':'import {x} from "@/util";', 'shared/util/index.ts':'export const x = 1;'})
    assert ('app/a.js','shared/util/index.ts',Resolution.RESOLVED) in imports(result)


def test_config_cycles_and_escape_do_not_invent_alias(tmp_path):
    result=fixture(tmp_path,{'tsconfig.json':'{"extends":"./other.json"}','other.json':'{"extends":"./tsconfig.json"}',
        'a.ts':'import x from "@/x";', 'x.ts':''})
    assert imports(result)[0][2] == Resolution.UNRESOLVED


def test_workspace_exports_conditions_and_private_subpath(tmp_path):
    result=fixture(tmp_path,{'package.json':'{"workspaces":["packages/*"]}',
        'a.ts':'import x from "@local/core"; import y from "@local/core/private";',
        'packages/core/package.json':'{"name":"@local/core","exports":{".":{"import":"./a.ts","require":"./b.ts"}}}',
        'packages/core/a.ts':'','packages/core/b.ts':'','packages/core/private.ts':''})
    statuses={s for _,_,s in imports(result)}
    assert statuses == {Resolution.AMBIGUOUS,Resolution.UNRESOLVED}


def test_pnpm_workspace_subpath_export(tmp_path):
    result=fixture(tmp_path,{'pnpm-workspace.yaml':"packages:\n  - 'packages/*'\n",
        'a.ts':'import x from "@local/core/util";',
        'packages/core/package.json':'{"name":"@local/core","exports":{"./*":"./src/*.ts"}}',
        'packages/core/src/util.ts':''})
    assert imports(result)[0][1:] == ('packages/core/src/util.ts',Resolution.RESOLVED)


def test_jsonc_strings_not_rewritten():
    from argus.analysis.jsonc import loads
    assert loads(b'{"url":"https://x/*ok*/,}","v":[1,],}') == {'url':'https://x/*ok*/,}','v':[1]}


def test_alias_precedence_and_extended_jsonc_basename(tmp_path):
    r=fixture(tmp_path,{'base.json':'{/*config*/"compilerOptions":{"paths":{"@/*":["general/*"],"@/exact":["special.ts"]},},}',
        'tsconfig.json':'{"extends":"./base.json"}', 'a.ts':'import x from "@/exact";',
        'general/exact.ts':'','special.ts':''})
    assert imports(r)[0][1]=='special.ts'


def test_workspace_globs_do_not_cross_directory_boundaries(tmp_path):
    r=fixture(tmp_path,{'package.json':'{"workspaces":["packages/*"]}',
        'a.ts':'import x from "nested-package";',
        'packages/one/nested/package.json':'{"name":"nested-package","main":"index.ts"}',
        'packages/one/nested/index.ts':''})
    assert imports(r)[0][2]==Resolution.EXTERNAL
