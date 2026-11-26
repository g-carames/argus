from argus.scanner import scan
from argus.models.analysis import RelationshipKind, Resolution


def fixture(tmp_path,sources):
    for path,source in sources.items():
        p=tmp_path/path
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text(source)
    return scan(tmp_path)


def test_local_imported_alias_and_external_calls(tmp_path):
    r=fixture(tmp_path,{'a.py':'from b import f as alias\nimport b as module\nimport requests as http\ndef local(): pass\nlocal()\nalias()\nmodule.f()\nhttp.get(url)\nunknown()\n','b.py':'def f(): pass'})
    calls=[e for e in r.graph.relationships if e.kind==RelationshipKind.CALL]
    assert sum(e.resolution==Resolution.RESOLVED for e in calls)==3
    assert sum(e.resolution==Resolution.EXTERNAL for e in calls)==1
    assert sum(e.resolution==Resolution.UNRESOLVED for e in calls)==1
    assert all(e.evidence_ids and e.limitations for e in calls)


def test_js_import_alias_local_constructor_and_unresolved_method(tmp_path):
    r=fixture(tmp_path,{'a.ts':'import {f as alias} from "./b"; function local() {} class A {} local(); alias(); new A(); obj.method();', 'b.ts':'export function f() {}'})
    calls=[e for e in r.graph.relationships if e.kind==RelationshipKind.CALL]
    assert sum(e.resolution==Resolution.RESOLVED for e in calls)==3
    assert any(e.resolution==Resolution.UNRESOLVED for e in calls)


def test_http_fastapi_flask_axios_fetch_and_ambiguous(tmp_path):
    r=fixture(tmp_path,{'backend.py':'from fastapi import FastAPI, APIRouter\napp=FastAPI()\nrouter=APIRouter(prefix="/api")\n@router.post("/generate")\ndef generate(): pass\napp.include_router(router)\n',
        'other.py':'from flask import Flask\napp=Flask(__name__)\n@app.route("/same",methods=["GET"])\ndef f(): pass\n@app.get("/same")\ndef g(): pass',
        'a.ts':'import axios from "axios"; const URL="/api/generate"; fetch(URL,{method:"POST"}); axios.get("/same"); fetch("/unknown"); fetch("https://example.invalid/api/generate");'})
    http=[e for e in r.graph.relationships if e.kind==RelationshipKind.HTTP]
    assert {e.resolution for e in http}=={Resolution.RESOLVED,Resolution.AMBIGUOUS,Resolution.UNRESOLVED,Resolution.EXTERNAL}
    assert all(e.provenance.value=='inferred' for e in http)
    assert len([n for n in r.graph.nodes if n.kind=='http_endpoint'])==3


def test_express_method_and_route_parameter(tmp_path):
    r=fixture(tmp_path,{'server.js':'import express from "express"; const app=express(); app.get("/items/:id", handler);',
        'client.ts':'fetch("/items/123"); fetch("/items/123",{method:"POST"});'})
    http=[e for e in r.graph.relationships if e.kind==RelationshipKind.HTTP]
    assert sum(e.resolution==Resolution.RESOLVED for e in http)==1
    assert sum(e.resolution==Resolution.UNRESOLVED for e in http)==1


def test_no_framework_evidence_or_dynamic_method_no_invented_match(tmp_path):
    r=fixture(tmp_path,{'server.py':'@app.get("/x")\ndef f(): pass', 'client.js':'const URL="/x"; fetch(URL,options);'})
    assert not any(n.kind=='http_endpoint' for n in r.graph.nodes)
    assert all(e.resolution!=Resolution.RESOLVED for e in r.graph.relationships if e.kind==RelationshipKind.HTTP)


def test_shadowed_call_bindings_do_not_resolve(tmp_path):
    r=fixture(tmp_path,{'a.py':'from b import f\ndef local(): pass\ndef g(f): f()\ndef h():\n local=callback\n local()\n','b.py':'def f(): pass',
        'a.ts':'import {f} from "./b"; function g(f: Function) { f(); }', 'b.ts':'export function f() {}'})
    calls=[e for e in r.graph.relationships if e.kind==RelationshipKind.CALL]
    assert calls and all(e.resolution!=Resolution.RESOLVED for e in calls)


def test_next_route_and_same_line_express_endpoints(tmp_path):
    r=fixture(tmp_path,{'app/api/items/[id]/route.ts':'import {NextResponse} from "next/server"; export function GET() { return NextResponse.json({}); }',
        'client.ts':'fetch("/api/items/123");',
        'server.js':'import express from "express"; const app=express(); app.get("/one", f); app.get("/two", g);'})
    assert len([n for n in r.graph.nodes if n.kind=='http_endpoint'])==3
    assert any(e.resolution==Resolution.RESOLVED for e in r.graph.relationships if e.kind==RelationshipKind.HTTP)


def test_computed_backend_path_not_invented(tmp_path):
    r=fixture(tmp_path,{'a.py':'from fastapi import FastAPI\napp=FastAPI()\n@app.get(computed)\ndef f(): pass', 'a.js':'fetch("/");'})
    assert not any(n.kind=='http_endpoint' for n in r.graph.nodes)


def test_shadowed_clients_and_bare_class_method_not_invented(tmp_path):
    r=fixture(tmp_path,{'a.ts':'import axios from "axios"; function f(axios: any, fetch: any) { axios.get("/x"); fetch("/x"); } class A { x() {} y() { x(); } }'})
    assert not any(e.kind==RelationshipKind.HTTP for e in r.graph.relationships)
    assert all(e.resolution!=Resolution.RESOLVED for e in r.graph.relationships if e.kind==RelationshipKind.CALL)
