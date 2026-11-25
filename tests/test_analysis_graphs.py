from argus.scanner import scan
from argus.analysis.graphs import NetworkXBackend, PROJECTION
from argus.models.analysis import Graph, GraphNode


def project(tmp_path, sources):
    for path, source in sources.items():
        (tmp_path / path).write_text(source)
    r = scan(tmp_path)
    paths = {f.id:f.path for f in r.files}
    modules = {paths[m.file_id]:m.id for m in r.modules}
    metrics = {(m.scope_id,m.name):m for m in r.graph.metrics}
    return r, modules, metrics


def test_dag_metrics_and_reachability(tmp_path):
    r, modules, metrics = project(tmp_path, {'a.py':'import b\nimport b\n','b.py':'import c\n','c.py':'','alone.py':''})
    a,b,c,z = [modules[p+'.py'] for p in ('a','b','c','alone')]
    assert metrics[a,'outgoing_coupling'].value == 1
    assert metrics[b,'incoming_coupling'].value == 1
    assert metrics[a,'dependency_depth'].value == 2
    assert metrics[c,'blast_radius'].value == 2
    assert metrics[z,'degree_centrality'].value == 0
    backend = NetworkXBackend()
    assert backend.reachable(r.graph,a) == tuple(sorted((b,c)))
    assert backend.reachable(r.graph,c,'incoming') == tuple(sorted((a,b)))
    assert not r.graph.cycles
    assert len(backend.strongly_connected_components(r.graph)) == 4


def test_cycle_components_not_all_cycles(tmp_path):
    r, modules, metrics = project(tmp_path, {'a.py':'import b\n','b.py':'import a\n','c.py':'import a\n','self.py':'import self\n'})
    assert len(r.graph.cycles) == 2
    assert metrics[modules['c.py'],'dependency_depth'].value is None
    assert metrics[modules['c.py'],'dependency_depth'].unavailable_reason
    assert metrics[modules['a.py'],'scc_size'].value == 2
    assert metrics[modules['a.py'],'blast_radius'].value == 2


def test_metric_resource_guard():
    graph = Graph(nodes=tuple(GraphNode(id=str(i), kind='module',label='opaque',language='python') for i in range(2001)))
    metrics = NetworkXBackend().metrics(graph,('blast_radius','incoming_coupling'))
    assert all(m.value is None and m.unavailable_reason for m in metrics if m.name == 'blast_radius')
    assert all(m.value == 0 for m in metrics if m.name == 'incoming_coupling')


def test_singleton_centrality_and_depth(tmp_path):
    r, modules, metrics=project(tmp_path,{'a.py':''})
    assert metrics[modules['a.py'],'degree_centrality'].value == 0
    assert metrics[modules['a.py'],'dependency_depth'].value == 0
