"""NetworkX behind Argus records: resolved local import projection only."""
from dataclasses import replace
import networkx as nx
from ..models.analysis import Cycle, Metric, Resolution, RelationshipKind

PROJECTION = 'resolved-local-imports-v1'
LIMITATIONS = ('Directed unweighted module imports; runtime, commonjs, dynamic, type-only and conditional edges included. Parallel imports collapse for metrics. External/unresolved edges excluded. Reachability is potential static influence, not runtime impact.',
               'Missing language/capability coverage can invalidate architectural conclusions; isolated modules may have unknown dependencies.')
DEFINITIONS = {
    'incoming_coupling': 'Number of distinct local modules importing this module.',
    'outgoing_coupling': 'Number of distinct local modules imported by this module.',
    'total_coupling': 'Incoming plus outgoing distinct-neighbor counts (directions counted separately).',
    'degree_centrality': 'Sum of in/out degrees divided by n-1; 0 for singleton; self loops may exceed 1.',
    'reachable_dependencies': 'Count of distinct descendants excluding self.',
    'blast_radius': 'Count of distinct ancestors excluding self; possible static reverse reachability only.',
    'dependency_depth': 'Maximum outgoing path length to a sink in an acyclic reachable subgraph; unavailable if a reachable cycle exists.',
    'scc_size': 'Number of modules in the strongly connected component containing this module.',
}

class NetworkXBackend:
    def _project(self, graph, projection):
        if projection != PROJECTION:
            raise ValueError('Unsupported graph projection')
        g = nx.DiGraph()
        g.add_nodes_from(n.id for n in graph.nodes if n.kind == 'module' and n.language in ('python', 'javascript', 'typescript', 'jsx', 'tsx'))
        g.add_edges_from((r.source_id, r.target_id) for r in graph.relationships
                         if r.kind == RelationshipKind.IMPORT and r.resolution == Resolution.RESOLVED
                         and r.source_id in g and r.target_id in g)
        return g

    def strongly_connected_components(self, graph, projection=PROJECTION):
        return tuple(sorted(tuple(sorted(c)) for c in nx.strongly_connected_components(self._project(graph, projection))))

    def circular_dependencies(self, graph, projection=PROJECTION):
        g = self._project(graph, projection)
        return tuple(Cycle(node_ids=members,
                           relationship_ids=tuple(sorted(r.id for r in graph.relationships
                               if r.kind == RelationshipKind.IMPORT and r.resolution == Resolution.RESOLVED
                               and r.source_id in members and r.target_id in members)), projection=projection)
                     for members in self.strongly_connected_components(graph, projection)
                     if len(members) > 1 or g.has_edge(members[0], members[0]))

    def reachable(self, graph, node_id, direction='outgoing', projection=PROJECTION):
        g = self._project(graph, projection)
        if direction not in ('outgoing', 'incoming') or node_id not in g:
            raise ValueError('Invalid reachability request')
        return tuple(sorted(nx.descendants(g, node_id) if direction == 'outgoing' else nx.ancestors(g, node_id)))

    def metrics(self, graph, names=tuple(DEFINITIONS), projection=PROJECTION):
        g = self._project(graph, projection)
        if any(n not in DEFINITIONS for n in names):
            raise ValueError('Unsupported metric')
        centrality = nx.degree_centrality(g) if len(g) > 1 else {n: 0.0 for n in g}
        components = list(nx.strongly_connected_components(g))
        size = {n: len(c) for c in components for n in c}
        # Condensation establishes cycle influence without enumerating paths.
        condensed = nx.condensation(g, components)
        affected_components = {index for index, c in enumerate(components)
                               if len(c) > 1 or any(g.has_edge(n, n) for n in c)}
        for component in reversed(list(nx.topological_sort(condensed))):
            if any(target in affected_components for target in condensed.successors(component)):
                affected_components.add(component)
        unavailable = {n for index in affected_components for n in components[index]}
        depths = {}
        dag = g.subgraph(set(g) - unavailable)
        for n in reversed(list(nx.topological_sort(dag))):
            depths[n] = max((depths[t] + 1 for t in dag.successors(n)), default=0)
        result = []
        # Repeated reachability bounded to 2000 nodes; cheap degree/SCC metrics remain available.
        for n in sorted(g):
            values = {'incoming_coupling': g.in_degree(n), 'outgoing_coupling': g.out_degree(n),
                      'total_coupling': g.in_degree(n) + g.out_degree(n), 'degree_centrality': centrality[n],
                      'scc_size': size[n], 'dependency_depth': depths.get(n)}
            if len(g) <= 2000:
                values.update(reachable_dependencies=len(nx.descendants(g, n)), blast_radius=len(nx.ancestors(g, n)))
            for name in names:
                value = values.get(name)
                result.append(Metric(name=name, definition=DEFINITIONS[name], scope_id=n, projection=projection,
                    algorithm_version='argus-1/networkx-' + nx.__version__, value=value,
                    unavailable_reason=('Reachable cycle prevents DAG depth.' if name == 'dependency_depth' else
                                        'Graph exceeds 2000-node repeated reachability budget.') if value is None else None,
                    limitations=LIMITATIONS))
        return tuple(result)

    def analyze(self, graph):
        return replace(graph, cycles=self.circular_dependencies(graph), metrics=self.metrics(graph), limitations=LIMITATIONS)
