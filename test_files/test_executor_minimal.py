"""Minimal test - just executor"""
import sys
sys.path.insert(0, 'c:\\Users\\huzai\\Desktop\\fyp\\Vulcan\\vulcan-backend\\vulcan-backend')

from app.domain.analysis.ast_parser import ASTParser
from app.domain.analysis.cfg_builder import CFGBuilder
from app.domain.analysis.dfg_builder_enhanced import EnhancedDFGBuilder
from semantic_engine.query_executor.executor import QueryExecutor
from semantic_engine.query_store.loader import QueryRule
from app.enums.edge_type import EdgeType

code = """def test(request):
    x = request.args.get('a')
    return x
"""

parser = ASTParser()
cfg = CFGBuilder()
dfg = EnhancedDFGBuilder()

graph = parser.parse(code, 'test.py')
graph = cfg.build(graph)
graph = dfg.build(graph, code, 'test.py')

print('Nodes:')
for n in graph.nodes:
    print(f'  {n.id:15} {str(n.type):30} {n.name or ""}')

print('\nDFG Edges:')
for e in graph.edges:
    if 'DFG' in str(e.type):
        print(f'  {e.from_node:15} -> {e.to_node:15} | {e.type}')

query = QueryRule(
    rule_id="TEST",
    name="Test",
    owasp="A03",
    description="Test",
    severity="high",
    sources=["request", "request.args"],
    sinks=["return"],
    patterns=["DFG_FLOW"],
    confidence="high"
)

executor = QueryExecutor(max_path_length=10)

# Manual source/sink resolution
sources = executor._resolve_sources(graph, query)
sinks = executor._resolve_sinks(graph, query)

print(f'\nSources found: {len(sources)}')
for s in sources:
    print(f'  {s.id:15} {s.type:30} {s.name or ""}')

print(f'\nSinks found: {len(sinks)}')
for s in sinks:
    print(f'  {s.id:15} {s.type:30} {s.name or ""}')

# Get edge types
edge_types = executor._get_edge_types_for_pattern("DFG_FLOW")
print(f'\nEdge types for DFG_FLOW: {[str(et) for et in edge_types]}')

# Build adjacency list
adj = executor._build_adjacency_list(graph, edge_types)
print(f'\nAdjacency list:')
for node_id, neighbors in adj.items():
    if neighbors:
        node = next((n for n in graph.nodes if n.id == node_id), None)
        print(f'  {node_id:15} ({node.type if node else "?"}):')
        for neighbor, edge_type, meta in neighbors:
            n_node = next((n for n in graph.nodes if n.id == neighbor), None)
            print(f'    -> {neighbor:15} ({n_node.type if n_node else "?"}) | {edge_type}')

# Try BFS manually
print('\nRunning BFS...')
source_ids = {s.id for s in sources}
sink_ids = {s.id for s in sinks}

for source in sources:
    paths = executor._bfs_paths_with_sanitizer_check(
        source.id, sink_ids, adj, graph, set()
    )
    print(f'  Paths from {source.id}: {len(paths)}')
    for path in paths[:3]:
        print(f'    Path: {" -> ".join([p[:10] for p in path])}')

results = executor.execute_query(graph, query, code)
print(f'\nFinal results: {len(results)}')
