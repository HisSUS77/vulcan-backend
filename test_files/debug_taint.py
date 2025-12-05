"""Debug taint tracking."""
from app.services.analysis_service import AnalysisService
from app.domain.analysis.taint_engine import TaintEngine


vulnerable_code = '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
'''

service = AnalysisService()

# Build graph
from app.domain.analysis.semantic_graph_builder import SemanticGraphBuilder
builder = SemanticGraphBuilder(language="python")
graph = builder.build(vulnerable_code, "test.py")

print("=== GRAPH SUMMARY ===")
print(f"Nodes: {len(graph.nodes)}")
print(f"Edges: {len(graph.edges)}")

# Check taint engine
engine = TaintEngine()

print("\n=== SOURCES ===")
sources = engine._find_sources(graph)
for src in sources:
    print(f"  {src.id} - {src.type} - {src.name}")

print("\n=== SINKS ===")
sinks = engine._find_sinks(graph)
for sink in sinks:
    print(f"  {sink.id} - {sink.type} - {sink.name}")

print("\n=== TAINT ANALYSIS ===")
taint_results = engine.analyze(graph)
print(f"Taint flows found: {len(taint_results)}")

for i, taint in enumerate(taint_results, 1):
    print(f"\n--- Flow {i} ---")
    print(f"Source: {taint.source_node.id} ({taint.source_node.name})")
    print(f"Sink: {taint.sink_node.id} ({taint.sink_node.name})")
    print(f"Path: {' -> '.join([n.id for n in taint.flow_path])}")
    print(f"Severity: {taint.severity}")
