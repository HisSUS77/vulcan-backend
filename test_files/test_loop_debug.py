"""
Debug loop CFG to see what's happening
"""
from app.domain.analysis.ast_parser import ASTParser
from app.domain.analysis.cfg_builder import CFGBuilder
from app.enums.edge_type import EdgeType
from app.enums.node_type import NodeType


code = """
for user_id in user_input.split(','):
    query = f"SELECT * FROM users WHERE id={user_id}"
    cursor.execute(query)
"""

# Parse AST
parser = ASTParser(language="python")
graph = parser.parse(code, "test_loop.py")

print("="*60)
print("NODES")
print("="*60)
for node in sorted(graph.nodes, key=lambda n: n.line):
    print(f"  line {node.line}: {node.type} | {node.name}")
    if node.type == NodeType.FOR_STATEMENT:
        print(f"    metadata: {node.metadata}")

# Build CFG
cfg_builder = CFGBuilder()

# Check function scopes
scopes = cfg_builder._build_function_scopes(graph.nodes)
print(f"\nFunction scopes: {len(scopes)}")

# Check top-level statements
top_level = cfg_builder._get_top_level_statements(graph.nodes)
print(f"\nTop-level statements: {len(top_level)}")
for stmt in top_level:
    print(f"  line {stmt.line}: {stmt.type}")

graph_with_cfg = cfg_builder.build(graph)

print("\n" + "="*60)
print("CFG EDGES")
print("="*60)
cfg_edges = [e for e in graph_with_cfg.edges if 'CFG' in str(e.type)]
print(f"Total CFG edges: {len(cfg_edges)}")
for edge in cfg_edges:
    from_node = next((n for n in graph_with_cfg.nodes if n.id == edge.from_node), None)
    to_node = next((n for n in graph_with_cfg.nodes if n.id == edge.to_node), None)
    print(f"  {edge.type}: {from_node.type if from_node else '?'} (line {from_node.line if from_node else '?'}) "
          f"-> {to_node.type if to_node else '?'} (line {to_node.line if to_node else '?'})")
