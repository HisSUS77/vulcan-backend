"""
Debug CFG builder to see what's happening
"""
from app.domain.analysis.ast_parser import ASTParser
from app.domain.analysis.cfg_builder import CFGBuilder
from app.enums.edge_type import EdgeType
from app.enums.node_type import NodeType


code = """
def check_user(is_admin):
    if is_admin:
        query = "SELECT * FROM admin_data"
    else:
        query = "SELECT * FROM user_data"
    
    cursor.execute(query)
"""

# Parse AST
parser = ASTParser(language="python")
graph = parser.parse(code, "test.py")

print("="*60)
print("BEFORE CFG BUILDER")
print("="*60)
print(f"Nodes: {len(graph.nodes)}")
for node in graph.nodes:
    print(f"  {node.id}: {node.type} | line={node.line} | name={node.name}")
    if node.type in (NodeType.IF_STATEMENT, NodeType.FOR_STATEMENT, NodeType.TRY_STATEMENT):
        print(f"    metadata: {node.metadata}")

print(f"\nEdges: {len(graph.edges)}")
for edge in graph.edges:
    print(f"  {edge.from_node} -> {edge.to_node} ({edge.type})")

# Build CFG
cfg_builder = CFGBuilder()
graph_with_cfg = cfg_builder.build(graph)

print("\n" + "="*60)
print("AFTER CFG BUILDER")
print("="*60)
print(f"Nodes: {len(graph_with_cfg.nodes)}")
print(f"Edges: {len(graph_with_cfg.edges)}")

# Show CFG edges
cfg_edges = [e for e in graph_with_cfg.edges if 'CFG' in str(e.type)]
print(f"\nCFG Edges: {len(cfg_edges)}")
for edge in cfg_edges:
    from_node = next((n for n in graph_with_cfg.nodes if n.id == edge.from_node), None)
    to_node = next((n for n in graph_with_cfg.nodes if n.id == edge.to_node), None)
    print(f"  {edge.from_node} ({from_node.type if from_node else '?'}) -> "
          f"{edge.to_node} ({to_node.type if to_node else '?'}) | {edge.type}")

# Debug: Check function scopes
print("\n" + "="*60)
print("DEBUG: Function Scopes")
print("="*60)
scopes = cfg_builder._build_function_scopes(graph.nodes)
print(f"Found {len(scopes)} function scopes:")
for func_id, statements in scopes.items():
    func_node = next((n for n in graph.nodes if n.id == func_id), None)
    print(f"\nFunction: {func_node.name if func_node else func_id}")
    print(f"  Statements ({len(statements)}):")
    for stmt in sorted(statements, key=lambda n: n.line):
        print(f"    line {stmt.line}: {stmt.type} | {stmt.name}")

# Debug: Statement types
print("\n" + "="*60)
print("DEBUG: Statement Types")
print("="*60)
stmt_types = cfg_builder._get_statement_types()
print(f"Recognized statement types: {stmt_types}")

statement_nodes = [n for n in graph.nodes if n.type in stmt_types]
print(f"\nFound {len(statement_nodes)} statement nodes:")
for node in sorted(statement_nodes, key=lambda n: n.line):
    print(f"  line {node.line}: {node.type} | {node.name}")
