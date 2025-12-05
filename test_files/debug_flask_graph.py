"""
Debug: Check what nodes are created in the graph for vulnerable code
"""
import asyncio
from pathlib import Path
from app.domain.analysis.ast_parser import ASTParser
from app.domain.analysis.cfg_builder import CFGBuilder
from app.domain.analysis.dfg_builder_enhanced import EnhancedDFGBuilder as DFGBuilder
from app.domain.analysis.semantic_graph_builder import SemanticGraphBuilder

async def debug_graph():
    code = '''
def get_user_by_id(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user = cursor.fetchone()
    conn.close()
    return user
'''
    
    # Build graph using SemanticGraphBuilder
    builder = SemanticGraphBuilder(language="python")
    graph = builder.build(code, filename="test.py")
    
    print(f"Total nodes: {len(graph.nodes)}")
    print(f"Total edges: {len(graph.edges)}")
    print()
    
    # Find execute calls
    execute_nodes = [n for n in graph.nodes if 'execute' in str(n.name).lower()]
    print(f"Execute nodes: {len(execute_nodes)}")
    for node in execute_nodes:
        print(f"  - {node.type}: {node.name} (line {node.line})")
    print()
    
    # Find user_id references
    user_id_nodes = [n for n in graph.nodes if 'user_id' in str(n.name).lower()]
    print(f"User_id nodes: {len(user_id_nodes)}")
    for node in user_id_nodes:
        print(f"  - {node.type}: {node.name} (line {node.line})")
    print()
    
    # Find data flow edges
    data_edges = [e for e in graph.edges if e.type.value in ['DFG_FLOW', 'TAINT_FLOW']]
    print(f"Data flow edges (DFG_FLOW + TAINT_FLOW): {len(data_edges)}")
    for edge in data_edges:
        src = next((n for n in graph.nodes if n.id == edge.from_node), None)
        dst = next((n for n in graph.nodes if n.id == edge.to_node), None)
        if src and dst:
            print(f"  [{edge.type.value}] {src.name or src.type} (line {src.line}) -> {dst.name or dst.type} (line {dst.line})")
    print()
    
    # Show all edge types
    edge_types = {}
    for edge in graph.edges:
        edge_type = str(edge.type.value)
        edge_types[edge_type] = edge_types.get(edge_type, 0) + 1
    print("Edge type distribution:")
    for edge_type, count in sorted(edge_types.items()):
        print(f"  {edge_type}: {count}")
    
    # Show some edges to understand structure
    print()
    print("Sample edges:")
    for edge in graph.edges[:10]:
        src = next((n for n in graph.nodes if n.id == edge.from_node), None)
        dst = next((n for n in graph.nodes if n.id == edge.to_node), None)
        if src and dst:
            print(f"  [{edge.type.value}] {src.name or src.type} -> {dst.name or dst.type}")
    
if __name__ == "__main__":
    asyncio.run(debug_graph())
