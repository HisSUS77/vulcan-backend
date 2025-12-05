"""
Debug: Check enhanced DFG builder with f-string tracking
"""
import asyncio
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
    
    print("="*80)
    print("ENHANCED DFG BUILDER TEST - F-STRING TRACKING")
    print("="*80)
    print()
    
    # Build graph using SemanticGraphBuilder with enhanced DFG
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
    
    # Find f-string nodes
    fstring_nodes = [n for n in graph.nodes if n.type.value in ['FString', 'StringConcat', 'StringFormat']]
    print(f"String operation nodes: {len(fstring_nodes)}")
    for node in fstring_nodes:
        print(f"  - {node.type}: {node.name} (line {node.line})")
    print()
    
    # Find data flow edges
    data_edges = [e for e in graph.edges if e.type.value in ['DFG_FLOW', 'TAINT_FLOW', 'DFG_INTERP', 'DFG_PARAM_PASS']]
    print(f"Data flow edges: {len(data_edges)}")
    for edge in data_edges:
        src = next((n for n in graph.nodes if n.id == edge.from_node), None)
        dst = next((n for n in graph.nodes if n.id == edge.to_node), None)
        if src and dst:
            src_name = src.name or src.type.value
            dst_name = dst.name or dst.type.value
            print(f"  [{edge.type.value}] {src_name} (line {src.line}) -> {dst_name} (line {dst.line})")
    print()
    
    # Show edge type distribution
    edge_types = {}
    for edge in graph.edges:
        edge_type = edge.type.value
        edge_types[edge_type] = edge_types.get(edge_type, 0) + 1
    
    print("Edge type distribution:")
    for edge_type, count in sorted(edge_types.items()):
        print(f"  {edge_type}: {count}")
    print()
    
    # Check if there's a path from user_id to execute
    print("="*80)
    print("CHECKING DATA FLOW PATH: user_id → execute")
    print("="*80)
    user_id_param = next((n for n in graph.nodes if n.type.value == 'Parameter' and n.name == 'user_id'), None)
    execute_call = next((n for n in graph.nodes if n.type.value == 'CallExpression' and 'execute' in str(n.name).lower()), None)
    
    if user_id_param and execute_call:
        print(f"Source: {user_id_param.name} ({user_id_param.id}) at line {user_id_param.line}")
        print(f"Sink: {execute_call.name} ({execute_call.id}) at line {execute_call.line}")
        print()
        
        # Simple BFS to find path
        from collections import deque
        queue = deque([(user_id_param.id, [user_id_param.id])])
        visited = set()
        found_path = None
        
        while queue and not found_path:
            current_id, path = queue.popleft()
            if current_id in visited:
                continue
            visited.add(current_id)
            
            if current_id == execute_call.id:
                found_path = path
                break
            
            # Find outgoing DFG edges
            for edge in graph.edges:
                if edge.from_node == current_id and edge.type.value in ['DFG_FLOW', 'DFG_INTERP', 'DFG_PARAM_PASS']:
                    if edge.to_node not in visited:
                        queue.append((edge.to_node, path + [edge.to_node]))
        
        if found_path:
            print(f"✅ FOUND VULNERABLE PATH ({len(found_path)} nodes):")
            for node_id in found_path:
                node = next((n for n in graph.nodes if n.id == node_id), None)
                if node:
                    node_name = node.name or node.type.value
                    print(f"   → {node.type.value}: {node_name} (line {node.line})")
            print()
            print("This confirms the enhanced DFG builder successfully tracks f-string interpolation!")
        else:
            print(f"❌ NO PATH FOUND - DFG builder needs further enhancement")
    else:
        print(f"❌ Could not find source or sink nodes")

if __name__ == "__main__":
    asyncio.run(debug_graph())
