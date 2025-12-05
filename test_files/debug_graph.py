"""Check what edges connect sys.argv to os.system"""
import asyncio
from semantic_engine.pipeline import get_pipeline, PipelineConfig

async def main():
    code = """
import os
import sys

def vulnerable_function():
    user_input = sys.argv[1]
    os.system(user_input)
    return "executed"
"""
    
    pipeline = get_pipeline(PipelineConfig(enable_llm=False))
    
    from app.domain.analysis.semantic_graph_builder import SemanticGraphBuilder
    builder = SemanticGraphBuilder(language="python")
    graph = builder.build(code, filename="test.py")
    
    # Find sys.argv and os.system nodes
    sys_argv_node = None
    os_system_node = None
    user_input_var = None
    
    for node in graph.nodes:
        if node.name == "sys.argv":
            sys_argv_node = node
            print(f"Found SOURCE: {node.id} | {node.type} | {node.name}")
        elif node.name == "os.system":
            os_system_node = node
            print(f"Found SINK: {node.id} | {node.type} | {node.name}")
        elif node.name == "user_input" and str(node.type) == "NodeType.VARIABLE":
            user_input_var = node
            print(f"Found VAR: {node.id} | {node.type} | {node.name}")
    
    print(f"\nAll {len(graph.edges)} edges:")
    for i, edge in enumerate(graph.edges, 1):
        from_node = next((n for n in graph.nodes if n.id == edge.from_node), None)
        to_node = next((n for n in graph.nodes if n.id == edge.to_node), None)
        from_name = (from_node.name if from_node and from_node.name else "?")[:20]
        to_name = (to_node.name if to_node and to_node.name else "?")[:20]
        print(f"{i:2}. {from_name:<20} --[{str(edge.type):<20}]--> {to_name:<20}")
    
    # Check path from source to sink
    if sys_argv_node and os_system_node:
        print(f"\nChecking path from {sys_argv_node.id} to {os_system_node.id}...")
        
        # Build adjacency
        adj = {}
        for edge in graph.edges:
            if edge.from_node not in adj:
                adj[edge.from_node] = []
            adj[edge.from_node].append((edge.to_node, edge.type))
        
        # BFS
        from collections import deque
        queue = deque([(sys_argv_node.id, [sys_argv_node.id])])
        visited = set()
        found_path = None
        
        while queue and not found_path:
            current, path = queue.popleft()
            if current == os_system_node.id:
                found_path = path
                break
            if current in visited or len(path) > 10:
                continue
            visited.add(current)
            
            for neighbor, edge_type in adj.get(current, []):
                queue.append((neighbor, path + [neighbor]))
        
        if found_path:
            print(f"✅ PATH FOUND ({len(found_path)} nodes):")
            for node_id in found_path:
                node = next((n for n in graph.nodes if n.id == node_id), None)
                if node:
                    print(f"  -> {node.name or node.id} ({node.type})")
        else:
            print(f"❌ NO PATH from {sys_argv_node.id} to {os_system_node.id}")
            print("\nDEBUG: Edges from source node:")
            for neighbor, edge_type in adj.get(sys_argv_node.id, []):
                node = next((n for n in graph.nodes if n.id == neighbor), None)
                print(f"  {sys_argv_node.id} --[{edge_type}]--> {neighbor} ({node.name if node else '?'})")

asyncio.run(main())
