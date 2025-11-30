"""Quick test to see what nodes are created"""
import asyncio
from app.domain.analysis.semantic_graph_builder import SemanticGraphBuilder

code = """
import os
import sys

def vulnerable_function():
    user_input = sys.argv[1]
    os.system(user_input)
    return "executed"
"""

builder = SemanticGraphBuilder(language="python")
graph = builder.build(code, filename="test.py")

print(f"Total nodes: {len(graph.nodes)}")
print("\nAll nodes:")
for i, node in enumerate(graph.nodes, 1):
    print(f"{i:2}. Type: {str(node.type):<25} | Name: {node.name or '(no name)'}")

print("\nLooking for 'sys.argv' or 'argv':")
for node in graph.nodes:
    if node.name and ('argv' in node.name.lower() or 'sys' in node.name.lower()):
        print(f"  FOUND: {node.id[:40]} | {node.type} | {node.name}")

print("\nLooking for 'system' or 'os.system':")
for node in graph.nodes:
    if node.name and 'system' in node.name.lower():
        print(f"  FOUND: {node.id[:40]} | {node.type} | {node.name}")
