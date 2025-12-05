"""
Debug AST parsing with queries.json
"""
from app.domain.analysis.ast_parser import ASTParser

code = """
import sqlite3

def check_user(sqli):
    if sqli:
        username = sqli.get("username")
        try:
            conn = sqlite3.connect('users.db')
            cur = conn.cursor()
            query = f"SELECT * FROM users WHERE username = '{username}'"
            cur.execute(query)
            result = cur.fetchall()
            return result
        except:
            pass
"""

print("="*60)
print("🔍 TESTING AST PARSER")
print("="*60)

parser = ASTParser()
graph = parser.parse(code, "test_sqli.py")

print(f"\n📊 Graph Statistics:")
print(f"  Total nodes: {len(graph.nodes)}")
print(f"  Total edges: {len(graph.edges)}")

print(f"\n📋 All Nodes:")
for node in graph.nodes:
    print(f"  {node.id}: {node.name} (type: {node.type})")

print(f"\n🔗 All Edges:")
for edge in graph.edges:
    from_node = next((n for n in graph.nodes if n.id == edge.from_node), None)
    to_node = next((n for n in graph.nodes if n.id == edge.to_node), None)
    if from_node and to_node:
        print(f"  {from_node.name} -> {to_node.name} ({edge.type})")

print(f"\n{'='*60}")
