"""
Test SQL injection detection with parameter sources
"""
import asyncio
from semantic_engine.pipeline import get_pipeline, PipelineConfig

async def test():
    pipeline = get_pipeline(PipelineConfig(enable_llm=False))
    
    code = """import sqlite3

conn = sqlite3.connect("vulns.db", check_same_thread=False)

def sqlinovuln():
    return "This is just a simple response"


def sqlivuln(sqli):
    username = sqli.get("username", "noprovided")
    password = sqli.get("password", "noprovided")

    if username and password:
        cur = conn.cursor()
        try:
            cur.execute(f"SELECT * FROM USERS WHERE USERNAME='{username}'")
            users = cur.fetchall()
        except Exception as e:
            return {"msg": f"{e}"}, 200
        return {"msg": f"Hello, {users}"}, 200
    else:
        return {"msg": f"Error"}, 400
"""
    
    result = await pipeline.analyze_code("test.py", code, "python")
    
    print(f"Nodes: {result.graph_nodes}")
    print(f"Edges: {result.graph_edges}")
    print(f"Vulnerabilities: {result.vulnerabilities_found}")
    
    # Check nodes
    print("\n=== NODES ===")
    for node in result.graph_data["nodes"][:20]:
        print(f"{node['id']}: {node['type']} - {node.get('label', 'N/A')}")
    
    # Check if there's a path from username to execute
    print("\n=== LOOKING FOR PATH ===")
    for node in result.graph_data["nodes"]:
        label = node.get("label", "").lower()
        if "username" in label:
            print(f"Username node: {node['id']} - {node['type']} - {node.get('label')}")
        if "execute" in label or "cur.execute" in label:
            print(f"Execute node: {node['id']} - {node['type']} - {node.get('label')}")
    
    print(f"\n=== VULNERABILITIES ===")
    for vuln in result.vulnerabilities:
        print(f"- {vuln['type']}: {vuln['evidence']['source']} -> {vuln['evidence']['sink']}")
    
    # Print all nodes to find execute
    print(f"\n=== ALL NODES ({len(result.graph_data['nodes'])}) ===")
    for node in result.graph_data["nodes"]:
        print(f"{node['id']}: {node['type']} - {node.get('label', 'N/A')}")
    
    # Print DFG edges
    print(f"\n=== DFG EDGES ===")
    for edge in result.graph_data["edges"]:
        if "DFG" in edge.get("type", ""):
            from_node = next((n for n in result.graph_data["nodes"] if n["id"] == edge["from"]), None)
            to_node = next((n for n in result.graph_data["nodes"] if n["id"] == edge["to"]), None)
            if from_node and to_node:
                print(f"{edge['from']} ({from_node.get('label')}) -> {edge['to']} ({to_node.get('label')}) [{edge['type']}]")

if __name__ == "__main__":
    asyncio.run(test())
