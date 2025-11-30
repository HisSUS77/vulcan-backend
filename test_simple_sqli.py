"""
Simple test to verify SQL injection detection with queries.json
"""
import asyncio
from semantic_engine.pipeline import SemanticPipeline

async def test():
    # SQL injection vulnerable code
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
    
    # Run semantic analysis
    pipeline = SemanticPipeline()
    result = await pipeline.analyze_code("test_sqli.py", code, "python")
    
    print("\n" + "="*60)
    print("🔍 SQL INJECTION DETECTION TEST")
    print("="*60)
    print(f"\nGraph Stats:")
    print(f"  Total nodes: {len(result.graph_data['nodes'])}")
    print(f"  Total edges: {len(result.graph_data['edges'])}")
    
    print(f"\n📊 Results:")
    print(f"  Vulnerabilities found: {len(result.vulnerabilities)}")
    
    if result.vulnerabilities:
        print(f"\n✅ DETECTED VULNERABILITIES:")
        for i, vuln in enumerate(result.vulnerabilities, 1):
            print(f"\n  {i}. Vulnerability:")
            for key, value in vuln.items():
                print(f"     {key}: {value}")
    else:
        print("\n❌ NO VULNERABILITIES DETECTED")
        print("\nDebug Info:")
        # Print some node info
        print(f"\nNode types found:")
        node_types = {}
        for node in result.graph_data['nodes']:
            ntype = node.get('type', 'unknown')
            node_types[ntype] = node_types.get(ntype, 0) + 1
        for ntype, count in sorted(node_types.items()):
            print(f"  {ntype}: {count}")
        
        # Look for username and execute nodes
        print(f"\nLooking for key nodes:")
        for node in result.graph_data['nodes']:
            if 'username' in str(node.get('label', '')).lower():
                print(f"  Found username node: {node.get('label')} (type: {node.get('type')})")
            if 'execute' in str(node.get('label', '')).lower():
                print(f"  Found execute node: {node.get('label')} (type: {node.get('type')})")

asyncio.run(test())
