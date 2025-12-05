"""
Direct test of semantic pipeline to check vulnerability detection
"""
import sys
import logging
import asyncio
from semantic_engine.pipeline import SemanticPipeline, PipelineConfig

# Enable detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s [%(name)s] %(message)s'
)

# Vulnerable Python code with SQL injection
vulnerable_code = """
import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SQL Injection vulnerability  
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
"""

async def main():
    print("="*80)
    print("TESTING SEMANTIC PIPELINE - SQL INJECTION DETECTION")
    print("="*80)

    # Create pipeline with LLM disabled for faster testing
    config = PipelineConfig(enable_llm=False)
    pipeline = SemanticPipeline(config)

    print(f"\n📋 Analyzing code ({len(vulnerable_code)} chars)...")
    print(f"🔧 LLM enabled: {config.enable_llm}")
    print(f"📚 Query store path: queries/queries.yaml")

    # Run analysis
    result = await pipeline.analyze_code("test.py", vulnerable_code, language="python")

    print(f"\n📊 ANALYSIS RESULTS:")
    print(f"   Status: {result.status}")
    print(f"   Duration: {result.analysis_duration:.3f}s")

    if result.graph_data:
        print(f"\n🌐 GRAPH DATA:")
        print(f"   Nodes: {len(result.graph_data.get('nodes', []))}")
        print(f"   Edges: {len(result.graph_data.get('edges', []))}")
        
        if result.graph_data.get('nodes'):
            print(f"\n   Node types:")
            node_types = {}
            for node in result.graph_data['nodes']:
                ntype = node.get('type', 'UNKNOWN')
                node_types[ntype] = node_types.get(ntype, 0) + 1
            for ntype, count in sorted(node_types.items()):
                print(f"      {ntype}: {count}")

    print(f"\n🐛 VULNERABILITIES: {len(result.vulnerabilities)}")
    if result.vulnerabilities:
        for i, vuln in enumerate(result.vulnerabilities, 1):
            print(f"\n   [{i}] {vuln.get('type', 'UNKNOWN')}")
            print(f"       Severity: {vuln.get('severity', 'N/A')}")
            print(f"       Line: {vuln.get('line', 'N/A')}")
            print(f"       Description: {vuln.get('description', 'N/A')[:100]}")
    else:
        print("   ❌ No vulnerabilities detected!")
        print("\n🔍 DEBUGGING:")
        print(f"      - Check if AST was built (nodes > 1)")
        print(f"      - Check if taint analysis ran")
        print(f"      - Check if query rules matched")

    if result.errors:
        print(f"\n❌ ERRORS: {len(result.errors)}")
        for error in result.errors:
            print(f"   - {error}")

    print("\n" + "="*80)

if __name__ == "__main__":
    asyncio.run(main())
