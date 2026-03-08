"""Debug script to test CPG parser function extraction"""
import sys
from pathlib import Path

# Add app to path
sys.path.insert(0, str(Path(__file__).parent))

from app.domain.analysis.cpg_parser import CPGParser, LanguageType

# Simple Python test code
test_code = """
def login(username, password):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return query

def cmd_exec(host):
    os.system("ping " + host)
"""

print("Testing CPG Parser...")
print("=" * 60)

try:
    parser = CPGParser()
    
    # Check if Python is loaded
    print(f"Available languages: {parser.available_languages()}")
    print(f"Has Python: {parser.has_language(LanguageType.PYTHON)}")
    
    # Parse the test code
    graph = parser.parse_code(test_code, LanguageType.PYTHON, "test.py")
    
    print(f"\nGraph stats:")
    print(f"  Total nodes: {len(graph.nodes)}")
    print(f"  Total edges: {len(graph.edges)}")
    
    # Find function nodes
    function_nodes = [n for n in graph.nodes if 'FUNCTION' in str(n.type)]
    print(f"\nFunction nodes found: {len(function_nodes)}")
    
    for fn in function_nodes:
        print(f"  - {fn.name} (type: {fn.type}, line: {fn.line})")
    
    # Show all unique node types
    node_types = set(n.type for n in graph.nodes)
    print(f"\nAll node types found: {sorted(node_types)}")
    
    # Now test with interprocedural DFG
    from app.domain.analysis.interprocedural_dfg import InterproceduralDFG
    
    print("\n" + "=" * 60)
    print("Testing Interprocedural DFG...")
    
    dfg = InterproceduralDFG(graph)
    enhanced_graph = dfg.build()
    
    print(f"Functions extracted: {len(dfg.functions)}")
    for fname, sig in dfg.functions.items():
        if isinstance(fname, str):
            print(f"  - {fname}: {len(sig.parameters)} params")
    
except Exception as e:
    import traceback
    print(f"\nERROR: {e}")
    traceback.print_exc()

print("\n" + "=" * 60)
print("Debug complete!")
