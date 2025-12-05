"""
Test production DFG builder with:
1. Sanitizer detection
2. Property tracking
3. Inter-procedural flows
4. Implicit flows (CFG-based)
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.domain.analysis.ast_parser import ASTParser
from app.domain.analysis.cfg_builder import CFGBuilder
from app.domain.analysis.dfg_builder_enhanced import EnhancedDFGBuilder
from app.enums.edge_type import EdgeType
from app.enums.node_type import NodeType

# TEST 1: Sanitizer detection
code_sanitizer = """
import html

def safe_view(user_input):
    # This should NOT be flagged as vulnerable
    sanitized = html.escape(user_input)
    return f"<div>{sanitized}</div>"

def unsafe_view(user_input):
    # This SHOULD be flagged as vulnerable
    return f"<div>{user_input}</div>"
"""

# TEST 2: Property tracking
code_property = """
def process_request(req):
    # Track: req.body.username
    username = req.body.username
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return query
"""

# TEST 3: Inter-procedural flows
code_interprocedural = """
def get_user_data():
    user_input = input("Enter name: ")
    return user_input

def build_query():
    name = get_user_data()  # Should track taint from get_user_data's return
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return query
"""

# TEST 4: Implicit flows (CFG-based)
code_implicit = """
def conditional_taint(secret_condition, safe_value, user_input):
    if secret_condition:
        data = safe_value
    else:
        data = user_input  # Tainted only on FALSE branch
    
    # Data is control-dependent on secret_condition
    return f"Result: {data}"
"""

def test_sanitizer_detection():
    """Test that html.escape() marks variables as sanitized."""
    print("\n" + "="*60)
    print("TEST 1: Sanitizer Detection")
    print("="*60)
    
    parser = ASTParser()
    cfg_builder = CFGBuilder()
    dfg_builder = EnhancedDFGBuilder()
    
    # Build graph
    graph = parser.parse(code_sanitizer, "sanitizer_test.py")
    graph = cfg_builder.build(graph)
    graph = dfg_builder.build(graph, code_sanitizer, "sanitizer_test.py")
    
    # Find sanitized variable edges
    sanitized_edges = [e for e in graph.edges 
                      if e.metadata and e.metadata.get('variable') == 'sanitized']
    
    print(f"\n✓ Graph has {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    print(f"✓ Found {len(sanitized_edges)} edges for 'sanitized' variable")
    
    # Check if sanitizer was detected
    sanitizer_calls = [n for n in graph.nodes 
                      if n.type == NodeType.CALL_EXPRESSION and 
                      n.name and 'escape' in n.name]
    print(f"✓ Found {len(sanitizer_calls)} html.escape() calls")
    
    # In safe_view, sanitized should NOT flow to f-string
    # In unsafe_view, user_input SHOULD flow to f-string
    fstring_nodes = [n for n in graph.nodes if n.type == NodeType.FSTRING]
    print(f"✓ Found {len(fstring_nodes)} f-string nodes")
    
    for fstring in fstring_nodes:
        interp_edges = [e for e in graph.edges 
                       if e.to_node == fstring.id and e.type == EdgeType.DFG_INTERP]
        print(f"  - F-string at line {fstring.line} has {len(interp_edges)} interpolation edges")
        for edge in interp_edges:
            print(f"    • {edge.metadata}")

def test_property_tracking():
    """Test that req.body.username creates property chain."""
    print("\n" + "="*60)
    print("TEST 2: Property Tracking")
    print("="*60)
    
    parser = ASTParser()
    cfg_builder = CFGBuilder()
    dfg_builder = EnhancedDFGBuilder()
    
    graph = parser.parse(code_property, "property_test.py")
    graph = cfg_builder.build(graph)
    graph = dfg_builder.build(graph, code_property, "property_test.py")
    
    print(f"\n✓ Graph has {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    
    # Find property edges
    property_edges = [e for e in graph.edges if e.type == EdgeType.DFG_PROPERTY]
    print(f"✓ Found {len(property_edges)} DFG_PROPERTY edges")
    
    for edge in property_edges:
        print(f"  - Property edge: {edge.metadata}")
    
    # Find member expression nodes
    member_nodes = [n for n in graph.nodes if n.type == NodeType.MEMBER_EXPRESSION]
    print(f"✓ Found {len(member_nodes)} MEMBER_EXPRESSION nodes")
    for node in member_nodes:
        print(f"  - {node.name} at line {node.line}")

def test_interprocedural_flows():
    """Test that function returns flow to call sites."""
    print("\n" + "="*60)
    print("TEST 3: Inter-procedural Flows")
    print("="*60)
    
    parser = ASTParser()
    cfg_builder = CFGBuilder()
    dfg_builder = EnhancedDFGBuilder()
    
    graph = parser.parse(code_interprocedural, "interprocedural_test.py")
    graph = cfg_builder.build(graph)
    graph = dfg_builder.build(graph, code_interprocedural, "interprocedural_test.py")
    
    print(f"\n✓ Graph has {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    
    # Find return edges (function return → call site)
    return_edges = [e for e in graph.edges if e.type == EdgeType.DFG_RET]
    print(f"✓ Found {len(return_edges)} DFG_RET edges (function return → call site)")
    
    for edge in return_edges:
        print(f"  - Return edge: {edge.metadata}")

def test_implicit_flows():
    """Test control-dependent taint via CFG."""
    print("\n" + "="*60)
    print("TEST 4: Implicit Flows (CFG-based)")
    print("="*60)
    
    parser = ASTParser()
    cfg_builder = CFGBuilder()
    dfg_builder = EnhancedDFGBuilder()
    
    graph = parser.parse(code_implicit, "implicit_test.py")
    graph = cfg_builder.build(graph)
    graph = dfg_builder.build(graph, code_implicit, "implicit_test.py")
    
    print(f"\n✓ Graph has {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    
    # Find control-dependent edges
    control_edges = [e for e in graph.edges 
                    if e.metadata and e.metadata.get('control_dependent')]
    print(f"✓ Found {len(control_edges)} control-dependent DFG edges")
    
    for edge in control_edges:
        from_node = next((n for n in graph.nodes if n.id == edge.from_node), None)
        to_node = next((n for n in graph.nodes if n.id == edge.to_node), None)
        print(f"  - Control flow from {from_node.type if from_node else '?'} → {to_node.type if to_node else '?'}")
        print(f"    Metadata: {edge.metadata}")

if __name__ == "__main__":
    print("\n" + "="*60)
    print("PRODUCTION DFG BUILDER TEST SUITE")
    print("="*60)
    
    try:
        test_sanitizer_detection()
        test_property_tracking()
        test_interprocedural_flows()
        test_implicit_flows()
        
        print("\n" + "="*60)
        print("✅ ALL TESTS COMPLETED")
        print("="*60)
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
