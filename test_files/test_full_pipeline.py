"""
FULL PIPELINE TEST - AST → CFG → DFG → Query Execution
Tests the complete vulnerability detection pipeline with production features:
- Property chain tracking
- Inter-procedural flows
- Sanitizer detection
- Implicit flows
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.domain.analysis.ast_parser import ASTParser
from app.domain.analysis.cfg_builder import CFGBuilder
from app.domain.analysis.dfg_builder_enhanced import EnhancedDFGBuilder
from semantic_engine.query_executor.executor import QueryExecutor
from semantic_engine.query_store.loader import QueryRule
from app.enums.edge_type import EdgeType
from app.enums.node_type import NodeType


# ================================================================
# TEST 1: SQL Injection with Property Chain
# ================================================================
code_sqli_property = """
def login(request):
    # Property chain: request.json.username
    username = request.json.username
    password = request.json.password
    
    # Vulnerable SQL query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone()
"""

# ================================================================
# TEST 2: XSS with Sanitizer (Should NOT detect)
# ================================================================
code_xss_sanitized = """
import html

def safe_render(request):
    user_input = request.args.get('name')
    
    # Sanitized - should NOT be flagged
    safe_name = html.escape(user_input)
    return f"<h1>Hello {safe_name}</h1>"
"""

# ================================================================
# TEST 3: XSS without Sanitizer (Should detect)
# ================================================================
code_xss_vulnerable = """
def unsafe_render(request):
    user_input = request.args.get('name')
    
    # NOT sanitized - should be flagged
    return f"<h1>Hello {user_input}</h1>"
"""

# ================================================================
# TEST 4: RCE with Inter-procedural Flow
# ================================================================
code_rce_interprocedural = """
def get_user_command():
    # Source: user input
    cmd = input("Enter command: ")
    return cmd

def execute_command():
    # Taint flows via function return
    command = get_user_command()
    
    # Sink: eval (RCE)
    eval(command)
"""

# ================================================================
# TEST 5: Path Traversal with String Concatenation
# ================================================================
code_path_traversal = """
import os

def read_file(request):
    filename = request.args.get('file')
    
    # Vulnerable: no sanitization
    filepath = "/var/www/uploads/" + filename
    
    with open(filepath, 'r') as f:
        return f.read()
"""


def create_test_query(
    rule_id: str,
    name: str,
    sources: list,
    sinks: list,
    sanitizers: list = None
) -> QueryRule:
    """Create a test query rule."""
    return QueryRule(
        rule_id=rule_id,
        name=name,
        owasp="A03",
        cwe="CWE-89",
        description=f"Test {name}",
        severity="high",
        sources=sources,
        sinks=sinks,
        patterns=["DFG_FLOW"],  # CRITICAL: Specify pattern type
        sanitizers=sanitizers or [],
        confidence="high"
    )


def test_sqli_with_property_chain():
    """Test SQL injection detection with property chain (request.json.username)."""
    print("\n" + "="*70)
    print("TEST 1: SQL Injection with Property Chain")
    print("="*70)
    
    # Build graph pipeline
    parser = ASTParser()
    cfg_builder = CFGBuilder()
    dfg_builder = EnhancedDFGBuilder()
    executor = QueryExecutor()
    
    graph = parser.parse(code_sqli_property, "sqli_test.py")
    graph = cfg_builder.build(graph)
    graph = dfg_builder.build(graph, code_sqli_property, "sqli_test.py")
    
    print(f"✓ Graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    
    # Check for property nodes
    property_nodes = [n for n in graph.nodes if n.type == NodeType.MEMBER_EXPRESSION]
    print(f"✓ Found {len(property_nodes)} MEMBER_EXPRESSION nodes:")
    for node in property_nodes:
        print(f"  - {node.name} at line {node.line}")
    
    # Check for property edges
    property_edges = [e for e in graph.edges if e.type == EdgeType.DFG_PROPERTY]
    print(f"✓ Found {len(property_edges)} DFG_PROPERTY edges")
    
    # Execute SQLi query
    query = create_test_query(
        rule_id="SQL_INJECTION_TEST",
        name="SQL Injection",
        sources=["request.json", "request.args", "request.form"],
        sinks=["execute", "cursor.execute", "executemany"]
    )
    
    results = executor.execute_query(graph, query, code_sqli_property)
    
    if results:
        print(f"\n✅ DETECTED: {len(results)} SQL injection vulnerability(ies)")
        for result in results:
            print(f"  - Source: {result.source_label}")
            print(f"  - Sink: {result.sink_label}")
            print(f"  - Path length: {len(result.path_nodes)}")
    else:
        print("\n❌ FAILED: Expected to detect SQL injection")
    
    return len(results) > 0


def test_xss_with_sanitizer():
    """Test XSS detection with html.escape() - should NOT detect."""
    print("\n" + "="*70)
    print("TEST 2: XSS with Sanitizer (Should NOT Detect)")
    print("="*70)
    
    parser = ASTParser()
    cfg_builder = CFGBuilder()
    dfg_builder = EnhancedDFGBuilder()
    executor = QueryExecutor()
    
    graph = parser.parse(code_xss_sanitized, "xss_safe_test.py")
    graph = cfg_builder.build(graph)
    graph = dfg_builder.build(graph, code_xss_sanitized, "xss_safe_test.py")
    
    print(f"✓ Graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    
    # Check for sanitizer calls
    sanitizer_calls = [n for n in graph.nodes 
                      if n.type == NodeType.CALL_EXPRESSION and 
                      n.name and 'escape' in n.name]
    print(f"✓ Found {len(sanitizer_calls)} sanitizer call(s): {[n.name for n in sanitizer_calls]}")
    
    # Execute XSS query
    query = create_test_query(
        rule_id="XSS_TEST",
        name="Cross-Site Scripting",
        sources=["request.args", "request.form", "request.json"],
        sinks=["render_template_string", "return"],
        sanitizers=["html.escape", "escape", "markupsafe.escape"]
    )
    
    results = executor.execute_query(graph, query, code_xss_sanitized)
    
    if results:
        print(f"\n❌ FAILED: Should NOT detect (sanitized)")
        print(f"  Detected {len(results)} false positive(s)")
    else:
        print(f"\n✅ PASSED: Correctly ignored sanitized code")
    
    return len(results) == 0


def test_xss_without_sanitizer():
    """Test XSS detection without sanitizer - should detect."""
    print("\n" + "="*70)
    print("TEST 3: XSS without Sanitizer (Should Detect)")
    print("="*70)
    
    parser = ASTParser()
    cfg_builder = CFGBuilder()
    dfg_builder = EnhancedDFGBuilder()
    executor = QueryExecutor()
    
    graph = parser.parse(code_xss_vulnerable, "xss_vuln_test.py")
    graph = cfg_builder.build(graph)
    graph = dfg_builder.build(graph, code_xss_vulnerable, "xss_vuln_test.py")
    
    print(f"✓ Graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    
    # Execute XSS query
    query = create_test_query(
        rule_id="XSS_TEST",
        name="Cross-Site Scripting",
        sources=["request.args", "request.args.get", "request.form", "request.json"],
        sinks=["return"],
        sanitizers=["html.escape"]
    )
    
    results = executor.execute_query(graph, query, code_xss_vulnerable)
    
    if results:
        print(f"\n✅ DETECTED: {len(results)} XSS vulnerability(ies)")
        for result in results:
            print(f"  - Source: {result.source_label}")
            print(f"  - Sink: {result.sink_label}")
    else:
        print(f"\n❌ FAILED: Expected to detect XSS")
    
    return len(results) > 0


def test_rce_interprocedural():
    """Test RCE detection with inter-procedural flow."""
    print("\n" + "="*70)
    print("TEST 4: RCE with Inter-procedural Flow")
    print("="*70)
    
    parser = ASTParser()
    cfg_builder = CFGBuilder()
    dfg_builder = EnhancedDFGBuilder()
    executor = QueryExecutor()
    
    graph = parser.parse(code_rce_interprocedural, "rce_test.py")
    graph = cfg_builder.build(graph)
    graph = dfg_builder.build(graph, code_rce_interprocedural, "rce_test.py")
    
    print(f"✓ Graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    
    # Check for DFG_RET edges
    ret_edges = [e for e in graph.edges if e.type == EdgeType.DFG_RET]
    print(f"✓ Found {len(ret_edges)} DFG_RET edge(s) (inter-procedural)")
    
    # Execute RCE query
    query = create_test_query(
        rule_id="RCE_TEST",
        name="Remote Code Execution",
        sources=["input", "sys.argv", "os.environ", "PARAMETER"],
        sinks=["eval", "exec", "compile", "__import__"]
    )
    
    results = executor.execute_query(graph, query, code_rce_interprocedural)
    
    if results:
        print(f"\n✅ DETECTED: {len(results)} RCE vulnerability(ies)")
        for result in results:
            print(f"  - Source: {result.source_label}")
            print(f"  - Sink: {result.sink_label}")
            print(f"  - Path length: {len(result.path_nodes)} (crosses function boundary)")
    else:
        print(f"\n❌ FAILED: Expected to detect RCE")
    
    return len(results) > 0


def test_path_traversal():
    """Test path traversal detection."""
    print("\n" + "="*70)
    print("TEST 5: Path Traversal")
    print("="*70)
    
    parser = ASTParser()
    cfg_builder = CFGBuilder()
    dfg_builder = EnhancedDFGBuilder()
    executor = QueryExecutor()
    
    graph = parser.parse(code_path_traversal, "path_test.py")
    graph = cfg_builder.build(graph)
    graph = dfg_builder.build(graph, code_path_traversal, "path_test.py")
    
    print(f"✓ Graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    
    # Check for string concat nodes
    concat_nodes = [n for n in graph.nodes if n.type == NodeType.STRING_CONCAT]
    print(f"✓ Found {len(concat_nodes)} STRING_CONCAT node(s)")
    
    # Execute path traversal query
    query = create_test_query(
        rule_id="PATH_TRAVERSAL_TEST",
        name="Path Traversal",
        sources=["request.args", "request.args.get", "request.form", "request.json"],
        sinks=["open", "file", "read", "write"]
    )
    
    results = executor.execute_query(graph, query, code_path_traversal)
    
    if results:
        print(f"\n✅ DETECTED: {len(results)} path traversal vulnerability(ies)")
        for result in results:
            print(f"  - Source: {result.source_label}")
            print(f"  - Sink: {result.sink_label}")
    else:
        print(f"\n❌ FAILED: Expected to detect path traversal")
    
    return len(results) > 0


if __name__ == "__main__":
    print("\n" + "="*70)
    print("FULL PIPELINE TEST SUITE")
    print("AST → CFG → DFG → Query Execution")
    print("="*70)
    
    results = {
        "SQL Injection (Property Chain)": False,
        "XSS with Sanitizer (No Detection)": False,
        "XSS without Sanitizer (Detection)": False,
        "RCE (Inter-procedural)": False,
        "Path Traversal": False
    }
    
    try:
        results["SQL Injection (Property Chain)"] = test_sqli_with_property_chain()
        results["XSS with Sanitizer (No Detection)"] = test_xss_with_sanitizer()
        results["XSS without Sanitizer (Detection)"] = test_xss_without_sanitizer()
        results["RCE (Inter-procedural)"] = test_rce_interprocedural()
        results["Path Traversal"] = test_path_traversal()
        
        # Summary
        print("\n" + "="*70)
        print("TEST SUMMARY")
        print("="*70)
        
        passed = sum(results.values())
        total = len(results)
        
        for test_name, result in results.items():
            status = "✅ PASSED" if result else "❌ FAILED"
            print(f"{status}: {test_name}")
        
        print(f"\nOverall: {passed}/{total} tests passed")
        
        if passed == total:
            print("\n🎉 ALL TESTS PASSED - PIPELINE WORKING!")
        else:
            print(f"\n⚠️ {total - passed} test(s) failed")
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
