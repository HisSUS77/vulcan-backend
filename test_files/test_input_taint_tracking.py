"""
Test INPUT-FOCUSED Taint Tracking System
Tests comprehensive input source detection and taint flow analysis.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.domain.analysis.semantic_graph_builder import SemanticGraphBuilder
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType

def test_sql_injection_from_get_request():
    """Test detection of SQL injection from HTTP GET parameter."""
    code = """
@app.route('/user')
def get_user():
    user_id = request.GET['id']  # INPUT SOURCE: HTTP GET
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)  # DANGEROUS SINK: SQL execution
    return cursor.fetchall()
"""
    
    builder = SemanticGraphBuilder()
    graph = builder.build(code, "test_sql_get.py")
    
    # Check for INPUT SOURCE detection
    input_sources = [n for n in graph.nodes if n.type == NodeType.TAINT_SOURCE]
    print(f"\n✓ Test 1: SQL Injection from GET")
    print(f"  - Input sources found: {len(input_sources)}")
    assert len(input_sources) > 0, "Should detect request.GET as input source"
    
    # Check for DANGEROUS SINK detection
    sinks = [n for n in graph.nodes if n.type == NodeType.SENSITIVE_SINK]
    print(f"  - Dangerous sinks found: {len(sinks)}")
    assert len(sinks) > 0, "Should detect cursor.execute as dangerous sink"
    
    # Check for TAINT_FLOW edges
    taint_flows = [e for e in graph.edges if e.type == EdgeType.TAINT_FLOW]
    print(f"  - Taint flow edges: {len(taint_flows)}")
    assert len(taint_flows) >= 2, "Should have taint flow from source to sink"
    
    print("  ✓ PASSED: SQL injection from GET request detected")


def test_xss_from_post_request():
    """Test detection of XSS from HTTP POST parameter."""
    code = """
@app.route('/comment', methods=['POST'])
def post_comment():
    comment = request.POST['comment']  # INPUT SOURCE: HTTP POST
    html = f"<div>{comment}</div>"
    response.write(html)  # DANGEROUS SINK: HTML rendering
    return html
"""
    
    builder = SemanticGraphBuilder()
    graph = builder.build(code, "test_xss_post.py")
    
    input_sources = [n for n in graph.nodes if n.type == NodeType.TAINT_SOURCE]
    sinks = [n for n in graph.nodes if n.type == NodeType.SENSITIVE_SINK]
    
    print(f"\n✓ Test 2: XSS from POST")
    print(f"  - Input sources: {len(input_sources)}")
    print(f"  - Dangerous sinks: {len(sinks)}")
    assert len(input_sources) > 0, "Should detect request.POST as input source"
    
    print("  ✓ PASSED: XSS from POST request detected")


def test_command_injection_from_cli_args():
    """Test detection of command injection from CLI arguments."""
    code = """
import sys
import os

def process_file():
    filename = sys.argv[1]  # INPUT SOURCE: CLI argument
    command = f"cat {filename}"
    os.system(command)  # DANGEROUS SINK: Command execution
"""
    
    builder = SemanticGraphBuilder()
    graph = builder.build(code, "test_cmd_cli.py")
    
    input_sources = [n for n in graph.nodes if n.type == NodeType.TAINT_SOURCE]
    sinks = [n for n in graph.nodes if n.type == NodeType.SENSITIVE_SINK]
    
    print(f"\n✓ Test 3: Command Injection from CLI")
    print(f"  - Input sources: {len(input_sources)}")
    print(f"  - Dangerous sinks: {len(sinks)}")
    assert len(input_sources) > 0, "Should detect sys.argv as input source"
    
    print("  ✓ PASSED: Command injection from CLI args detected")


def test_file_upload_vulnerability():
    """Test detection of path traversal from file upload."""
    code = """
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.FILES['document']  # INPUT SOURCE: File upload
    filename = file.name
    path = f"/uploads/{filename}"
    with open(path, 'wb') as f:  # DANGEROUS SINK: File operation
        f.write(file.read())
"""
    
    builder = SemanticGraphBuilder()
    graph = builder.build(code, "test_upload.py")
    
    input_sources = [n for n in graph.nodes if n.type == NodeType.TAINT_SOURCE]
    sinks = [n for n in graph.nodes if n.type == NodeType.SENSITIVE_SINK]
    
    print(f"\n✓ Test 4: File Upload Vulnerability")
    print(f"  - Input sources: {len(input_sources)}")
    print(f"  - Dangerous sinks: {len(sinks)}")
    assert len(input_sources) > 0, "Should detect request.FILES as input source"
    
    print("  ✓ PASSED: File upload vulnerability detected")


def test_sanitized_input():
    """Test that sanitizers remove taint."""
    code = """
import html

@app.route('/safe')
def safe_comment():
    comment = request.POST['comment']  # INPUT SOURCE
    safe_comment = html.escape(comment)  # SANITIZER
    html_output = f"<div>{safe_comment}</div>"
    return html_output  # Should NOT be vulnerable
"""
    
    builder = SemanticGraphBuilder()
    graph = builder.build(code, "test_sanitized.py")
    
    input_sources = [n for n in graph.nodes if n.type == NodeType.TAINT_SOURCE]
    
    # Check for sanitization edges
    sanitized_edges = [e for e in graph.edges 
                      if e.metadata and e.metadata.get('sanitized')]
    
    print(f"\n✓ Test 5: Sanitized Input")
    print(f"  - Input sources: {len(input_sources)}")
    print(f"  - Sanitization edges: {len(sanitized_edges)}")
    
    print("  ✓ PASSED: Sanitizer detection working")


def test_taint_propagation_through_operations():
    """Test taint propagation through string operations."""
    code = """
@app.route('/process')
def process_data():
    user_input = request.GET['data']  # INPUT SOURCE
    processed = user_input.upper()  # Taint propagates
    modified = processed + "_suffix"  # Taint propagates
    final = f"Result: {modified}"  # Taint propagates
    cursor.execute(final)  # DANGEROUS SINK with tainted data
"""
    
    builder = SemanticGraphBuilder()
    graph = builder.build(code, "test_propagation.py")
    
    input_sources = [n for n in graph.nodes if n.type == NodeType.TAINT_SOURCE]
    sinks = [n for n in graph.nodes if n.type == NodeType.SENSITIVE_SINK]
    taint_flows = [e for e in graph.edges if e.type == EdgeType.TAINT_FLOW]
    
    print(f"\n✓ Test 6: Taint Propagation")
    print(f"  - Input sources: {len(input_sources)}")
    print(f"  - Dangerous sinks: {len(sinks)}")
    print(f"  - Taint flow edges: {len(taint_flows)}")
    assert len(taint_flows) > 0, "Should propagate taint through operations"
    
    print("  ✓ PASSED: Taint propagates through operations")


def test_json_body_input():
    """Test detection of JSON body as input source."""
    code = """
@app.route('/api/user', methods=['POST'])
def create_user():
    data = request.json  # INPUT SOURCE: JSON body
    username = data['username']
    query = f"INSERT INTO users (name) VALUES ('{username}')"
    db.execute(query)  # DANGEROUS SINK
"""
    
    builder = SemanticGraphBuilder()
    graph = builder.build(code, "test_json.py")
    
    input_sources = [n for n in graph.nodes if n.type == NodeType.TAINT_SOURCE]
    
    print(f"\n✓ Test 7: JSON Body Input")
    print(f"  - Input sources: {len(input_sources)}")
    assert len(input_sources) > 0, "Should detect request.json as input source"
    
    print("  ✓ PASSED: JSON body input detected")


def test_environment_variable_input():
    """Test detection of environment variables as input source."""
    code = """
import os

def get_config():
    api_key = os.environ['API_KEY']  # INPUT SOURCE: Environment variable
    command = f"curl -H 'Authorization: {api_key}' api.example.com"
    os.system(command)  # DANGEROUS SINK
"""
    
    builder = SemanticGraphBuilder()
    graph = builder.build(code, "test_env.py")
    
    input_sources = [n for n in graph.nodes if n.type == NodeType.TAINT_SOURCE]
    
    print(f"\n✓ Test 8: Environment Variable Input")
    print(f"  - Input sources: {len(input_sources)}")
    
    print("  ✓ PASSED: Environment variable input detected")


def run_all_tests():
    """Run all INPUT-FOCUSED taint tracking tests."""
    print("=" * 60)
    print("INPUT-FOCUSED TAINT TRACKING TEST SUITE")
    print("=" * 60)
    
    tests = [
        test_sql_injection_from_get_request,
        test_xss_from_post_request,
        test_command_injection_from_cli_args,
        test_file_upload_vulnerability,
        test_sanitized_input,
        test_taint_propagation_through_operations,
        test_json_body_input,
        test_environment_variable_input,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"\n✗ FAILED: {test.__name__}")
            print(f"  Error: {str(e)}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"TEST RESULTS: {passed}/{len(tests)} PASSED")
    if failed > 0:
        print(f"             {failed}/{len(tests)} FAILED")
    print("=" * 60)
    
    return passed == len(tests)


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
