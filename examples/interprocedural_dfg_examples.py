"""
Interprocedural DFG Examples and Tests
======================================

Demonstrates interprocedural data flow tracking for:
1. Parameter-to-argument propagation
2. Return value flows
3. JavaScript closures
4. JavaScript callbacks
5. Python tuple unpacking
6. Multi-function paths
7. Uncertainty handling
"""

import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.domain.analysis.cpg_parser import CPGParser
from app.domain.analysis.interprocedural_dfg import (
    InterproceduralDFG,
    DFGEdgeType,
    UncertaintyLevel
)


# ==============================================
# Test Case 1: Simple Function Call (Python)
# ==============================================

PYTHON_SIMPLE_CALL = """
def sanitize_input(user_input):
    cleaned = user_input.strip().lower()
    return cleaned

def process_user_data(data):
    safe_data = sanitize_input(data)
    query = f"SELECT * FROM users WHERE name = '{safe_data}'"
    return query

result = process_user_data(request.args['username'])
"""

# ==============================================
# Test Case 2: JavaScript Closure
# ==============================================

JS_CLOSURE = """
function createCounter(initialValue) {
    let count = initialValue;
    
    return function increment() {
        count = count + 1;  // 'count' captured from outer scope
        return count;
    };
}

const counter = createCounter(10);
const value = counter();  // value = 11
"""

# ==============================================
# Test Case 3: JavaScript Callback
# ==============================================

JS_CALLBACK = """
function processData(data, callback) {
    const result = data.map(x => x * 2);
    callback(result);  // Pass result to callback
}

function handleResult(output) {
    console.log(output);  // output receives result
}

processData([1, 2, 3], handleResult);

// Also test inline callback
processData([4, 5, 6], function(res) {
    document.body.innerHTML = res;  // Potential XSS if res is tainted
});
"""

# ==============================================
# Test Case 4: Python Tuple Unpacking
# ==============================================

PYTHON_TUPLE_UNPACK = """
def get_user_info(user_id):
    name = fetch_name(user_id)
    age = fetch_age(user_id)
    email = fetch_email(user_id)
    return name, age, email  # Multiple returns

def process_user(uid):
    user_name, user_age, user_email = get_user_info(uid)  # Tuple unpacking
    
    # Track each value separately
    print(f"Name: {user_name}")
    print(f"Age: {user_age}")
    send_email(user_email)
"""

# ==============================================
# Test Case 5: Multi-Function Path
# ==============================================

PYTHON_MULTI_PATH = """
def level1(x):
    return x + 10

def level2(y):
    z = level1(y)
    return z * 2

def level3(a):
    b = level2(a)
    return b - 5

# Track data flow: tainted_input -> level3 -> level2 -> level1 -> dangerous_sink
tainted_input = request.GET['param']
intermediate = level3(tainted_input)
execute(intermediate)  # SQL injection if tainted
"""

# ==============================================
# Test Case 6: Uncertainty - Dynamic Call
# ==============================================

JS_UNCERTAIN = """
function dynamicCall(obj, methodName, arg) {
    // Dynamic property access - uncertain which method is called
    return obj[methodName](arg);
}

const result = dynamicCall(userObject, computedKey, taintedData);
dangerousFunction(result);  // Uncertain flow
"""

# ==============================================
# Test Case 7: Complex Interprocedural (Real-world)
# ==============================================

COMPLEX_INTERPROCEDURAL = """
# Simulates a vulnerable web application

def authenticate(username, password):
    # Tainted inputs
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = db.execute(query)  # SQL Injection sink
    return result

def authorize(user_id):
    permissions = get_permissions(user_id)
    return permissions

def get_permissions(uid):
    query = f"SELECT * FROM permissions WHERE user_id={uid}"  # Another SQLi
    return db.execute(query)

def handle_request(request):
    username = request.form['user']    # Tainted source
    password = request.form['pass']    # Tainted source
    
    auth_result = authenticate(username, password)  # Flow to authenticate
    
    if auth_result:
        user_id = request.form['id']   # Tainted source
        perms = authorize(user_id)     # Flow to authorize -> get_permissions
        
        return render_template('dashboard.html', permissions=perms)
"""


def test_python_simple_call():
    """Test 1: Simple function call with argument passing"""
    print("\n" + "="*60)
    print("TEST 1: Python Simple Function Call")
    print("="*60)
    
    parser = CPGParser()
    cpg = parser.parse_code(PYTHON_SIMPLE_CALL, "python", "test.py")
    
    print(f"✓ Parsed CPG: {len(cpg.nodes)} nodes, {len(cpg.edges)} edges")
    
    # Build interprocedural DFG
    dfg_builder = InterproceduralDFG(cpg)
    enhanced_cpg = dfg_builder.build()
    
    stats = dfg_builder.get_statistics()
    print(f"\n📊 DFG Statistics:")
    print(f"  Functions: {stats['total_functions']}")
    print(f"  Call sites: {stats['total_call_sites']}")
    print(f"  DFG edges: {stats['total_dfg_edges']}")
    print(f"  Edge types: {stats['edge_types']}")
    
    # Find argument passing edges
    arg_pass_edges = [e for e in dfg_builder.dfg_edges 
                      if e.edge_type == DFGEdgeType.DFG_ARG_PASS.value]
    
    print(f"\n🔗 Argument Passing Edges: {len(arg_pass_edges)}")
    for edge in arg_pass_edges:
        print(f"  {edge.source} → {edge.target}")
        if edge.metadata:
            print(f"    Context: {edge.metadata.get('context', 'N/A')}")
            print(f"    Arg position: {edge.metadata.get('arg_position', 'N/A')}")
    
    # Find return edges
    ret_edges = [e for e in dfg_builder.dfg_edges 
                 if e.edge_type == DFGEdgeType.DFG_RET.value]
    
    print(f"\n↩️  Return Value Edges: {len(ret_edges)}")
    for edge in ret_edges:
        print(f"  {edge.source} → {edge.target}")
        if edge.metadata:
            print(f"    Context: {edge.metadata.get('context', 'N/A')}")
    
    return enhanced_cpg


def test_js_closure():
    """Test 2: JavaScript closure variable capture"""
    print("\n" + "="*60)
    print("TEST 2: JavaScript Closure")
    print("="*60)
    
    parser = CPGParser()
    cpg = parser.parse_code(JS_CLOSURE, "javascript", "closure.js")
    
    print(f"✓ Parsed CPG: {len(cpg.nodes)} nodes, {len(cpg.edges)} edges")
    
    dfg_builder = InterproceduralDFG(cpg)
    enhanced_cpg = dfg_builder.build()
    
    stats = dfg_builder.get_statistics()
    print(f"\n📊 DFG Statistics:")
    print(f"  Closure captures: {stats.get('closure_captures', 0)}")
    
    # Find closure edges
    closure_edges = [e for e in dfg_builder.dfg_edges 
                     if e.edge_type == DFGEdgeType.DFG_CLOSURE.value]
    
    print(f"\n🔒 Closure Capture Edges: {len(closure_edges)}")
    for edge in closure_edges:
        print(f"  {edge.source} → {edge.target}")
        if edge.metadata:
            print(f"    Variable: {edge.metadata.get('context', 'N/A')}")
            print(f"    Scope: {edge.metadata.get('closure_scope', 'N/A')}")
    
    return enhanced_cpg


def test_js_callback():
    """Test 3: JavaScript callback data flow"""
    print("\n" + "="*60)
    print("TEST 3: JavaScript Callback")
    print("="*60)
    
    parser = CPGParser()
    cpg = parser.parse_code(JS_CALLBACK, "javascript", "callback.js")
    
    print(f"✓ Parsed CPG: {len(cpg.nodes)} nodes, {len(cpg.edges)} edges")
    
    dfg_builder = InterproceduralDFG(cpg)
    enhanced_cpg = dfg_builder.build()
    
    stats = dfg_builder.get_statistics()
    print(f"\n📊 DFG Statistics:")
    print(f"  Call sites: {stats['total_call_sites']}")
    
    # Find callback edges
    callback_edges = [e for e in dfg_builder.dfg_edges 
                      if e.edge_type == DFGEdgeType.DFG_CALLBACK.value]
    
    print(f"\n📞 Callback Edges: {len(callback_edges)}")
    for edge in callback_edges:
        print(f"  {edge.source} → {edge.target}")
        if edge.metadata:
            print(f"    Context: {edge.metadata.get('context', 'N/A')}")
            print(f"    Uncertainty: {edge.metadata.get('uncertainty', 'N/A')}")
            print(f"    Confidence: {edge.metadata.get('confidence', 1.0)}")
    
    return enhanced_cpg


def test_python_tuple_unpack():
    """Test 4: Python tuple unpacking"""
    print("\n" + "="*60)
    print("TEST 4: Python Tuple Unpacking")
    print("="*60)
    
    parser = CPGParser()
    cpg = parser.parse_code(PYTHON_TUPLE_UNPACK, "python", "tuple.py")
    
    print(f"✓ Parsed CPG: {len(cpg.nodes)} nodes, {len(cpg.edges)} edges")
    
    dfg_builder = InterproceduralDFG(cpg)
    enhanced_cpg = dfg_builder.build()
    
    # Find tuple unpacking edges
    unpack_edges = [e for e in dfg_builder.dfg_edges 
                    if e.edge_type == DFGEdgeType.DFG_TUPLE_UNPACK.value]
    
    print(f"\n📦 Tuple Unpacking Edges: {len(unpack_edges)}")
    for edge in unpack_edges:
        print(f"  {edge.source} → {edge.target}")
        if edge.metadata:
            print(f"    Position: {edge.metadata.get('return_index', 'N/A')}")
            print(f"    Context: {edge.metadata.get('context', 'N/A')}")
    
    return enhanced_cpg


def test_multi_function_path():
    """Test 5: Multi-function interprocedural path"""
    print("\n" + "="*60)
    print("TEST 5: Multi-Function Path")
    print("="*60)
    
    parser = CPGParser()
    cpg = parser.parse_code(PYTHON_MULTI_PATH, "python", "multipath.py")
    
    print(f"✓ Parsed CPG: {len(cpg.nodes)} nodes, {len(cpg.edges)} edges")
    
    dfg_builder = InterproceduralDFG(cpg)
    enhanced_cpg = dfg_builder.build()
    
    stats = dfg_builder.get_statistics()
    print(f"\n📊 DFG Statistics:")
    print(f"  Functions: {stats['total_functions']}")
    print(f"  Call sites: {stats['total_call_sites']}")
    print(f"  DFG edges: {stats['total_dfg_edges']}")
    
    # Find source and sink nodes
    source_node = None
    sink_node = None
    
    for node in cpg.nodes:
        if node.code and "request.GET" in node.code:
            source_node = node.id
        if node.code and "execute(" in node.code:
            sink_node = node.id
    
    if source_node and sink_node:
        print(f"\n🔍 Extracting paths from source to sink...")
        paths = dfg_builder.extract_interprocedural_paths(source_node, sink_node)
        
        print(f"\n📍 Found {len(paths)} interprocedural paths:")
        for i, path in enumerate(paths, 1):
            print(f"\n  Path {i}:")
            print(f"    Uncertainty: {path.uncertainty.value}")
            print(f"    Confidence: {path.confidence:.2f}")
            print(f"    Steps: {len(path.path_edges)}")
            print(f"    Description: {path.description}")
    else:
        print("\n⚠️  Could not find source/sink nodes for path extraction")
    
    return enhanced_cpg


def test_uncertainty():
    """Test 6: Uncertainty tracking"""
    print("\n" + "="*60)
    print("TEST 6: Uncertainty Tracking")
    print("="*60)
    
    parser = CPGParser()
    cpg = parser.parse_code(JS_UNCERTAIN, "javascript", "uncertain.js")
    
    print(f"✓ Parsed CPG: {len(cpg.nodes)} nodes, {len(cpg.edges)} edges")
    
    dfg_builder = InterproceduralDFG(cpg)
    enhanced_cpg = dfg_builder.build()
    
    stats = dfg_builder.get_statistics()
    print(f"\n📊 DFG Statistics:")
    print(f"  Total DFG edges: {stats['total_dfg_edges']}")
    print(f"  Uncertain edges: {stats['uncertain_edges']}")
    
    # Find uncertain edges
    uncertain_edges = [e for e in dfg_builder.dfg_edges 
                       if e.edge_type == DFGEdgeType.DFG_UNCERTAIN.value]
    
    print(f"\n❓ Uncertain Flow Edges: {len(uncertain_edges)}")
    for edge in uncertain_edges:
        print(f"  {edge.source} → {edge.target}")
        if edge.metadata:
            print(f"    Reason: {edge.metadata.get('context', 'N/A')}")
            print(f"    Uncertainty: {edge.metadata.get('uncertainty', 'N/A')}")
            print(f"    Confidence: {edge.metadata.get('confidence', 0.0)}")
    
    return enhanced_cpg


def test_complex_interprocedural():
    """Test 7: Complex real-world interprocedural flow"""
    print("\n" + "="*60)
    print("TEST 7: Complex Interprocedural Flow (Real-world)")
    print("="*60)
    
    parser = CPGParser()
    cpg = parser.parse_code(COMPLEX_INTERPROCEDURAL, "python", "webapp.py")
    
    print(f"✓ Parsed CPG: {len(cpg.nodes)} nodes, {len(cpg.edges)} edges")
    
    dfg_builder = InterproceduralDFG(cpg)
    enhanced_cpg = dfg_builder.build()
    
    stats = dfg_builder.get_statistics()
    print(f"\n📊 DFG Statistics:")
    print(f"  Functions: {stats['total_functions']}")
    print(f"  Call sites: {stats['total_call_sites']}")
    print(f"  DFG edges: {stats['total_dfg_edges']}")
    print(f"\n  Edge Type Breakdown:")
    for edge_type, count in stats['edge_types'].items():
        print(f"    {edge_type}: {count}")
    
    # Visualize function call graph
    print(f"\n🔗 Function Call Graph:")
    for call_site in dfg_builder.call_sites:
        print(f"  {call_site.caller_function} → {call_site.callee_name}")
        print(f"    Line: {call_site.line_number}")
        print(f"    Arguments: {len(call_site.arguments)}")
    
    # Export enhanced CPG
    output_file = "cpg_interprocedural_complex.json"
    with open(output_file, 'w') as f:
        json.dump(enhanced_cpg.model_dump(), f, indent=2)
    
    print(f"\n💾 Exported enhanced CPG to: {output_file}")
    print(f"   Size: {Path(output_file).stat().st_size:,} bytes")
    
    return enhanced_cpg


def demonstrate_dfg_schema():
    """Demonstrate DFG node/edge schema"""
    print("\n" + "="*60)
    print("DFG SCHEMA DOCUMENTATION")
    print("="*60)
    
    print("\n📋 DFG Edge Types:")
    for edge_type in DFGEdgeType:
        print(f"  • {edge_type.value}")
    
    print("\n📊 Uncertainty Levels:")
    for level in UncertaintyLevel:
        print(f"  • {level.value}")
    
    print("\n📝 DFG Edge Metadata Schema:")
    print("""
  {
    "edge_type": "DFG_ARG_PASS | DFG_RET | DFG_CLOSURE | ...",
    "uncertainty": "certain | likely | possible | unknown",
    "context": "Human-readable description",
    "arg_position": 0,           // For argument passing
    "return_index": 0,            // For tuple unpacking
    "closure_scope": "func_id",   // For closure captures
    "confidence": 0.0 - 1.0       // Confidence score
  }
    """)
    
    print("\n💡 Uncertainty Representation:")
    print("""
  The DFG represents uncertainty in several ways:
  
  1. EDGE TYPE:
     - DFG_UNCERTAIN: Explicitly uncertain flow
     - DFG_CALLBACK: Likely but not guaranteed (callbacks)
     
  2. UNCERTAINTY LEVEL:
     - CERTAIN: Definite flow (x = y)
     - LIKELY: Probable flow (known callback patterns)
     - POSSIBLE: Possible flow (dynamic property access)
     - UNKNOWN: Unknown flow (eval, dynamic imports)
     
  3. CONFIDENCE SCORE:
     - 1.0: Completely certain
     - 0.8: High confidence (e.g., callbacks)
     - 0.5: Medium confidence
     - 0.3: Low confidence (dynamic operations)
     - 0.0: No confidence (unknown functions)
     
  4. CONTEXT:
     - Provides explanation of why flow is uncertain
     - Examples: "Dynamic property access", "Unknown function"
    """)


def run_all_tests():
    """Run all interprocedural DFG tests"""
    print("\n" + "="*70)
    print(" INTERPROCEDURAL DFG - COMPREHENSIVE TEST SUITE")
    print("="*70)
    
    tests = [
        ("Python Simple Call", test_python_simple_call),
        ("JavaScript Closure", test_js_closure),
        ("JavaScript Callback", test_js_callback),
        ("Python Tuple Unpack", test_python_tuple_unpack),
        ("Multi-Function Path", test_multi_function_path),
        ("Uncertainty Tracking", test_uncertainty),
        ("Complex Interprocedural", test_complex_interprocedural),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            enhanced_cpg = test_func()
            results.append((test_name, "✅ PASSED", len(enhanced_cpg.edges)))
        except Exception as e:
            results.append((test_name, f"❌ FAILED: {str(e)}", 0))
            print(f"\n⚠️  Error in {test_name}: {e}")
    
    # Demonstrate schema
    demonstrate_dfg_schema()
    
    # Summary
    print("\n" + "="*70)
    print(" TEST SUMMARY")
    print("="*70)
    
    for name, status, edge_count in results:
        print(f"{status} {name:30s} ({edge_count} edges)" if edge_count else f"{status} {name}")
    
    passed = sum(1 for _, status, _ in results if "PASSED" in status)
    total = len(results)
    
    print(f"\n✓ {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! Interprocedural DFG is working correctly.")
    else:
        print("\n⚠️  Some tests failed. Review output above for details.")


if __name__ == "__main__":
    run_all_tests()
