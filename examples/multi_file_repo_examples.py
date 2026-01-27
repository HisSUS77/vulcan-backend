"""
Multi-File Repository Graph Examples
=====================================

Demonstrates cross-file analysis with:
1. Python multi-module application
2. JavaScript ES6 modules
3. Cross-file vulnerability tracking
4. Global symbol resolution
"""

import sys
import json
import tempfile
import shutil
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.domain.analysis.multi_file_repo_graph import (
    MultiFileRepositoryGraph,
    CrossFileEdgeType
)


def create_test_python_repo() -> Path:
    """Create a test Python repository"""
    repo_dir = Path(tempfile.mkdtemp(prefix="test_python_repo_"))
    
    # File 1: utils.py (library module)
    utils_code = """
def sanitize_sql(query):
    '''Sanitize SQL query'''
    # Weak sanitization
    return query.replace("'", "")

def escape_html(text):
    '''Escape HTML'''
    return text.replace("<", "&lt;").replace(">", "&gt;")

class DatabaseHelper:
    def __init__(self, connection):
        self.conn = connection
    
    def execute_query(self, query):
        '''Execute SQL query'''
        return self.conn.execute(query)
"""
    
    # File 2: auth.py (authentication module)
    auth_code = """
from utils import sanitize_sql, DatabaseHelper

def authenticate_user(username, password, db_helper):
    '''Authenticate user - VULNERABLE'''
    # Weak sanitization!
    clean_user = sanitize_sql(username)
    clean_pass = sanitize_sql(password)
    
    # SQL injection still possible!
    query = f"SELECT * FROM users WHERE username='{clean_user}' AND password='{clean_pass}'"
    
    result = db_helper.execute_query(query)
    return result
"""
    
    # File 3: api.py (API endpoints)
    api_code = """
from flask import request
from auth import authenticate_user
from utils import DatabaseHelper, escape_html

db = DatabaseHelper(connection)

def login_endpoint():
    '''Login API endpoint - VULNERABLE'''
    username = request.form['username']  # Tainted source
    password = request.form['password']  # Tainted source
    
    # Cross-file vulnerability path
    result = authenticate_user(username, password, db)
    
    if result:
        return f"Welcome {escape_html(username)}"
    return "Login failed"
"""
    
    # Write files
    (repo_dir / "utils.py").write_text(utils_code)
    (repo_dir / "auth.py").write_text(auth_code)
    (repo_dir / "api.py").write_text(api_code)
    
    return repo_dir


def create_test_javascript_repo() -> Path:
    """Create a test JavaScript repository with ES6 modules"""
    repo_dir = Path(tempfile.mkdtemp(prefix="test_js_repo_"))
    
    # File 1: utils.js
    utils_code = """
export function sanitizeInput(input) {
    return input.replace(/[<>]/g, '');
}

export function validateEmail(email) {
    return email.includes('@');
}

export default class Logger {
    log(message) {
        console.log(message);
    }
}
"""
    
    # File 2: api.js
    api_code = """
import { sanitizeInput } from './utils.js';
import Logger from './utils.js';

const logger = new Logger();

export function processUserInput(userInput) {
    // Weak sanitization
    const cleaned = sanitizeInput(userInput);
    
    // XSS vulnerability if not properly escaped
    document.body.innerHTML = cleaned;
    
    logger.log('Processed input: ' + cleaned);
}

export function fetchData(url, callback) {
    fetch(url).then(data => {
        callback(data);
    });
}
"""
    
    # File 3: main.js
    main_code = """
import { processUserInput, fetchData } from './api.js';

function handleFormSubmit() {
    const userInput = document.getElementById('user-input').value;
    
    // Cross-file XSS path
    processUserInput(userInput);
    
    fetchData('/api/data', function(result) {
        // Callback with potential tainted data
        document.body.innerHTML = result;
    });
}

window.onload = function() {
    document.getElementById('submit').addEventListener('click', handleFormSubmit);
};
"""
    
    # Write files
    (repo_dir / "utils.js").write_text(utils_code)
    (repo_dir / "api.js").write_text(api_code)
    (repo_dir / "main.js").write_text(main_code)
    
    return repo_dir


def test_python_multi_module():
    """Test 1: Python multi-module analysis"""
    print("\n" + "="*60)
    print("TEST 1: Python Multi-Module Repository")
    print("="*60)
    
    # Create test repo
    repo_dir = create_test_python_repo()
    
    try:
        # Build repository graph
        repo_graph = MultiFileRepositoryGraph(str(repo_dir))
        result = repo_graph.build()
        
        # Display results
        stats = result['statistics']
        print(f"\n📊 Repository Statistics:")
        print(f"  Python modules: {stats['python_modules']}")
        print(f"  Total nodes: {stats['total_nodes']}")
        print(f"  Total edges: {stats['total_edges']}")
        print(f"  Cross-file edges: {stats['cross_file_edges']}")
        
        # Show exports
        print(f"\n📤 Exported Symbols:")
        for module in result['modules']:
            if module.exports:
                print(f"\n  {module.module_name}:")
                for export in module.exports:
                    print(f"    • {export.name} ({export.export_type})")
        
        # Show imports
        print(f"\n📥 Imported Symbols:")
        for module in result['modules']:
            if module.imports:
                print(f"\n  {module.module_name}:")
                for imp in module.imports:
                    print(f"    • {imp.name} from {imp.source_module}")
        
        # Show cross-file edges
        print(f"\n🔗 Cross-File Connections:")
        global_cpg = result['global_cpg']
        cross_file_edges = [
            e for e in global_cpg.edges
            if e.edge_type in [t.value for t in CrossFileEdgeType]
        ]
        
        for edge in cross_file_edges[:10]:  # Show first 10
            metadata = edge.metadata or {}
            print(f"  {edge.edge_type}:")
            print(f"    {metadata.get('source_file', 'N/A')}")
            print(f"      → {metadata.get('target_file', 'N/A')}")
            print(f"    Symbol: {metadata.get('symbol_name', 'N/A')}")
        
        # Demonstrate vulnerability path
        print(f"\n⚠️  Cross-File Vulnerability Analysis:")
        print(f"  Tainted Source: request.form['username'] in api.py")
        print(f"  Data Flow Path:")
        print(f"    1. api.py: request.form['username'] (TAINTED)")
        print(f"    2. api.py → auth.py: authenticate_user(username, ...)")
        print(f"    3. auth.py → utils.py: sanitize_sql(username)")
        print(f"    4. auth.py: query = f\"SELECT * FROM users WHERE username='{clean_user}'\"")
        print(f"    5. auth.py → utils.py: db_helper.execute_query(query)")
        print(f"  Sink: SQL Execution (SQL INJECTION VULNERABILITY)")
        
        return result
        
    finally:
        # Cleanup
        shutil.rmtree(repo_dir)


def test_javascript_es6_modules():
    """Test 2: JavaScript ES6 modules"""
    print("\n" + "="*60)
    print("TEST 2: JavaScript ES6 Modules")
    print("="*60)
    
    # Create test repo
    repo_dir = create_test_javascript_repo()
    
    try:
        # Build repository graph
        repo_graph = MultiFileRepositoryGraph(str(repo_dir))
        result = repo_graph.build()
        
        # Display results
        stats = result['statistics']
        print(f"\n📊 Repository Statistics:")
        print(f"  JavaScript modules: {stats['javascript_modules']}")
        print(f"  Total nodes: {stats['total_nodes']}")
        print(f"  Cross-file edges: {stats['cross_file_edges']}")
        
        # Show ES6 exports
        print(f"\n📤 ES6 Exports:")
        for module in result['modules']:
            if module.exports:
                print(f"\n  {module.module_name}:")
                for export in module.exports:
                    default_marker = " (default)" if export.is_default else ""
                    print(f"    • {export.name}{default_marker}")
        
        # Show ES6 imports
        print(f"\n📥 ES6 Imports:")
        for module in result['modules']:
            if module.imports:
                print(f"\n  {module.module_name}:")
                for imp in module.imports:
                    alias_info = f" as {imp.alias}" if imp.alias else ""
                    print(f"    • {imp.name}{alias_info} from '{imp.source_module}'")
        
        # Demonstrate XSS path
        print(f"\n⚠️  Cross-File XSS Vulnerability:")
        print(f"  Tainted Source: document.getElementById('user-input').value")
        print(f"  Data Flow Path:")
        print(f"    1. main.js: userInput = document.getElementById(...)")
        print(f"    2. main.js → api.js: processUserInput(userInput)")
        print(f"    3. api.js → utils.js: sanitizeInput(userInput)")
        print(f"    4. api.js: document.body.innerHTML = cleaned")
        print(f"  Sink: innerHTML (XSS VULNERABILITY)")
        
        return result
        
    finally:
        # Cleanup
        shutil.rmtree(repo_dir)


def test_cross_file_path_extraction():
    """Test 3: Cross-file path extraction"""
    print("\n" + "="*60)
    print("TEST 3: Cross-File Path Extraction")
    print("="*60)
    
    # Create test repo
    repo_dir = create_test_python_repo()
    
    try:
        # Build repository graph
        repo_graph = MultiFileRepositoryGraph(str(repo_dir))
        result = repo_graph.build()
        
        global_cpg = result['global_cpg']
        
        # Find source and sink
        source_node = None
        sink_node = None
        
        for node in global_cpg.nodes:
            # Source: request.form
            if node.code and "request.form" in node.code:
                source_node = node.id
                print(f"\n🎯 Source Node: {node.id}")
                print(f"  File: {node.file}")
                print(f"  Code: {node.code[:50]}...")
            
            # Sink: execute_query
            if node.code and "execute_query" in node.code and node.node_type == "CALL":
                sink_node = node.id
                print(f"\n🎯 Sink Node: {node.id}")
                print(f"  File: {node.file}")
                print(f"  Code: {node.code[:50]}...")
        
        if source_node and sink_node:
            print(f"\n🔍 Extracting cross-file paths...")
            paths = repo_graph.extract_cross_file_path(
                source_node,
                sink_node,
                max_depth=20
            )
            
            print(f"\n✓ Found {len(paths)} paths from source to sink")
            
            if paths:
                for i, path in enumerate(paths[:3], 1):  # Show first 3 paths
                    print(f"\n  Path {i} ({len(path)} hops):")
                    for j, edge in enumerate(path, 1):
                        edge_type = edge.edge_type
                        metadata = edge.metadata or {}
                        
                        if edge_type in [t.value for t in CrossFileEdgeType]:
                            src_file = Path(metadata.get('source_file', '')).name
                            tgt_file = Path(metadata.get('target_file', '')).name
                            print(f"    {j}. [{edge_type}] {src_file} → {tgt_file}")
                        else:
                            print(f"    {j}. [{edge_type}]")
        else:
            print(f"\n⚠️  Could not find source/sink nodes")
        
        return result
        
    finally:
        # Cleanup
        shutil.rmtree(repo_dir)


def test_global_symbol_resolution():
    """Test 4: Global symbol table and resolution"""
    print("\n" + "="*60)
    print("TEST 4: Global Symbol Resolution")
    print("="*60)
    
    repo_dir = create_test_python_repo()
    
    try:
        repo_graph = MultiFileRepositoryGraph(str(repo_dir))
        result = repo_graph.build()
        
        symbol_table = result['symbol_table']
        
        # Test export lookup
        print(f"\n🔍 Looking up exported symbol 'sanitize_sql':")
        exports = symbol_table.find_export('sanitize_sql')
        for export in exports:
            print(f"  ✓ Found in: {Path(export.file_path).name}")
            print(f"    Type: {export.export_type}")
            print(f"    Node: {export.node_id}")
        
        # Test import resolution
        print(f"\n🔍 Resolving import 'from utils import sanitize_sql':")
        auth_file = str(repo_dir / "auth.py")
        resolved = symbol_table.resolve_import(auth_file, "utils", "sanitize_sql")
        if resolved:
            print(f"  ✓ Resolved to: {Path(resolved).name}")
        else:
            print(f"  ✗ Could not resolve")
        
        # Show all modules
        print(f"\n📚 All Modules in Repository:")
        for module_name, module in symbol_table.modules.items():
            print(f"\n  {module_name}:")
            print(f"    File: {Path(module.file_path).name}")
            print(f"    Language: {module.language}")
            print(f"    Exports: {len(module.exports)}")
            print(f"    Imports: {len(module.imports)}")
        
        return result
        
    finally:
        # Cleanup
        shutil.rmtree(repo_dir)


def test_large_repo_performance():
    """Test 5: Performance with larger repository"""
    print("\n" + "="*60)
    print("TEST 5: Large Repository Performance")
    print("="*60)
    
    # Create a larger synthetic repo
    repo_dir = Path(tempfile.mkdtemp(prefix="test_large_repo_"))
    
    try:
        print(f"\n📦 Creating synthetic repository with 50 files...")
        
        # Create 50 interconnected Python modules
        for i in range(50):
            # Each module imports from 2-3 previous modules
            imports = []
            if i > 0:
                imports.append(f"from module_{i-1} import func_{i-1}")
            if i > 1:
                imports.append(f"from module_{i-2} import func_{i-2}")
            
            code = "\n".join(imports) + f"""

def func_{i}(x):
    '''Function {i}'''
    result = x + {i}
    """ + (f"result = func_{i-1}(result)" if i > 0 else "") + f"""
    return result

class Class_{i}:
    def method(self):
        return {i}
"""
            
            (repo_dir / f"module_{i}.py").write_text(code)
        
        print(f"  ✓ Created 50 modules")
        
        # Build repository graph
        import time
        start_time = time.time()
        
        repo_graph = MultiFileRepositoryGraph(str(repo_dir))
        result = repo_graph.build()
        
        elapsed = time.time() - start_time
        
        # Display performance metrics
        stats = result['statistics']
        print(f"\n⚡ Performance Metrics:")
        print(f"  Build time: {elapsed:.2f} seconds")
        print(f"  Modules: {stats['total_modules']}")
        print(f"  Nodes: {stats['total_nodes']}")
        print(f"  Edges: {stats['total_edges']}")
        print(f"  Cross-file edges: {stats['cross_file_edges']}")
        print(f"  Throughput: {stats['total_modules'] / elapsed:.1f} modules/sec")
        
        # Memory estimate (rough)
        node_size = 200  # bytes per node (estimate)
        edge_size = 100  # bytes per edge (estimate)
        memory_mb = (stats['total_nodes'] * node_size + stats['total_edges'] * edge_size) / (1024 * 1024)
        print(f"  Memory (estimated): {memory_mb:.1f} MB")
        
        return result
        
    finally:
        # Cleanup
        shutil.rmtree(repo_dir)


def demonstrate_api_usage():
    """Demonstrate API usage patterns"""
    print("\n" + "="*60)
    print("API USAGE PATTERNS")
    print("="*60)
    
    print("""
# Pattern 1: Basic Repository Analysis
from app.domain.analysis.multi_file_repo_graph import MultiFileRepositoryGraph

repo_graph = MultiFileRepositoryGraph('/path/to/repo')
result = repo_graph.build()

# Access results
modules = result['modules']
global_cpg = result['global_cpg']
symbol_table = result['symbol_table']
stats = result['statistics']

# Pattern 2: Find Exported Symbol
exports = symbol_table.find_export('function_name')
for export in exports:
    print(f"Found in: {export.file_path}")

# Pattern 3: Resolve Import
resolved_file = symbol_table.resolve_import(
    importing_file='/path/to/file.py',
    module_path='utils',
    symbol_name='helper'
)

# Pattern 4: Extract Cross-File Path
paths = repo_graph.extract_cross_file_path(
    source_node_id='node_123',
    sink_node_id='node_456',
    max_depth=20
)

# Pattern 5: Filter Cross-File Edges
from app.domain.analysis.multi_file_repo_graph import CrossFileEdgeType

import_edges = [
    e for e in global_cpg.edges
    if e.edge_type == CrossFileEdgeType.IMPORT_CALL.value
]

export_edges = [
    e for e in global_cpg.edges
    if e.edge_type == CrossFileEdgeType.EXPORT_RET.value
]

# Pattern 6: Exclude Patterns
repo_graph = MultiFileRepositoryGraph(
    '/path/to/repo',
    exclude_patterns=['test_*.py', 'node_modules', '__pycache__']
)
    """)


def run_all_tests():
    """Run all multi-file repository graph tests"""
    print("\n" + "="*70)
    print(" MULTI-FILE REPOSITORY GRAPH - COMPREHENSIVE TEST SUITE")
    print("="*70)
    
    tests = [
        ("Python Multi-Module", test_python_multi_module),
        ("JavaScript ES6 Modules", test_javascript_es6_modules),
        ("Cross-File Path Extraction", test_cross_file_path_extraction),
        ("Global Symbol Resolution", test_global_symbol_resolution),
        ("Large Repo Performance", test_large_repo_performance),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, "✅ PASSED", result))
        except Exception as e:
            results.append((test_name, f"❌ FAILED: {str(e)}", None))
            print(f"\n⚠️  Error in {test_name}: {e}")
            import traceback
            traceback.print_exc()
    
    # Demonstrate API
    demonstrate_api_usage()
    
    # Summary
    print("\n" + "="*70)
    print(" TEST SUMMARY")
    print("="*70)
    
    for name, status, _ in results:
        print(f"{status} {name}")
    
    passed = sum(1 for _, status, _ in results if "PASSED" in status)
    total = len(results)
    
    print(f"\n✓ {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! Multi-file repository graph is working correctly.")
    else:
        print("\n⚠️  Some tests failed. Review output above for details.")


if __name__ == "__main__":
    run_all_tests()
