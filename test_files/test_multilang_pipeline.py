"""
Comprehensive Test Suite for Enhanced Multi-Language AST Parser
Tests Python and JavaScript/TypeScript support across the entire pipeline
"""
import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from semantic_engine.pipeline import get_pipeline, PipelineConfig
from app.domain.analysis.semantic_graph_builder import SemanticGraphBuilder
from app.enums.node_type import NodeType


def test_python_enhanced_features():
    """Test enhanced Python features: async, lambda, comprehensions, exceptions"""
    print("\n" + "="*70)
    print("TEST 1: Python Enhanced Features (Async, Lambda, Comprehensions)")
    print("="*70)
    
    code = """
import os
import subprocess

async def async_handler(user_input):
    # Async function with dangerous command execution
    result = await subprocess.run(user_input, shell=True)
    return result

def process_data():
    # Lambda with user input
    sanitize = lambda x: x.strip()
    user_data = input("Enter data: ")
    
    # List comprehension with f-string injection
    queries = [f"SELECT * FROM users WHERE id={user_id}" for user_id in user_data]
    
    # Try-except with SQL execution
    try:
        cursor.execute(queries[0])
    except Exception as e:
        raise ValueError("Database error")
    finally:
        print("Done")

# Global variable
global debug_mode
debug_mode = True

class UserHandler:
    def __init__(self, db):
        self.db = db
    
    def get_user(self, user_id):
        # Attribute access with injection
        return self.db.execute(f"SELECT * FROM users WHERE id={user_id}")
"""
    
    # Build semantic graph
    builder = SemanticGraphBuilder(language="python")
    graph = builder.build(code, "test_enhanced.py")
    
    # Count node types
    node_counts = {}
    for node in graph.nodes:
        node_type = str(node.type)
        node_counts[node_type] = node_counts.get(node_type, 0) + 1
    
    print(f"\n📊 Graph Statistics:")
    print(f"   Total Nodes: {len(graph.nodes)}")
    print(f"   Total Edges: {len(graph.edges)}")
    
    # Check for new node types
    expected_types = [
        NodeType.IMPORT,
        NodeType.ASYNC_FUNCTION,
        NodeType.LAMBDA,
        NodeType.LIST_COMP,
        NodeType.TRY,
        NodeType.EXCEPT,
        NodeType.RAISE,
        NodeType.GLOBAL,
        NodeType.CLASS,
        NodeType.ATTRIBUTE
    ]
    
    print(f"\n✅ New Node Types Detected:")
    found_count = 0
    for node_type in expected_types:
        count = node_counts.get(str(node_type), 0)
        if count > 0:
            print(f"   ✓ {node_type}: {count} instances")
            found_count += 1
        else:
            print(f"   ✗ {node_type}: NOT FOUND")
    
    print(f"\n📈 Coverage: {found_count}/{len(expected_types)} new node types detected")
    
    return found_count >= 8  # At least 8 out of 10 should be found


def test_javascript_parsing():
    """Test JavaScript/TypeScript parsing"""
    print("\n" + "="*70)
    print("TEST 2: JavaScript/TypeScript Parsing")
    print("="*70)
    
    js_code = """
import express from 'express';
import { validateInput } from './utils';

const app = express();

async function handleRequest(req, res) {
    const userId = req.query.id;
    
    // Dangerous eval
    eval(userId);
    
    // DOM manipulation
    document.innerHTML = userId;
    
    // SQL injection
    const query = `SELECT * FROM users WHERE id=${userId}`;
    db.query(query);
}

const processData = async (data) => {
    return await fetch(data);
};

var debug = true;
"""
    
    # Build semantic graph for JavaScript
    builder = SemanticGraphBuilder(language="javascript")
    graph = builder.build(js_code, "test.js")
    
    print(f"\n📊 JavaScript Graph Statistics:")
    print(f"   Total Nodes: {len(graph.nodes)}")
    print(f"   Total Edges: {len(graph.edges)}")
    
    # Check for JS-specific nodes
    js_features = {
        "imports": 0,
        "async_functions": 0,
        "arrow_functions": 0,
        "assignments": 0,
        "dangerous_calls": 0
    }
    
    for node in graph.nodes:
        if node.type == NodeType.IMPORT:
            js_features["imports"] += 1
        elif node.type == NodeType.ASYNC_FUNCTION:
            js_features["async_functions"] += 1
        elif node.type == NodeType.ARROW_FUNCTION:
            js_features["arrow_functions"] += 1
        elif node.type == NodeType.ASSIGNMENT:
            js_features["assignments"] += 1
        elif node.type == NodeType.CALL_EXPRESSION:
            js_features["dangerous_calls"] += 1
    
    print(f"\n✅ JavaScript Features Detected:")
    for feature, count in js_features.items():
        status = "✓" if count > 0 else "✗"
        print(f"   {status} {feature}: {count}")
    
    success = js_features["imports"] > 0 and js_features["async_functions"] > 0
    return success


async def test_end_to_end_pipeline_python():
    """Test end-to-end pipeline with Python code"""
    print("\n" + "="*70)
    print("TEST 3: End-to-End Pipeline - Python SQL Injection")
    print("="*70)
    
    vulnerable_code = """
import sqlite3

async def get_user_data(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE id={user_id}"
    cursor.execute(query)
    
    return cursor.fetchall()

def lambda_test():
    # Lambda with dangerous operation
    exec_cmd = lambda cmd: os.system(cmd)
    user_input = input("Enter command: ")
    exec_cmd(user_input)
"""
    
    # Configure pipeline
    config = PipelineConfig(
        enable_llm=False,  # Disable LLM for faster testing
        max_graph_nodes=50000,
        max_path_length=20
    )
    
    pipeline = get_pipeline(config)
    
    # Run analysis
    result = await pipeline.analyze_code(
        filename="test_vulnerable.py",
        code=vulnerable_code,
        language="python"
    )
    
    print(f"\n📊 Analysis Results:")
    print(f"   Success: {result.success}")
    print(f"   Analysis Time: {result.analysis_time_seconds}s")
    print(f"   Graph Nodes: {result.graph_nodes}")
    print(f"   Graph Edges: {result.graph_edges}")
    print(f"   Rules Executed: {result.rules_executed}")
    print(f"   Slices Found: {result.slices_found}")
    print(f"   Vulnerabilities: {result.vulnerabilities_found}")
    
    if result.vulnerabilities_found > 0:
        print(f"\n🔴 Vulnerabilities Detected:")
        for vuln in result.vulnerabilities:
            print(f"   • {vuln['type']} (Severity: {vuln['severity']})")
            print(f"     Location: Line {vuln['location']['start_line']}")
            print(f"     Source: {vuln['evidence']['source']} → Sink: {vuln['evidence']['sink']}")
    
    return result.success and result.vulnerabilities_found > 0


async def test_end_to_end_pipeline_javascript():
    """Test end-to-end pipeline with JavaScript code"""
    print("\n" + "="*70)
    print("TEST 4: End-to-End Pipeline - JavaScript XSS")
    print("="*70)
    
    js_vulnerable = """
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
    const query = req.query.q;
    
    // XSS vulnerability
    res.send('<h1>Results for: ' + query + '</h1>');
    
    // Command injection
    const { exec } = require('child_process');
    exec('ls ' + query);
});
"""
    
    config = PipelineConfig(enable_llm=False)
    pipeline = get_pipeline(config)
    
    result = await pipeline.analyze_code(
        filename="app.js",
        code=js_vulnerable,
        language="javascript"
    )
    
    print(f"\n📊 JavaScript Analysis Results:")
    print(f"   Success: {result.success}")
    print(f"   Graph Nodes: {result.graph_nodes}")
    print(f"   Vulnerabilities: {result.vulnerabilities_found}")
    
    return result.success


def test_language_detection():
    """Test automatic language detection in LLM service"""
    print("\n" + "="*70)
    print("TEST 5: Language Auto-Detection")
    print("="*70)
    
    from semantic_engine.classifier.llm_service import LLMService
    
    llm_service = LLMService()
    
    # Test Python detection
    python_code = """
def process_data(user_input):
    query = f"SELECT * FROM users WHERE id={user_input}"
    cursor.execute(query)
"""
    python_lang = llm_service._detect_language(python_code)
    print(f"   Python code detected as: {python_lang}")
    
    # Test JavaScript detection
    js_code = """
const handleRequest = async (req, res) => {
    const userId = req.query.id;
    document.innerHTML = userId;
};
"""
    js_lang = llm_service._detect_language(js_code)
    print(f"   JavaScript code detected as: {js_lang}")
    
    # Test TypeScript detection
    ts_code = """
interface User {
    id: string;
    name: string;
}

const getUser = async (id: string): Promise<User> => {
    return await fetch(`/api/users/${id}`);
};
"""
    ts_lang = llm_service._detect_language(ts_code)
    print(f"   TypeScript code detected as: {ts_lang}")
    
    success = (
        python_lang == "python" and 
        js_lang == "javascript" and 
        ts_lang == "typescript"
    )
    
    if success:
        print(f"\n   ✅ All languages detected correctly!")
    else:
        print(f"\n   ⚠️  Some detections incorrect")
    
    return success


def test_node_type_enum():
    """Verify all new node types are in enum"""
    print("\n" + "="*70)
    print("TEST 6: NodeType Enum Validation")
    print("="*70)
    
    required_types = [
        'IMPORT', 'ASYNC_FUNCTION', 'AWAIT', 'LAMBDA',
        'LIST_COMP', 'DICT_COMP', 'SET_COMP', 'GENERATOR_EXP',
        'TRY', 'EXCEPT', 'RAISE', 'GLOBAL', 'NONLOCAL', 'ATTRIBUTE'
    ]
    
    missing = []
    found = []
    
    for node_type_name in required_types:
        if hasattr(NodeType, node_type_name):
            found.append(node_type_name)
            print(f"   ✓ NodeType.{node_type_name} exists")
        else:
            missing.append(node_type_name)
            print(f"   ✗ NodeType.{node_type_name} MISSING")
    
    print(f"\n   Coverage: {len(found)}/{len(required_types)} node types present")
    
    return len(missing) == 0


async def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("🚀 MULTI-LANGUAGE AST PARSER TEST SUITE")
    print("="*70)
    
    tests = [
        ("Python Enhanced Features", test_python_enhanced_features),
        ("JavaScript Parsing", test_javascript_parsing),
        ("End-to-End Python", test_end_to_end_pipeline_python),
        ("End-to-End JavaScript", test_end_to_end_pipeline_javascript),
        ("Language Auto-Detection", test_language_detection),
        ("NodeType Enum", test_node_type_enum),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            if asyncio.iscoroutinefunction(test_func):
                result = await test_func()
            else:
                result = test_func()
            
            status = "✅ PASS" if result else "❌ FAIL"
            results.append((test_name, result))
            print(f"\n{status}: {test_name}\n")
        except Exception as e:
            print(f"\n❌ ERROR in {test_name}: {e}\n")
            results.append((test_name, False))
            import traceback
            traceback.print_exc()
    
    # Print summary
    print("\n" + "="*70)
    print("📊 TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {status}: {test_name}")
    
    print(f"\n   Total: {passed}/{total} tests passed ({passed*100//total}%)")
    
    if passed == total:
        print("\n   🎉 ALL TESTS PASSED! Multi-language support is working!")
    else:
        print(f"\n   ⚠️  {total - passed} test(s) failed")
    
    return passed == total


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
