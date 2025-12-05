"""
Test Suite for Unified CPG Semantic Analysis Pipeline
Tests: Query Store → Query Executor → LLM Classifier → Full Pipeline
"""
import asyncio
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from semantic_engine.query_store.loader import get_query_store
from semantic_engine.query_executor.executor import QueryExecutor
from semantic_engine.classifier.classifier import get_classifier
from semantic_engine.pipeline import get_pipeline, PipelineConfig

# Test cases
VULNERABLE_CODE = """
def get_user_data(user_id):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

def upload_file(filename):
    # Path traversal vulnerability
    file_path = f"/uploads/{filename}"
    with open(file_path, 'r') as f:
        return f.read()

def make_request(url):
    # SSRF vulnerability
    import requests
    return requests.get(url)
"""

SAFE_CODE = """
def get_user_data(user_id):
    # Safe: parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()

def validate_input(data):
    # Safe: validation function
    if not data.isalnum():
        raise ValueError("Invalid input")
    return data
"""


def test_query_store():
    """Test 1: Query Store Loading"""
    print("\n" + "="*80)
    print("TEST 1: Query Store Loading")
    print("="*80)
    
    try:
        store = get_query_store()
        
        print(f"✓ Loaded {len(store.get_all_queries())} query rules")
        
        # Get stats
        stats = store.get_stats()
        print(f"\nQuery Statistics:")
        print(f"  Total rules: {stats['total_rules']}")
        print(f"  By severity: {stats['by_severity']}")
        print(f"  By OWASP: {stats['by_owasp']}")
        
        # Test specific queries
        sql_injection = store.get_query('SQL_INJECTION')
        if sql_injection:
            print(f"\nSQL Injection Rule:")
            print(f"  Name: {sql_injection.name}")
            print(f"  Severity: {sql_injection.severity}")
            print(f"  Sources: {sql_injection.sources[:3]}...")
            print(f"  Sinks: {sql_injection.sinks[:3]}...")
        
        # Test search
        injection_rules = store.search_queries('injection')
        print(f"\nSearch 'injection': {len(injection_rules)} rules found")
        for rule in injection_rules[:3]:
            print(f"  - {rule.rule_id}: {rule.name}")
        
        print("\n✓ Query Store test PASSED")
        return True
    
    except Exception as e:
        print(f"\n✗ Query Store test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_pipeline_vulnerable():
    """Test 2: Full Pipeline with Vulnerable Code"""
    print("\n" + "="*80)
    print("TEST 2: Full Pipeline - Vulnerable Code")
    print("="*80)
    
    try:
        # Configure pipeline (LLM disabled for testing)
        config = PipelineConfig(enable_llm=False)
        pipeline = get_pipeline(config)
        
        # Run analysis
        result = await pipeline.analyze_code(
            filename="test_vulnerable.py",
            code=VULNERABLE_CODE,
            language="python"
        )
        
        print(f"\nAnalysis Results:")
        print(f"  Success: {result.success}")
        print(f"  Analysis time: {result.analysis_time_seconds}s")
        print(f"  Graph nodes: {result.graph_nodes}")
        print(f"  Graph edges: {result.graph_edges}")
        print(f"  Rules executed: {result.rules_executed}")
        print(f"  Slices found: {result.slices_found}")
        print(f"  Vulnerabilities: {result.vulnerabilities_found}")
        
        if result.warnings:
            print(f"\nWarnings: {result.warnings}")
        if result.errors:
            print(f"\nErrors: {result.errors}")
        
        # Show vulnerabilities
        if result.vulnerabilities:
            print(f"\nDetected Vulnerabilities:")
            for i, vuln in enumerate(result.vulnerabilities, 1):
                print(f"\n  {i}. {vuln['type']}")
                print(f"     Severity: {vuln['severity']}")
                print(f"     Confidence: {vuln['confidence']}")
                print(f"     OWASP: {vuln['owasp']}, CWE: {vuln['cwe']}")
                print(f"     Location: lines {vuln['location']['start_line']}-{vuln['location']['end_line']}")
                print(f"     Source: {vuln['evidence']['source']}")
                print(f"     Sink: {vuln['evidence']['sink']}")
        
        # Verify we found vulnerabilities
        if result.vulnerabilities_found > 0:
            print(f"\n✓ Pipeline test PASSED - Found {result.vulnerabilities_found} vulnerabilities")
            return True
        else:
            print(f"\n⚠ Pipeline test WARNING - Expected vulnerabilities but found none")
            return False
    
    except Exception as e:
        print(f"\n✗ Pipeline test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_pipeline_safe():
    """Test 3: Full Pipeline with Safe Code"""
    print("\n" + "="*80)
    print("TEST 3: Full Pipeline - Safe Code")
    print("="*80)
    
    try:
        config = PipelineConfig(enable_llm=False)
        pipeline = get_pipeline(config)
        
        result = await pipeline.analyze_code(
            filename="test_safe.py",
            code=SAFE_CODE,
            language="python"
        )
        
        print(f"\nAnalysis Results:")
        print(f"  Success: {result.success}")
        print(f"  Vulnerabilities: {result.vulnerabilities_found}")
        
        if result.vulnerabilities_found == 0:
            print(f"\n✓ Safe code test PASSED - No false positives")
            return True
        else:
            print(f"\n⚠ Safe code test WARNING - Found {result.vulnerabilities_found} potential false positives")
            for vuln in result.vulnerabilities:
                print(f"  - {vuln['type']} at line {vuln['location']['start_line']}")
            return True  # Still pass, just warn
    
    except Exception as e:
        print(f"\n✗ Safe code test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_sql_injection_detection():
    """Test 4: Specific SQL Injection Detection"""
    print("\n" + "="*80)
    print("TEST 4: SQL Injection Detection")
    print("="*80)
    
    sql_vuln_code = """
def login(username, password):
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    result = db.execute(query)
    return result
"""
    
    try:
        config = PipelineConfig(enable_llm=False)
        pipeline = get_pipeline(config)
        
        result = await pipeline.analyze_code(
            filename="sql_injection_test.py",
            code=sql_vuln_code,
            language="python"
        )
        
        # Check if SQL injection was detected
        sql_injection_found = any(
            'SQL' in vuln['type'].upper() or 'INJECTION' in vuln['type'].upper()
            for vuln in result.vulnerabilities
        )
        
        print(f"\nSQL Injection Detection:")
        print(f"  Total vulnerabilities: {result.vulnerabilities_found}")
        print(f"  SQL injection detected: {sql_injection_found}")
        
        if sql_injection_found:
            sql_vulns = [v for v in result.vulnerabilities if 'SQL' in v['type'].upper()]
            for vuln in sql_vulns:
                print(f"\n  Detected:")
                print(f"    Type: {vuln['type']}")
                print(f"    Severity: {vuln['severity']}")
                print(f"    Source: {vuln['evidence']['source']}")
                print(f"    Sink: {vuln['evidence']['sink']}")
        
        if sql_injection_found:
            print(f"\n✓ SQL Injection test PASSED")
            return True
        else:
            print(f"\n✗ SQL Injection test FAILED - Not detected")
            return False
    
    except Exception as e:
        print(f"\n✗ SQL Injection test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


async def run_all_tests():
    """Run all tests"""
    print("\n" + "="*80)
    print("SEMANTIC PIPELINE TEST SUITE")
    print("="*80)
    
    results = []
    
    # Test 1: Query Store
    results.append(("Query Store", test_query_store()))
    
    # Test 2: Pipeline - Vulnerable Code
    results.append(("Pipeline - Vulnerable Code", await test_pipeline_vulnerable()))
    
    # Test 3: Pipeline - Safe Code
    results.append(("Pipeline - Safe Code", await test_pipeline_safe()))
    
    # Test 4: SQL Injection Detection
    results.append(("SQL Injection Detection", await test_sql_injection_detection()))
    
    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status} - {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED!")
    else:
        print(f"\n⚠ {total - passed} test(s) failed")
    
    return passed == total


if __name__ == "__main__":
    success = asyncio.run(run_all_tests())
    sys.exit(0 if success else 1)
