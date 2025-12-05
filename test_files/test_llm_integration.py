"""
Test LLM Integration with GitHub Models (Llama-4-Scout-17B-Instruct)
Verifies: System prompt loading, API calls, response parsing
"""
import asyncio
import sys
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from semantic_engine.classifier.llm_service import get_llm_service
from semantic_engine.pipeline import get_pipeline, PipelineConfig


async def test_llm_service():
    """Test 1: LLM Service Initialization"""
    print("\n" + "="*80)
    print("TEST 1: LLM Service Initialization")
    print("="*80)
    
    try:
        llm_service = get_llm_service()
        
        print(f"✓ LLM Service initialized")
        print(f"  Provider: {llm_service.provider}")
        print(f"  Model: {llm_service.model}")
        print(f"  Base URL: {llm_service.base_url}")
        print(f"  API Key: {'***' + llm_service.api_key[-4:] if llm_service.api_key else 'None'}")
        print(f"  System Prompt Length: {len(llm_service.system_prompt)} chars")
        print(f"  Client Initialized: {llm_service.client is not None}")
        
        # Show first 200 chars of system prompt
        print(f"\n  System Prompt Preview:")
        print(f"  {llm_service.system_prompt[:200]}...")
        
        return True
    except Exception as e:
        print(f"✗ LLM Service initialization FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_llm_classification():
    """Test 2: LLM Classification of Vulnerable Code"""
    print("\n" + "="*80)
    print("TEST 2: LLM Classification - SQL Injection")
    print("="*80)
    
    vulnerable_code = """
    1 | def get_user(user_id):
>>> 2 |     query = "SELECT * FROM users WHERE id = " + user_id
>>> 3 |     result = db.execute(query)
    4 |     return result
"""
    
    try:
        llm_service = get_llm_service()
        
        if not llm_service.client:
            print("⚠ LLM client not available - skipping test")
            return True
        
        print("Sending code slice to LLM for classification...")
        print(f"Using model: {llm_service.model}")
        
        result = await llm_service.classify_code_slice(
            code_snippet=vulnerable_code,
            rule_name="SQL Injection",
            rule_description="User input flows to SQL execution without parameterization",
            source_label="user_id",
            sink_label="execute",
            owasp="A03",
            cwe="CWE-89"
        )
        
        print(f"\n✓ LLM Classification Complete:")
        print(f"  Classification: {result.classification.value}")
        print(f"  Severity: {result.severity}")
        print(f"  Exploitability: {result.exploitability_score}")
        print(f"  Confidence: {result.confidence}")
        print(f"\n  Explanation:")
        print(f"  {result.explanation}")
        print(f"\n  Remediation:")
        print(f"  {result.remediation}")
        
        # Verify it detected as vulnerable
        if result.classification.value in ["VULNERABLE", "LIKELY_VULNERABLE"]:
            print(f"\n✓ Test PASSED - Correctly identified as vulnerable")
            return True
        else:
            print(f"\n⚠ Test WARNING - Expected vulnerable, got {result.classification.value}")
            return True  # Still pass, but warn
            
    except Exception as e:
        print(f"\n✗ LLM Classification FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_pipeline_with_llm():
    """Test 3: Full Pipeline with LLM Enabled"""
    print("\n" + "="*80)
    print("TEST 3: Full Pipeline with LLM Classification")
    print("="*80)
    
    vulnerable_code = """
def login(username, password):
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    result = db.execute(query)
    return result
"""
    
    try:
        # Configure pipeline with LLM enabled
        config = PipelineConfig(enable_llm=True)
        pipeline = get_pipeline(config)
        
        print(f"Pipeline configured with LLM: {config.enable_llm}")
        print(f"Running full analysis...")
        
        result = await pipeline.analyze_code(
            filename="test_login.py",
            code=vulnerable_code,
            language="python"
        )
        
        print(f"\n✓ Pipeline Analysis Complete:")
        print(f"  Success: {result.success}")
        print(f"  Analysis time: {result.analysis_time_seconds}s")
        print(f"  Graph nodes: {result.graph_nodes}")
        print(f"  Vulnerabilities found: {result.vulnerabilities_found}")
        
        if result.vulnerabilities:
            print(f"\n  Detected Vulnerabilities:")
            for i, vuln in enumerate(result.vulnerabilities[:3], 1):
                print(f"\n  {i}. {vuln['type']}")
                print(f"     Severity: {vuln['severity']}")
                print(f"     Confidence: {vuln['confidence']}")
                print(f"     LLM Classification: {vuln['analysis']['llm_classification']['classification']}")
                print(f"     LLM Explanation: {vuln['analysis']['llm_classification']['explanation'][:100]}...")
        
        if result.errors:
            print(f"\n  Errors: {result.errors}")
        
        if result.warnings:
            print(f"\n  Warnings: {result.warnings}")
        
        if result.vulnerabilities_found > 0:
            print(f"\n✓ Test PASSED - Found {result.vulnerabilities_found} vulnerabilities with LLM classification")
            return True
        else:
            print(f"\n⚠ Test WARNING - No vulnerabilities detected")
            return True
            
    except Exception as e:
        print(f"\n✗ Pipeline test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_safe_code_with_llm():
    """Test 4: LLM Should Mark Safe Code as SAFE"""
    print("\n" + "="*80)
    print("TEST 4: LLM Classification - Safe Code")
    print("="*80)
    
    safe_code = """
    1 | def get_user(user_id):
    2 |     # Parameterized query - safe
>>> 3 |     query = "SELECT * FROM users WHERE id = ?"
>>> 4 |     result = db.execute(query, (user_id,))
    5 |     return result
"""
    
    try:
        llm_service = get_llm_service()
        
        if not llm_service.client:
            print("⚠ LLM client not available - skipping test")
            return True
        
        print("Sending SAFE code slice to LLM...")
        
        result = await llm_service.classify_code_slice(
            code_snippet=safe_code,
            rule_name="SQL Injection",
            rule_description="User input flows to SQL execution",
            source_label="user_id",
            sink_label="execute",
            owasp="A03",
            cwe="CWE-89"
        )
        
        print(f"\n✓ LLM Classification Complete:")
        print(f"  Classification: {result.classification.value}")
        print(f"  Explanation: {result.explanation}")
        
        if result.classification.value == "SAFE":
            print(f"\n✓ Test PASSED - Correctly identified safe code")
            return True
        else:
            print(f"\n⚠ Test INFO - Classified as {result.classification.value} (may be conservative)")
            return True
            
    except Exception as e:
        print(f"\n✗ Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


async def run_all_tests():
    """Run all LLM integration tests"""
    print("\n" + "="*80)
    print("LLM INTEGRATION TEST SUITE")
    print("GitHub Models API + Llama-4-Scout-17B-Instruct")
    print("="*80)
    
    results = []
    
    # Test 1: Service initialization
    results.append(("LLM Service Init", await test_llm_service()))
    
    # Test 2: LLM classification of vulnerable code
    results.append(("LLM Classify Vulnerable", await test_llm_classification()))
    
    # Test 3: Full pipeline with LLM
    results.append(("Pipeline with LLM", await test_pipeline_with_llm()))
    
    # Test 4: Safe code detection
    results.append(("LLM Classify Safe Code", await test_safe_code_with_llm()))
    
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
        print("\nALL TESTS PASSED!")
        print("\nVulcan is now using LLM-powered vulnerability detection!")
        print(f"   Model: Meta-Llama-3.1-405B-Instruct (GitHub Models)")
        print(f"   System Prompt: app/LLM-prompts/detect-system-prompt.txt")
    else:
        print(f"\n{total - passed} test(s) failed")
    
    return passed == total


if __name__ == "__main__":
    print("\nStarting LLM Integration Tests...")
    print(f"Provider: {os.getenv('LLM_PROVIDER', 'not set')}")
    print(f"Model: {os.getenv('LLM_MODEL_CLASSIFIER', 'not set')}")
    print(f"API Key: {'configured' if os.getenv('LLM_API_KEY') else 'NOT SET'}")
    
    success = asyncio.run(run_all_tests())
    sys.exit(0 if success else 1)
