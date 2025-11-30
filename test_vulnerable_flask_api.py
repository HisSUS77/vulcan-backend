"""
Test Vulcan's LLM-powered detection on a real vulnerable Flask API
"""
import asyncio
import time
import logging
from pathlib import Path
from dotenv import load_dotenv

from semantic_engine.pipeline import SemanticPipeline, PipelineConfig

# Enable debug logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Load environment variables
load_dotenv()

async def test_vulnerable_flask_api():
    """Analyze vulnerable Flask API with Vulcan's LLM-powered detection"""
    
    print("="*80)
    print("VULCAN LLM-POWERED VULNERABILITY DETECTION")
    print("Testing: vulnerable_api.py (Flask API with multiple security issues)")
    print("="*80)
    print()
    
    # Read the vulnerable code
    test_file = Path(__file__).parent / "test_files" / "vulnerable_api.py"
    code = test_file.read_text()
    
    print(f"File: {test_file.name}")
    print(f"Lines of code: {len(code.splitlines())}")
    print(f"Language: Python (Flask)")
    print()
    
    # Configure pipeline with LLM enabled
    config = PipelineConfig(
        enable_llm=True,
        max_paths_per_rule=50
    )
    
    pipeline = SemanticPipeline(config)
    
    print("Starting analysis with LLM classification...")
    print("-" * 80)
    
    start_time = time.time()
    
    # Run analysis
    result = await pipeline.analyze_code(
        code=code,
        language="python",
        filename="vulnerable_api.py"
    )
    
    analysis_time = time.time() - start_time
    
    print()
    print("="*80)
    print("ANALYSIS RESULTS")
    print("="*80)
    print(f"Analysis time: {analysis_time:.2f}s")
    print(f"Total vulnerabilities: {len(result.vulnerabilities)}")
    print()
    
    if result.vulnerabilities:
        # Group by severity
        critical = [v for v in result.vulnerabilities if v.severity == "critical"]
        high = [v for v in result.vulnerabilities if v.severity == "high"]
        medium = [v for v in result.vulnerabilities if v.severity == "medium"]
        low = [v for v in result.vulnerabilities if v.severity == "low"]
        
        print(f"Severity breakdown:")
        print(f"  Critical: {len(critical)}")
        print(f"  High:     {len(high)}")
        print(f"  Medium:   {len(medium)}")
        print(f"  Low:      {len(low)}")
        print()
        print("-" * 80)
        
        for idx, vuln in enumerate(result.vulnerabilities, 1):
            print()
            print(f"[{idx}] {vuln.vuln_type}")
            print(f"    Severity: {vuln.severity.upper()}")
            print(f"    Location: Line {vuln.line}")
            print(f"    OWASP: {vuln.owasp_category}")
            print(f"    CWE: {vuln.cwe_id}")
            
            if vuln.analysis and vuln.analysis.llm_classification:
                llm = vuln.analysis.llm_classification
                print()
                print(f"    LLM Classification: {llm.classification}")
                print(f"    Confidence: {llm.confidence:.2%}")
                
                if llm.explanation:
                    print()
                    print("    Explanation:")
                    # Wrap explanation text
                    words = llm.explanation.split()
                    line = "      "
                    for word in words:
                        if len(line + word) > 76:
                            print(line)
                            line = "      " + word + " "
                        else:
                            line += word + " "
                    if line.strip():
                        print(line)
                
                if llm.remediation:
                    print()
                    print("    Remediation:")
                    # Wrap remediation text
                    words = llm.remediation.split()
                    line = "      "
                    for word in words:
                        if len(line + word) > 76:
                            print(line)
                            line = "      " + word + " "
                        else:
                            line += word + " "
                    if line.strip():
                        print(line)
            
            print()
            print("    Vulnerable code:")
            if vuln.analysis and vuln.analysis.code_slice:
                for line in vuln.analysis.code_slice.split('\n')[:5]:  # Show first 5 lines
                    print(f"      {line}")
            
            print("-" * 80)
    else:
        print("No vulnerabilities detected!")
    
    print()
    print("="*80)
    print("EXPECTED VULNERABILITIES IN THIS FILE:")
    print("="*80)
    print("1. SQL Injection in get_user_by_id() - user_id parameter")
    print("2. SQL Injection in login() - username parameter")
    print("3. SQL Injection in login() - password parameter")
    print("4. SQL Injection in get_order() - order_id parameter")
    print("5. SQL Injection in create_order() - item/quantity/price parameters")
    print("6. Broken Access Control - /users endpoint (no auth)")
    print("7. Broken Object Level Authorization - /orders/<id> endpoint")
    print("8. Security Misconfiguration - /admin endpoint (no auth)")
    print("9. SSRF in fetch_url() - url parameter")
    print("10. Information Exposure in debug_info() - reveals secret key")
    print("11. Hardcoded Credentials - SECRET_KEY")
    print("="*80)
    
    return result

if __name__ == "__main__":
    asyncio.run(test_vulnerable_flask_api())
