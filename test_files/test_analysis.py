"""
Test script for the semantic analysis pipeline.
Run this to verify the analysis features work correctly.
"""
from app.services.analysis_service import AnalysisService


def test_sql_injection():
    """Test SQL injection detection."""
    vulnerable_code = '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
'''
    
    service = AnalysisService()
    result = service.analyze_code(vulnerable_code, language="python", filename="test.py")
    
    print("=" * 60)
    print("SQL INJECTION TEST")
    print("=" * 60)
    print(f"Graph nodes: {len(result['graph']['nodes'])}")
    print(f"Graph edges: {len(result['graph']['edges'])}")
    print(f"Vulnerabilities found: {len(result['vulnerabilities'])}")
    
    if result['vulnerabilities']:
        for i, vuln in enumerate(result['vulnerabilities'], 1):
            print(f"\n--- Vulnerability {i} ---")
            print(f"Severity: {vuln['severity']}")
            print(f"Source: {vuln['source']['name']} (line {vuln['source']['line']})")
            print(f"Sink: {vuln['sink']['name']} (line {vuln['sink']['line']})")
            print(f"Explanation: {vuln['explanation']}")
            print(f"Recommended Fix: {vuln['recommended_fix']}")
            if vuln.get('patch'):
                print(f"Patch:\n{vuln['patch']}")
    else:
        print("No vulnerabilities detected.")
    
    print("\n")


def test_command_injection():
    """Test command injection detection."""
    vulnerable_code = '''
import os

def run_command(filename):
    os.system("cat " + filename)
'''
    
    service = AnalysisService()
    result = service.analyze_code(vulnerable_code, language="python", filename="test.py")
    
    print("=" * 60)
    print("COMMAND INJECTION TEST")
    print("=" * 60)
    print(f"Graph nodes: {len(result['graph']['nodes'])}")
    print(f"Graph edges: {len(result['graph']['edges'])}")
    print(f"Vulnerabilities found: {len(result['vulnerabilities'])}")
    
    if result['vulnerabilities']:
        for i, vuln in enumerate(result['vulnerabilities'], 1):
            print(f"\n--- Vulnerability {i} ---")
            print(f"Severity: {vuln['severity']}")
            print(f"Source: {vuln['source']['name']} (line {vuln['source']['line']})")
            print(f"Sink: {vuln['sink']['name']} (line {vuln['sink']['line']})")
            print(f"Explanation: {vuln['explanation']}")
    else:
        print("No vulnerabilities detected.")
    
    print("\n")


def test_safe_code():
    """Test that safe code doesn't trigger false positives."""
    safe_code = '''
def add_numbers(a, b):
    return a + b

result = add_numbers(5, 10)
print(result)
'''
    
    service = AnalysisService()
    result = service.analyze_code(safe_code, language="python", filename="test.py")
    
    print("=" * 60)
    print("SAFE CODE TEST")
    print("=" * 60)
    print(f"Graph nodes: {len(result['graph']['nodes'])}")
    print(f"Graph edges: {len(result['graph']['edges'])}")
    print(f"Vulnerabilities found: {len(result['vulnerabilities'])}")
    
    if result['vulnerabilities']:
        print("⚠️  False positive detected!")
        for vuln in result['vulnerabilities']:
            print(f"  - {vuln['explanation']}")
    else:
        print("✓ No vulnerabilities (as expected)")
    
    print("\n")


if __name__ == "__main__":
    print("\n🔍 Testing Semantic Analysis Pipeline\n")
    
    test_sql_injection()
    test_command_injection()
    test_safe_code()
    
    print("=" * 60)
    print("✅ All tests completed!")
    print("=" * 60)
