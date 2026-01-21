"""
Test script to verify LLM provider configurations and fallback mechanisms.
"""
import asyncio
import os
from dotenv import load_dotenv
from semantic_engine.classifier.llm_service import LLMService

# Load environment variables
load_dotenv()

async def test_primary_provider():
    """Test the primary LLM provider."""
    print("\n" + "="*60)
    print("Testing Primary Provider")
    print("="*60)
    
    provider = os.getenv('LLM_PROVIDER', 'not set')
    api_key = os.getenv('LLM_API_KEY', 'not set')
    model = os.getenv('LLM_MODEL_CLASSIFIER', 'not set')
    
    print(f"Provider: {provider}")
    print(f"Model: {model}")
    print(f"API Key: {'✓ Configured' if api_key != 'not set' and api_key else '✗ Not set'}")
    
    if api_key == 'not set' or not api_key:
        print("⚠️  Primary provider not configured!")
        return False
    
    # Initialize LLM service
    llm_service = LLMService()
    
    # Test with a simple SQL injection example
    test_code = """
@app.route('/user/<user_id>')
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    result = db.execute(query)
    return result
"""
    
    try:
        result = await llm_service.classify_code_slice(
            code_snippet=test_code,
            rule_name="SQL Injection",
            rule_description="Direct user input in SQL query without sanitization",
            source_label="request.args",
            sink_label="db.execute",
            owasp="A03:2021 – Injection",
            cwe="CWE-89"
        )
        
        print(f"\n✓ Classification: {result.classification}")
        print(f"✓ Severity: {result.severity}")
        print(f"✓ Confidence: {result.confidence:.2f}")
        print(f"✓ Explanation: {result.explanation[:100]}...")
        return True
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        return False

async def test_groq_fallback():
    """Test Groq fallback provider."""
    print("\n" + "="*60)
    print("Testing Groq Fallback")
    print("="*60)
    
    groq_key = os.getenv('GROQ_API_KEY', 'not set')
    groq_model = os.getenv('GROQ_MODEL', 'llama-3.3-70b-versatile')
    
    print(f"Groq API Key: {'✓ Configured' if groq_key != 'not set' and groq_key else '✗ Not set'}")
    print(f"Groq Model: {groq_model}")
    
    if groq_key == 'not set' or not groq_key:
        print("⚠️  Groq fallback not configured!")
        return False
    
    # Initialize with Groq directly
    llm_service = LLMService(provider='groq', api_key=groq_key, model=groq_model)
    
    test_code = """
@app.route('/eval')
def evaluate():
    user_input = request.args.get('code')
    result = eval(user_input)
    return str(result)
"""
    
    try:
        result = await llm_service.classify_code_slice(
            code_snippet=test_code,
            rule_name="Code Injection",
            rule_description="Unsafe eval() with user input",
            source_label="request.args",
            sink_label="eval",
            owasp="A03:2021 – Injection",
            cwe="CWE-95"
        )
        
        print(f"\n✓ Classification: {result.classification}")
        print(f"✓ Severity: {result.severity}")
        print(f"✓ Confidence: {result.confidence:.2f}")
        print(f"✓ Explanation: {result.explanation[:100]}...")
        return True
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        return False

async def test_automatic_fallback():
    """Test automatic fallback when primary fails."""
    print("\n" + "="*60)
    print("Testing Automatic Fallback Mechanism")
    print("="*60)
    
    # Initialize with invalid primary provider to trigger fallback
    llm_service = LLMService(
        provider='github',
        api_key='invalid_key_to_trigger_fallback',
        model='meta/Llama-4-Scout-17B-16E-Instruct'
    )
    
    test_code = """
import os
command = request.form['cmd']
os.system(command)
"""
    
    try:
        print("Attempting classification with invalid primary key (should fallback to Groq)...")
        result = await llm_service.classify_code_slice(
            code_snippet=test_code,
            rule_name="Command Injection",
            rule_description="Direct execution of user input",
            source_label="request.form",
            sink_label="os.system",
            owasp="A03:2021 – Injection",
            cwe="CWE-78"
        )
        
        print(f"\n✓ Fallback successful!")
        print(f"✓ Classification: {result.classification}")
        print(f"✓ Provider used: {llm_service.current_provider}")
        return True
        
    except Exception as e:
        print(f"\n✗ Fallback test failed: {e}")
        return False

async def main():
    """Run all tests."""
    print("\n🔍 LLM Provider Configuration Test")
    print("="*60)
    
    results = {
        'primary': await test_primary_provider(),
        'groq': await test_groq_fallback(),
        'fallback': await test_automatic_fallback()
    }
    
    print("\n" + "="*60)
    print("Test Summary")
    print("="*60)
    print(f"Primary Provider: {'✓ PASS' if results['primary'] else '✗ FAIL'}")
    print(f"Groq Fallback: {'✓ PASS' if results['groq'] else '✗ FAIL'}")
    print(f"Auto Fallback: {'✓ PASS' if results['fallback'] else '✗ FAIL'}")
    
    if all(results.values()):
        print("\n✅ All tests passed! LLM vulnerability detection is working.")
    elif results['groq']:
        print("\n⚠️  Primary provider failed but Groq fallback works!")
    else:
        print("\n❌ LLM detection not working properly. Check your API keys.")

if __name__ == "__main__":
    asyncio.run(main())
