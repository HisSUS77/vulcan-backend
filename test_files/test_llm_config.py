"""
Test LLM configuration and initialization
"""
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

print("="*60)
print("🔍 LLM CONFIGURATION CHECK")
print("="*60)

# Check environment variables
print("\n📋 Environment Variables:")
print(f"  ENABLE_LLM: {os.getenv('ENABLE_LLM')}")
print(f"  LLM_PROVIDER: {os.getenv('LLM_PROVIDER')}")
print(f"  LLM_API_KEY: {os.getenv('LLM_API_KEY')[:20]}..." if os.getenv('LLM_API_KEY') else "  LLM_API_KEY: None")
print(f"  LLM_MODEL_CLASSIFIER: {os.getenv('LLM_MODEL_CLASSIFIER')}")

# Test LLM service initialization
print("\n🔧 Testing LLM Service:")
from semantic_engine.classifier.llm_service import LLMService

try:
    client = LLMService()
    print(f"  ✅ LLM Client initialized")
    print(f"     Provider: {client.provider}")
    print(f"     Model: {client.model}")
    print(f"     API Key present: {client.api_key is not None}")
    print(f"     Client initialized: {client.client is not None}")
    
    # Test a simple call
    print("\n🧪 Testing LLM Call:")
    import asyncio
    
    result = asyncio.run(client.classify_code_slice(
        rule_id="SQL_INJECTION",
        rule_name="SQL Injection",
        rule_description="User input flows to SQL execution without sanitization",
        code_slice="username = request.args.get('username')\ncursor.execute(f'SELECT * FROM users WHERE name={username}')",
        source_node="username",
        sink_node="cursor.execute",
        pattern="DFG_FLOW"
    ))
    
    print(f"  ✅ LLM responded:")
    print(f"     Classification: {result.classification}")
    print(f"     Severity: {result.severity}")
    print(f"     Confidence: {result.confidence}")
    print(f"     Explanation: {result.explanation[:100]}...")
    
except Exception as e:
    print(f"  ❌ Error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*60)
