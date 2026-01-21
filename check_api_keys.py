"""
Quick API key validation script - checks format and basic connectivity
"""
import os
from dotenv import load_dotenv

load_dotenv()

def check_api_key_format():
    print("\n🔑 API Key Validation\n" + "="*60)
    
    # GitHub PAT
    github_key = os.getenv('LLM_API_KEY', '')
    if github_key:
        if github_key.startswith('github_pat_'):
            print(f"✅ GitHub PAT: Valid format")
            print(f"   Prefix: {github_key[:20]}...")
        else:
            print(f"⚠️  GitHub PAT: Invalid format (should start with 'github_pat_')")
    else:
        print(f"❌ GitHub PAT: Not configured")
    
    # Groq API Key
    groq_key = os.getenv('GROQ_API_KEY', '')
    if groq_key:
        if groq_key.startswith('gsk_'):
            print(f"✅ Groq API Key: Valid format")
            print(f"   Prefix: {groq_key[:20]}...")
        else:
            print(f"⚠️  Groq API Key: Invalid format (should start with 'gsk_')")
    else:
        print(f"❌ Groq API Key: Not configured")
    
    # OpenAI (optional)
    openai_key = os.getenv('OPENAI_API_KEY', '')
    if openai_key:
        if openai_key.startswith('sk-'):
            print(f"✅ OpenAI API Key: Valid format")
        else:
            print(f"⚠️  OpenAI API Key: Invalid format (should start with 'sk-')")
    else:
        print(f"ℹ️  OpenAI API Key: Not configured (optional)")
    
    # Anthropic (optional)
    anthropic_key = os.getenv('ANTHROPIC_API_KEY', '')
    if anthropic_key:
        if anthropic_key.startswith('sk-ant-'):
            print(f"✅ Anthropic API Key: Valid format")
        else:
            print(f"⚠️  Anthropic API Key: Invalid format (should start with 'sk-ant-')")
    else:
        print(f"ℹ️  Anthropic API Key: Not configured (optional)")
    
    print("\n" + "="*60)
    print("Configuration Summary:")
    print(f"  Primary Provider: {os.getenv('LLM_PROVIDER', 'not set')}")
    print(f"  Primary Model: {os.getenv('LLM_MODEL_CLASSIFIER', 'not set')}")
    print(f"  Fallback Available: {'Yes' if groq_key else 'No'}")
    
    if github_key and groq_key:
        print("\n✅ Ready for LLM-powered vulnerability detection!")
    elif groq_key:
        print("\n⚠️  Only Groq configured - consider adding GitHub Models")
    else:
        print("\n❌ No LLM providers configured - vulnerability detection will use pattern-based only")

if __name__ == "__main__":
    check_api_key_format()
