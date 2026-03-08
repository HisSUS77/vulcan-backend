"""
Vulcan Backend - Installation and Setup Verification Script
============================================================
This script verifies all dependencies and configurations are correct.
"""
import sys
from pathlib import Path
import importlib

print("=" * 70)
print(" VULCAN BACKEND - INSTALLATION VERIFICATION")
print("=" * 70)

# Check Python version
print(f"\n1. Python Version: {sys.version}")
required_version = (3, 8)
if sys.version_info < required_version:
    print(f"   ❌ FAIL: Python {required_version[0]}.{required_version[1]}+ required")
    sys.exit(1)
else:
    print(f"   ✅ PASS: Python version OK")

# Check required packages
print("\n2. Required Packages:")
critical_packages = {
    'fastapi': 'FastAPI web framework',
    'uvicorn': 'ASGI server',
    'pydantic': 'Data validation',
    'motor': 'MongoDB async driver',
    'tree_sitter': 'Tree-sitter parser',
    'tree_sitter_languages': 'Pre-built language grammars',
}

all_ok = True
for pkg_name, description in critical_packages.items():
    try:
        mod = importlib.import_module(pkg_name)
        version = getattr(mod, '__version__', 'unknown')
        print(f"   ✅ {pkg_name} ({version}) - {description}")
    except ImportError:
        print(f"   ❌ {pkg_name} - {description} [NOT INSTALLED]")
        all_ok = False

if not all_ok:
    print("\n   ❌ FAIL: Missing required packages")
    print("   Install with: pip install -r requirements.txt")
    sys.exit(1)

# Check tree-sitter languages
print("\n3. Tree-sitter Language Support:")
try:
    from tree_sitter_languages import get_language, get_parser
    
    languages_to_test = ['python', 'javascript', 'typescript']
    for lang in languages_to_test:
        try:
            get_language(lang)
            print(f"   ✅ {lang.capitalize()} grammar loaded")
        except Exception as e:
            print(f"   ❌ {lang.capitalize()} grammar failed: {e}")
            all_ok = False
except Exception as e:
    print(f"   ❌ tree-sitter-languages import failed: {e}")
    all_ok = False

# Check CPG Parser
print("\n4. CPG Parser:")
try:
    from app.domain.analysis.cpg_parser import CPGParser, LanguageType
    parser = CPGParser()
    print(f"   ✅ CPG Parser initialized")
    print(f"   ✅ Available languages: {parser.available_languages()}")
    
    # Test parse
    test_code = "def test(): pass"
    graph = parser.parse_code(test_code, LanguageType.PYTHON, "test.py")
    func_nodes = [n for n in graph.nodes if 'FUNCTION' in str(n.type)]
    if func_nodes:
        print(f"   ✅ Function extraction works ({len(func_nodes)} functions found)")
    else:
        print(f"   ⚠️  Warning: No functions extracted from test code")
except Exception as e:
    print(f"   ❌ CPG Parser failed: {e}")
    import traceback
    traceback.print_exc()
    all_ok = False

# Check Interprocedural DFG
print("\n5. Interprocedural DFG:")
try:
    from app.domain.analysis.interprocedural_dfg import InterproceduralDFG
    from app.domain.analysis.cpg_parser import CPGParser, LanguageType
    
    parser = CPGParser()
    test_code = """
def foo(x):
    return x + 1

def bar():
    result = foo(5)
    return result
"""
    graph = parser.parse_code(test_code, LanguageType.PYTHON, "test.py")
    dfg = InterproceduralDFG(graph)
    enhanced_graph = dfg.build()
    
    print(f"   ✅ DFG Builder works")
    print(f"   ✅ Functions extracted: {len([k for k in dfg.functions.keys() if isinstance(k, str)])}")
    print(f"   ✅ DFG edges: {len([e for e in enhanced_graph.edges if 'DFG' in str(e.type)])}")
except Exception as e:
    print(f"   ❌ DFG Builder failed: {e}")
    import traceback
    traceback.print_exc()
    all_ok = False

# Check test repository files
print("\n6. Test Repository Files:")
test_repo = Path("test_vuln_repo")
if not test_repo.exists():
    print(f"   ❌ Test repository not found: {test_repo}")
    all_ok = False
else:
    expected_files = ['app.py', 'server.py', 'vuln_cmd_injection.py', 'vuln_sqli.py']
    for filename in expected_files:
        file_path = test_repo / filename
        if file_path.exists():
            print(f"   ✅ {filename} exists")
        else:
            print(f"   ❌ {filename} missing")
            all_ok = False

# Check configuration
print("\n7. Configuration:")
try:
    from app.core.config import settings
    print(f"   ✅ Settings loaded")
    print(f"   ✅ MongoDB URI: {settings.MONGO_URI[:30]}...")
    print(f"   ✅ Repo storage: {settings.REPO_STORAGE_DIR}")
except Exception as e:
    print(f"   ⚠️  Configuration warning: {e}")

# Final summary
print("\n" + "=" * 70)
if all_ok:
    print(" ✅ ALL CHECKS PASSED - System is ready!")
    print("=" * 70)
    print("\nNext steps:")
    print("1. Start MongoDB if not already running")
    print("2. Run the backend: uvicorn app.main:app --reload")
    print("3. Access API docs: http://localhost:8000/docs")
    sys.exit(0)
else:
    print(" ❌ SOME CHECKS FAILED - Please fix the issues above")
    print("=" * 70)
    sys.exit(1)
