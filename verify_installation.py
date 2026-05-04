"""
Vulcan Backend - Installation and Setup Verification Script
===========================================================
This script verifies all dependencies and configurations are correct.
"""

import importlib
import sys
from pathlib import Path

PASS = "[PASS]"
FAIL = "[FAIL]"
WARN = "[WARN]"


def main() -> int:
    print("=" * 70)
    print(" VULCAN BACKEND - INSTALLATION VERIFICATION")
    print("=" * 70)

    print(f"\n1. Python Version: {sys.version}")
    required_version = (3, 8)
    if sys.version_info < required_version:
        print(f"   {FAIL} Python {required_version[0]}.{required_version[1]}+ required")
        return 1
    print(f"   {PASS} Python version OK")

    print("\n2. Required Packages:")
    critical_packages = {
        "fastapi": "FastAPI web framework",
        "uvicorn": "ASGI server",
        "pydantic": "Data validation",
        "motor": "MongoDB async driver",
        "tree_sitter": "Tree-sitter parser",
        "tree_sitter_languages": "Pre-built language grammars",
    }

    all_ok = True
    for pkg_name, description in critical_packages.items():
        try:
            mod = importlib.import_module(pkg_name)
            version = getattr(mod, "__version__", "unknown")
            print(f"   {PASS} {pkg_name} ({version}) - {description}")
        except ImportError:
            print(f"   {FAIL} {pkg_name} - {description} [NOT INSTALLED]")
            all_ok = False

    if not all_ok:
        print(f"\n   {FAIL} Missing required packages")
        print("   Install with: pip install -r requirements.txt")
        return 1

    print("\n3. Tree-sitter Language Support:")
    try:
        from app.domain.analysis.cpg_parser import CPGParser

        parser = CPGParser()
        available_languages = set(parser.available_languages())
        for lang in ["python", "javascript", "typescript"]:
            if lang in available_languages:
                print(f"   {PASS} {lang.capitalize()} grammar loaded")
            else:
                print(f"   {FAIL} {lang.capitalize()} grammar unavailable")
                all_ok = False
    except Exception as exc:
        print(f"   {FAIL} Grammar loading failed: {exc}")
        all_ok = False

    print("\n4. CPG Parser:")
    try:
        from app.domain.analysis.cpg_parser import CPGParser, LanguageType

        parser = CPGParser()
        print(f"   {PASS} CPG Parser initialized")
        print(f"   {PASS} Available languages: {parser.available_languages()}")

        test_code = "def test(): pass"
        graph = parser.parse_code(test_code, LanguageType.PYTHON, "test.py")
        func_nodes = [n for n in graph.nodes if "FUNCTION" in str(n.type)]
        if func_nodes:
            print(f"   {PASS} Function extraction works ({len(func_nodes)} functions found)")
        else:
            print(f"   {WARN} No functions extracted from test code")
    except Exception as exc:
        print(f"   {FAIL} CPG Parser failed: {exc}")
        import traceback

        traceback.print_exc()
        all_ok = False

    print("\n5. Interprocedural DFG:")
    try:
        from app.domain.analysis.cpg_parser import CPGParser, LanguageType
        from app.domain.analysis.interprocedural_dfg import InterproceduralDFG

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

        print(f"   {PASS} DFG Builder works")
        print(f"   {PASS} Functions extracted: {len([k for k in dfg.functions.keys() if isinstance(k, str)])}")
        print(f"   {PASS} DFG edges: {len([e for e in enhanced_graph.edges if 'DFG' in str(e.type)])}")
    except Exception as exc:
        print(f"   {FAIL} DFG Builder failed: {exc}")
        import traceback

        traceback.print_exc()
        all_ok = False

    print("\n6. Test Repository Files:")
    test_repo = Path("test_vuln_repo")
    if not test_repo.exists():
        print(f"   {FAIL} Test repository not found: {test_repo}")
        all_ok = False
    else:
        expected_files = ["app.py", "server.py", "vuln_cmd_injection.py", "vuln_sqli.py"]
        for filename in expected_files:
            file_path = test_repo / filename
            if file_path.exists():
                print(f"   {PASS} {filename} exists")
            else:
                print(f"   {FAIL} {filename} missing")
                all_ok = False

    print("\n7. Configuration:")
    try:
        from app.core.config import settings

        print(f"   {PASS} Settings loaded")
        print(f"   {PASS} MongoDB URI: {settings.MONGO_URI[:30]}...")
        print(f"   {PASS} Repo storage: {settings.REPO_STORAGE_DIR}")
    except Exception as exc:
        print(f"   {WARN} Configuration warning: {exc}")

    print("\n" + "=" * 70)
    if all_ok:
        print(f" {PASS} ALL CHECKS PASSED - System is ready!")
        print("=" * 70)
        print("\nNext steps:")
        print("1. Start MongoDB if not already running")
        print("2. Run the backend: uvicorn app.main:app --reload")
        print("3. Access API docs: http://localhost:8000/docs")
        return 0

    print(f" {FAIL} SOME CHECKS FAILED - Please fix the issues above")
    print("=" * 70)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
