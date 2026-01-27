"""
Simple Multi-File Repository Graph Test
========================================

Basic test to verify the core multi-file graph infrastructure works.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.domain.analysis.multi_file_repo_graph import (
    GlobalSymbolTable,
    ModuleDefinition,
    ExportedSymbol,
    ImportedSymbol,
    RepositoryScanner
)

def test_global_symbol_table():
    """Test 1: Global Symbol Table"""
    print("\n" + "="*60)
    print("TEST 1: Global Symbol Table")
    print("="*60)
    
    # Create symbol table
    symbol_table = GlobalSymbolTable()
    
    # Create a mock module
    module = ModuleDefinition(
        module_name="utils",
        file_path="/path/to/utils.py",
        language="python",
        exports=[
            ExportedSymbol(
                name="sanitize_sql",
                file_path="/path/to/utils.py",
                node_id="node_123",
                export_type="function"
            )
        ],
        imports=[],
        cpg=None
    )
    
    # Add module
    symbol_table.add_module(module)
    
    # Test export lookup
    print("\n✅ Adding module to symbol table...")
    exports = symbol_table.find_export("sanitize_sql")
    
    if exports:
        print(f"✅ Found {len(exports)} export(s) for 'sanitize_sql'")
        for exp in exports:
            print(f"   - File: {exp.file_path}")
            print(f"   - Type: {exp.export_type}")
            print(f"   - Node: {exp.node_id}")
    else:
        print("❌ Export not found!")
        return False
    
    # Test get_module
    retrieved = symbol_table.file_to_module.get("/path/to/utils.py")
    if retrieved:
        print(f"\n✅ Retrieved module by path:")
        print(f"   - Name: {retrieved.module_name}")
        print(f"   - Language: {retrieved.language}")
    else:
        print("❌ Module retrieval failed!")
        return False
    
    print("\n🎉 Symbol Table test passed!")
    return True


def test_repository_scanner():
    """Test 2: Repository Scanner"""
    print("\n" + "="*60)
    print("TEST 2: Repository Scanner")
    print("="*60)
    
    # Create a small test directory
    import tempfile
    import shutil
    test_dir = Path(tempfile.mkdtemp(prefix="test_scan_"))
    
    try:
        # Create test files
        (test_dir / "module1.py").write_text("def test(): pass")
        (test_dir / "module2.js").write_text("function test() {}")
        (test_dir / "app.ts").write_text("const x = 1;")
        (test_dir / "__pycache__").mkdir()
        (test_dir / "__pycache__" / "cached.pyc").write_text("")
        
        print(f"\n📁 Scanning test directory: {test_dir}")
        
        scanner = RepositoryScanner(
            repo_path=str(test_dir),
            exclude_patterns=['__pycache__', '.venv', 'node_modules']
        )
    
        files = scanner.scan()
        
        # Count by extension
        py_files = [f for f in files if f.suffix == '.py']
        js_files = [f for f in files if f.suffix in ['.js', '.jsx']]
        ts_files = [f for f in files if f.suffix in ['.ts', '.tsx']]
        
        print(f"\n📊 Scan Results:")
        print(f"   Total files: {len(files)}")
        print(f"   Python files (.py): {len(py_files)}")
        print(f"   JavaScript files (.js, .jsx): {len(js_files)}")
        print(f"   TypeScript files (.ts, .tsx): {len(ts_files)}")
        
        # Show all files
        print(f"\n📄 Discovered files:")
        for f in sorted(files):
            print(f"   - {f.name}")
        
        # Verify exclusions work
        pycache_files = [f for f in files if '__pycache__' in str(f)]
        if pycache_files:
            print(f"\n❌ Exclusion failed: Found {len(pycache_files)} __pycache__ files")
            return False
        
        # Verify expected files found
        if len(py_files) != 1 or len(js_files) != 1 or len(ts_files) != 1:
            print(f"\n❌ Expected 1 Python, 1 JavaScript, 1 TypeScript file")
            return False
        
        print("\n🎉 Repository Scanner test passed!")
        return True
    finally:
        # Cleanup
        shutil.rmtree(test_dir, ignore_errors=True)


def test_import_export_dataclasses():
    """Test 3: Import/Export dataclasses"""
    print("\n" + "="*60)
    print("TEST 3: Import/Export Dataclasses")
    print("="*60)
    
    # Test ExportedSymbol
    export = ExportedSymbol(
        name="my_function",
        file_path="/path/to/file.py",
        node_id="node_456",
        export_type="function",
        is_default=False
    )
    
    print(f"\n✅ Created ExportedSymbol:")
    print(f"   Name: {export.name}")
    print(f"   File: {export.file_path}")
    print(f"   Type: {export.export_type}")
    print(f"   Default: {export.is_default}")
    
    # Test ImportedSymbol
    imported = ImportedSymbol(
        name="imported_func",
        source_module="utils",
        file_path="/path/to/api.py",
        node_id="node_789",
        import_type="PYTHON_IMPORT",
        alias=None,
        is_wildcard=False
    )
    
    print(f"\n✅ Created ImportedSymbol:")
    print(f"   Name: {imported.name}")
    print(f"   From: {imported.source_module}")
    print(f"   File: {imported.file_path}")
    print(f"   Type: {imported.import_type}")
    print(f"   Wildcard: {imported.is_wildcard}")
    
    # Test ModuleDefinition
    module = ModuleDefinition(
        module_name="test_module",
        file_path="/path/to/test.py",
        language="python",
        exports=[export],
        imports=[imported],
        cpg=None
    )
    
    print(f"\n✅ Created ModuleDefinition:")
    print(f"   Module: {module.module_name}")
    print(f"   Language: {module.language}")
    print(f"   Exports: {len(module.exports)}")
    print(f"   Imports: {len(module.imports)}")
    
    print("\n🎉 Dataclass test passed!")
    return True


def run_basic_tests():
    """Run basic infrastructure tests"""
    print("\n" + "="*70)
    print(" MULTI-FILE REPOSITORY GRAPH - BASIC INFRASTRUCTURE TESTS")
    print("="*70)
    
    tests = [
        ("Global Symbol Table", test_global_symbol_table),
        ("Repository Scanner", test_repository_scanner),
        ("Import/Export Dataclasses", test_import_export_dataclasses),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            passed = test_func()
            results.append((test_name, "✅ PASSED" if passed else "❌ FAILED", None))
        except Exception as e:
            results.append((test_name, f"❌ FAILED: {str(e)}", None))
            print(f"\n⚠️  Error in {test_name}: {e}")
            import traceback
            traceback.print_exc()
    
    # Summary
    print("\n" + "="*70)
    print(" TEST SUMMARY")
    print("="*70)
    
    for name, status, _ in results:
        print(f"{status} {name}")
    
    passed = sum(1 for _, status, _ in results if "PASSED" in status)
    total = len(results)
    
    print(f"\n✓ {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL BASIC TESTS PASSED!")
        print("\nThe multi-file repository graph infrastructure is working correctly.")
        print("Core components tested:")
        print("  ✅ GlobalSymbolTable (symbol tracking)")
        print("  ✅ RepositoryScanner (file discovery)")
        print("  ✅ Data structures (ExportedSymbol, ImportedSymbol, ModuleDefinition)")
    else:
        print("\n⚠️  Some tests failed. Review output above for details.")


if __name__ == "__main__":
    run_basic_tests()
