"""
Comprehensive Test Suite for Tree-sitter UniversalParser

Tests all supported languages and features:
- Python, JavaScript, TypeScript parsing
- Error resilience
- Complex constructs (closures, destructuring, async)
- Adapter conversion to GraphNode
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.domain.analysis.universal_parser import (
    UniversalParser, 
    StandardNode, 
    LanguageType,
    TREE_SITTER_AVAILABLE
)
from app.domain.analysis.parser_adapter import (
    UniversalASTParser,
    StandardToGraphAdapter
)


def test_tree_sitter_available():
    """Test 1: Verify tree-sitter is installed"""
    print("=" * 60)
    print("TEST 1: Tree-sitter Installation Check")
    print("=" * 60)
    
    if TREE_SITTER_AVAILABLE:
        print("✓ tree-sitter is installed")
        return True
    else:
        print("✗ tree-sitter NOT installed")
        print("  Run: pip install tree-sitter")
        return False


def test_parser_initialization():
    """Test 2: Initialize UniversalParser"""
    print("\n" + "=" * 60)
    print("TEST 2: Parser Initialization")
    print("=" * 60)
    
    try:
        parser = UniversalParser()
        available = parser.get_available_languages()
        
        print(f"✓ Parser initialized successfully")
        print(f"  Available languages: {[lang.value for lang in available]}")
        
        if len(available) == 0:
            print("  ⚠ No languages loaded. Run setup_grammars.py first!")
            return False
        
        return True
        
    except Exception as e:
        print(f"✗ Failed to initialize parser: {e}")
        return False


def test_python_parsing():
    """Test 3: Parse Python code"""
    print("\n" + "=" * 60)
    print("TEST 3: Python Parsing")
    print("=" * 60)
    
    python_code = """
def calculate_total(items, tax_rate=0.1):
    '''Calculate total with tax'''
    subtotal = sum(item['price'] for item in items)
    tax = subtotal * tax_rate
    return subtotal + tax

class ShoppingCart:
    def __init__(self):
        self.items = []
    
    def add_item(self, item):
        self.items.append(item)
        
    async def checkout(self):
        total = calculate_total(self.items)
        return total
"""
    
    try:
        parser = UniversalParser()
        tree = parser.parse_code(python_code, LanguageType.PYTHON, "test.py")
        
        if tree is None:
            print("✗ Failed to parse Python code")
            return False
        
        print(f"✓ Parsed Python successfully")
        print(f"  Root type: {tree.type}")
        print(f"  Children: {len(tree.children)}")
        
        # Find specific nodes
        functions = find_nodes_by_type(tree, "function_definition")
        classes = find_nodes_by_type(tree, "class_definition")
        
        print(f"  Functions found: {len(functions)}")
        for func in functions:
            print(f"    - {func.name} at line {func.start_point[0] + 1}")
        
        print(f"  Classes found: {len(classes)}")
        for cls in classes:
            print(f"    - {cls.name} at line {cls.start_point[0] + 1}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error parsing Python: {e}")
        return False


def test_javascript_parsing():
    """Test 4: Parse JavaScript code"""
    print("\n" + "=" * 60)
    print("TEST 4: JavaScript Parsing")
    print("=" * 60)
    
    js_code = """
// Complex JavaScript with modern features
const express = require('express');
const { validateUser, sanitizeInput } = require('./utils');

// Arrow function with destructuring
const handleLogin = async ({ username, password }) => {
    const sanitized = sanitizeInput(username);
    const user = await validateUser(sanitized, password);
    return user;
};

// Regular function
function dangerousEval(userInput) {
    // Security issue!
    return eval(userInput);
}

// Class with methods
class UserService {
    constructor(db) {
        this.db = db;
    }
    
    async findUser(id) {
        return this.db.query(`SELECT * FROM users WHERE id = ${id}`);
    }
}

// Closure
function createCounter() {
    let count = 0;
    return () => ++count;
}

// Export
module.exports = { handleLogin, UserService };
"""
    
    try:
        parser = UniversalParser()
        tree = parser.parse_code(js_code, LanguageType.JAVASCRIPT, "test.js")
        
        if tree is None:
            print("✗ Failed to parse JavaScript code")
            return False
        
        print(f"✓ Parsed JavaScript successfully")
        print(f"  Root type: {tree.type}")
        
        # Find various node types
        functions = find_nodes_by_type(tree, "function_declaration")
        arrow_funcs = find_nodes_by_type(tree, "arrow_function")
        classes = find_nodes_by_type(tree, "class_declaration")
        calls = find_nodes_by_type(tree, "call_expression")
        
        print(f"  Function declarations: {len(functions)}")
        for func in functions:
            print(f"    - {func.name} at line {func.start_point[0] + 1}")
        
        print(f"  Arrow functions: {len(arrow_funcs)}")
        print(f"  Classes: {len(classes)}")
        for cls in classes:
            print(f"    - {cls.name} at line {cls.start_point[0] + 1}")
        
        print(f"  Call expressions: {len(calls)}")
        
        # Find dangerous calls
        dangerous = find_dangerous_calls(tree)
        if dangerous:
            print(f"  ⚠ Dangerous calls found:")
            for call in dangerous:
                print(f"    - {call}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error parsing JavaScript: {e}")
        return False


def test_typescript_parsing():
    """Test 5: Parse TypeScript code"""
    print("\n" + "=" * 60)
    print("TEST 5: TypeScript Parsing")
    print("=" * 60)
    
    ts_code = """
interface User {
    id: number;
    name: string;
    email: string;
}

type RequestHandler = (req: Request, res: Response) => Promise<void>;

class AuthService {
    private users: Map<number, User>;
    
    constructor() {
        this.users = new Map();
    }
    
    async authenticate(username: string, password: string): Promise<User | null> {
        // Authentication logic
        return null;
    }
    
    validateToken(token: string): boolean {
        return token.length > 0;
    }
}

// Generic function
function processItems<T>(items: T[]): T[] {
    return items.filter(item => item !== null);
}

// Async arrow function with type annotation
const fetchUser: RequestHandler = async (req, res) => {
    const userId = req.params.id;
    const user = await db.users.findOne({ id: userId });
    res.json(user);
};

export { AuthService, fetchUser };
"""
    
    try:
        parser = UniversalParser()
        
        if not parser.is_language_supported(LanguageType.TYPESCRIPT):
            print("⚠ TypeScript grammar not loaded, skipping test")
            return True
        
        tree = parser.parse_code(ts_code, LanguageType.TYPESCRIPT, "test.ts")
        
        if tree is None:
            print("✗ Failed to parse TypeScript code")
            return False
        
        print(f"✓ Parsed TypeScript successfully")
        
        classes = find_nodes_by_type(tree, "class_declaration")
        interfaces = find_nodes_by_type(tree, "interface_declaration")
        
        print(f"  Classes: {len(classes)}")
        print(f"  Interfaces: {len(interfaces)}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error parsing TypeScript: {e}")
        return False


def test_error_resilience():
    """Test 6: Handle syntax errors gracefully"""
    print("\n" + "=" * 60)
    print("TEST 6: Error Resilience")
    print("=" * 60)
    
    broken_code = """
def broken_function(
    # Missing closing paren!
    
def working_function():
    return "I should still be parsed!"
    
class WorkingClass:
    def method(self):
        pass
"""
    
    try:
        parser = UniversalParser()
        tree = parser.parse_code(broken_code, LanguageType.PYTHON, "broken.py")
        
        if tree is None:
            print("✗ Parser returned None (should handle errors)")
            return False
        
        # Tree-sitter should still parse the valid parts
        functions = find_nodes_by_type(tree, "function_definition")
        classes = find_nodes_by_type(tree, "class_definition")
        
        print(f"✓ Parser handled errors gracefully")
        print(f"  Still found {len(functions)} functions")
        print(f"  Still found {len(classes)} classes")
        
        if tree.attributes.get("has_error"):
            print(f"  ✓ Error flag correctly set")
        
        return True
        
    except Exception as e:
        print(f"✗ Parser crashed on error: {e}")
        return False


def test_adapter_conversion():
    """Test 7: StandardNode to GraphNode conversion"""
    print("\n" + "=" * 60)
    print("TEST 7: Adapter Conversion")
    print("=" * 60)
    
    code = """
def vulnerable_sql(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query
"""
    
    try:
        parser = UniversalParser()
        adapter = StandardToGraphAdapter()
        
        tree = parser.parse_code(code, LanguageType.PYTHON, "vuln.py")
        graph = adapter.convert(tree, "vuln.py")
        
        print(f"✓ Conversion successful")
        print(f"  StandardNode children: {len(tree.children)}")
        print(f"  GraphNode count: {len(graph.nodes)}")
        print(f"  GraphEdge count: {len(graph.edges)}")
        
        # Check nodes
        print(f"\n  Sample GraphNodes:")
        for node in graph.nodes[:5]:
            print(f"    - {node.type}: {node.name} (line {node.line})")
        
        return True
        
    except Exception as e:
        print(f"✗ Conversion failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_universal_ast_parser():
    """Test 8: Drop-in replacement UniversalASTParser"""
    print("\n" + "=" * 60)
    print("TEST 8: UniversalASTParser (Drop-in Replacement)")
    print("=" * 60)
    
    code = """
function processInput(userInput) {
    const result = eval(userInput);  // Dangerous!
    return result;
}

async function fetchData(url) {
    const response = await fetch(url);
    return response.json();
}
"""
    
    try:
        # This is the drop-in replacement for old ASTParser
        parser = UniversalASTParser(language="javascript")
        graph = parser.parse(code, "test.js")
        
        print(f"✓ UniversalASTParser works!")
        print(f"  Nodes: {len(graph.nodes)}")
        print(f"  Edges: {len(graph.edges)}")
        
        # Find function nodes
        func_nodes = [n for n in graph.nodes if "FUNCTION" in n.type.name]
        print(f"  Function nodes: {len(func_nodes)}")
        for node in func_nodes:
            print(f"    - {node.name} at line {node.line}")
        
        return True
        
    except Exception as e:
        print(f"✗ UniversalASTParser failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_complex_constructs():
    """Test 9: Complex JavaScript constructs"""
    print("\n" + "=" * 60)
    print("TEST 9: Complex JavaScript Constructs")
    print("=" * 60)
    
    complex_js = """
// Destructuring
const { user: { name, email }, settings = {} } = response.data;

// Spread operator
const combined = { ...defaultOptions, ...userOptions };

// Template literals
const message = `Hello ${name}, your email is ${email}`;

// Async/await with try-catch
async function fetchWithRetry(url, retries = 3) {
    try {
        const response = await fetch(url);
        return await response.json();
    } catch (error) {
        if (retries > 0) {
            return fetchWithRetry(url, retries - 1);
        }
        throw error;
    }
}

// Closure with arrow function
const createMultiplier = (factor) => (num) => num * factor;
const double = createMultiplier(2);

// Generator function
function* generateIds() {
    let id = 0;
    while (true) {
        yield ++id;
    }
}
"""
    
    try:
        parser = UniversalParser()
        tree = parser.parse_code(complex_js, LanguageType.JAVASCRIPT, "complex.js")
        
        if tree is None:
            print("✗ Failed to parse complex constructs")
            return False
        
        print(f"✓ Parsed complex constructs successfully")
        
        # Count different node types
        async_funcs = find_nodes_by_type(tree, "function_declaration")
        arrow_funcs = find_nodes_by_type(tree, "arrow_function")
        generators = find_nodes_by_type(tree, "generator_function_declaration")
        
        print(f"  Functions: {len(async_funcs)}")
        print(f"  Arrow functions: {len(arrow_funcs)}")
        print(f"  Generators: {len(generators)}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error parsing complex constructs: {e}")
        return False


# Helper functions

def find_nodes_by_type(tree, node_type):
    """Recursively find all nodes of a specific type"""
    results = []
    
    if tree.type == node_type:
        results.append(tree)
    
    for child in tree.children:
        results.extend(find_nodes_by_type(child, node_type))
    
    return results


def find_dangerous_calls(tree):
    """Find dangerous function calls (eval, exec, etc.)"""
    dangerous = []
    
    if tree.type == "call_expression":
        # Check if it's a dangerous call
        code = tree.source_code.strip()
        if code.startswith(("eval(", "exec(", "Function(")):
            dangerous.append(f"{tree.source_code[:30]}... at line {tree.start_point[0] + 1}")
    
    for child in tree.children:
        dangerous.extend(find_dangerous_calls(child))
    
    return dangerous


def run_all_tests():
    """Run all tests and report results"""
    print("\n" + "=" * 60)
    print("TREE-SITTER UNIVERSAL PARSER TEST SUITE")
    print("=" * 60)
    
    tests = [
        test_tree_sitter_available,
        test_parser_initialization,
        test_python_parsing,
        test_javascript_parsing,
        test_typescript_parsing,
        test_error_resilience,
        test_adapter_conversion,
        test_universal_ast_parser,
        test_complex_constructs,
    ]
    
    results = []
    for test in tests:
        try:
            passed = test()
            results.append((test.__name__, passed))
        except Exception as e:
            print(f"\n✗ Test crashed: {e}")
            import traceback
            traceback.print_exc()
            results.append((test.__name__, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n⚠ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    exit(exit_code)
