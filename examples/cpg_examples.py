"""
Comprehensive Examples and Test Suite for CPG Parser

Demonstrates Code Property Graph extraction from JavaScript/TypeScript:
- Function declarations and arrow functions
- Class declarations with methods
- Imports and exports
- Call expressions and member access chains
- Lexical scope tracking
- Symbol references
- CFG and DFG extraction

Similar to Joern/CodeQL analysis capabilities.
"""

import json
import logging
import sys
from pathlib import Path

# Add parent directory to path to allow imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.domain.analysis.cpg_parser import CPGParser, LanguageType
from app.domain.analysis.cfg_dfg_extractor import extract_cfg_dfg
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


# ============================================================================
# EXAMPLE 1: Complete JavaScript Application with Security Vulnerabilities
# ============================================================================

EXAMPLE_VULN_APP = """
// Vulnerable Express.js API with multiple security issues

import express from 'express';
import { Pool } from 'pg';
import jwt from 'jsonwebtoken';

const app = express();
const db = new Pool({
    host: 'localhost',
    database: 'myapp'
});

// VULNERABILITY: SQL Injection
async function getUserById(userId) {
    // Bad: String concatenation in SQL query
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    const result = await db.query(query);
    return result.rows[0];
}

// VULNERABILITY: XSS in template
function renderUserProfile(user) {
    return `<div>Welcome, ${user.name}!</div>`;  // Unescaped output
}

// VULNERABILITY: Missing authentication
app.get('/api/admin/users', async (req, res) => {
    // No auth check before sensitive operation
    const users = await db.query('SELECT * FROM users');
    res.json(users.rows);
});

// VULNERABILITY: eval() code injection
app.post('/api/calculate', (req, res) => {
    const expression = req.body.expr;
    const result = eval(expression);  // Dangerous!
    res.json({ result });
});

// Proper authentication (for comparison)
function verifyToken(req, res, next) {
    const token = req.headers['authorization'];
    
    if (!token) {
        return res.status(403).json({ error: 'No token' });
    }
    
    jwt.verify(token, process.env.SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        req.userId = decoded.id;
        next();
    });
}

// Secure endpoint (with auth)
app.get('/api/profile', verifyToken, async (req, res) => {
    const user = await getUserById(req.userId);
    res.json(user);
});

// VULNERABILITY: Prototype pollution
app.post('/api/config', (req, res) => {
    const config = req.body;
    Object.assign(global.appConfig, config);  // Dangerous merge
    res.json({ status: 'updated' });
});

// Class with methods
class UserService {
    constructor(database) {
        this.db = database;
        this.cache = new Map();
    }
    
    async findUser(username) {
        if (this.cache.has(username)) {
            return this.cache.get(username);
        }
        
        // VULNERABILITY: SQL injection
        const query = `SELECT * FROM users WHERE username = '${username}'`;
        const result = await this.db.query(query);
        
        if (result.rows.length > 0) {
            this.cache.set(username, result.rows[0]);
            return result.rows[0];
        }
        
        return null;
    }
    
    async createUser(userData) {
        const { username, email, password } = userData;
        
        // Better: Parameterized query
        const query = 'INSERT INTO users (username, email, password) VALUES ($1, $2, $3)';
        await this.db.query(query, [username, email, password]);
        
        return { username, email };
    }
}

export { app, UserService, verifyToken };
"""


# ============================================================================
# EXAMPLE 2: TypeScript with Complex Features
# ============================================================================

EXAMPLE_TYPESCRIPT = """
// TypeScript example with interfaces, generics, and async/await

interface User {
    id: number;
    username: string;
    email: string;
    roles: string[];
}

interface ApiResponse<T> {
    data: T;
    error?: string;
    timestamp: Date;
}

type AuthResult = {
    token: string;
    user: User;
} | null;

// Generic async function
async function fetchData<T>(url: string): Promise<ApiResponse<T>> {
    try {
        const response = await fetch(url);
        const data = await response.json();
        
        return {
            data,
            timestamp: new Date()
        };
    } catch (error) {
        return {
            data: null as any,
            error: error.message,
            timestamp: new Date()
        };
    }
}

// Class with private fields and async methods
class AuthenticationService {
    private apiUrl: string;
    private tokenCache: Map<string, string>;
    
    constructor(apiUrl: string) {
        this.apiUrl = apiUrl;
        this.tokenCache = new Map();
    }
    
    async authenticate(username: string, password: string): Promise<AuthResult> {
        const response = await fetchData<AuthResult>(
            `${this.apiUrl}/auth/login`
        );
        
        if (response.data) {
            this.tokenCache.set(username, response.data.token);
            return response.data;
        }
        
        return null;
    }
    
    async hasPermission(userId: number, resource: string): Promise<boolean> {
        const user = await fetchData<User>(`${this.apiUrl}/users/${userId}`);
        
        if (!user.data) {
            return false;
        }
        
        return user.data.roles.includes('admin') || 
               user.data.roles.includes(`${resource}:read`);
    }
}

// Arrow functions with destructuring
const processUsers = async (userIds: number[]) => {
    const results = await Promise.all(
        userIds.map(id => fetchData<User>(`/api/users/${id}`))
    );
    
    return results
        .filter(({ data }) => data !== null)
        .map(({ data }) => data);
};

// Closure example
function createRateLimiter(maxRequests: number, windowMs: number) {
    const requests = new Map<string, number[]>();
    
    return (clientId: string): boolean => {
        const now = Date.now();
        const clientRequests = requests.get(clientId) || [];
        
        // Remove old requests
        const recentRequests = clientRequests.filter(
            timestamp => now - timestamp < windowMs
        );
        
        if (recentRequests.length >= maxRequests) {
            return false;
        }
        
        recentRequests.push(now);
        requests.set(clientId, recentRequests);
        return true;
    };
}

export { fetchData, AuthenticationService, processUsers, createRateLimiter };
export type { User, ApiResponse, AuthResult };
"""


# ============================================================================
# TEST FUNCTIONS
# ============================================================================

def test_parse_vulnerable_app():
    """Test parsing vulnerable JavaScript application"""
    print("\n" + "=" * 80)
    print("TEST 1: Parse Vulnerable JavaScript Application")
    print("=" * 80)
    
    parser = CPGParser()
    cpg = parser.parse_code(EXAMPLE_VULN_APP, LanguageType.JAVASCRIPT, "vulnerable_app.js")
    
    print(f"\n📊 CPG Statistics:")
    print(f"  Total nodes: {len(cpg.nodes)}")
    print(f"  Total edges: {len(cpg.edges)}")
    print(f"  Scopes: {len(cpg.scopes)}")
    print(f"  Symbols: {len(cpg.symbol_table)}")
    
    # Analyze functions
    functions = [n for n in cpg.nodes if n.type in (NodeType.FUNCTION, NodeType.ASYNC_FUNCTION, NodeType.ARROW_FUNCTION)]
    print(f"\n🔧 Functions extracted: {len(functions)}")
    for func in functions:
        scope_info = ""
        if func.metadata and func.metadata.scope_id:
            scope_info = f" (scope: {func.metadata.scope_id})"
        async_info = " [async]" if func.metadata and func.metadata.is_async else ""
        print(f"  - {func.name}{async_info} at line {func.line}{scope_info}")
    
    # Analyze classes
    classes = [n for n in cpg.nodes if n.type == NodeType.CLASS]
    print(f"\n📦 Classes extracted: {len(classes)}")
    for cls in classes:
        print(f"  - {cls.name} at line {cls.line}")
    
    # Analyze imports
    imports = [n for n in cpg.nodes if n.type == NodeType.IMPORT]
    print(f"\n📥 Imports extracted: {len(imports)}")
    for imp in imports:
        print(f"  - {imp.name} at line {imp.line}")
    
    # Analyze dangerous calls
    dangerous_calls = []
    for node in cpg.nodes:
        if node.type == NodeType.CALL_EXPRESSION:
            if any(danger in (node.name or "") for danger in ["eval", "exec", "Function"]):
                dangerous_calls.append(node)
    
    print(f"\n⚠️  Dangerous calls found: {len(dangerous_calls)}")
    for call in dangerous_calls:
        print(f"  - {call.name}() at line {call.line}")
        print(f"    Code: {call.source_code[:80]}...")
    
    # Analyze SQL queries (potential injections)
    sql_patterns = []
    for node in cpg.nodes:
        if node.source_code and any(sql in node.source_code for sql in ["SELECT", "INSERT", "UPDATE", "DELETE"]):
            if "${" in node.source_code or "+" in node.source_code:
                sql_patterns.append(node)
    
    print(f"\n🔍 Potential SQL injections: {len(sql_patterns)}")
    for node in sql_patterns:
        print(f"  - Line {node.line}: {node.source_code[:80]}...")
    
    # Show scope hierarchy
    print(f"\n🔭 Scope Hierarchy:")
    for scope_id, scope_info in cpg.scopes.items():
        parent = scope_info.get('parent', 'None')
        scope_type = scope_info.get('type', 'unknown')
        symbols = len(scope_info.get('symbols', {}))
        print(f"  {scope_id} ({scope_type})")
        print(f"    Parent: {parent}")
        print(f"    Symbols: {symbols}")
        if symbols > 0 and symbols < 10:
            for sym in scope_info.get('symbols', {}).keys():
                print(f"      - {sym}")
    
    return cpg


def test_parse_typescript():
    """Test parsing TypeScript with complex features"""
    print("\n" + "=" * 80)
    print("TEST 2: Parse TypeScript with Complex Features")
    print("=" * 80)
    
    parser = CPGParser()
    cpg = parser.parse_code(EXAMPLE_TYPESCRIPT, LanguageType.TYPESCRIPT, "auth_service.ts")
    
    print(f"\n📊 CPG Statistics:")
    print(f"  Total nodes: {len(cpg.nodes)}")
    print(f"  Total edges: {len(cpg.edges)}")
    print(f"  Scopes: {len(cpg.scopes)}")
    
    # Analyze async functions
    async_funcs = [n for n in cpg.nodes if n.type == NodeType.ASYNC_FUNCTION or (n.metadata and n.metadata.is_async)]
    print(f"\n⚡ Async functions: {len(async_funcs)}")
    for func in async_funcs:
        print(f"  - {func.name} at line {func.line}")
    
    # Analyze classes with methods
    classes = [n for n in cpg.nodes if n.type == NodeType.CLASS]
    print(f"\n📦 Classes: {len(classes)}")
    for cls in classes:
        print(f"  - {cls.name} at line {cls.line}")
        # Find methods of this class
        methods = [n for n in cpg.nodes if n.parent_id == cls.id and n.type == NodeType.FUNCTION]
        if methods:
            print(f"    Methods:")
            for method in methods:
                visibility = ""
                if method.metadata and method.metadata.visibility:
                    visibility = f" [{method.metadata.visibility}]"
                print(f"      - {method.name}{visibility}")
    
    # Analyze arrow functions
    arrow_funcs = [n for n in cpg.nodes if n.type == NodeType.ARROW_FUNCTION]
    print(f"\n➡️  Arrow functions: {len(arrow_funcs)}")
    for func in arrow_funcs:
        print(f"  - {func.name} at line {func.line}")
    
    # Symbol table analysis
    print(f"\n📚 Symbol Table:")
    for symbol, refs in cpg.symbol_table.items():
        if len(symbol) > 0 and not symbol.startswith('_'):
            print(f"  {symbol}: {len(refs)} reference(s)")
    
    return cpg


def test_cfg_dfg_extraction():
    """Test CFG and DFG extraction"""
    print("\n" + "=" * 80)
    print("TEST 3: CFG and DFG Extraction")
    print("=" * 80)
    
    simple_code = """
function processData(input) {
    let result = input.trim();
    
    if (result.length > 0) {
        result = result.toUpperCase();
        console.log(result);
    } else {
        result = "empty";
    }
    
    return result;
}

async function fetchAndProcess(url) {
    const data = await fetch(url);
    const json = await data.json();
    const processed = processData(json.value);
    return processed;
}
"""
    
    parser = CPGParser()
    cpg = parser.parse_code(simple_code, LanguageType.JAVASCRIPT, "process.js")
    
    print(f"\n📊 Base CPG:")
    print(f"  Nodes: {len(cpg.nodes)}")
    print(f"  Edges: {len(cpg.edges)}")
    
    # Extract CFG and DFG
    enhanced_cpg = extract_cfg_dfg(cpg)
    
    print(f"\n📊 Enhanced CPG with CFG/DFG:")
    print(f"  Total edges: {len(enhanced_cpg.edges)}")
    
    # Count edge types
    edge_counts = {}
    for edge in enhanced_cpg.edges:
        edge_type = edge.type.value
        edge_counts[edge_type] = edge_counts.get(edge_type, 0) + 1
    
    print(f"\n📈 Edge Type Distribution:")
    for edge_type, count in sorted(edge_counts.items()):
        print(f"  {edge_type}: {count}")
    
    # Show control flow edges
    cf_edges = [e for e in enhanced_cpg.edges if e.type == EdgeType.CONTROL_FLOW]
    print(f"\n🔀 Control Flow Edges: {len(cf_edges)}")
    for edge in cf_edges[:10]:  # Show first 10
        from_node = next((n for n in enhanced_cpg.nodes if n.id == edge.from_node), None)
        to_node = next((n for n in enhanced_cpg.nodes if n.id == edge.to_node), None)
        label = edge.label or "next"
        if from_node and to_node:
            print(f"  {from_node.name or from_node.type.value} -> {to_node.name or to_node.type.value} [{label}]")
    
    # Show data flow edges
    df_edges = [e for e in enhanced_cpg.edges if e.type == EdgeType.DATA_FLOW]
    print(f"\n📊 Data Flow Edges: {len(df_edges)}")
    for edge in df_edges[:10]:  # Show first 10
        from_node = next((n for n in enhanced_cpg.nodes if n.id == edge.from_node), None)
        to_node = next((n for n in enhanced_cpg.nodes if n.id == edge.to_node), None)
        variable = edge.label or "?"
        if from_node and to_node:
            print(f"  {from_node.name or from_node.type.value} -> {to_node.name or to_node.type.value} [{variable}]")
    
    return enhanced_cpg


def export_cpg_to_json(cpg, filename: str):
    """Export CPG to JSON for external analysis"""
    print(f"\n💾 Exporting CPG to {filename}...")
    
    # Convert to JSON-serializable format
    cpg_data = {
        "nodes": [
            {
                "id": node.id,
                "type": node.type.value,
                "name": node.name,
                "file": node.file,
                "line": node.line,
                "column": node.column,
                "source_code": node.source_code,
                "metadata": node.metadata.dict() if node.metadata else None
            }
            for node in cpg.nodes
        ],
        "edges": [
            {
                "from": edge.from_node,
                "to": edge.to_node,
                "type": edge.type.value,
                "label": edge.label
            }
            for edge in cpg.edges
        ],
        "symbol_table": cpg.symbol_table,
        "scopes": cpg.scopes
    }
    
    with open(filename, 'w') as f:
        json.dump(cpg_data, f, indent=2)
    
    print(f"✓ Exported CPG to {filename}")
    print(f"  Size: {Path(filename).stat().st_size:,} bytes")


def main():
    """Run all tests and examples"""
    print("\n" + "=" * 80)
    print("CODE PROPERTY GRAPH (CPG) PARSER - COMPREHENSIVE EXAMPLES")
    print("Similar to Joern/CodeQL")
    print("=" * 80)
    
    # Test 1: Vulnerable app
    cpg1 = test_parse_vulnerable_app()
    export_cpg_to_json(cpg1, "cpg_vulnerable_app.json")
    
    # Test 2: TypeScript
    cpg2 = test_parse_typescript()
    export_cpg_to_json(cpg2, "cpg_typescript.json")
    
    # Test 3: CFG/DFG
    cpg3 = test_cfg_dfg_extraction()
    export_cpg_to_json(cpg3, "cpg_with_cfg_dfg.json")
    
    print("\n" + "=" * 80)
    print("✅ ALL TESTS COMPLETED")
    print("=" * 80)
    print("\nGenerated files:")
    print("  - cpg_vulnerable_app.json")
    print("  - cpg_typescript.json")
    print("  - cpg_with_cfg_dfg.json")
    print("\nThese JSON files can be imported into external analysis tools.")


if __name__ == "__main__":
    main()
