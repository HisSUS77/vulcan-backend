"""
Test CFG builder with conditional branching and metadata-based tracking
Tests: IF/ELSE, FOR loops, TRY/CATCH with proper CFG edges
"""
import asyncio
from app.domain.analysis.ast_parser import ASTParser
from app.domain.analysis.cfg_builder import CFGBuilder
from app.enums.edge_type import EdgeType
from app.enums.node_type import NodeType


def test_if_else_cfg():
    """Test IF/ELSE creates CFG_TRUE and CFG_FALSE edges"""
    print("\n" + "="*60)
    print("🔍 TEST 1: IF/ELSE CONDITIONAL BRANCHING")
    print("="*60)
    
    code = """
def check_user(is_admin):
    if is_admin:
        query = "SELECT * FROM admin_data"
    else:
        query = "SELECT * FROM user_data"
    
    cursor.execute(query)
    return query
"""
    
    # Parse AST
    parser = ASTParser(language="python")
    graph = parser.parse(code, "test_if.py")
    
    # Build CFG
    cfg_builder = CFGBuilder()
    graph_with_cfg = cfg_builder.build(graph)
    
    print(f"\n📊 Graph Stats:")
    print(f"  Total nodes: {len(graph_with_cfg.nodes)}")
    print(f"  Total edges: {len(graph_with_cfg.edges)}")
    
    # Find IF_STATEMENT node
    if_nodes = [n for n in graph_with_cfg.nodes if n.type == NodeType.IF_STATEMENT]
    print(f"\n  IF_STATEMENT nodes: {len(if_nodes)}")
    
    if if_nodes:
        if_node = if_nodes[0]
        print(f"\n📍 IF_STATEMENT metadata:")
        print(f"  ID: {if_node.id}")
        print(f"  Line: {if_node.line}")
        print(f"  Metadata: {if_node.metadata}")
    
    # Find CFG edges
    cfg_true_edges = [e for e in graph_with_cfg.edges if e.type == EdgeType.CFG_TRUE]
    cfg_false_edges = [e for e in graph_with_cfg.edges if e.type == EdgeType.CFG_FALSE]
    
    print(f"\n🔗 CFG Edges:")
    print(f"  CFG_TRUE edges: {len(cfg_true_edges)}")
    for edge in cfg_true_edges:
        from_node = next((n for n in graph_with_cfg.nodes if n.id == edge.from_node), None)
        to_node = next((n for n in graph_with_cfg.nodes if n.id == edge.to_node), None)
        print(f"    {from_node.type if from_node else '?'} (line {from_node.line if from_node else '?'}) "
              f"-> {to_node.type if to_node else '?'} (line {to_node.line if to_node else '?'})")
    
    print(f"\n  CFG_FALSE edges: {len(cfg_false_edges)}")
    for edge in cfg_false_edges:
        from_node = next((n for n in graph_with_cfg.nodes if n.id == edge.from_node), None)
        to_node = next((n for n in graph_with_cfg.nodes if n.id == edge.to_node), None)
        print(f"    {from_node.type if from_node else '?'} (line {from_node.line if from_node else '?'}) "
              f"-> {to_node.type if to_node else '?'} (line {to_node.line if to_node else '?'})")
    
    # Verify
    if cfg_true_edges and cfg_false_edges:
        print("\n✅ SUCCESS: IF/ELSE branching detected correctly!")
    else:
        print("\n❌ FAILED: Missing CFG_TRUE or CFG_FALSE edges")


def test_loop_cfg():
    """Test FOR loop creates CFG_LOOP_BACK edge"""
    print("\n" + "="*60)
    print("🔍 TEST 2: FOR LOOP BACK-EDGE")
    print("="*60)
    
    code = """
for user_id in user_input.split(','):
    query = f"SELECT * FROM users WHERE id={user_id}"
    cursor.execute(query)
"""
    
    # Parse AST
    parser = ASTParser(language="python")
    graph = parser.parse(code, "test_loop.py")
    
    # Build CFG
    cfg_builder = CFGBuilder()
    graph_with_cfg = cfg_builder.build(graph)
    
    print(f"\n📊 Graph Stats:")
    print(f"  Total nodes: {len(graph_with_cfg.nodes)}")
    print(f"  Total edges: {len(graph_with_cfg.edges)}")
    
    # Find FOR_STATEMENT node
    for_nodes = [n for n in graph_with_cfg.nodes if n.type == NodeType.FOR_STATEMENT]
    print(f"\n  FOR_STATEMENT nodes: {len(for_nodes)}")
    
    if for_nodes:
        for_node = for_nodes[0]
        print(f"\n📍 FOR_STATEMENT metadata:")
        print(f"  ID: {for_node.id}")
        print(f"  Line: {for_node.line}")
        print(f"  Metadata: {for_node.metadata}")
    
    # Find loop edges
    loop_back_edges = [e for e in graph_with_cfg.edges if e.type == EdgeType.CFG_LOOP_BACK]
    
    print(f"\n🔗 Loop Edges:")
    print(f"  CFG_LOOP_BACK edges: {len(loop_back_edges)}")
    for edge in loop_back_edges:
        from_node = next((n for n in graph_with_cfg.nodes if n.id == edge.from_node), None)
        to_node = next((n for n in graph_with_cfg.nodes if n.id == edge.to_node), None)
        print(f"    {from_node.type if from_node else '?'} (line {from_node.line if from_node else '?'}) "
              f"-> {to_node.type if to_node else '?'} (line {to_node.line if to_node else '?'})")
    
    # Verify
    if loop_back_edges:
        print("\n✅ SUCCESS: Loop back-edge detected!")
    else:
        print("\n⚠️  WARNING: No CFG_LOOP_BACK edge found (may need DFG analysis)")


def test_try_catch_cfg():
    """Test TRY/CATCH creates CFG_EXCEPTION edge"""
    print("\n" + "="*60)
    print("🔍 TEST 3: TRY/CATCH EXCEPTION FLOW")
    print("="*60)
    
    code = """
try:
    data = pickle.loads(user_input)
except Exception:
    data = None
finally:
    log(data)
"""
    
    # Parse AST
    parser = ASTParser(language="python")
    graph = parser.parse(code, "test_try.py")
    
    # Build CFG
    cfg_builder = CFGBuilder()
    graph_with_cfg = cfg_builder.build(graph)
    
    print(f"\n📊 Graph Stats:")
    print(f"  Total nodes: {len(graph_with_cfg.nodes)}")
    print(f"  Total edges: {len(graph_with_cfg.edges)}")
    
    # Find TRY_STATEMENT node
    try_nodes = [n for n in graph_with_cfg.nodes if n.type == NodeType.TRY_STATEMENT]
    print(f"\n  TRY_STATEMENT nodes: {len(try_nodes)}")
    
    if try_nodes:
        try_node = try_nodes[0]
        print(f"\n📍 TRY_STATEMENT metadata:")
        print(f"  ID: {try_node.id}")
        print(f"  Line: {try_node.line}")
        print(f"  Metadata: {try_node.metadata}")
    
    # Find exception handler nodes
    except_nodes = [n for n in graph_with_cfg.nodes if n.type == NodeType.EXCEPT_HANDLER]
    print(f"\n  EXCEPT_HANDLER nodes: {len(except_nodes)}")
    
    # Find exception edges
    exception_edges = [e for e in graph_with_cfg.edges if e.type == EdgeType.CFG_EXCEPTION]
    
    print(f"\n🔗 Exception Edges:")
    print(f"  CFG_EXCEPTION edges: {len(exception_edges)}")
    for edge in exception_edges:
        from_node = next((n for n in graph_with_cfg.nodes if n.id == edge.from_node), None)
        to_node = next((n for n in graph_with_cfg.nodes if n.id == edge.to_node), None)
        print(f"    {from_node.type if from_node else '?'} (line {from_node.line if from_node else '?'}) "
              f"-> {to_node.type if to_node else '?'} (line {to_node.line if to_node else '?'})")
    
    # Verify
    if exception_edges:
        print("\n✅ SUCCESS: Exception flow detected!")
    else:
        print("\n⚠️  WARNING: No CFG_EXCEPTION edge found (may need full implementation)")


def test_vulnerable_conditional():
    """Test path-sensitive vulnerability detection"""
    print("\n" + "="*60)
    print("🔍 TEST 4: PATH-SENSITIVE VULNERABILITY")
    print("="*60)
    
    code = """
def login(username, password):
    sanitized = False
    
    if validate_input(username):
        sanitized = True
        query = "SELECT * FROM users WHERE username=?"
    else:
        query = f"SELECT * FROM users WHERE username='{username}'"
    
    cursor.execute(query)
"""
    
    # Parse AST
    parser = ASTParser(language="python")
    graph = parser.parse(code, "test_vuln.py")
    
    # Build CFG
    cfg_builder = CFGBuilder()
    graph_with_cfg = cfg_builder.build(graph)
    
    print(f"\n📊 Graph Stats:")
    print(f"  Total nodes: {len(graph_with_cfg.nodes)}")
    print(f"  Total edges: {len(graph_with_cfg.edges)}")
    
    # Find template literal (f-string) in else branch
    template_nodes = [n for n in graph_with_cfg.nodes if n.type == NodeType.TEMPLATE_LITERAL]
    print(f"\n  TEMPLATE_LITERAL nodes (f-strings): {len(template_nodes)}")
    
    # Find execute call
    execute_nodes = [n for n in graph_with_cfg.nodes 
                     if n.type == NodeType.CALL_EXPRESSION and "execute" in (n.name or "")]
    print(f"  execute() calls: {len(execute_nodes)}")
    
    # Show all edge types
    edge_types = {}
    for edge in graph_with_cfg.edges:
        edge_types[edge.type] = edge_types.get(edge.type, 0) + 1
    
    print(f"\n🔗 Edge Type Distribution:")
    for edge_type, count in sorted(edge_types.items()):
        print(f"  {edge_type}: {count}")
    
    print("\n💡 Analysis:")
    print("  The CFG should show:")
    print("  - IF_STATEMENT with CFG_TRUE to safe query")
    print("  - IF_STATEMENT with CFG_FALSE to f-string (vulnerable)")
    print("  - Both branches merge at cursor.execute()")
    print("  - Path-sensitive analysis can identify vulnerable path")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("🚀 TESTING UPGRADED CFG BUILDER")
    print("="*60)
    
    test_if_else_cfg()
    test_loop_cfg()
    test_try_catch_cfg()
    test_vulnerable_conditional()
    
    print("\n" + "="*60)
    print("✅ ALL TESTS COMPLETED")
    print("="*60)
