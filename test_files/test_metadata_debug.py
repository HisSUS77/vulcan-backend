"""
Debug _find_branch_statements to see what's being returned
"""
from app.domain.analysis.ast_parser import ASTParser
from app.domain.analysis.cfg_builder import CFGBuilder
from app.enums.node_type import NodeType


code = """
def check_user(is_admin):
    if is_admin:
        query = "SELECT * FROM admin_data"
    else:
        query = "SELECT * FROM user_data"
    
    cursor.execute(query)
"""

# Parse AST
parser = ASTParser(language="python")
graph = parser.parse(code, "test.py")

# Get the IF_STATEMENT node
if_node = next((n for n in graph.nodes if n.type == NodeType.IF_STATEMENT), None)

if if_node:
    print("IF_STATEMENT found:")
    print(f"  ID: {if_node.id}")
    print(f"  Line: {if_node.line}")
    print(f"  Metadata: {if_node.metadata}")
    
    # Get all statements
    cfg_builder = CFGBuilder()
    stmt_types = cfg_builder._get_statement_types()
    all_statements = [n for n in graph.nodes if n.type in stmt_types]
    all_statements_sorted = sorted(all_statements, key=lambda n: n.line)
    
    print(f"\nAll statements ({len(all_statements_sorted)}):")
    for stmt in all_statements_sorted:
        print(f"  line {stmt.line}: {stmt.type} | {stmt.name}")
    
    # Test _find_branch_statements
    print("\n" + "="*60)
    print("Testing _find_branch_statements")
    print("="*60)
    
    then_branch = cfg_builder._find_branch_statements(if_node, all_statements_sorted, "then")
    print(f"\nTHEN branch ({len(then_branch)} statements):")
    for stmt in then_branch:
        print(f"  line {stmt.line}: {stmt.type} | {stmt.name}")
    
    else_branch = cfg_builder._find_branch_statements(if_node, all_statements_sorted, "else")
    print(f"\nELSE branch ({len(else_branch)} statements):")
    for stmt in else_branch:
        print(f"  line {stmt.line}: {stmt.type} | {stmt.name}")
    
    # Check metadata access
    print("\n" + "="*60)
    print("Metadata Access Test")
    print("="*60)
    print(f"Type of metadata: {type(if_node.metadata)}")
    print(f"Is dict: {isinstance(if_node.metadata, dict)}")
    
    if if_node.metadata:
        if isinstance(if_node.metadata, dict):
            print(f"then_block_start: {if_node.metadata.get('then_block_start')}")
            print(f"then_block_end: {if_node.metadata.get('then_block_end')}")
            print(f"else_block_start: {if_node.metadata.get('else_block_start')}")
            print(f"else_block_end: {if_node.metadata.get('else_block_end')}")
        else:
            # It's a NodeMetadata object
            print("Metadata is NodeMetadata object, checking attributes...")
            print(f"Has then_block_start: {hasattr(if_node.metadata, 'then_block_start')}")
            if hasattr(if_node.metadata, 'then_block_start'):
                print(f"then_block_start: {getattr(if_node.metadata, 'then_block_start')}")
else:
    print("No IF_STATEMENT node found!")
