import sys
sys.path.insert(0, 'c:\\Users\\huzai\\Desktop\\fyp\\Vulcan\\vulcan-backend\\vulcan-backend')

from app.domain.analysis.ast_parser import ASTParser
from app.domain.analysis.cfg_builder import CFGBuilder
from app.domain.analysis.dfg_builder_enhanced import EnhancedDFGBuilder
from semantic_engine.query_executor.executor import QueryExecutor
from semantic_engine.query_store.loader import QueryRule
from app.enums.edge_type import EdgeType
from app.enums.node_type import NodeType

code = """def unsafe_view(request):
    user_input = request.args.get('name')
    return f"Hello {user_input}"
"""

parser = ASTParser()
cfg_builder = CFGBuilder()
dfg_builder = EnhancedDFGBuilder()

graph = parser.parse(code, 'test.py')
graph = cfg_builder.build(graph)
graph = dfg_builder.build(graph, code, 'test.py')

print(f'Nodes: {len(graph.nodes)}, Edges: {len(graph.edges)}')

print('\nAll nodes:')
for n in graph.nodes:
    print(f'  {str(n.type):30} | {n.name or "N/A":30} | {n.id}')

print('\nSources (request.args):')
for n in graph.nodes:
    if n.name and 'request' in n.name.lower():
        print(f'  {n.type} | {n.name} | {n.id}')

print('\nSinks (return):')
for n in graph.nodes:
    if n.type == NodeType.RETURN:
        print(f'  {n.type} | {n.name or "RETURN"} | {n.id}')

print('\nF-strings:')
for n in graph.nodes:
    if n.type == NodeType.FSTRING:
        print(f'  {n.type} | {n.name} | {n.id}')

print('\nDFG_INTERP edges:')
for e in graph.edges:
    if e.type == EdgeType.DFG_INTERP:
        from_node = next((n for n in graph.nodes if n.id == e.from_node), None)
        to_node = next((n for n in graph.nodes if n.id == e.to_node), None)
        print(f'  {e.from_node} -> {e.to_node}')
        if from_node:
            print(f'    From: {from_node.type} | {from_node.name}')
        if to_node:
            print(f'    To: {to_node.type} | {to_node.name}')
        print(f'    Meta: {e.metadata}')

if not any(e.type == EdgeType.DFG_INTERP for e in graph.edges):
    print('  No DFG_INTERP edges found!')
    print('\n  Checking AST structure around f-string...')
    fstring_node = next((n for n in graph.nodes if n.type == NodeType.FSTRING), None)
    if fstring_node:
        print(f'  F-string node: {fstring_node.id}')
        print(f'  AST children of f-string:')
        for e in graph.edges:
            if e.from_node == fstring_node.id and e.type == EdgeType.AST_CHILD:
                child = next((n for n in graph.nodes if n.id == e.to_node), None)
                if child:
                    print(f'    - {child.type} | {child.name}')


print('\nDFG_FLOW edges:')
for e in graph.edges:
    if e.type == EdgeType.DFG_FLOW:
        print(f'  {e.from_node} -> {e.to_node} | {e.metadata}')

# Test query execution
query = QueryRule(
    rule_id="XSS_TEST",
    name="XSS",
    owasp="A03",
    description="Test",
    severity="high",
    sources=["request.args", "request", "PARAMETER"],  # Try multiple patterns
    sinks=["return"],
    patterns=["DFG_FLOW"],
    confidence="high"
)

print('\nQuery sources:', query.sources)
print('Query sinks:', query.sinks)

executor = QueryExecutor()

# Check source matching
print('\nSource matching check:')
for node in graph.nodes:
    for pattern in query.sources:
        if executor._matches_source_pattern(node, pattern):
            print(f'  ✓ {pattern} matches {node.type} | {node.name}')

# Check sink matching
print('\nSink matching check:')
for node in graph.nodes:
    for pattern in query.sinks:
        if executor._matches_sink_pattern(node, pattern):
            print(f'  ✓ {pattern} matches {node.type} | {node.name or "N/A"}')

results = executor.execute_query(graph, query, code)
print(f'\nQuery results: {len(results)} vulnerabilities')
