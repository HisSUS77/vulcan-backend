"""
UPGRADED Query Executor - Production-Grade Pattern Matching
Supports: Property chains, inter-procedural flows, sanitizers, implicit flows, async
"""
import re
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict, deque
import logging

from app.schemas.graph import SemanticGraph, GraphNode, GraphEdge
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType
from semantic_engine.query_store.loader import QueryRule

logger = logging.getLogger(__name__)


@dataclass
class CodeSlice:
    """Represents a minimal code slice containing vulnerability evidence."""
    slice_id: str
    rule_id: str
    rule_name: str
    owasp: str
    cwe: Optional[str]
    severity: str
    confidence: str
    
    # Path information
    source_node_id: str
    sink_node_id: str
    path_nodes: List[str]
    
    # Code context
    code_snippet: str
    location: Dict
    
    # Evidence
    source_label: str
    sink_label: str
    pattern_type: str
    reason: str


class QueryExecutor:
    """
    Production-grade query executor with:
    - Property chain matching
    - Inter-procedural flow tracking
    - Sanitizer awareness
    - Implicit flow detection
    - Framework-specific patterns
    """
    
    # Known sanitization functions (expanded list)
    SANITIZER_FUNCTIONS = {
        'escape', 'html.escape', 'cgi.escape', 'markupsafe.escape',
        'jinja2.escape', 'django.utils.html.escape', 'bleach.clean',
        'quote', 'quote_plus', 'urllib.parse.quote', 'shlex.quote',
        'sanitize', 'clean', 'validate', 'filter',
        'secure_filename', 'werkzeug.utils.secure_filename',
        'base64.b64encode', 'hashlib.sha256', 'secrets.token_hex'
    }
    
    def __init__(self, max_path_length: int = 50, max_paths_per_rule: int = 100):
        """
        Initialize Query Executor.
        
        Args:
            max_path_length: Maximum path length to search
            max_paths_per_rule: Maximum paths to return per rule
        """
        self.max_path_length = max_path_length
        self.max_paths_per_rule = max_paths_per_rule
    
    def execute_query(
        self,
        graph: SemanticGraph,
        query: QueryRule,
        source_code: str
    ) -> List[CodeSlice]:
        """Execute a security query against the graph."""
        logger.debug(f"Executing query: {query.rule_id}")
        
        # Build node map for fast lookup
        self.node_map = {n.id: n for n in graph.nodes}
        
        # Build edge map for metadata access
        self.edge_map = defaultdict(list)
        for edge in graph.edges:
            self.edge_map[edge.from_node].append(edge)
        
        # Step 1: Resolve source nodes (with property chain awareness)
        source_nodes = self._resolve_sources(graph, query)
        if not source_nodes:
            logger.debug(f"No source nodes found for {query.rule_id}")
            return []
        
        # Step 2: Resolve sink nodes (with property chain awareness)
        sink_nodes = self._resolve_sinks(graph, query)
        if not sink_nodes:
            logger.debug(f"No sink nodes found for {query.rule_id}")
            return []
        
        logger.debug(f"Found {len(source_nodes)} sources, {len(sink_nodes)} sinks")
        
        # Step 3: Find paths with all DFG edge types
        slices = []
        for pattern in query.patterns:
            paths = self._find_paths(
                graph, source_nodes, sink_nodes, pattern, query
            )
            
            # Step 4: Extract slices
            for path in paths[:self.max_paths_per_rule]:
                slice_obj = self._extract_slice(
                    graph, path, query, pattern, source_code
                )
                if slice_obj:
                    slices.append(slice_obj)
        
        # Step 5: Deduplicate and rank
        slices = self._deduplicate_slices(slices)
        
        logger.info(f"Query {query.rule_id}: found {len(slices)} potential issues")
        return slices
    
    # ================================================================
    # ENHANCED SOURCE/SINK RESOLUTION
    # ================================================================
    
    def _resolve_sources(
        self, graph: SemanticGraph, query: QueryRule
    ) -> List[GraphNode]:
        """
        Find all source nodes with property chain awareness.
        
        Examples:
        - Pattern "request.json" matches:
          * node.name = "request.json"
          * node.name = "request.json.get"
          * node.type = MEMBER_EXPRESSION with name starting with "request.json"
        """
        sources = []
        
        for node in graph.nodes:
            for source_pattern in query.sources:
                if self._matches_source_pattern(node, source_pattern):
                    sources.append(node)
                    break
        
        return sources
    
    def _resolve_sinks(
        self, graph: SemanticGraph, query: QueryRule
    ) -> List[GraphNode]:
        """Find all sink nodes with property chain awareness."""
        sinks = []
        
        for node in graph.nodes:
            for sink_pattern in query.sinks:
                if self._matches_sink_pattern(node, sink_pattern):
                    sinks.append(node)
                    break
        
        return sinks
    
    def _matches_source_pattern(self, node: GraphNode, pattern: str) -> bool:
        """
        Enhanced source pattern matching with property chain support.
        
        Matches:
        - PARAMETER nodes (function parameters)
        - SUBSCRIPT nodes (sys.argv[1], req.body['id'])
        - MEMBER_EXPRESSION nodes (req.body.username)
        - Property chains (req.body.username matches "req.body")
        """
        node_label = (node.name or node.id).lower()
        pattern_lower = pattern.lower()
        
        # 1. PARAMETER special case
        if pattern == 'PARAMETER' and node.type == NodeType.PARAMETER:
            return True
        
        # 2. Exact match
        if pattern_lower == node_label:
            return True
        
        # 3. Property chain match: "req.body.username" matches pattern "req.body"
        if '.' in node_label and '.' in pattern_lower:
            if node_label.startswith(pattern_lower):
                return True
            if pattern_lower in node_label:  # Substring match for property chains
                return True
        
        # 4. Subscript match: sys.argv[1] matches "sys.argv"
        if node.type == NodeType.SUBSCRIPT:
            # Extract base: sys.argv[1] → sys.argv
            base = node_label.split('[')[0] if '[' in node_label else node_label
            if pattern_lower in base:
                return True
        
        # 5. Member expression match
        if node.type == NodeType.MEMBER_EXPRESSION:
            if pattern_lower in node_label:
                return True
        
        # 6. Framework-specific patterns
        if self._matches_framework_source(node, pattern):
            return True
        
        # 7. Generic substring match (fallback)
        if pattern_lower in node_label:
            return True
        
        return False
    
    def _matches_sink_pattern(self, node: GraphNode, pattern: str) -> bool:
        """
        Enhanced sink pattern matching.
        
        Matches:
        - CALL_EXPRESSION nodes (cursor.execute, os.system)
        - Method calls (db.execute, subprocess.call)
        - Function calls with dangerous names
        - RETURN statements (for data exfiltration like XSS)
        """
        node_label = (node.name or node.id).lower()
        pattern_lower = pattern.lower()
        
        # 1. RETURN statement special case (for XSS, data leakage)
        if pattern_lower == "return" and node.type == NodeType.RETURN:
            return True
        
        # 2. Must be a call expression for most sinks
        if node.type not in (NodeType.CALL_EXPRESSION, NodeType.ASSIGNMENT):
            return False
        
        # 2. Exact match
        if pattern_lower == node_label:
            return True
        
        # 3. Method call match: "cursor.execute" matches pattern "execute"
        if '.' in node_label:
            parts = node_label.split('.')
            if pattern_lower in parts:
                return True
            # Full match: pattern "cursor.execute" matches "cursor.execute"
            if pattern_lower in node_label:
                return True
        
        # 4. Function name match (last part)
        if '.' in node_label:
            func_name = node_label.split('.')[-1]
            if pattern_lower == func_name:
                return True
        
        # 5. Dangerous function keywords
        dangerous_keywords = ['execute', 'query', 'eval', 'exec', 'system', 'call', 'run', 'load', 'render']
        if any(keyword in node_label for keyword in dangerous_keywords):
            if pattern_lower in node_label or any(kw in pattern_lower for kw in dangerous_keywords):
                return True
        
        # 6. Generic substring match
        if pattern_lower in node_label:
            return True
        
        return False
    
    def _matches_framework_source(self, node: GraphNode, pattern: str) -> bool:
        """
        Match framework-specific source patterns.
        
        Python:
        - request.args, request.form, request.json (Flask)
        - request.GET, request.POST (Django)
        - sys.argv, os.environ
        
        JavaScript:
        - req.body, req.params, req.query (Express)
        - process.argv, process.env (Node)
        """
        node_label = (node.name or node.id).lower()
        pattern_lower = pattern.lower()
        
        # Python frameworks
        python_sources = [
            'request.args', 'request.form', 'request.json', 'request.data',
            'request.get', 'request.post', 'request.cookies',
            'sys.argv', 'os.environ', 'input()'
        ]
        
        # JavaScript frameworks
        js_sources = [
            'req.body', 'req.params', 'req.query', 'req.cookies',
            'process.argv', 'process.env', 'window.location'
        ]
        
        all_sources = python_sources + js_sources
        
        for source in all_sources:
            if pattern_lower in source and source in node_label:
                return True
        
        return False
    
    # ================================================================
    # ENHANCED PATH FINDING WITH NEW EDGE TYPES
    # ================================================================
    
    def _find_paths(
        self,
        graph: SemanticGraph,
        sources: List[GraphNode],
        sinks: List[GraphNode],
        pattern_type: str,
        query: QueryRule
    ) -> List[List[str]]:
        """Find paths using ALL DFG edge types."""
        # Get edge types for pattern
        edge_types = self._get_edge_types_for_pattern(pattern_type)
        adj_list = self._build_adjacency_list(graph, edge_types)
        
        # Build sanitizer set (from query + known sanitizers)
        sanitizers = set(query.sanitizers) | self.SANITIZER_FUNCTIONS
        
        # Find paths
        all_paths = []
        source_ids = {s.id for s in sources}
        sink_ids = {s.id for s in sinks}
        
        for source in sources:
            paths = self._bfs_paths_with_sanitizer_check(
                source.id, sink_ids, adj_list, graph, sanitizers
            )
            all_paths.extend(paths)
        
        return all_paths
    
    def _get_edge_types_for_pattern(self, pattern_type: str) -> List[EdgeType]:
        """
        Map pattern type to ALL relevant edge types.
        
        CRITICAL: Now includes NEW edge types from production DFG!
        """
        if pattern_type == "DFG_FLOW":
            return [
                EdgeType.DFG_FLOW,           # Basic data flow
                EdgeType.DFG_INTERP,         # String interpolation (f-strings)
                EdgeType.DFG_PARAM_PASS,     # Argument → parameter
                EdgeType.DFG_RET,            # Function return → call site (NEW)
                EdgeType.DFG_ATTR,           # Object → attribute (OLD)
                EdgeType.DFG_PROPERTY,       # Object property chains (NEW)
                EdgeType.DFG_SUBSCRIPT,      # Array/dict access (NEW)
                EdgeType.DFG_CONTROL,        # Implicit flows (NEW)
                EdgeType.DFG_ASYNC,          # Async/await flows (NEW)
                EdgeType.TAINT_FLOW          # Legacy taint edges
            ]
        
        elif pattern_type == "TAINT_FLOW":
            return [
                EdgeType.TAINT_FLOW,
                EdgeType.DFG_FLOW,
                EdgeType.DFG_INTERP,
                EdgeType.DFG_PROPERTY,       # NEW
                EdgeType.DFG_SUBSCRIPT,      # NEW
                EdgeType.DFG_PARAM_PASS
            ]
        
        elif pattern_type == "CFG_PATH":
            return [
                EdgeType.CFG_NEXT,
                EdgeType.CFG_TRUE,           # Conditional branches (NEW)
                EdgeType.CFG_FALSE,          # Conditional branches (NEW)
                EdgeType.CFG_CALL,           # Function calls (NEW)
                EdgeType.CFG_RETURN          # Function returns (NEW)
            ]
        
        elif pattern_type == "INTERPROCEDURAL":
            return [
                EdgeType.DFG_FLOW,
                EdgeType.DFG_RET,            # Function return flows (NEW)
                EdgeType.DFG_PARAM_PASS,     # Argument passing
                EdgeType.CFG_CALL,           # Call edges (NEW)
                EdgeType.CFG_RETURN          # Return edges (NEW)
            ]
        
        elif pattern_type == "ANY":
            # All edge types for comprehensive analysis
            return [
                EdgeType.DFG_FLOW,
                EdgeType.DFG_INTERP,
                EdgeType.DFG_PARAM_PASS,
                EdgeType.DFG_RET,            # NEW
                EdgeType.DFG_PROPERTY,       # NEW
                EdgeType.DFG_SUBSCRIPT,      # NEW
                EdgeType.DFG_CONTROL,        # NEW
                EdgeType.DFG_ASYNC,          # NEW
                EdgeType.TAINT_FLOW,
                EdgeType.CFG_NEXT
            ]
        
        else:
            logger.warning(f"Unknown pattern type: {pattern_type}, using comprehensive set")
            return [
                EdgeType.DFG_FLOW,
                EdgeType.DFG_INTERP,
                EdgeType.DFG_PROPERTY,       # NEW
                EdgeType.DFG_SUBSCRIPT,      # NEW
                EdgeType.DFG_RET,            # NEW
                EdgeType.DFG_PARAM_PASS
            ]
    
    def _build_adjacency_list(
        self, graph: SemanticGraph, edge_types: List[EdgeType]
    ) -> Dict[str, List[Tuple[str, EdgeType, Dict]]]:
        """
        Build adjacency list with edge metadata.
        
        Returns: {node_id: [(target_id, edge_type, metadata), ...]}
        """
        adj = defaultdict(list)
        
        for edge in graph.edges:
            if edge.type in edge_types:
                metadata = edge.metadata if hasattr(edge, 'metadata') else {}
                adj[edge.from_node].append((edge.to_node, edge.type, metadata))
        
        return adj
    
    def _bfs_paths_with_sanitizer_check(
        self,
        start: str,
        targets: Set[str],
        adj_list: Dict[str, List[Tuple[str, EdgeType, Dict]]],
        graph: SemanticGraph,
        sanitizers: Set[str]
    ) -> List[List[str]]:
        """
        BFS with:
        - Sanitizer detection (stops at sanitized nodes)
        - Property chain tracking
        - Inter-procedural flow support
        """
        paths = []
        queue = deque([(start, [start], set())])  # (current, path, sanitized_vars)
        visited_paths = set()
        
        while queue and len(paths) < self.max_paths_per_rule:
            current, path, sanitized_vars = queue.popleft()
            
            # Check if reached target
            if current in targets:
                # Only add if no sanitizers in path
                if not self._path_has_sanitizer(path, sanitized_vars):
                    paths.append(path)
                continue
            
            # Path length limit
            if len(path) >= self.max_path_length:
                continue
            
            # Explore neighbors
            for neighbor, edge_type, metadata in adj_list.get(current, []):
                if neighbor in path:  # Avoid cycles
                    continue
                
                # Check if neighbor is sanitizer
                neighbor_node = self.node_map.get(neighbor)
                if neighbor_node and self._is_sanitizer_node(neighbor_node, sanitizers):
                    # Mark variable as sanitized
                    new_sanitized = sanitized_vars.copy()
                    if neighbor_node.name:
                        new_sanitized.add(neighbor_node.name)
                    
                    # Continue but mark as sanitized
                    new_path = path + [neighbor]
                    path_key = tuple(new_path)
                    
                    if path_key not in visited_paths:
                        visited_paths.add(path_key)
                        queue.append((neighbor, new_path, new_sanitized))
                    
                    continue  # Don't add unsanitized path
                
                # Check if variable is already sanitized
                if neighbor_node and neighbor_node.name in sanitized_vars:
                    continue  # Skip sanitized variables
                
                new_path = path + [neighbor]
                path_key = tuple(new_path)
                
                if path_key not in visited_paths:
                    visited_paths.add(path_key)
                    queue.append((neighbor, new_path, sanitized_vars))
        
        return paths
    
    def _is_sanitizer_node(self, node: GraphNode, sanitizers: Set[str]) -> bool:
        """
        Enhanced sanitizer detection.
        
        Checks:
        1. Node type is SANITIZER (if exists)
        2. Node name matches known sanitizer
        3. Edge metadata indicates sanitization
        """
        node_label = (node.name or node.id).lower()
        
        # Check node type
        if hasattr(NodeType, 'SANITIZER') and node.type == NodeType.SANITIZER:
            return True
        
        # Check if call expression is a sanitizer
        if node.type == NodeType.CALL_EXPRESSION:
            for sanitizer in sanitizers:
                if sanitizer.lower() in node_label:
                    return True
        
        # Check metadata
        if hasattr(node, 'metadata') and node.metadata:
            # Handle both dict and Pydantic model
            if isinstance(node.metadata, dict):
                if node.metadata.get('is_sanitizer'):
                    return True
            else:
                if getattr(node.metadata, 'is_sanitizer', None):
                    return True
        
        return False
    
    def _path_has_sanitizer(self, path: List[str], sanitized_vars: Set[str]) -> bool:
        """Check if path goes through sanitized variables."""
        for node_id in path:
            node = self.node_map.get(node_id)
            if node and node.name in sanitized_vars:
                return True
        return False
    
    # ================================================================
    # CODE SLICE EXTRACTION
    # ================================================================
    
    def _extract_slice(
        self,
        graph: SemanticGraph,
        path: List[str],
        query: QueryRule,
        pattern_type: str,
        source_code: str
    ) -> Optional[CodeSlice]:
        """Extract minimal code slice with enhanced context."""
        if not path or len(path) < 2:
            return None
        
        # Get source and sink
        source_node = self.node_map.get(path[0])
        sink_node = self.node_map.get(path[-1])
        
        if not source_node or not sink_node:
            return None
        
        # Extract line numbers
        line_numbers = set()
        for node_id in path:
            node = self.node_map.get(node_id)
            if node and hasattr(node, 'line') and node.line:
                line_numbers.add(node.line)
        
        if not line_numbers:
            if hasattr(source_node, 'line') and source_node.line:
                line_numbers.add(source_node.line)
            if hasattr(sink_node, 'line') and sink_node.line:
                line_numbers.add(sink_node.line)
        
        # Extract snippet
        snippet = self._extract_code_snippet(source_code, line_numbers, context=3)
        
        # Location
        min_line = min(line_numbers) if line_numbers else 1
        max_line = max(line_numbers) if line_numbers else 1
        
        location = {
            "file": "input",
            "start_line": min_line,
            "end_line": max_line
        }
        
        # Enhanced reason with path info
        reason = self._generate_enhanced_reason(
            source_node, sink_node, query, pattern_type, path
        )
        
        # Create slice
        slice_id = f"{query.rule_id}_{source_node.id}_{sink_node.id}"
        
        return CodeSlice(
            slice_id=slice_id,
            rule_id=query.rule_id,
            rule_name=query.name,
            owasp=query.owasp,
            cwe=query.cwe,
            severity=query.severity,
            confidence=query.confidence,
            source_node_id=source_node.id,
            sink_node_id=sink_node.id,
            path_nodes=path,
            code_snippet=snippet,
            location=location,
            source_label=source_node.name or source_node.id,
            sink_label=sink_node.name or sink_node.id,
            pattern_type=pattern_type,
            reason=reason
        )
    
    def _extract_code_snippet(
        self, source_code: str, line_numbers: Set[int], context: int = 3
    ) -> str:
        """Extract code snippet with context lines."""
        lines = source_code.split('\n')
        
        if not line_numbers:
            return ""
        
        min_line = max(1, min(line_numbers) - context)
        max_line = min(len(lines), max(line_numbers) + context)
        
        snippet_lines = []
        for i in range(min_line - 1, max_line):
            line_num = i + 1
            prefix = ">>> " if line_num in line_numbers else "    "
            snippet_lines.append(f"{prefix}{line_num:4d} | {lines[i]}")
        
        return "\n".join(snippet_lines)
    
    def _generate_enhanced_reason(
        self,
        source_node: GraphNode,
        sink_node: GraphNode,
        query: QueryRule,
        pattern_type: str,
        path: List[str]
    ) -> str:
        """Generate detailed explanation with path info."""
        source_label = source_node.name or source_node.id
        sink_label = sink_node.name or sink_node.id
        
        # Build path description
        path_desc = " → ".join([
            self.node_map.get(nid).name or self.node_map.get(nid).id
            for nid in path[:5]  # Show first 5 nodes
        ])
        
        if len(path) > 5:
            path_desc += " → ..."
        
        return (
            f"Potential {query.name}: "
            f"Tainted data from '{source_label}' "
            f"flows to dangerous sink '{sink_label}' "
            f"via path: {path_desc}. "
            f"Pattern: {pattern_type}. "
            f"No sanitization detected."
        )
    
    def _deduplicate_slices(self, slices: List[CodeSlice]) -> List[CodeSlice]:
        """Remove duplicates and rank by severity."""
        seen = set()
        unique_slices = []
        
        for slice_obj in slices:
            key = (
                slice_obj.rule_id,
                slice_obj.source_node_id,
                slice_obj.sink_node_id
            )
            
            if key not in seen:
                seen.add(key)
                unique_slices.append(slice_obj)
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        unique_slices.sort(
            key=lambda s: severity_order.get(s.severity.lower(), 4)
        )
        
        return unique_slices