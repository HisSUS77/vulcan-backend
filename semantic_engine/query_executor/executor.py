"""
Query Executor - Pattern Matching Engine
Executes static security queries against unified code property graph.
Finds source→sink paths, extracts minimal code slices for LLM classification.
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
    path_nodes: List[str]  # List of node IDs in path
    
    # Code context
    code_snippet: str
    location: Dict  # {file, start_line, end_line}
    
    # Evidence
    source_label: str
    sink_label: str
    pattern_type: str  # DFG_FLOW, TAINT_FLOW, CFG_NEXT, etc.
    reason: str  # Human-readable explanation


class QueryExecutor:
    """
    Executes security queries against code property graph.
    Finds source→sink paths and extracts minimal slices.
    """
    
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
        """
        Execute a single query rule against the graph.
        
        Args:
            graph: Unified code property graph
            query: Security detection rule
            source_code: Original source code for snippet extraction
        
        Returns:
            List of detected code slices (potential vulnerabilities)
        """
        logger.debug(f"Executing query: {query.rule_id}")
        
        # Step 1: Resolve source nodes
        source_nodes = self._resolve_sources(graph, query)
        if not source_nodes:
            logger.debug(f"No source nodes found for {query.rule_id}")
            return []
        
        # Step 2: Resolve sink nodes
        sink_nodes = self._resolve_sinks(graph, query)
        if not sink_nodes:
            logger.debug(f"No sink nodes found for {query.rule_id}")
            return []
        
        logger.debug(f"Found {len(source_nodes)} sources, {len(sink_nodes)} sinks")
        
        # Step 3: Find paths based on pattern type
        slices = []
        for pattern in query.patterns:
            paths = self._find_paths(
                graph, source_nodes, sink_nodes, pattern, query
            )
            
            # Step 4: Extract slices from paths
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
    
    def _resolve_sources(
        self, graph: SemanticGraph, query: QueryRule
    ) -> List[GraphNode]:
        """
        Find all source nodes matching query criteria.
        
        Args:
            graph: Code property graph
            query: Query rule with source patterns
        
        Returns:
            List of matching source nodes
        """
        sources = []
        
        for node in graph.nodes:
            # Check if node matches any source pattern
            for source_pattern in query.sources:
                if self._matches_pattern(node, source_pattern):
                    sources.append(node)
                    break
        
        return sources
    
    def _resolve_sinks(
        self, graph: SemanticGraph, query: QueryRule
    ) -> List[GraphNode]:
        """
        Find all sink nodes matching query criteria.
        
        Args:
            graph: Code property graph
            query: Query rule with sink patterns
        
        Returns:
            List of matching sink nodes
        """
        sinks = []
        
        for node in graph.nodes:
            # Check if node matches any sink pattern
            for sink_pattern in query.sinks:
                if self._matches_pattern(node, sink_pattern):
                    sinks.append(node)
                    break
        
        return sinks
    
    def _matches_pattern(self, node: GraphNode, pattern: str) -> bool:
        """
        Check if a node matches a pattern string.
        
        Args:
            node: Graph node to check
            pattern: Pattern string (e.g., 'request.GET', 'execute', 'os.system')
        
        Returns:
            True if node matches pattern
        """
        # Get node label (use name or fallback to id)
        node_label = node.name or node.id
        
        # Check node label
        if pattern.lower() in node_label.lower():
            return True
        
        # Check node type for common patterns
        if pattern in ['input', 'user_input'] and node.type == NodeType.PARAMETER:
            return True
        
        # Subscripts like sys.argv are common sources
        if node.type == NodeType.SUBSCRIPT and pattern.lower() in node_label.lower():
            return True
        
        if pattern in ['execute', 'query'] and node.type == NodeType.CALL_EXPRESSION:
            return 'execute' in node_label.lower() or 'query' in node_label.lower()
        
        # Check value field if available
        if hasattr(node, 'value') and node.value:
            if pattern.lower() in str(node.value).lower():
                return True
        
        # Check metadata if available
        if hasattr(node, 'metadata') and node.metadata:
            metadata_str = str(node.metadata).lower()
            if pattern.lower() in metadata_str:
                return True
        
        return False
    
    def _find_paths(
        self,
        graph: SemanticGraph,
        sources: List[GraphNode],
        sinks: List[GraphNode],
        pattern_type: str,
        query: QueryRule
    ) -> List[List[str]]:
        """
        Find all paths from sources to sinks matching pattern.
        
        Args:
            graph: Code property graph
            sources: Source nodes
            sinks: Sink nodes
            pattern_type: Path pattern (DFG_FLOW, TAINT_FLOW, CFG_NEXT)
            query: Query rule (for sanitizer checking)
        
        Returns:
            List of paths (each path is list of node IDs)
        """
        # Build adjacency list for specified edge type
        edge_types = self._get_edge_types_for_pattern(pattern_type)
        adj_list = self._build_adjacency_list(graph, edge_types)
        
        # Build sanitizer set
        sanitizers = set(query.sanitizers)
        
        # Find paths using BFS
        all_paths = []
        source_ids = {s.id for s in sources}
        sink_ids = {s.id for s in sinks}
        
        for source in sources:
            paths = self._bfs_paths(
                source.id, sink_ids, adj_list, graph, sanitizers
            )
            all_paths.extend(paths)
        
        return all_paths
    
    def _get_edge_types_for_pattern(self, pattern_type: str) -> List[EdgeType]:
        """Map pattern type to edge types."""
        if pattern_type == "DFG_FLOW":
            return [
                EdgeType.DFG_FLOW, 
                EdgeType.TAINT_FLOW, 
                EdgeType.DFG_INTERP,      # Variable → f-string/template
                EdgeType.DFG_PARAM_PASS,  # Argument → parameter
                EdgeType.DFG_RET,         # Return → caller
                EdgeType.DFG_ATTR         # Object → attribute
            ]
        elif pattern_type == "TAINT_FLOW":
            return [
                EdgeType.TAINT_FLOW, 
                EdgeType.DFG_FLOW,
                EdgeType.DFG_INTERP,
                EdgeType.DFG_PARAM_PASS
            ]
        elif pattern_type == "CFG_NEXT":
            return [EdgeType.CFG_NEXT]
        elif pattern_type == "ANY":
            return [
                EdgeType.DFG_FLOW, 
                EdgeType.TAINT_FLOW, 
                EdgeType.CFG_NEXT,
                EdgeType.DFG_INTERP,
                EdgeType.DFG_PARAM_PASS
            ]
        else:
            logger.warning(f"Unknown pattern type: {pattern_type}, using DFG_FLOW")
            return [
                EdgeType.DFG_FLOW,
                EdgeType.DFG_INTERP,
                EdgeType.DFG_PARAM_PASS
            ]
    
    def _build_adjacency_list(
        self, graph: SemanticGraph, edge_types: List[EdgeType]
    ) -> Dict[str, List[str]]:
        """Build adjacency list for specified edge types."""
        adj = defaultdict(list)
        
        for edge in graph.edges:
            if edge.type in edge_types:
                adj[edge.from_node].append(edge.to_node)
        
        return adj
    
    def _bfs_paths(
        self,
        start: str,
        targets: Set[str],
        adj_list: Dict[str, List[str]],
        graph: SemanticGraph,
        sanitizers: Set[str]
    ) -> List[List[str]]:
        """
        BFS to find all paths from start to any target.
        
        Args:
            start: Start node ID
            targets: Set of target node IDs
            adj_list: Adjacency list
            graph: Full graph (for sanitizer checking)
            sanitizers: Set of sanitizer patterns
        
        Returns:
            List of paths (node ID lists)
        """
        paths = []
        queue = deque([(start, [start])])
        visited_paths = set()
        
        node_map = {n.id: n for n in graph.nodes}
        
        while queue and len(paths) < self.max_paths_per_rule:
            current, path = queue.popleft()
            
            # Check if we reached a target
            if current in targets:
                paths.append(path)
                continue
            
            # Check path length limit
            if len(path) >= self.max_path_length:
                continue
            
            # Explore neighbors
            for neighbor in adj_list.get(current, []):
                if neighbor in path:  # Avoid cycles
                    continue
                
                # Check if neighbor is a sanitizer
                if neighbor in node_map:
                    neighbor_node = node_map[neighbor]
                    if self._is_sanitizer(neighbor_node, sanitizers):
                        continue  # Skip sanitized paths
                
                new_path = path + [neighbor]
                path_key = tuple(new_path)
                
                if path_key not in visited_paths:
                    visited_paths.add(path_key)
                    queue.append((neighbor, new_path))
        
        return paths
    
    def _is_sanitizer(self, node: GraphNode, sanitizers: Set[str]) -> bool:
        """Check if node represents a sanitizer function."""
        node_label = node.name or node.id
        for sanitizer in sanitizers:
            if sanitizer.lower() in node_label.lower():
                return True
        return False
    
    def _extract_slice(
        self,
        graph: SemanticGraph,
        path: List[str],
        query: QueryRule,
        pattern_type: str,
        source_code: str
    ) -> Optional[CodeSlice]:
        """
        Extract minimal code slice from path.
        
        Args:
            graph: Code property graph
            path: Path of node IDs
            query: Query rule
            pattern_type: Pattern type used
            source_code: Original source code
        
        Returns:
            CodeSlice object or None
        """
        if not path or len(path) < 2:
            return None
        
        node_map = {n.id: n for n in graph.nodes}
        
        # Get source and sink nodes
        source_node = node_map.get(path[0])
        sink_node = node_map.get(path[-1])
        
        if not source_node or not sink_node:
            return None
        
        # Extract line numbers from path
        line_numbers = set()
        for node_id in path:
            node = node_map.get(node_id)
            if node and hasattr(node, 'line') and node.line:
                line_numbers.add(node.line)
        
        if not line_numbers:
            # Fallback: use source/sink lines
            if hasattr(source_node, 'line') and source_node.line:
                line_numbers.add(source_node.line)
            if hasattr(sink_node, 'line') and sink_node.line:
                line_numbers.add(sink_node.line)
        
        # Extract code snippet with context (±3 lines)
        snippet = self._extract_code_snippet(source_code, line_numbers, context=3)
        
        # Determine location
        min_line = min(line_numbers) if line_numbers else 1
        max_line = max(line_numbers) if line_numbers else 1
        
        location = {
            "file": "input",  # Will be filled by caller
            "start_line": min_line,
            "end_line": max_line
        }
        
        # Generate reason
        reason = self._generate_reason(source_node, sink_node, query, pattern_type)
        
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
        """
        Extract code snippet with context lines.
        
        Args:
            source_code: Full source code
            line_numbers: Set of line numbers to include
            context: Number of context lines before/after
        
        Returns:
            Code snippet string
        """
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
    
    def _generate_reason(
        self,
        source_node: GraphNode,
        sink_node: GraphNode,
        query: QueryRule,
        pattern_type: str
    ) -> str:
        """Generate human-readable explanation."""
        source_label = source_node.name or source_node.id
        sink_label = sink_node.name or sink_node.id
        
        return (
            f"Potential {query.name}: "
            f"User input from '{source_label}' "
            f"flows to dangerous sink '{sink_label}' "
            f"via {pattern_type} without sanitization."
        )
    
    def _deduplicate_slices(self, slices: List[CodeSlice]) -> List[CodeSlice]:
        """
        Remove duplicate slices and rank by severity.
        
        Args:
            slices: List of code slices
        
        Returns:
            Deduplicated and sorted list
        """
        seen = set()
        unique_slices = []
        
        for slice_obj in slices:
            # Create unique key
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
