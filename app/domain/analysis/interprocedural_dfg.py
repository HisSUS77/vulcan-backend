"""
Interprocedural Data Flow Graph (DFG) Builder
==============================================

Tracks data flow across function boundaries with support for:
- Parameter-to-argument propagation (DFG_ARG_PASS)
- Return value propagation (DFG_RET)
- JavaScript closures and callbacks
- Python tuple unpacking and multiple returns
- Graceful degradation with uncertainty tracking

Integration:
- Works with CPG parser (Tree-sitter based AST)
- Extends existing CPG with interprocedural edges
- Supports Python and JavaScript
"""

from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from app.schemas.graph import GraphNode, GraphEdge, SemanticGraph
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType
from pydantic import BaseModel, Field


class DFGEdgeType(str, Enum):
    """Data flow edge types for interprocedural analysis"""
    # Intraprocedural (within function)
    DFG_VAR_DEF = "DFG_VAR_DEF"           # Variable definition
    DFG_VAR_USE = "DFG_VAR_USE"           # Variable usage
    DFG_ASSIGN = "DFG_ASSIGN"             # Assignment flow
    
    # Interprocedural (across functions)
    DFG_ARG_PASS = "DFG_ARG_PASS"         # Argument → Parameter
    DFG_RET = "DFG_RET"                   # Return value → Call site
    DFG_CLOSURE = "DFG_CLOSURE"           # Closure capture
    DFG_CALLBACK = "DFG_CALLBACK"         # Callback invocation
    
    # Python-specific
    DFG_TUPLE_UNPACK = "DFG_TUPLE_UNPACK" # Tuple unpacking flow
    DFG_MULTI_RET = "DFG_MULTI_RET"       # Multiple return values
    
    # Uncertainty tracking
    DFG_UNCERTAIN = "DFG_UNCERTAIN"       # Flow with uncertainty


class UncertaintyLevel(str, Enum):
    """Levels of uncertainty in data flow analysis"""
    CERTAIN = "certain"                    # Definite flow (e.g., x = y)
    LIKELY = "likely"                      # Probable flow (e.g., known callback pattern)
    POSSIBLE = "possible"                  # Possible flow (e.g., dynamic property access)
    UNKNOWN = "unknown"                    # Unknown flow (e.g., eval, dynamic imports)


class DFGMetadata(BaseModel):
    """Metadata for DFG edges"""
    edge_type: DFGEdgeType
    uncertainty: UncertaintyLevel = UncertaintyLevel.CERTAIN
    context: Optional[str] = None          # Additional context about the flow
    arg_position: Optional[int] = None     # For argument passing
    return_index: Optional[int] = None     # For tuple unpacking
    closure_scope: Optional[str] = None    # For closure captures
    confidence: float = 1.0                # Confidence score (0.0 - 1.0)


@dataclass
class CallSite:
    """Represents a function call site"""
    call_node_id: str
    caller_function: str
    callee_name: str
    arguments: List[str]                   # Argument node IDs
    line_number: int
    is_async: bool = False
    is_callback: bool = False
    callback_arg_pos: Optional[int] = None


@dataclass
class FunctionSignature:
    """Represents a function signature for interprocedural analysis"""
    function_name: str
    node_id: str
    parameters: List[str]                  # Parameter names
    param_node_ids: List[str]              # Parameter node IDs
    return_nodes: List[str]                # Return statement node IDs
    is_async: bool = False
    is_generator: bool = False
    captured_vars: Set[str] = field(default_factory=set)  # For closures
    parent_scope: Optional[str] = None     # For nested functions


@dataclass
class DataFlowPath:
    """Represents a complete interprocedural data flow path"""
    source_node_id: str
    sink_node_id: str
    path_edges: List[Tuple[str, str, DFGEdgeType]]
    uncertainty: UncertaintyLevel
    confidence: float
    description: str


class InterproceduralDFG:
    """
    Interprocedural Data Flow Graph Builder
    
    Builds comprehensive DFG with:
    1. Intraprocedural flows (within functions)
    2. Interprocedural flows (across function calls)
    3. JavaScript closure and callback tracking
    4. Python tuple unpacking and multi-return
    5. Uncertainty representation
    
    Usage:
        dfg_builder = InterproceduralDFG(cpg)
        dfg_builder.build()
        enhanced_cpg = dfg_builder.get_cpg()
    """
    
    def __init__(self, cpg: SemanticGraph):
        """
        Initialize interprocedural DFG builder
        
        Args:
            cpg: Code Property Graph from CPG parser
        """
        self.cpg = cpg
        self.dfg_edges: List[GraphEdge] = []
        
        # Analysis state
        self.functions: Dict[str, FunctionSignature] = {}
        self.call_sites: List[CallSite] = []
        self.variable_defs: Dict[str, List[str]] = {}  # var_name -> [node_ids]
        self.variable_uses: Dict[str, List[str]] = {}  # var_name -> [node_ids]
        
        # Closure tracking (JavaScript)
        self.closure_captures: Dict[str, Set[str]] = {}  # func_id -> {captured_vars}
        self.callback_bindings: Dict[str, str] = {}       # callback_id -> parent_func
        
        # Return value tracking
        self.return_values: Dict[str, List[str]] = {}     # func_name -> [return_node_ids]
        
    def build(self) -> SemanticGraph:
        """
        Build interprocedural DFG
        
        Steps:
        1. Extract function signatures
        2. Identify call sites
        3. Build intraprocedural DFG (within functions)
        4. Build interprocedural edges (arg pass, return)
        5. Handle special cases (closures, callbacks, tuple unpacking)
        6. Add uncertainty annotations
        
        Returns:
            Enhanced CPG with DFG edges
        """
        print("🔄 Building Interprocedural DFG...")
        
        # Step 1: Extract function signatures and call sites
        self._extract_functions()
        self._extract_call_sites()
        
        # Step 2: Build intraprocedural DFG
        self._build_intraprocedural_dfg()
        
        # Step 3: Build interprocedural edges
        self._build_argument_flows()
        self._build_return_flows()
        
        # Step 4: Handle language-specific features
        self._handle_closures()          # JavaScript
        self._handle_callbacks()         # JavaScript
        self._handle_tuple_unpacking()   # Python
        
        # Step 5: Add uncertainty annotations
        self._annotate_uncertainty()
        
        print(f"✓ Built DFG with {len(self.dfg_edges)} interprocedural edges")
        
        return self.get_cpg()
    
    def _extract_functions(self):
        """Extract all function signatures from CPG"""
        for node in self.cpg.nodes:
            if node.node_type in ["FUNCTION", "ASYNC_FUNCTION", "METHOD", "ARROW_FUNCTION"]:
                # Find parameter nodes (children with PARAMETER type)
                params = self._find_parameters(node.id)
                
                # Find return statements
                returns = self._find_return_statements(node.id)
                
                # Check for closure captures (JavaScript)
                captured = self._detect_closure_captures(node.id)
                
                signature = FunctionSignature(
                    function_name=node.name or f"anonymous_{node.id}",
                    node_id=node.id,
                    parameters=[p.name for p in params],
                    param_node_ids=[p.id for p in params],
                    return_nodes=returns,
                    is_async=node.node_type == "ASYNC_FUNCTION",
                    captured_vars=captured,
                    parent_scope=self._get_parent_scope(node.id)
                )
                
                self.functions[node.name or node.id] = signature
                
        print(f"  ✓ Extracted {len(self.functions)} function signatures")
    
    def _extract_call_sites(self):
        """Extract all function call sites"""
        for node in self.cpg.nodes:
            if node.node_type in ["CALL", "CALL_EXPRESSION", "ASYNC_CALL"]:
                # Find caller function
                caller = self._find_enclosing_function(node.id)
                
                # Find callee name
                callee = self._get_callee_name(node)
                
                # Find arguments
                args = self._find_arguments(node.id)
                
                # Check if callback
                is_callback, cb_pos = self._is_callback_invocation(node, args)
                
                call_site = CallSite(
                    call_node_id=node.id,
                    caller_function=caller,
                    callee_name=callee,
                    arguments=[arg.id for arg in args],
                    line_number=node.line_start,
                    is_async=node.node_type == "ASYNC_CALL",
                    is_callback=is_callback,
                    callback_arg_pos=cb_pos
                )
                
                self.call_sites.append(call_site)
        
        print(f"  ✓ Found {len(self.call_sites)} call sites")
    
    def _build_intraprocedural_dfg(self):
        """Build data flow within each function"""
        for func_sig in self.functions.values():
            # Get all nodes within this function
            func_nodes = self._get_function_body_nodes(func_sig.node_id)
            
            # Track variable definitions and uses
            for node in func_nodes:
                if node.node_type in ["VARIABLE_DECLARATION", "ASSIGNMENT", "IDENTIFIER"]:
                    self._track_variable_flow(node, func_sig)
            
            # Build def-use chains
            self._build_def_use_chains(func_sig)
    
    def _build_argument_flows(self):
        """Build parameter-to-argument data flow edges"""
        for call_site in self.call_sites:
            # Find callee function
            callee_sig = self.functions.get(call_site.callee_name)
            
            if not callee_sig:
                # Unknown function - add uncertain edge
                self._add_uncertain_call(call_site)
                continue
            
            # Match arguments to parameters
            for i, arg_id in enumerate(call_site.arguments):
                if i < len(callee_sig.param_node_ids):
                    param_id = callee_sig.param_node_ids[i]
                    
                    # Create DFG_ARG_PASS edge
                    metadata = DFGMetadata(
                        edge_type=DFGEdgeType.DFG_ARG_PASS,
                        uncertainty=UncertaintyLevel.CERTAIN,
                        context=f"Arg {i} → Param '{callee_sig.parameters[i]}'",
                        arg_position=i,
                        confidence=1.0
                    )
                    
                    edge = GraphEdge(
                        **{
                            "from": arg_id,
                            "to": param_id,
                            "type": EdgeType.DATA_FLOW
                        }
                    )
                    if not edge.metadata:
                        edge.metadata = {}
                    edge.metadata.update(metadata.model_dump())
                    edge.metadata['dfg_edge_type'] = DFGEdgeType.DFG_ARG_PASS.value
                    
                    self.dfg_edges.append(edge)
    
    def _build_return_flows(self):
        """Build return value to call site data flow edges"""
        for call_site in self.call_sites:
            callee_sig = self.functions.get(call_site.callee_name)
            
            if not callee_sig:
                continue
            
            # Connect each return statement to call site
            for return_node_id in callee_sig.return_nodes:
                # Get the actual return value node (child of return statement)
                return_value = self._get_return_value_node(return_node_id)
                
                if return_value:
                    metadata = DFGMetadata(
                        edge_type=DFGEdgeType.DFG_RET,
                        uncertainty=UncertaintyLevel.CERTAIN,
                        context=f"Return from '{callee_sig.function_name}'",
                        confidence=1.0
                    )
                    
                    edge = GraphEdge(
                        **{
                            "from": return_value,
                            "to": call_site.call_node_id,
                            "type": EdgeType.DATA_FLOW
                        }
                    )
                    if not edge.metadata:
                        edge.metadata = {}
                    edge.metadata.update(metadata.model_dump())
                    edge.metadata['dfg_edge_type'] = DFGEdgeType.DFG_RET.value
                    
                    self.dfg_edges.append(edge)
    
    def _handle_closures(self):
        """
        Handle JavaScript closures
        
        Example:
            function outer(x) {
                return function inner(y) {
                    return x + y;  // 'x' is captured from outer scope
                }
            }
        """
        for func_sig in self.functions.values():
            if not func_sig.captured_vars:
                continue
            
            # Find where captured variables are defined
            for captured_var in func_sig.captured_vars:
                # Find definition in parent scope
                parent_def_nodes = self._find_var_in_parent_scope(
                    captured_var,
                    func_sig.parent_scope
                )
                
                # Find uses in inner function
                inner_use_nodes = self._find_var_uses_in_function(
                    captured_var,
                    func_sig.node_id
                )
                
                # Create closure capture edges
                for def_node in parent_def_nodes:
                    for use_node in inner_use_nodes:
                        metadata = DFGMetadata(
                            edge_type=DFGEdgeType.DFG_CLOSURE,
                            uncertainty=UncertaintyLevel.CERTAIN,
                            context=f"Closure capture '{captured_var}'",
                            closure_scope=func_sig.parent_scope,
                            confidence=1.0
                        )
                        
                        edge = GraphEdge(
                            **{
                                "from": def_node,
                                "to": use_node,
                                "type": EdgeType.DATA_FLOW
                            }
                        )
                        if not edge.metadata:
                            edge.metadata = {}
                        edge.metadata.update(metadata.model_dump())
                        edge.metadata['dfg_edge_type'] = DFGEdgeType.DFG_CLOSURE.value
                        
                        self.dfg_edges.append(edge)
    
    def _handle_callbacks(self):
        """
        Handle JavaScript callback patterns
        
        Example:
            function processData(data, callback) {
                const result = transform(data);
                callback(result);  // Track flow from result to callback param
            }
            
            processData(input, function(output) {
                console.log(output);  // output receives result
            });
        """
        for call_site in self.call_sites:
            if not call_site.is_callback:
                continue
            
            # Find callback function argument
            if call_site.callback_arg_pos is not None:
                callback_arg_id = call_site.arguments[call_site.callback_arg_pos]
                
                # Find the callback function node
                callback_func = self._resolve_callback_function(callback_arg_id)
                
                if callback_func:
                    # Find where callback is invoked inside callee
                    callee_sig = self.functions.get(call_site.callee_name)
                    if callee_sig:
                        callback_invocations = self._find_callback_invocations(
                            callee_sig.node_id,
                            callee_sig.parameters[call_site.callback_arg_pos]
                        )
                        
                        # Connect callback invocation arguments to callback parameters
                        for invocation in callback_invocations:
                            self._connect_callback_flow(
                                invocation,
                                callback_func
                            )
    
    def _handle_tuple_unpacking(self):
        """
        Handle Python tuple unpacking
        
        Example:
            def get_user():
                return name, age, email  # Multiple returns
            
            user_name, user_age, user_email = get_user()  # Unpacking
        """
        for node in self.cpg.nodes:
            if node.node_type == "TUPLE_PATTERN" or \
               (node.node_type == "ASSIGNMENT" and self._is_tuple_unpack(node)):
                
                # Find the call expression on RHS
                call_node = self._find_call_in_assignment(node.id)
                
                if call_node:
                    callee_sig = self.functions.get(self._get_callee_name_from_node(call_node))
                    
                    if callee_sig:
                        # Find unpacking targets (LHS variables)
                        unpack_targets = self._find_unpack_targets(node.id)
                        
                        # Find return tuple elements
                        return_elements = self._find_return_tuple_elements(callee_sig)
                        
                        # Connect each return element to corresponding unpack target
                        for i, (return_elem, target) in enumerate(
                            zip(return_elements, unpack_targets)
                        ):
                            metadata = DFGMetadata(
                                edge_type=DFGEdgeType.DFG_TUPLE_UNPACK,
                                uncertainty=UncertaintyLevel.CERTAIN,
                                context=f"Tuple unpack position {i}",
                                return_index=i,
                                confidence=1.0
                            )
                            
                            edge = GraphEdge(
                                **{
                                    "from": return_elem,
                                    "to": target,
                                    "type": EdgeType.DATA_FLOW
                                }
                            )
                            if not edge.metadata:
                                edge.metadata = {}
                            edge.metadata.update(metadata.model_dump())
                            edge.metadata['dfg_edge_type'] = DFGEdgeType.DFG_TUPLE_UNPACK.value
                            
                            self.dfg_edges.append(edge)
    
    def _annotate_uncertainty(self):
        """
        Add uncertainty annotations for flows that cannot be determined statically
        
        Cases:
        - Dynamic property access: obj[computed_key]
        - Dynamic imports: require(variable_path)
        - eval/exec calls
        - Reflection APIs
        """
        uncertain_patterns = [
            "COMPUTED_MEMBER_EXPRESSION",  # obj[key]
            "EVAL_CALL",                   # eval()
            "DYNAMIC_IMPORT",              # import(path)
            "REFLECT_CALL"                 # Reflect.get()
        ]
        
        for node in self.cpg.nodes:
            if node.node_type in uncertain_patterns:
                # Add uncertain DFG edge
                metadata = DFGMetadata(
                    edge_type=DFGEdgeType.DFG_UNCERTAIN,
                    uncertainty=UncertaintyLevel.UNKNOWN,
                    context=f"Dynamic operation: {node.node_type}",
                    confidence=0.3  # Low confidence
                )
                
                # Find potential sources and sinks
                sources = self._find_potential_sources(node.id)
                sinks = self._find_potential_sinks(node.id)
                
                for source in sources:
                    for sink in sinks:
                        edge = GraphEdge(
                            **{
                                "from": source,
                                "to": sink,
                                "type": EdgeType.DATA_FLOW
                            }
                        )
                        if not edge.metadata:
                            edge.metadata = {}
                        edge.metadata.update(metadata.model_dump())
                        edge.metadata['dfg_edge_type'] = DFGEdgeType.DFG_UNCERTAIN.value
                        
                        self.dfg_edges.append(edge)
    
    # =========================
    # Helper Methods
    # =========================
    
    def _find_parameters(self, func_node_id: str) -> List[GraphNode]:
        """Find parameter nodes of a function"""
        params = []
        for edge in self.cpg.edges:
            if edge.source == func_node_id and edge.edge_type in ["AST_CHILD", "HAS_PARAMETER"]:
                param_node = self._get_node_by_id(edge.target)
                if param_node and param_node.node_type in ["PARAMETER", "FORMAL_PARAMETER"]:
                    params.append(param_node)
        return params
    
    def _find_return_statements(self, func_node_id: str) -> List[str]:
        """Find all return statement node IDs in a function"""
        returns = []
        func_nodes = self._get_function_body_nodes(func_node_id)
        for node in func_nodes:
            if node.node_type in ["RETURN", "RETURN_STATEMENT"]:
                returns.append(node.id)
        return returns
    
    def _detect_closure_captures(self, func_node_id: str) -> Set[str]:
        """
        Detect variables captured by closure
        
        A variable is captured if:
        1. It's used inside the function
        2. It's not defined in the function
        3. It's defined in an enclosing scope
        """
        captured = set()
        
        func_nodes = self._get_function_body_nodes(func_node_id)
        used_vars = set()
        defined_vars = set()
        
        # Find all variables used and defined
        for node in func_nodes:
            if node.node_type == "IDENTIFIER":
                used_vars.add(node.name)
            if node.node_type in ["VARIABLE_DECLARATION", "PARAMETER"]:
                defined_vars.add(node.name)
        
        # Captured = used but not defined locally
        captured = used_vars - defined_vars
        
        return captured
    
    def _get_parent_scope(self, node_id: str) -> Optional[str]:
        """Find parent scope (enclosing function) of a node"""
        # Walk up AST_CHILD edges
        current = node_id
        while current:
            # Find parent
            parent_edge = next(
                (e for e in self.cpg.edges 
                 if e.target == current and e.edge_type == "AST_CHILD"),
                None
            )
            
            if not parent_edge:
                break
            
            parent_node = self._get_node_by_id(parent_edge.source)
            if parent_node and parent_node.node_type in ["FUNCTION", "ASYNC_FUNCTION"]:
                return parent_node.id
            
            current = parent_edge.source
        
        return "global"
    
    def _find_enclosing_function(self, node_id: str) -> str:
        """Find the function containing this node"""
        scope = self._get_parent_scope(node_id)
        if scope == "global":
            return "__global__"
        
        func_node = self._get_node_by_id(scope)
        return func_node.name if func_node else "__unknown__"
    
    def _get_callee_name(self, call_node: GraphNode) -> str:
        """Extract callee function name from call node"""
        # Look for function name in call expression
        # Check node's name or find child with function identifier
        if call_node.name:
            return call_node.name
        
        # Find function identifier child
        for edge in self.cpg.edges:
            if edge.source == call_node.id and edge.edge_type == "AST_CHILD":
                child = self._get_node_by_id(edge.target)
                if child and child.node_type in ["IDENTIFIER", "MEMBER_EXPRESSION"]:
                    return child.name or child.code
        
        return "__unknown__"
    
    def _find_arguments(self, call_node_id: str) -> List[GraphNode]:
        """Find argument nodes of a call"""
        args = []
        for edge in self.cpg.edges:
            if edge.source == call_node_id and edge.edge_type == "AST_CHILD":
                arg_node = self._get_node_by_id(edge.target)
                if arg_node and arg_node.node_type in ["ARGUMENT", "EXPRESSION"]:
                    args.append(arg_node)
        return args
    
    def _is_callback_invocation(self, call_node: GraphNode, args: List[GraphNode]) -> Tuple[bool, Optional[int]]:
        """
        Detect if this call passes a callback function
        
        Returns: (is_callback, callback_argument_position)
        """
        for i, arg in enumerate(args):
            if arg.node_type in ["ARROW_FUNCTION", "FUNCTION", "FUNCTION_EXPRESSION"]:
                return True, i
        
        return False, None
    
    def _get_function_body_nodes(self, func_node_id: str) -> List[GraphNode]:
        """Get all nodes in function body (recursive traversal)"""
        visited = set()
        result = []
        
        def traverse(node_id: str):
            if node_id in visited:
                return
            visited.add(node_id)
            
            node = self._get_node_by_id(node_id)
            if node:
                result.append(node)
            
            # Traverse children
            for edge in self.cpg.edges:
                if edge.source == node_id and edge.edge_type == "AST_CHILD":
                    traverse(edge.target)
        
        traverse(func_node_id)
        return result
    
    def _track_variable_flow(self, node: GraphNode, func_sig: FunctionSignature):
        """Track variable definitions and uses"""
        if node.node_type == "VARIABLE_DECLARATION":
            # This is a definition
            if node.name:
                if node.name not in self.variable_defs:
                    self.variable_defs[node.name] = []
                self.variable_defs[node.name].append(node.id)
        
        elif node.node_type == "IDENTIFIER":
            # This is a use
            if node.name:
                if node.name not in self.variable_uses:
                    self.variable_uses[node.name] = []
                self.variable_uses[node.name].append(node.id)
    
    def _build_def_use_chains(self, func_sig: FunctionSignature):
        """Build def-use chains within a function"""
        # For each variable, connect defs to uses
        func_nodes = self._get_function_body_nodes(func_sig.node_id)
        func_node_ids = {n.id for n in func_nodes}
        
        for var_name in self.variable_defs.keys():
            if var_name not in self.variable_uses:
                continue
            
            # Filter to only nodes in this function
            defs = [d for d in self.variable_defs[var_name] if d in func_node_ids]
            uses = [u for u in self.variable_uses[var_name] if u in func_node_ids]
            
            # Connect each def to subsequent uses
            for def_id in defs:
                for use_id in uses:
                    # Check if use comes after def (simplistic check)
                    def_node = self._get_node_by_id(def_id)
                    use_node = self._get_node_by_id(use_id)
                    
                    if def_node and use_node and def_node.line_start <= use_node.line_start:
                        metadata = DFGMetadata(
                            edge_type=DFGEdgeType.DFG_VAR_USE,
                            uncertainty=UncertaintyLevel.CERTAIN,
                            context=f"Variable '{var_name}'",
                            confidence=1.0
                        )
                        
                        edge = GraphEdge(
                            **{
                                "from": def_id,
                                "to": use_id,
                                "type": EdgeType.DATA_FLOW
                            }
                        )
                        if not edge.metadata:
                            edge.metadata = {}
                        edge.metadata.update(metadata.model_dump())
                        edge.metadata['dfg_edge_type'] = DFGEdgeType.DFG_VAR_USE.value
                        
                        self.dfg_edges.append(edge)
    
    def _add_uncertain_call(self, call_site: CallSite):
        """Add uncertain edges for unknown function calls"""
        metadata = DFGMetadata(
            edge_type=DFGEdgeType.DFG_UNCERTAIN,
            uncertainty=UncertaintyLevel.UNKNOWN,
            context=f"Unknown function '{call_site.callee_name}'",
            confidence=0.0
        )
        
        # Mark call site as uncertain
        # (Could be refined with heuristics or external info)
    
    def _get_return_value_node(self, return_stmt_id: str) -> Optional[str]:
        """Get the actual value being returned"""
        for edge in self.cpg.edges:
            if edge.source == return_stmt_id and edge.edge_type == "AST_CHILD":
                return edge.target
        return None
    
    def _find_var_in_parent_scope(self, var_name: str, parent_scope: Optional[str]) -> List[str]:
        """Find variable definition in parent scope"""
        if not parent_scope or parent_scope == "global":
            # Search global scope
            return [d for d in self.variable_defs.get(var_name, [])]
        
        # Search in specific parent function
        parent_nodes = self._get_function_body_nodes(parent_scope)
        parent_node_ids = {n.id for n in parent_nodes}
        
        return [d for d in self.variable_defs.get(var_name, []) if d in parent_node_ids]
    
    def _find_var_uses_in_function(self, var_name: str, func_id: str) -> List[str]:
        """Find variable uses within a specific function"""
        func_nodes = self._get_function_body_nodes(func_id)
        func_node_ids = {n.id for n in func_nodes}
        
        return [u for u in self.variable_uses.get(var_name, []) if u in func_node_ids]
    
    def _resolve_callback_function(self, callback_arg_id: str) -> Optional[FunctionSignature]:
        """Resolve callback argument to actual function"""
        callback_node = self._get_node_by_id(callback_arg_id)
        
        if callback_node and callback_node.node_type in ["ARROW_FUNCTION", "FUNCTION_EXPRESSION"]:
            # Direct callback function
            return self.functions.get(callback_node.id)
        
        # Could be a variable reference - would need more analysis
        return None
    
    def _find_callback_invocations(self, func_id: str, callback_param_name: str) -> List[GraphNode]:
        """Find where callback parameter is invoked"""
        invocations = []
        func_nodes = self._get_function_body_nodes(func_id)
        
        for node in func_nodes:
            if node.node_type == "CALL_EXPRESSION":
                callee_name = self._get_callee_name(node)
                if callee_name == callback_param_name:
                    invocations.append(node)
        
        return invocations
    
    def _connect_callback_flow(self, invocation_node: GraphNode, callback_func: FunctionSignature):
        """Connect callback invocation to callback function parameters"""
        # Find arguments to callback invocation
        args = self._find_arguments(invocation_node.id)
        
        # Connect to callback parameters
        for i, arg_id in enumerate([a.id for a in args]):
            if i < len(callback_func.param_node_ids):
                param_id = callback_func.param_node_ids[i]
                
                metadata = DFGMetadata(
                    edge_type=DFGEdgeType.DFG_CALLBACK,
                    uncertainty=UncertaintyLevel.LIKELY,  # Callbacks have some uncertainty
                    context=f"Callback arg {i}",
                    arg_position=i,
                    confidence=0.8
                )
                
                edge = GraphEdge(
                    **{
                        "from": arg_id,
                        "to": param_id,
                        "type": EdgeType.DATA_FLOW
                    }
                )
                if not edge.metadata:
                    edge.metadata = {}
                edge.metadata.update(metadata.model_dump())
                edge.metadata['dfg_edge_type'] = DFGEdgeType.DFG_CALLBACK.value
                
                self.dfg_edges.append(edge)
    
    def _is_tuple_unpack(self, node: GraphNode) -> bool:
        """Check if assignment is tuple unpacking"""
        # Look for tuple pattern on LHS or multiple assignment targets
        return "," in (node.code or "")  # Simplistic check
    
    def _find_call_in_assignment(self, assignment_id: str) -> Optional[GraphNode]:
        """Find call expression on RHS of assignment"""
        for edge in self.cpg.edges:
            if edge.source == assignment_id and edge.edge_type == "AST_CHILD":
                child = self._get_node_by_id(edge.target)
                if child and child.node_type in ["CALL", "CALL_EXPRESSION"]:
                    return child
        return None
    
    def _get_callee_name_from_node(self, call_node: GraphNode) -> str:
        """Get callee name from call node"""
        return self._get_callee_name(call_node)
    
    def _find_unpack_targets(self, assignment_id: str) -> List[str]:
        """Find unpacking target variable IDs"""
        targets = []
        for edge in self.cpg.edges:
            if edge.source == assignment_id and edge.edge_type == "AST_CHILD":
                child = self._get_node_by_id(edge.target)
                if child and child.node_type == "IDENTIFIER":
                    targets.append(child.id)
        return targets
    
    def _find_return_tuple_elements(self, func_sig: FunctionSignature) -> List[str]:
        """Find elements of returned tuple"""
        elements = []
        for return_id in func_sig.return_nodes:
            # Find tuple expression
            for edge in self.cpg.edges:
                if edge.source == return_id and edge.edge_type == "AST_CHILD":
                    child = self._get_node_by_id(edge.target)
                    if child and child.node_type in ["TUPLE", "ARRAY"]:
                        # Find tuple elements
                        for e2 in self.cpg.edges:
                            if e2.source == child.id and e2.edge_type == "AST_CHILD":
                                elements.append(e2.target)
        return elements
    
    def _find_potential_sources(self, node_id: str) -> List[str]:
        """Find potential data sources for uncertain flow"""
        # For uncertain nodes, look at incoming edges
        sources = []
        for edge in self.cpg.edges:
            if edge.target == node_id:
                sources.append(edge.source)
        return sources
    
    def _find_potential_sinks(self, node_id: str) -> List[str]:
        """Find potential data sinks for uncertain flow"""
        # For uncertain nodes, look at outgoing edges
        sinks = []
        for edge in self.cpg.edges:
            if edge.source == node_id:
                sinks.append(edge.target)
        return sinks
    
    def _get_node_by_id(self, node_id: str) -> Optional[GraphNode]:
        """Helper to get node by ID"""
        return next((n for n in self.cpg.nodes if n.id == node_id), None)
    
    def get_cpg(self) -> SemanticGraph:
        """Return CPG with DFG edges added"""
        all_edges = list(self.cpg.edges) + self.dfg_edges
        return SemanticGraph(
            nodes=self.cpg.nodes,
            edges=all_edges
        )
    
    def extract_interprocedural_paths(
        self,
        source_node_id: str,
        sink_node_id: str,
        max_depth: int = 10
    ) -> List[DataFlowPath]:
        """
        Extract all interprocedural data flow paths from source to sink
        
        Args:
            source_node_id: Starting node ID
            sink_node_id: Target node ID
            max_depth: Maximum path length
        
        Returns:
            List of data flow paths with uncertainty info
        """
        paths = []
        visited = set()
        
        def dfs(current: str, target: str, path: List[Tuple[str, str, DFGEdgeType]], depth: int):
            if depth > max_depth:
                return
            
            if current == target:
                # Found a path
                uncertainty = self._compute_path_uncertainty(path)
                confidence = self._compute_path_confidence(path)
                
                paths.append(DataFlowPath(
                    source_node_id=source_node_id,
                    sink_node_id=sink_node_id,
                    path_edges=list(path),
                    uncertainty=uncertainty,
                    confidence=confidence,
                    description=self._describe_path(path)
                ))
                return
            
            if current in visited:
                return
            
            visited.add(current)
            
            # Follow DFG edges
            for edge in self.dfg_edges:
                if edge.source == current:
                    edge_type = DFGEdgeType(edge.edge_type)
                    path.append((edge.source, edge.target, edge_type))
                    dfs(edge.target, target, path, depth + 1)
                    path.pop()
            
            visited.remove(current)
        
        dfs(source_node_id, sink_node_id, [], 0)
        return paths
    
    def _compute_path_uncertainty(self, path: List[Tuple[str, str, DFGEdgeType]]) -> UncertaintyLevel:
        """Compute overall uncertainty of a path"""
        if any(edge_type == DFGEdgeType.DFG_UNCERTAIN for _, _, edge_type in path):
            return UncertaintyLevel.UNKNOWN
        
        if any(edge_type == DFGEdgeType.DFG_CALLBACK for _, _, edge_type in path):
            return UncertaintyLevel.LIKELY
        
        return UncertaintyLevel.CERTAIN
    
    def _compute_path_confidence(self, path: List[Tuple[str, str, DFGEdgeType]]) -> float:
        """Compute confidence score for a path"""
        if not path:
            return 0.0
        
        # Average confidence of all edges
        confidences = []
        for source, target, edge_type in path:
            edge = next((e for e in self.dfg_edges 
                        if e.source == source and e.target == target), None)
            if edge and edge.metadata:
                confidences.append(edge.metadata.get("confidence", 1.0))
        
        return sum(confidences) / len(confidences) if confidences else 0.0
    
    def _describe_path(self, path: List[Tuple[str, str, DFGEdgeType]]) -> str:
        """Generate human-readable path description"""
        steps = []
        for source, target, edge_type in path:
            source_node = self._get_node_by_id(source)
            target_node = self._get_node_by_id(target)
            
            src_name = source_node.name if source_node else source
            tgt_name = target_node.name if target_node else target
            
            steps.append(f"{src_name} --[{edge_type.value}]--> {tgt_name}")
        
        return " → ".join(steps)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get DFG statistics"""
        stats = {
            "total_functions": len(self.functions),
            "total_call_sites": len(self.call_sites),
            "total_dfg_edges": len(self.dfg_edges),
            "edge_types": {},
            "uncertain_edges": 0,
            "closure_captures": sum(len(c) for c in self.closure_captures.values()),
        }
        
        # Count edge types
        for edge in self.dfg_edges:
            edge_type = edge.edge_type
            stats["edge_types"][edge_type] = stats["edge_types"].get(edge_type, 0) + 1
            
            if edge.metadata and edge.metadata.get("uncertainty") != "certain":
                stats["uncertain_edges"] += 1
        
        return stats
