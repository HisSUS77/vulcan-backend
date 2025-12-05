from enum import Enum


class EdgeType(str, Enum):
    # Structural
    AST_CHILD = "AST_CHILD"                  # Parent → Child in AST
    
    # Control flow
    CFG_NEXT = "CFG_NEXT"                    # Sequential execution
    CFG_TRUE = "CFG_TRUE"                    # If condition true
    CFG_FALSE = "CFG_FALSE"                  # If condition false
    CFG_BRANCH_TRUE = "CFG_BRANCH_TRUE"      # Alias for CFG_TRUE
    CFG_BRANCH_FALSE = "CFG_BRANCH_FALSE"    # Alias for CFG_FALSE
    CFG_LOOP_BACK = "CFG_LOOP_BACK"          # Loop back edge (iteration)
    CFG_LOOP_ENTRY = "CFG_LOOP_ENTRY"        # Loop start
    CFG_LOOP_EXIT = "CFG_LOOP_EXIT"          # Loop end
    CFG_EXCEPTION = "CFG_EXCEPTION"          # Exception thrown
    CFG_CALL = "CFG_CALL"                    # Function call edge
    CFG_RETURN = "CFG_RETURN"                # Return from function
    CFG_ASYNC = "CFG_ASYNC"                  # Async/await suspension point
    
    # Data flow
    DFG_FLOW = "DFG_FLOW"                    # General data flow
    DFG_INTERP = "DFG_INTERP"                # Variable → f-string/template literal
    DFG_TEMPLATE = "DFG_TEMPLATE"            # JS template literal interpolation
    DFG_PARAM_PASS = "DFG_PARAM_PASS"        # Argument → Parameter
    DFG_RET = "DFG_RET"                      # Return → Caller
    DFG_PROPERTY = "DFG_PROPERTY"            # Object → Property access
    DFG_ATTR = "DFG_ATTR"                    # Object → Attribute
    DFG_SUBSCRIPT = "DFG_SUBSCRIPT"          # Array/dict subscript access
    DFG_CONTROL = "DFG_CONTROL"              # Control-dependent flow (implicit)
    DFG_ASYNC = "DFG_ASYNC"                  # Async/await data flow
    
    # Call graph
    CALL_GRAPH = "CALL_GRAPH"                # Caller → Callee
    CALL_ARG = "CALL_ARG"                    # Call → Argument
    CALL_RETURN = "CALL_RETURN"              # Callee → Return value
    
    # Module relationships
    IMPORTS = "IMPORTS"                      # Module → Module
    DEFINES = "DEFINES"                      # Class → Methods
    USES = "USES"                            # Variable → Usage
    
    # Taint analysis
    TAINT_FLOW = "TAINT_FLOW"                # Source → Sink (tainted)
    TAINT_SOURCE = "TAINT_SOURCE"            # Input → Taint origin
    TAINT_SINK = "TAINT_SINK"                # Tainted → Dangerous operation
    SANITIZED = "SANITIZED"                  # Sanitizer applied
    
    # Security-specific
    AUTH_COVERAGE = "AUTH_COVERAGE"          # Endpoint → Auth check
    PERMISSION_FLOW = "PERMISSION_FLOW"      # Role → Resource
    
    # HTTP and APIs
    HTTP_FLOW = "HTTP_FLOW"                  # Frontend → Backend
    HTTP_ROUTE = "HTTP_ROUTE"                # Route → Handler
    HTTP_MIDDLEWARE = "HTTP_MIDDLEWARE"      # Middleware → Endpoint
    
    # Database
    ORM_FLOW = "ORM_FLOW"                    # Backend → Database
    SQL_PARAM = "SQL_PARAM"                  # Param → Query
