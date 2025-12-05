from enum import Enum


class NodeType(str, Enum):
    # Program structure
    PROGRAM = "Program"
    MODULE = "Module"
    FILE = "File"
    
    # Functions and classes
    FUNCTION = "Function"
    CLASS = "Class"
    METHOD = "Method"
    PARAMETER = "Parameter"
    VARIABLE = "Variable"
    ASSIGNMENT = "Assignment"
    RETURN = "Return"
    BINARY_OP = "BinaryOperation"
    IDENTIFIER = "Identifier"
    
    # Control flow
    IF_STATEMENT = "IfStatement"
    FOR_STATEMENT = "ForStatement"
    WHILE_STATEMENT = "WhileStatement"
    TRY_STATEMENT = "TryStatement"
    EXCEPT_HANDLER = "ExceptHandler"
    THROW_STATEMENT = "ThrowStatement"
    BREAK_STATEMENT = "BreakStatement"
    CONTINUE_STATEMENT = "ContinueStatement"
    
    # Expressions
    CALL_EXPRESSION = "CallExpression"
    ATTRIBUTE_ACCESS = "AttributeAccess"
    SUBSCRIPT = "Subscript"                  # Array/dict subscript like arr[i] or sys.argv[1]
    IMPORT = "Import"
    LITERAL = "Literal"
    
    # String operations (NEW - for injection detection)
    FSTRING = "FString"                      # Python f"...{var}..."
    STRING_CONCAT = "StringConcat"           # "a" + b or `template ${var}`
    STRING_FORMAT = "StringFormat"           # "{}".format(var)
    STRING_PERCENT = "StringPercent"         # "%s" % var
    STRING_JOIN = "StringJoin"               # "".join([...])
    STRING_TEMPLATE = "StringTemplate"       # string.Template
    TEMPLATE_LITERAL = "TemplateLiteral"     # JS/TS `...${var}...` and Python f-strings
    AWAIT_EXPRESSION = "AwaitExpression"     # await keyword for async operations
    MEMBER_EXPRESSION = "MemberExpression"   # Object property access (obj.prop)
    
    # Security-specific nodes (NEW)
    TAINT_SOURCE = "TaintSource"             # User input entry point
    SENSITIVE_SINK = "SensitiveSink"         # Dangerous operation
    AUTH_CHECK = "AuthCheck"                 # Authentication verification
    PERMISSION_CHECK = "PermissionCheck"     # Authorization check
    SANITIZER = "Sanitizer"                  # Input sanitization
    VALIDATOR = "Validator"                  # Input validation
    
    # HTTP and APIs
    HTTP_ENDPOINT = "HttpEndpoint"
    HTTP_REQUEST = "HttpRequest"
    HTTP_RESPONSE = "HttpResponse"
    ROUTE_DECORATOR = "RouteDecorator"
    MIDDLEWARE = "Middleware"
    
    # Database
    ORM_QUERY = "ORMQuery"
    SQL_QUERY = "SQLQuery"
    DB_CONNECTION = "DBConnection"
    DB_CURSOR = "DBCursor"
    
    # JavaScript/TypeScript specific
    REACT_COMPONENT = "ReactComponent"
    JSX_ELEMENT = "JSXElement"
    TS_INTERFACE = "TSInterface"
    ARROW_FUNCTION = "ArrowFunction"
    ASYNC_FUNCTION = "AsyncFunction"
    PROMISE = "Promise"
    
    # External calls
    EXTERNAL_CALL = "ExternalCall"           # HTTP client, subprocess, etc.
    SYSTEM_CALL = "SystemCall"               # OS commands
    EVAL_CALL = "EvalCall"                   # eval(), exec(), Function()
    
    # DOM (for XSS detection)
    DOM_ELEMENT = "DOMElement"
    DOM_PROPERTY = "DOMProperty"
    
    TEMPLATE_NODE = "TemplateNode"
    UNKNOWN = "Unknown"
