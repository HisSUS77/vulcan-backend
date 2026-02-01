# Interprocedural DFG - Architecture Diagrams

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    VULCAN BACKEND                           │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         Analysis Service (API Layer)                 │  │
│  └────────────────┬─────────────────────────────────────┘  │
│                   │                                         │
│  ┌────────────────▼─────────────────────────────────────┐  │
│  │      SemanticGraphBuilder (Orchestrator)             │  │
│  │  • High-level API                                    │  │
│  │  • Backward compatible with old system               │  │
│  └────────────────┬─────────────────────────────────────┘  │
│                   │                                         │
│         ┌─────────┴─────────┐                              │
│         │                   │                              │
│  ┌──────▼──────┐    ┌──────▼─────────────────────┐        │
│  │  CPGParser  │    │  InterproceduralDFG        │        │
│  │  (Tree-     │    │  • Function extraction     │        │
│  │   sitter)   │───▶│  • Call site detection     │        │
│  │             │    │  • Arg-param matching      │        │
│  └─────────────┘    │  • Return tracking         │        │
│                     │  • Closure capture         │        │
│                     │  • Callback flow           │        │
│                     │  • Tuple unpacking         │        │
│                     │  • Uncertainty annotation  │        │
│                     └────────────────────────────┘        │
│                                 │                          │
│                     ┌───────────▼───────────┐             │
│                     │   Enhanced CPG        │             │
│                     │   (AST+CFG+DFG)       │             │
│                     └───────────┬───────────┘             │
│                                 │                          │
│                     ┌───────────▼───────────┐             │
│                     │   TaintEngine /       │             │
│                     │   Vulnerability       │             │
│                     │   Detection           │             │
│                     └───────────────────────┘             │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow Pipeline

```
   Source Code (Python/JavaScript)
          ↓
   ┌──────────────────┐
   │   CPG Parser     │  ← Tree-sitter based AST extraction
   └────────┬─────────┘
            ↓
   ┌──────────────────┐
   │   CPG            │  • Nodes (AST elements)
   │   (Initial)      │  • AST_CHILD edges
   │                  │  • CONTROL_FLOW edges (basic CFG)
   └────────┬─────────┘
            ↓
   ┌──────────────────────────────────────────┐
   │   InterproceduralDFG.build()             │
   │                                          │
   │   Step 1: Extract Functions              │
   │   ├─ Parse function signatures           │
   │   ├─ Find parameters                     │
   │   ├─ Find return statements              │
   │   └─ Detect closure captures             │
   │                                          │
   │   Step 2: Extract Call Sites             │
   │   ├─ Find all CALL nodes                 │
   │   ├─ Match callers to callees            │
   │   ├─ Extract arguments                   │
   │   └─ Detect callbacks                    │
   │                                          │
   │   Step 3: Build Intraprocedural DFG      │
   │   ├─ Track variable defs                 │
   │   ├─ Track variable uses                 │
   │   └─ Build def-use chains                │
   │                                          │
   │   Step 4: Build Interprocedural Edges    │
   │   ├─ Argument → Parameter (DFG_ARG_PASS) │
   │   └─ Return → Call site (DFG_RET)        │
   │                                          │
   │   Step 5: Language-Specific Features     │
   │   ├─ Closures (JavaScript)               │
   │   ├─ Callbacks (JavaScript)              │
   │   └─ Tuple unpacking (Python)            │
   │                                          │
   │   Step 6: Uncertainty Annotation         │
   │   └─ Mark dynamic/unknown flows          │
   └────────┬─────────────────────────────────┘
            ↓
   ┌──────────────────┐
   │  Enhanced CPG    │  • All original nodes/edges
   │  with DFG        │  • + DFG_ARG_PASS edges
   │                  │  • + DFG_RET edges
   │                  │  • + DFG_CLOSURE edges
   │                  │  • + DFG_CALLBACK edges
   │                  │  • + DFG_TUPLE_UNPACK edges
   │                  │  • + DFG_VAR_USE edges
   │                  │  • + DFG_UNCERTAIN edges
   └────────┬─────────┘
            ↓
   ┌──────────────────┐
   │  Security        │  • Taint analysis
   │  Analysis        │  • Vulnerability detection
   │                  │  • Path extraction
   └──────────────────┘
```

## Interprocedural Edge Creation

### 1. Argument Passing (DFG_ARG_PASS)

```
   Function Call                Function Definition
   ───────────────             ───────────────────
   
   func(arg1, arg2)      →     def func(param1, param2):
        │     │                         ↑       ↑
        │     └─────────────────────────┘       │
        └───────────────────────────────────────┘
            DFG_ARG_PASS edges
            (with arg_position metadata)
```

### 2. Return Value (DFG_RET)

```
   Function Definition          Function Call
   ───────────────────         ───────────────
   
   def func():                  result = func()
       ...                              ↑
       return value          ───────────┘
              │              DFG_RET edge
              └──────────────┘
```

### 3. Closure Capture (DFG_CLOSURE)

```
   Outer Function              Inner Function
   ──────────────             ──────────────
   
   def outer():                return function inner():
       x = 10                      return x + 1
       │                                  ↑
       └──────────────────────────────────┘
              DFG_CLOSURE edge
              (x captured from outer scope)
```

### 4. Callback Flow (DFG_CALLBACK)

```
   Caller Function             Callback Function
   ───────────────            ─────────────────
   
   processData(input, cb)      function cb(result):
       ...                         console.log(result)
       cb(transformed)                         ↑
              │                ────────────────┘
              └────────────────┘
                  DFG_CALLBACK edge
                  (uncertainty=LIKELY, confidence=0.8)
```

## Edge Type Hierarchy

```
DFG Edges
├── Intraprocedural (within function)
│   ├── DFG_VAR_DEF ────── Variable definition
│   ├── DFG_VAR_USE ────── Variable usage (def-use chain)
│   └── DFG_ASSIGN ──────── Assignment flow
│
├── Interprocedural (across functions)
│   ├── DFG_ARG_PASS ───── Argument → Parameter
│   ├── DFG_RET ─────────── Return → Call site
│   ├── DFG_CLOSURE ────── Closure variable capture (JS)
│   ├── DFG_CALLBACK ───── Callback invocation (JS)
│   └── DFG_TUPLE_UNPACK ─ Tuple unpacking (Python)
│
└── Uncertainty
    └── DFG_UNCERTAIN ───── Dynamic/unknown flow
```

## Uncertainty Model

```
┌─────────────────────────────────────────────────────────┐
│              UNCERTAINTY SPECTRUM                       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  CERTAIN (1.0) ═══════════════════════════════════════  │
│     x = y                                               │
│     Direct assignment, no ambiguity                     │
│                                                         │
│  LIKELY (0.8)  ─────────────────────────────────────── │
│     callback(data)                                      │
│     Known callback patterns, high confidence            │
│                                                         │
│  POSSIBLE (0.5) ·······································  │
│     obj[computedKey]                                    │
│     Dynamic with hints, medium confidence               │
│                                                         │
│  UNKNOWN (0.3)  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄  │
│     eval(userCode)                                      │
│     Cannot determine statically, low confidence         │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Example: SQL Injection Path

```
┌────────────────────────────────────────────────────────┐
│              VULNERABLE APPLICATION                    │
├────────────────────────────────────────────────────────┤
│                                                        │
│  def authenticate(username):                           │
│      query = f"SELECT * FROM users WHERE u='{username}'"│
│      return db.execute(query)                          │
│                                                        │
│  username = request.GET['user']  ← TAINTED SOURCE      │
│  authenticate(username)                                │
│                                                        │
└────────────────────────────────────────────────────────┘

Interprocedural DFG Path:

request.GET['user']
    │ (DFG_VAR_DEF)
    ↓
username (line 6)
    │ (DFG_ARG_PASS, arg_position=0)
    ↓
username parameter (line 1)
    │ (DFG_VAR_USE)
    ↓
query variable (line 2)
    │ (DFG_ARG_PASS, arg_position=0)
    ↓
db.execute() ← SQL INJECTION SINK

Path Properties:
  • Length: 4 hops
  • Uncertainty: CERTAIN
  • Confidence: 1.0
  • Interprocedural: YES (crosses function boundary)
```

## Example: Closure Capture (JavaScript)

```
┌────────────────────────────────────────────────────────┐
│              CLOSURE EXAMPLE                           │
├────────────────────────────────────────────────────────┤
│                                                        │
│  function createCounter(initial) {                     │
│      let count = initial;                              │
│      return function increment() {                     │
│          count = count + 1;                            │
│          return count;                                 │
│      };                                                │
│  }                                                     │
│                                                        │
│  const counter = createCounter(tainted);               │
│  const value = counter();                              │
│                                                        │
└────────────────────────────────────────────────────────┘

Interprocedural DFG:

tainted
    │ (DFG_ARG_PASS)
    ↓
initial parameter
    │ (DFG_VAR_USE)
    ↓
count variable (outer scope)
    │ (DFG_CLOSURE, closure_scope="createCounter")
    ↓
count reference in increment()
    │ (DFG_RET)
    ↓
value

Path Properties:
  • Uncertainty: CERTAIN
  • Confidence: 1.0
  • Closure captured: count
  • Parent scope: createCounter
```

## Integration Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  EXISTING VULCAN SYSTEM                 │
│                                                         │
│  ┌────────────────────────────────────────────────┐    │
│  │        analysis_service.py (API)               │    │
│  └─────────────────┬──────────────────────────────┘    │
│                    │                                    │
│  ┌─────────────────▼──────────────────────────────┐    │
│  │   semantic_graph_builder.py (UPDATED)          │    │
│  │   • Uses CPGParser (NEW)                       │    │
│  │   • Uses InterproceduralDFG (NEW)              │    │
│  │   • Backward compatible with SemanticGraph     │    │
│  └─────────────────┬──────────────────────────────┘    │
│                    │                                    │
│         ┌──────────┴──────────┐                        │
│         │                     │                        │
│  ┌──────▼─────┐     ┌────────▼──────────────┐         │
│  │ CPGParser  │     │ InterproceduralDFG   │         │
│  │ (NEW)      │────▶│ (NEW)                │         │
│  └────────────┘     └───────────────────────┘         │
│                                                        │
│  REMOVED (Deprecated):                                 │
│  ✗ ast_parser_enhanced.py                             │
│  ✗ cfg_builder.py                                     │
│  ✗ dfg_builder.py (old intraprocedural only)          │
│                                                        │
└─────────────────────────────────────────────────────────┘
```

## Memory Layout

```
┌─────────────────────────────────────────────────────────┐
│            INTERPROCEDURAL DFG STATE                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  functions: Dict[str, FunctionSignature]                │
│  ├─ "authenticate": FunctionSignature(...)              │
│  ├─ "authorize": FunctionSignature(...)                 │
│  └─ "get_user": FunctionSignature(...)                  │
│                                                         │
│  call_sites: List[CallSite]                             │
│  ├─ CallSite(caller="handle_request", callee="auth")    │
│  └─ CallSite(caller="auth", callee="get_user")          │
│                                                         │
│  variable_defs: Dict[str, List[str]]                    │
│  ├─ "username": ["node_12", "node_45"]                  │
│  └─ "query": ["node_23"]                                │
│                                                         │
│  variable_uses: Dict[str, List[str]]                    │
│  ├─ "username": ["node_34", "node_56"]                  │
│  └─ "query": ["node_78"]                                │
│                                                         │
│  closure_captures: Dict[str, Set[str]]                  │
│  └─ "inner_func": {"count", "prefix"}                   │
│                                                         │
│  dfg_edges: List[CPGEdge]                               │
│  ├─ CPGEdge(source="node_12", target="node_34", ...)    │
│  └─ CPGEdge(source="node_45", target="node_56", ...)    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Performance Characteristics

```
Operation                Time Complexity    Space Complexity
────────────────────────────────────────────────────────────
Function extraction      O(n)              O(f) where f = functions
Call site detection      O(n)              O(c) where c = call sites
Def-use chain building   O(n²) worst-case  O(v) where v = variables
Argument matching        O(c × p)          O(c × p)
Return tracking          O(c × r)          O(c × r)
Closure detection        O(n × s)          O(f × v)
Path extraction          O(n^d)            O(d × p) where d = depth

Where:
  n = total nodes
  f = number of functions
  c = number of call sites
  p = average parameters per function
  r = average returns per function
  s = average scope depth
  d = max path depth
  v = number of variables
```

---

## Legend

```
═══  Certain flow (confidence = 1.0)
───  Likely flow (confidence = 0.8)
···  Possible flow (confidence = 0.5)
┄┄┄  Unknown flow (confidence = 0.3)

→    Data flow direction
├─   Tree branch
└─   Tree leaf
│    Connection/pipe
```
