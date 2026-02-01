# Vulcan Semantic Engine Architecture (2026-01-28)

## Overview
This document describes the current semantic analysis pipeline after the latest upgrades:
- Tree-sitter CPG parsing for Python/JS/TS
- Interprocedural DFG with argument/return propagation
- Multi-file repository graph linking
- Stage-1 path discovery + LLM classification
- HTML parsing via tree-sitter + template regex fallback
- Route decorators and auth guards linked to handlers

---

## Architecture Map (Textual)

```
                         +------------------------------+
                         |          ScanService         |
                         | (direct code / repository)   |
                         +--------------+---------------+
                                        |
                                        v
                         +------------------------------+
                         |     SemanticPipeline         |
                         |  analyze_code / repository   |
                         +--------------+---------------+
                                        |
                      +-----------------+-----------------+
                      |                                   |
                      v                                   v
         +--------------------------+         +---------------------------+
         |   SemanticGraphBuilder   |         |  MultiFileRepositoryGraph |
         | (single file CPG + DFG)  |         | (repo CPG + import links)  |
         +-----------+--------------+         +-------------+-------------+
                     |                                      |
                     v                                      v
        +-----------------------------+        +-----------------------------+
        |   CPGParser (Tree-sitter)   |        |   Interprocedural DFG       |
        |  Python/JS/TS AST + scopes  |        |  ARG_PASS/RET/CLOSURE        |
        +-----------------------------+        +-----------------------------+
                     |                                      |
                     v                                      v
                 SemanticGraph -------------------------> SemanticGraph
                     |
                     v
        +-----------------------------+
        |   Stage-1 Path Discovery    |
        |   (IIS + scoring + ranking) |
        +--------------+--------------+
                       v
        +-----------------------------+
        |  LLM Classification Service |
        +-----------------------------+
```

HTML flow integration:
- Tree-sitter HTML parsing (DOM structure)
- Regex template parsing (Jinja/EJS/Handlebars/JSX)
- HTML backend linker adds cross-layer edges

---

## New/Updated Node Types (NodeType)
Existing NodeType already covers many of these. The pipeline now relies on:
- FILE, FUNCTION, CLASS, METHOD, PARAMETER, ASSIGNMENT, RETURN
- CALL_EXPRESSION, IDENTIFIER, LITERAL
- IMPORT, MEMBER_ACCESS, ATTRIBUTE_ACCESS, SUBSCRIPT
- ARROW_FUNCTION, ASYNC_FUNCTION
- TAINT_SOURCE, SENSITIVE_SINK, SANITIZER
- TEMPLATE_LITERAL, STRING_CONCAT, STRING_FORMAT
- ROUTE_DECORATOR, AUTH_GUARD

Note: HTML nodes are stored as NodeType.EXPRESSION/IDENTIFIER with `html_node_type` in `value`.

---

## New/Updated Edge Types (EdgeType)
The engine uses:
- AST_CHILD
- CONTROL_FLOW, CFG_NEXT
- DFG_FLOW, DFG_PARAM_PASS, DFG_RET, DFG_INTERP, DFG_TEMPLATE
- TAINT_FLOW
- IMPORTS (cross-file import->export)
- HTTP_ROUTE, AUTH_COVERAGE

Cross-file edges are marked via metadata:
- `cross_file_edge_type`: IMPORT_CALL, EXPORT_RET

---

## Migration Notes
Reused:
- Existing SemanticGraph schema
- QueryExecutor and LLM classifier
- HTML regex patterns for template variables

Repaired/Upgraded:
- `CPGParser` now supports Python + normalized language input
- `InterproceduralDFG` fixed to use GraphNode/GraphEdge schema
- `MultiFileRepositoryGraph` fixed for schema consistency and DFG enrichment
- `SemanticGraphBuilder` now returns enhanced CPG directly
- Added Stage-1 Path Discovery (broad candidate generation)

Left Unchanged (intentionally):
- Existing rule-based query definitions (used as fallback)
- Report/export logic

---

## TODOs (Research-Grade Extensions)
- Full call-graph and points-to analysis
- Type inference and alias tracking
- Cross-language linking (JS <-> Python APIs)
- LLM prompt augmentation with semantic context windows
- HTML-to-backend endpoint detection via framework routing
- Support for additional languages (Go/Java/PH P)
