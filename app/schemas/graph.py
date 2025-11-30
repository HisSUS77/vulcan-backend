from typing import Optional, Any, Literal
from pydantic import BaseModel, Field
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType


class NodeMetadata(BaseModel):
    language: Optional[Literal["python", "javascript", "typescript"]] = None
    framework: Optional[Literal["django", "fastapi", "react", "node"]] = None
    is_tainted: bool = False
    security_role: Optional[Literal["source", "sink", "sanitizer"]] = None


class GraphNode(BaseModel):
    id: str
    type: NodeType
    name: Optional[str] = None
    value: Optional[Any] = None
    file: str
    line: int
    column: int
    metadata: Optional[NodeMetadata] = None


class GraphEdge(BaseModel):
    from_node: str = Field(alias="from")
    to_node: str = Field(alias="to")
    type: EdgeType
    metadata: Optional[dict[str, Any]] = None

    model_config = {"populate_by_name": True}


class SemanticGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
