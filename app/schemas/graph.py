from typing import Optional, Any, Literal, Dict, Union
from pydantic import BaseModel, Field, field_validator
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType


class NodeMetadata(BaseModel):
    language: Optional[Literal["python", "javascript", "typescript"]] = None
    framework: Optional[Literal["django", "fastapi", "react", "node"]] = None
    is_tainted: bool = False
    security_role: Optional[Literal["source", "sink", "sanitizer"]] = None
    
    # Allow extra fields for CFG metadata
    model_config = {"extra": "allow"}


class GraphNode(BaseModel):
    id: str
    type: NodeType
    name: Optional[str] = None
    value: Optional[Any] = None
    file: str
    line: int
    column: int
    metadata: Optional[Union[NodeMetadata, Dict[str, Any]]] = None  # Support both structured and dict metadata
    
    @field_validator('metadata', mode='before')
    @classmethod
    def validate_metadata(cls, v):
        # If it's already a dict, keep it as dict (don't convert to NodeMetadata)
        if isinstance(v, dict):
            # Check if it has CFG-specific fields
            cfg_fields = {'then_block_start', 'else_block_start', 'loop_block_start', 
                         'try_block_start', 'except_handlers', 'is_fstring', 'is_async'}
            if any(key in v for key in cfg_fields):
                return v  # Keep as dict for CFG metadata
        return v  # Let Pydantic handle it normally


class GraphEdge(BaseModel):
    from_node: str = Field(alias="from")
    to_node: str = Field(alias="to")
    type: EdgeType
    metadata: Optional[dict[str, Any]] = None

    model_config = {"populate_by_name": True}


class SemanticGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
