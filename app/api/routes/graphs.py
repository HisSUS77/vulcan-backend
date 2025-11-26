from fastapi import APIRouter, Depends
from app.api.deps import get_current_user
from app.services.graph_service import GraphService


router = APIRouter(prefix="/graphs", tags=["graphs"])
service = GraphService()


@router.get("/{scan_id}/file/{file_id}")
async def file_graph(scan_id: str, file_id: str, type: str = "AST", user=Depends(get_current_user)):
    return service.graph(scan_id, file_id, type)


@router.get("/{scan_id}/nodes/{node_id}")
async def node_details(scan_id: str, node_id: str, user=Depends(get_current_user)):
    return {"node_id": node_id, "details": {"severity": "LOW"}, "insight": "Likely benign"}


@router.get("/{scan_id}/paths/{path_id}")
async def path_details(scan_id: str, path_id: str, user=Depends(get_current_user)):
    return {"path_id": path_id, "steps": ["source", "sanitize", "sink"], "risk": "LOW"}
