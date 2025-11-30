from fastapi import APIRouter, Depends, HTTPException
from app.api.deps import get_current_user
from app.schemas.analysis import AnalyzeRequest, AnalyzeResponse
from app.services.analysis_service import AnalysisService


router = APIRouter(prefix="/analysis", tags=["analysis"])
service = AnalysisService()


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_code(request: AnalyzeRequest, user=Depends(get_current_user)):
    """
    Analyze source code for security vulnerabilities using semantic graph analysis.
    
    - Builds AST + CFG + DFG
    - Runs taint tracking
    - Validates findings with LLM reasoning
    - Generates patches
    """
    try:
        result = service.analyze_code(
            code=request.code,
            language=request.language,
            filename=request.filename or f"source.{request.language}"
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/findings")
async def list_findings(user=Depends(get_current_user)):
    """
    List recent vulnerability findings.
    (For now, returns placeholder. Can integrate with DB to store findings.)
    """
    return {
        "findings": [],
        "message": "No stored findings yet. Use POST /analysis/analyze to analyze code."
    }


@router.post("/graph")
async def build_graph(request: AnalyzeRequest, user=Depends(get_current_user)):
    """
    Build and return just the semantic graph (AST + CFG + DFG) without taint analysis.
    Useful for visualization and debugging.
    """
    try:
        graph = service.get_graph(
            code=request.code,
            language=request.language,
            filename=request.filename or f"source.{request.language}"
        )
        return graph.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Graph building failed: {str(e)}")
