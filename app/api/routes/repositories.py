from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.schemas.repository import RepositoryCreate, RepositoryRead
from app.services.repository_service import RepositoryService, MAX_UPLOAD_SIZE


router = APIRouter(prefix="/repositories", tags=["repositories"])
service = RepositoryService()


@router.get("/", response_model=list[RepositoryRead])
async def list_repos(session: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    return await service.list_repos(session)


@router.post("/", response_model=RepositoryRead, status_code=201)
async def create_repo(payload: RepositoryCreate, session: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    return await service.create(session, payload.model_dump())


@router.get("/{repo_id}", response_model=RepositoryRead)
async def get_repo(repo_id: int, session: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    return await service.get(session, repo_id)


@router.delete("/{repo_id}")
async def delete_repo(repo_id: int, session: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    await service.delete(session, repo_id)
    return {"ok": True}


@router.get("/{repo_id}/branches")
async def branches(repo_id: int, session: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    return {"branches": await service.branches(session, repo_id)}


@router.post("/{repo_id}/upload")
async def upload(repo_id: int, file: UploadFile = File(...), user=Depends(get_current_user)):
    # Size check
    contents = await file.read()
    if len(contents) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File too large")
    if file.content_type not in ("application/zip", "application/gzip", "application/x-zip-compressed", "application/x-tar"):
        raise HTTPException(status_code=422, detail="Unsupported archive format")
    return {"filename": file.filename, "size": len(contents), "status": "RECEIVED"}
