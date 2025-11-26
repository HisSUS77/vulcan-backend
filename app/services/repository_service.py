from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status
from app.models.repository import Repository


MAX_UPLOAD_SIZE = 200 * 1024 * 1024  # 200MB


class RepositoryService:
    async def list_repos(self, session: AsyncSession) -> list[Repository]:
        result = await session.execute(select(Repository))
        return list(result.scalars().all())

    async def create(self, session: AsyncSession, data: dict) -> Repository:
        repo = Repository(
            name=data.get("name"),
            provider=data.get("provider"),
            url=data.get("url"),
            access_token=(data.get("token") or None),
            status=data.get("status") or "CONNECTED",
        )
        session.add(repo)
        await session.commit()
        await session.refresh(repo)
        return repo

    async def get(self, session: AsyncSession, repo_id: int) -> Repository:
        repo = await session.get(Repository, repo_id)
        if not repo:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found")
        return repo

    async def delete(self, session: AsyncSession, repo_id: int) -> None:
        repo = await self.get(session, repo_id)
        await session.delete(repo)
        await session.commit()

    async def branches(self, session: AsyncSession, repo_id: int) -> list[str]:
        await self.get(session, repo_id)
        return ["main", "develop", "feature/demo"]
