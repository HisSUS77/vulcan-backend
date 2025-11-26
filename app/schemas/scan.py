from datetime import datetime
from app.schemas.common import APIModel


class ScanStart(APIModel):
    repo_id: int
    branch: str
    scan_mode: str


class ScanStatusRead(APIModel):
    state: str
    progress: int
    eta: int | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
