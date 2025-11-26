from datetime import datetime
from app.schemas.common import APIModel


class PatchGenerate(APIModel):
    vulnerability_id: int
    options: dict | None = None


class PatchRead(APIModel):
    id: int
    scan_id: str
    vuln_id: str
    original_code: str
    patched_code: str
    explanation: str
    confidence: float
    status: str
    created_at: datetime | None = None
    updated_at: datetime | None = None
