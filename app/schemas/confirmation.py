from __future__ import annotations
from datetime import datetime
from typing import Optional
from app.schemas.common import APIModel


class ConfirmedFinding(APIModel):
    id: Optional[str] = None
    scan_id: str
    finding_hash: str
    vuln_type: str
    cwe: str
    severity: str
    language: str = "python"
    file_path: str
    start_line: Optional[int] = None
    code_snippet: str
    oracle_verdict: str           # "confirmed" | "rejected"
    oracle_confidence: float
    oracle_reasoning: str
    oracle_model: str
    exploit_type: str = ""
    poc_code: str = ""
    spotcheck_required: bool = False
    human_verdict: Optional[str] = None
    human_reviewer: Optional[str] = None
    human_reviewed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


class FieldMetrics(APIModel):
    total: int = 0
    oracle_confirmed: int = 0
    oracle_rejected: int = 0
    field_precision: float = 0.0    # confirmed / (confirmed + rejected)
    spotcheck_pending: int = 0
    spotcheck_reviewed: int = 0
    human_agreement_rate: Optional[float] = None   # how often human agrees with oracle


class SpotCheckVerdict(APIModel):
    verdict: str    # "confirmed" | "rejected"
