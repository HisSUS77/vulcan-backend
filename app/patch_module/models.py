from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Any

from pydantic import Field
from app.schemas.common import APIModel


class ValidationResult(APIModel):
    name: str
    passed: bool
    details: str | None = None


class VulnerabilityContext(APIModel):
    vulnerability_id: Optional[str] = None
    file_path: str
    language: str
    vuln_type: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    vulnerable_slice: str = Field(..., description="Code slice containing the vulnerability")
    context_before_after: Optional[str] = None
    taint_path: Optional[list[Any] | str] = None
    sink: Optional[str] = None
    source: Optional[str] = None


class PatchGenerateRequest(APIModel):
    vulnerability_id: Optional[str] = None
    context: Optional[VulnerabilityContext] = None


class PatchGenerateResponse(APIModel):
    patch_id: str
    unified_diff: str
    explanation: str
    confidence: float
    # Multi-dimensional breakdown: structural / semantic / overall / label / generation_attempts
    score_breakdown: Optional[dict] = None
    generation_attempts: int = 1
    validations: List[ValidationResult]
    status: str
    review_status: str = "pending_review"
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    version: int = 1


class PatchValidateResponse(APIModel):
    patch_id: str
    validations: List[ValidationResult]
    status: str


class PatchApplyResponse(APIModel):
    patch_id: str
    status: str
    pending_apply_id: str
    branch_suggestion: str
    instructions: str


class PatchExportResponse(APIModel):
    patch_id: str
    filename: str
    content: str


class PatchReviewResponse(APIModel):
    patch_id: str
    status: str
    review_status: str


class PatchHistoryItem(APIModel):
    patch_id: str
    vulnerability_id: Optional[str] = None
    vuln_type: Optional[str] = None
    file_path: Optional[str] = None
    status: str
    review_status: str = "pending_review"
    confidence: float
    version: int = 1
    created_at: Optional[datetime] = None


class PatchRecord(APIModel):
    patch_id: str
    vulnerability_id: Optional[str] = None
    user_id: str
    repo_id: Optional[str] = None
    file_path: str
    language: str
    unified_diff: str
    explanation: str
    confidence: float
    validations: List[ValidationResult]
    status: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
