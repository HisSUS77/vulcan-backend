from __future__ import annotations
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import Field
from app.schemas.common import APIModel


class BenchmarkRunRequest(APIModel):
    enable_llm: bool = False


class CodeQLBenchmarkRunRequest(APIModel):
    enable_llm: bool = False
    roots: Optional[List[str]] = None
    line_tolerance: int = 2
    limit: Optional[int] = None
    supported_only: bool = True


class TestCase(APIModel):
    id: Optional[str] = None
    name: str
    code: str
    language: str                    # "python" | "javascript"
    cwe: str                         # e.g. "CWE-89"
    vuln_type: str                   # e.g. "SQL_INJECTION"
    label: str                       # "vulnerable" | "safe"
    source: str = "manual"           # "owasp" | "juliet" | "manual"
    created_at: Optional[datetime] = None


class TestCaseCreate(APIModel):
    name: str
    code: str
    language: str
    cwe: str
    vuln_type: str
    label: str
    source: str = "manual"


class CWEMetrics(APIModel):
    cwe: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0


class CaseResult(APIModel):
    test_case_id: str
    name: str
    cwe: str
    vuln_type: str
    label: str                       # ground truth
    detected: bool                   # did scanner find anything?
    detected_type: Optional[str] = None
    outcome: str                     # "TP" | "TN" | "FP" | "FN"
    confidence: float = 0.0


class BenchmarkRun(APIModel):
    id: Optional[str] = None
    run_date: Optional[datetime] = None
    model_used: str = "unknown"
    run_type: str = "synthetic"      # "synthetic" | "field"
    total: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    fp_rate: float = 0.0
    per_cwe: List[CWEMetrics] = Field(default_factory=list)
    case_results: List[CaseResult] = Field(default_factory=list)
    duration_ms: int = 0


class LeaderboardEntry(APIModel):
    model_used: str
    runs: int
    best_f1: float
    avg_precision: float
    avg_recall: float
    avg_f1: float
    last_run: Optional[datetime] = None
    trend: str = "—"                 # "↑" | "↓" | "—"
