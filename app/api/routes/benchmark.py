from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from typing import List, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import get_current_user, get_mongo_db
from app.services.benchmark_service import BenchmarkService
from app.services.confirmation_service import ConfirmationService
from app.schemas.benchmark import (
    TestCase, TestCaseCreate, BenchmarkRun, LeaderboardEntry, BenchmarkRunRequest,
    CodeQLBenchmarkRunRequest, BenchmarkJob
)
from app.schemas.confirmation import ConfirmedFinding, FieldMetrics, SpotCheckVerdict
from app.db.seed_benchmark import SEED_CASES

router = APIRouter(prefix="/benchmark", tags=["benchmark"])


def _svc(db: AsyncIOMotorDatabase = Depends(get_mongo_db)) -> BenchmarkService:
    return BenchmarkService(db)


def _conf(db: AsyncIOMotorDatabase = Depends(get_mongo_db)) -> ConfirmationService:
    return ConfirmationService(db)


async def _run_codeql_corpus_job(
    db: AsyncIOMotorDatabase,
    job_id: str,
    body: CodeQLBenchmarkRunRequest,
) -> None:
    svc = BenchmarkService(db)
    try:
        await svc.mark_benchmark_job_running(job_id)
        run = await svc.run_codeql_corpus_benchmark(
            enable_llm=body.enable_llm,
            roots=body.roots,
            line_tolerance=body.line_tolerance,
            limit=body.limit,
            supported_only=body.supported_only,
        )
        await svc.mark_benchmark_job_completed(job_id, run.id)
    except Exception as exc:
        await svc.mark_benchmark_job_failed(job_id, str(exc))


# ── Test Cases ────────────────────────────────────────────────────────────────

@router.get("/test-cases", response_model=List[TestCase])
async def list_test_cases(
    cwe: Optional[str]      = Query(None),
    language: Optional[str] = Query(None),
    label: Optional[str]    = Query(None),
    svc: BenchmarkService   = Depends(_svc),
    _user=Depends(get_current_user),
):
    """List all benchmark test cases with optional filters."""
    await svc.seed_if_empty(SEED_CASES)
    return await svc.list_test_cases(cwe=cwe, language=language, label=label)


@router.post("/test-cases", response_model=TestCase, status_code=status.HTTP_201_CREATED)
async def create_test_case(
    body: TestCaseCreate,
    svc: BenchmarkService = Depends(_svc),
    _user=Depends(get_current_user),
):
    """Add a custom test case to the library."""
    return await svc.create_test_case(body)


@router.delete("/test-cases/{tc_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_test_case(
    tc_id: str,
    svc: BenchmarkService = Depends(_svc),
    _user=Depends(get_current_user),
):
    """Remove a test case."""
    deleted = await svc.delete_test_case(tc_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Test case not found")


# ── Benchmark runs ────────────────────────────────────────────────────────────

@router.post("/run", response_model=BenchmarkRun)
async def run_benchmark(
    body: BenchmarkRunRequest = BenchmarkRunRequest(),
    svc: BenchmarkService     = Depends(_svc),
    _user=Depends(get_current_user),
):
    """Run all test cases through the scanner and save results."""
    await svc.seed_if_empty(SEED_CASES)
    return await svc.run_benchmark(enable_llm=body.enable_llm)


@router.post("/run-codeql-corpus", response_model=BenchmarkRun)
async def run_codeql_corpus_benchmark(
    body: CodeQLBenchmarkRunRequest = CodeQLBenchmarkRunRequest(),
    svc: BenchmarkService           = Depends(_svc),
    _user=Depends(get_current_user),
):
    """Run the independently auditable CodeQL fixture corpus benchmark."""
    return await svc.run_codeql_corpus_benchmark(
        enable_llm=body.enable_llm,
        roots=body.roots,
        line_tolerance=body.line_tolerance,
        limit=body.limit,
        supported_only=body.supported_only,
    )


@router.post("/run-codeql-corpus-job", response_model=BenchmarkJob, status_code=status.HTTP_202_ACCEPTED)
async def start_codeql_corpus_benchmark_job(
    background_tasks: BackgroundTasks,
    body: CodeQLBenchmarkRunRequest = CodeQLBenchmarkRunRequest(),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
    _user=Depends(get_current_user),
):
    """Start the CodeQL corpus benchmark asynchronously and return a pollable job."""
    svc = BenchmarkService(db)
    job = await svc.create_benchmark_job(run_type="codeql-corpus")
    background_tasks.add_task(_run_codeql_corpus_job, db, job.id, body)
    return job


@router.get("/jobs/{job_id}", response_model=BenchmarkJob)
async def get_benchmark_job(
    job_id: str,
    svc: BenchmarkService = Depends(_svc),
    _user=Depends(get_current_user),
):
    """Get benchmark job status. When completed, use run_id to fetch persisted results."""
    job = await svc.get_benchmark_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Benchmark job not found")
    return job


@router.get("/runs", response_model=List[BenchmarkRun])
async def list_runs(
    limit: int            = Query(20, ge=1, le=100),
    run_type: str         = Query("synthetic", description="synthetic | field | (empty for all)"),
    svc: BenchmarkService = Depends(_svc),
    _user=Depends(get_current_user),
):
    """List past benchmark runs (without per-case detail)."""
    return await svc.list_runs(limit=limit, run_type=run_type or None)


@router.get("/runs/{run_id}", response_model=BenchmarkRun)
async def get_run(
    run_id: str,
    svc: BenchmarkService = Depends(_svc),
    _user=Depends(get_current_user),
):
    """Get full detail for a single run including per-case results."""
    run = await svc.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


# ── Leaderboard ───────────────────────────────────────────────────────────────

@router.get("/leaderboard", response_model=List[LeaderboardEntry])
async def leaderboard(
    svc: BenchmarkService = Depends(_svc),
    _user=Depends(get_current_user),
):
    """Model comparison leaderboard ranked by best F1."""
    return await svc.leaderboard()


# ── AI-oracle field confirmation ───────────────────────────────────────────────

@router.get("/field-metrics", response_model=FieldMetrics)
async def get_field_metrics(
    conf: ConfirmationService = Depends(_conf),
    _user=Depends(get_current_user),
):
    """Precision / recall metrics computed from AI-oracle confirmed real-world findings."""
    data = await conf.get_field_metrics()
    return FieldMetrics(**data)


@router.get("/confirmed-findings", response_model=List[ConfirmedFinding])
async def list_confirmed_findings(
    verdict: Optional[str]    = Query(None, description="confirmed | rejected"),
    limit: int                = Query(100, ge=1, le=500),
    conf: ConfirmationService = Depends(_conf),
    _user=Depends(get_current_user),
):
    """List AI-oracle confirmed (or rejected) real-world findings."""
    items = await conf.list_confirmed_findings(verdict=verdict, limit=limit)
    return [ConfirmedFinding(**i) for i in items]


@router.get("/spotcheck", response_model=List[ConfirmedFinding])
async def list_spotcheck(
    only_pending: bool        = Query(True),
    conf: ConfirmationService = Depends(_conf),
    _user=Depends(get_current_user),
):
    """Return the 10% sample of oracle decisions flagged for human spot-check review."""
    items = await conf.list_spotcheck_items(only_pending=only_pending)
    return [ConfirmedFinding(**i) for i in items]


@router.patch("/spotcheck/{finding_id}", status_code=status.HTTP_200_OK)
async def submit_spotcheck_verdict(
    finding_id: str,
    body: SpotCheckVerdict,
    conf: ConfirmationService = Depends(_conf),
    user=Depends(get_current_user),
):
    """Submit a human verdict (confirmed/rejected) for a spot-check item."""
    if body.verdict not in ("confirmed", "rejected"):
        raise HTTPException(status_code=400, detail="verdict must be 'confirmed' or 'rejected'")
    reviewer_id = str(user.get("id", "unknown"))
    updated = await conf.submit_verdict(finding_id, body.verdict, reviewer_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"ok": True}


@router.post("/run-field", response_model=BenchmarkRun)
async def run_field_benchmark(
    svc: BenchmarkService = Depends(_svc),
    _user=Depends(get_current_user),
):
    """Run the static pipeline against AI-oracle confirmed real-world findings."""
    return await svc.run_field_benchmark()
