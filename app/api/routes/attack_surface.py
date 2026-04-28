import re
import uuid
from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.api.deps import get_current_user
from app.db.mongo import get_mongo_db
from app.core.permissions import can_access_resource
from app.core.exceptions import AuthorizationException

router = APIRouter(prefix="/attack-surface", tags=["attack-surface"])

_PYTHON_ROUTE_RE = re.compile(
    r'@(?:app|router|bp|blueprint|api|ns)\s*\.'
    r'(get|post|put|delete|patch|route|websocket)\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_JS_ROUTE_RE = re.compile(
    r'(?:app|router|express|server)\s*\.'
    r'(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

def _extract_route(snippet: str):
    for pat in [_PYTHON_ROUTE_RE, _JS_ROUTE_RE]:
        m = pat.search(snippet or "")
        if m:
            return m.group(1).upper(), m.group(2)
    return None, None

def _sev_rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get((sev or "").lower(), 0)

def _rank_to_risk(rank: int) -> str:
    return ["clean", "low", "medium", "high", "critical"][min(rank, 4)]

_ROUTE_HINTS = {"view", "route", "endpoint", "handler", "controller", "api", "resource", "url"}
_DATA_HINTS  = {"model", "db", "database", "query", "repo", "store", "schema", "orm", "dao"}
_UTIL_HINTS  = {"util", "helper", "middleware", "auth", "security", "service", "mixin", "lib"}


def _file_type(path: str) -> str:
    p = path.lower()
    if any(h in p for h in _ROUTE_HINTS):
        return "route"
    if any(h in p for h in _DATA_HINTS):
        return "data"
    if any(h in p for h in _UTIL_HINTS):
        return "util"
    return "other"


@router.get("/{scan_id}")
async def get_attack_surface(
    scan_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """
    Build an attack surface graph from a completed scan.

    Returns nodes (files / detected routes) with risk levels and vulnerability
    details, plus edges representing data-flow relationships between layers.
    """
    scan = await db.scans.find_one({"scan_id": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not can_access_resource(user, str(scan.get("user_id"))):
        raise AuthorizationException(f"Not authorized to access scan {scan_id}")

    summary   = scan.get("summary") or {}
    all_vulns = summary.get("vulnerabilities") or []

    # Group vulnerabilities by source file
    by_file: dict[str, list] = {}
    for v in all_vulns:
        f = (v.get("location") or {}).get("file") or "unknown"
        by_file.setdefault(f, []).append(v)

    nodes: list[dict] = []
    id_map: dict[str, str] = {}

    for file_path, file_vulns in by_file.items():
        nid = uuid.uuid4().hex[:8]
        id_map[file_path] = nid

        max_rank = max((_sev_rank(v.get("severity")) for v in file_vulns), default=0)
        risk = _rank_to_risk(max_rank)

        # Try to detect HTTP route + method from code evidence snippets
        method, route_path = None, None
        for v in file_vulns:
            snippet = (v.get("evidence") or {}).get("code_snippet") or ""
            m, p = _extract_route(snippet)
            if m and p:
                method, route_path = m, p
                break

        node_type = _file_type(file_path)
        label = route_path or file_path.replace("\\", "/").split("/")[-1]

        nodes.append({
            "id":         nid,
            "label":      label,
            "file":       file_path.replace("\\", "/"),
            "method":     method,
            "route":      route_path,
            "node_type":  node_type,
            "risk":       risk,
            "vuln_count": len(file_vulns),
            "vulnerabilities": [
                {
                    "id":          v.get("id"),
                    "type":        v.get("type"),
                    "severity":    v.get("severity"),
                    "cwe":         v.get("cwe"),
                    "owasp":       v.get("owasp"),
                    "cvss_score":  v.get("cvss_score"),
                    "location":    v.get("location"),
                    "explanation": (
                        (v.get("analysis") or {})
                        .get("llm_classification", {})
                        .get("explanation")
                    ),
                }
                for v in file_vulns
            ],
        })

    # Build edges: route-layer → data-layer and route-layer → util-layer
    edges: list[dict] = []
    by_type: dict[str, list[str]] = {"route": [], "data": [], "util": [], "other": []}
    for n in nodes:
        by_type[n["node_type"]].append(n["id"])

    for rn in by_type["route"]:
        for dn in by_type["data"]:
            edges.append({"id": f"{rn}-{dn}", "source": rn, "target": dn, "type": "data_flow"})
        for un in by_type["util"]:
            edges.append({"id": f"{rn}-{un}", "source": rn, "target": un, "type": "uses"})
    # Connect data → util as well (e.g. db helpers)
    for dn in by_type["data"]:
        for un in by_type["util"]:
            edges.append({"id": f"{dn}-{un}", "source": dn, "target": un, "type": "uses"})

    risk_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0}
    for n in nodes:
        risk_counts[n["risk"]] = risk_counts.get(n["risk"], 0) + 1

    return {
        "scan_id": scan_id,
        "nodes":   nodes,
        "edges":   edges,
        "stats":   {"total": len(nodes), **risk_counts},
    }
