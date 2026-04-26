import uuid
from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.api.deps import get_current_user
from app.db.mongo import get_mongo_db

router = APIRouter(prefix="/kill-chain", tags=["kill-chain"])

_STAGES = [
    {"id": "reconnaissance",       "tactic": "Reconnaissance",       "tactic_id": "TA0043", "order": 1, "color": "#6366f1", "description": "Attacker gathers intelligence about the target application, its structure, and exposed data.", "techniques": ["T1595", "T1592", "T1589"]},
    {"id": "initial_access",       "tactic": "Initial Access",       "tactic_id": "TA0001", "order": 2, "color": "#f59e0b", "description": "Attacker gains a foothold through exploitation of vulnerabilities in the application perimeter.", "techniques": ["T1190", "T1078", "T1133"]},
    {"id": "execution",            "tactic": "Execution",            "tactic_id": "TA0002", "order": 3, "color": "#ef4444", "description": "Attacker executes arbitrary malicious code within the application or server context.", "techniques": ["T1059", "T1203", "T1569"]},
    {"id": "persistence",          "tactic": "Persistence",          "tactic_id": "TA0003", "order": 4, "color": "#8b5cf6", "description": "Attacker establishes long-term access mechanisms to survive restarts and credential changes.", "techniques": ["T1505.003", "T1078", "T1543"]},
    {"id": "privilege_escalation", "tactic": "Privilege Escalation", "tactic_id": "TA0004", "order": 5, "color": "#ec4899", "description": "Attacker gains higher-level permissions within the application or underlying system.", "techniques": ["T1548", "T1134", "T1068"]},
    {"id": "credential_access",    "tactic": "Credential Access",    "tactic_id": "TA0006", "order": 6, "color": "#14b8a6", "description": "Attacker steals credentials, API keys, and secrets to gain unauthorized access to systems.", "techniques": ["T1552", "T1555", "T1528"]},
    {"id": "exfiltration",         "tactic": "Exfiltration",         "tactic_id": "TA0010", "order": 7, "color": "#f97316", "description": "Attacker extracts sensitive data from the application or target network.", "techniques": ["T1567", "T1048", "T1030"]},
    {"id": "impact",               "tactic": "Impact",               "tactic_id": "TA0040", "order": 8, "color": "#dc2626", "description": "Attacker causes direct damage to the organization's systems, data, or business operations.", "techniques": ["T1565", "T1499", "T1485"]},
]

_VULN_TO_STAGE = {
    # Reconnaissance
    "sensitive data exposure":           "reconnaissance",
    "information disclosure":            "reconnaissance",
    "verbose error":                     "reconnaissance",
    "directory traversal":               "reconnaissance",
    "path disclosure":                   "reconnaissance",
    # Initial Access
    "sql injection":                     "initial_access",
    "nosql injection":                   "initial_access",
    "xml external entity":               "initial_access",
    "xxe":                               "initial_access",
    "server-side request forgery":       "initial_access",
    "ssrf":                              "initial_access",
    "authentication bypass":             "initial_access",
    "broken authentication":             "initial_access",
    "open redirect":                     "initial_access",
    "ldap injection":                    "initial_access",
    "xpath injection":                   "initial_access",
    # Execution
    "code injection":                    "execution",
    "command injection":                 "execution",
    "os command injection":              "execution",
    "server-side template injection":    "execution",
    "ssti":                              "execution",
    "remote code execution":             "execution",
    "eval injection":                    "execution",
    "expression language injection":     "execution",
    "insecure deserialization":          "execution",
    "unsafe eval":                       "execution",
    # Persistence
    "arbitrary file upload":             "persistence",
    "unrestricted file upload":          "persistence",
    "file upload":                       "persistence",
    "path traversal":                    "persistence",
    "local file inclusion":              "persistence",
    "remote file inclusion":             "persistence",
    # Privilege Escalation
    "broken access control":             "privilege_escalation",
    "insecure direct object reference":  "privilege_escalation",
    "idor":                              "privilege_escalation",
    "privilege escalation":              "privilege_escalation",
    "missing authorization":             "privilege_escalation",
    "mass assignment":                   "privilege_escalation",
    # Credential Access
    "hardcoded secret":                  "credential_access",
    "hardcoded credential":              "credential_access",
    "cleartext transmission":            "credential_access",
    "cleartext storage":                 "credential_access",
    "weak cryptography":                 "credential_access",
    "weak password":                     "credential_access",
    "insecure randomness":               "credential_access",
    "jwt":                               "credential_access",
    "session fixation":                  "credential_access",
    # Exfiltration
    "cross-site scripting":              "exfiltration",
    "xss":                               "exfiltration",
    "cross-site request forgery":        "exfiltration",
    "csrf":                              "exfiltration",
    "clickjacking":                      "exfiltration",
    # Impact
    "denial of service":                 "impact",
    "buffer overflow":                   "impact",
    "integer overflow":                  "impact",
    "resource exhaustion":               "impact",
    "uncontrolled resource consumption": "impact",
    "open redirect":                     "impact",
}

_SEV_WEIGHT  = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}
_RISK_ORDER  = ["critical", "high", "medium", "low", "none"]

_CHAIN_TEMPLATES = [
    {"name": "Full Application Takeover",          "stages": ["reconnaissance", "initial_access", "execution", "persistence", "impact"],             "weight": 1.00},
    {"name": "Credential Theft & Privilege Abuse", "stages": ["reconnaissance", "credential_access", "privilege_escalation", "exfiltration"],         "weight": 0.90},
    {"name": "Injection → Data Breach",            "stages": ["initial_access", "execution", "exfiltration"],                                         "weight": 0.85},
    {"name": "Web Shell Deployment",               "stages": ["initial_access", "execution", "persistence"],                                          "weight": 0.80},
    {"name": "Insider Threat / Lateral Movement",  "stages": ["reconnaissance", "privilege_escalation", "exfiltration", "impact"],                    "weight": 0.70},
]


def _map_stage(vuln_type: str) -> str:
    t = (vuln_type or "").lower()
    for key, stage in _VULN_TO_STAGE.items():
        if key in t:
            return stage
    return "reconnaissance"


def _blast_radius(stage_vulns: dict, all_vulns: list) -> int:
    stages_hit  = len([s for s, v in stage_vulns.items() if v])
    breadth     = min(stages_hit / 8 * 40, 40)
    sev_total   = sum(_SEV_WEIGHT.get((v.get("severity") or "").lower(), 0) for v in all_vulns)
    sev_score   = min(sev_total / max(len(all_vulns), 1) * 40, 40)
    exec_bonus  = 20 if (stage_vulns.get("execution") or stage_vulns.get("impact")) else 0
    return min(int(breadth + sev_score + exec_bonus), 100)


def _kill_chains(stage_vulns: dict) -> list:
    active = {s for s, v in stage_vulns.items() if v}
    result = []
    for tmpl in _CHAIN_TEMPLATES:
        matched = [s for s in tmpl["stages"] if s in active]
        if len(matched) < 2:
            continue
        prob = round(len(matched) / len(tmpl["stages"]) * tmpl["weight"], 2)
        result.append({
            "id":          uuid.uuid4().hex[:8],
            "name":        tmpl["name"],
            "stages":      matched,
            "probability": prob,
        })
    result.sort(key=lambda c: c["probability"], reverse=True)
    return result[:4]


def _narrative(stage_vulns: dict, blast_radius: int) -> str:
    if not any(stage_vulns.values()):
        return "No exploitable vulnerabilities detected. The application appears secure against known attack patterns."
    parts = []
    if stage_vulns.get("reconnaissance"):
        parts.append(f"an attacker begins by harvesting {len(stage_vulns['reconnaissance'])} information disclosure point(s)")
    if stage_vulns.get("initial_access"):
        types = list({v.get("type", "vulnerability") for v in stage_vulns["initial_access"]})[:2]
        parts.append(f"then exploits {', '.join(types)} to breach the application perimeter")
    if stage_vulns.get("execution"):
        parts.append("gaining arbitrary code execution on the server")
    if stage_vulns.get("persistence"):
        parts.append("establishing persistent backdoor access")
    if stage_vulns.get("credential_access"):
        parts.append("harvesting credentials and API secrets from the codebase")
    if stage_vulns.get("privilege_escalation"):
        parts.append("escalating to administrative privileges")
    if stage_vulns.get("exfiltration"):
        parts.append(f"and exfiltrating sensitive data through {len(stage_vulns['exfiltration'])} channel(s)")
    if stage_vulns.get("impact"):
        parts.append("ultimately causing critical damage to the application and its data")
    chain = ", ".join(parts)
    if chain:
        chain = chain[0].upper() + chain[1:] + "."
    return f"Blast Radius {blast_radius}/100 — {chain}"


def _risk_level(vulns: list) -> str:
    for sev in ["critical", "high", "medium", "low"]:
        if any((v.get("severity") or "").lower() == sev for v in vulns):
            return sev
    return "none" if not vulns else "low"


@router.get("/{scan_id}")
async def get_kill_chain(
    scan_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    scan = await db.scans.find_one({"scan_id": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    all_vulns: list = (scan.get("summary") or {}).get("vulnerabilities") or []

    stage_vulns: dict[str, list] = {s["id"]: [] for s in _STAGES}
    for v in all_vulns:
        stage = _map_stage(v.get("type") or "")
        stage_vulns[stage].append({
            "id":          v.get("id"),
            "type":        v.get("type"),
            "severity":    v.get("severity"),
            "cvss_score":  v.get("cvss_score"),
            "cwe":         v.get("cwe"),
            "owasp":       v.get("owasp"),
            "file":        (v.get("location") or {}).get("file"),
            "line":        (v.get("location") or {}).get("start_line"),
            "explanation": ((v.get("analysis") or {}).get("llm_classification") or {}).get("explanation"),
        })

    br = _blast_radius(stage_vulns, all_vulns)

    stages_out = []
    for s in _STAGES:
        vulns = stage_vulns[s["id"]]
        stages_out.append({
            **s,
            "vulnerabilities": vulns,
            "vuln_count":      len(vulns),
            "active":          len(vulns) > 0,
            "risk_level":      _risk_level(vulns),
        })

    active_ordered = [s for s in stages_out if s["active"]]
    edges = []
    for i in range(len(active_ordered) - 1):
        a, b = active_ordered[i], active_ordered[i + 1]
        edges.append({
            "source":   a["id"],
            "target":   b["id"],
            "strength": round((a["vuln_count"] + b["vuln_count"]) / max(len(all_vulns), 1), 2),
        })

    chains = _kill_chains(stage_vulns)

    return {
        "scan_id":      scan_id,
        "blast_radius": br,
        "narrative":    _narrative(stage_vulns, br),
        "stages":       stages_out,
        "kill_chains":  chains,
        "edges":        edges,
        "stats": {
            "total_vulns":  len(all_vulns),
            "stages_hit":   len([s for s in stages_out if s["active"]]),
            "chains_found": len(chains),
        },
    }
