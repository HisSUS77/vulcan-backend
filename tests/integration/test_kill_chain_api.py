"""
Integration tests — GET /api/v1/kill-chain/{scan_id}

Tests stage mapping, blast radius computation, kill chain generation,
edge list construction, and error handling against mocked MongoDB scans.
"""
import pytest
from bson import ObjectId
from datetime import datetime, timezone


def _insert_scan(mongo_db, scan_id: str, vulns: list) -> dict:
    doc = {
        "_id": ObjectId(),
        "scan_id": scan_id,
        "status": "COMPLETED",
        "summary": {"vulnerabilities": vulns},
        "created_at": datetime.now(timezone.utc),
    }
    mongo_db.scans.insert_one(doc)
    return doc


SQL_VULN = {
    "id": "v1", "type": "SQL Injection", "severity": "critical",
    "cvss_score": 9.8, "cwe": "CWE-89", "owasp": "A03",
    "location": {"file": "app.py", "start_line": 10},
    "analysis": {"llm_classification": {"explanation": "SQL injection via f-string"}},
}

CMD_VULN = {
    "id": "v2", "type": "Command Injection", "severity": "critical",
    "cvss_score": 9.8, "cwe": "CWE-78", "owasp": "A03",
    "location": {"file": "utils.py", "start_line": 5},
    "analysis": {"llm_classification": {"explanation": "Shell=True detected"}},
}

XSS_VULN = {
    "id": "v3", "type": "Cross-Site Scripting", "severity": "high",
    "cvss_score": 7.5, "cwe": "CWE-79", "owasp": "A07",
    "location": {"file": "template.html", "start_line": 20},
    "analysis": {"llm_classification": {"explanation": "Unescaped user input"}},
}

SECRET_VULN = {
    "id": "v4", "type": "Hardcoded Secret", "severity": "critical",
    "cvss_score": 9.1, "cwe": "CWE-798", "owasp": "A07",
    "location": {"file": "config.py", "start_line": 3},
    "analysis": {"llm_classification": {"explanation": "API key in source"}},
}


class TestKillChainResponse:
    def test_returns_200_for_existing_scan(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-kc-001", [SQL_VULN])
        r = client.get("/api/v1/kill-chain/scan-kc-001")
        assert r.status_code == 200

    def test_returns_404_for_missing_scan(self, client):
        r = client.get("/api/v1/kill-chain/does-not-exist")
        assert r.status_code == 404

    def test_response_has_required_top_level_keys(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-kc-002", [SQL_VULN])
        body = client.get("/api/v1/kill-chain/scan-kc-002").json()
        for key in ("scan_id", "blast_radius", "narrative", "stages", "kill_chains", "edges", "stats"):
            assert key in body, f"Missing key: {key}"

    def test_stages_count_is_always_8(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-kc-003", [SQL_VULN, XSS_VULN])
        body = client.get("/api/v1/kill-chain/scan-kc-003").json()
        assert len(body["stages"]) == 8

    def test_each_stage_has_required_fields(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-kc-004", [SQL_VULN])
        stages = client.get("/api/v1/kill-chain/scan-kc-004").json()["stages"]
        for stage in stages:
            for field in ("id", "tactic", "tactic_id", "order", "active",
                          "vulnerabilities", "vuln_count", "risk_level"):
                assert field in stage

    def test_scan_id_echoed_in_response(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-kc-echo", [SQL_VULN])
        body = client.get("/api/v1/kill-chain/scan-kc-echo").json()
        assert body["scan_id"] == "scan-kc-echo"

    def test_unauthenticated_returns_401(self, mongo_db):
        from app.main import app
        from app.db.mongo import get_mongo_db
        _insert_scan(mongo_db, "scan-kc-unauth", [SQL_VULN])
        async def _db():
            yield mongo_db
        app.dependency_overrides[get_mongo_db] = _db
        from fastapi.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as c:
            r = c.get("/api/v1/kill-chain/scan-kc-unauth")
        app.dependency_overrides.clear()
        assert r.status_code == 401


class TestKillChainStageMapping:
    def test_sql_injection_mapped_to_initial_access(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-stage-01", [SQL_VULN])
        body = client.get("/api/v1/kill-chain/scan-stage-01").json()
        ia_stage = next(s for s in body["stages"] if s["id"] == "initial_access")
        assert ia_stage["active"] is True
        assert ia_stage["vuln_count"] == 1

    def test_command_injection_mapped_to_execution(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-stage-02", [CMD_VULN])
        body = client.get("/api/v1/kill-chain/scan-stage-02").json()
        exec_stage = next(s for s in body["stages"] if s["id"] == "execution")
        assert exec_stage["active"] is True

    def test_xss_mapped_to_exfiltration(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-stage-03", [XSS_VULN])
        body = client.get("/api/v1/kill-chain/scan-stage-03").json()
        exfil = next(s for s in body["stages"] if s["id"] == "exfiltration")
        assert exfil["active"] is True

    def test_hardcoded_secret_mapped_to_credential_access(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-stage-04", [SECRET_VULN])
        body = client.get("/api/v1/kill-chain/scan-stage-04").json()
        cred = next(s for s in body["stages"] if s["id"] == "credential_access")
        assert cred["active"] is True

    def test_inactive_stages_have_zero_vuln_count(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-stage-05", [SQL_VULN])
        body = client.get("/api/v1/kill-chain/scan-stage-05").json()
        for stage in body["stages"]:
            if not stage["active"]:
                assert stage["vuln_count"] == 0
                assert stage["vulnerabilities"] == []


class TestKillChainBlastRadius:
    def test_empty_scan_has_zero_blast_radius(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-br-01", [])
        body = client.get("/api/v1/kill-chain/scan-br-01").json()
        assert body["blast_radius"] == 0

    def test_blast_radius_is_integer(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-br-02", [SQL_VULN])
        body = client.get("/api/v1/kill-chain/scan-br-02").json()
        assert isinstance(body["blast_radius"], int)

    def test_blast_radius_between_0_and_100(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-br-03", [SQL_VULN, CMD_VULN, XSS_VULN, SECRET_VULN])
        body = client.get("/api/v1/kill-chain/scan-br-03").json()
        assert 0 <= body["blast_radius"] <= 100

    def test_multi_vuln_higher_radius_than_single(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-br-04", [SQL_VULN])
        _insert_scan(mongo_db, "scan-br-05", [SQL_VULN, CMD_VULN, XSS_VULN, SECRET_VULN])
        br_single = client.get("/api/v1/kill-chain/scan-br-04").json()["blast_radius"]
        br_multi  = client.get("/api/v1/kill-chain/scan-br-05").json()["blast_radius"]
        assert br_multi >= br_single


class TestKillChainChains:
    def test_no_vulns_returns_empty_kill_chains(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-chain-01", [])
        body = client.get("/api/v1/kill-chain/scan-chain-01").json()
        assert body["kill_chains"] == []

    def test_multi_stage_vulns_produce_kill_chains(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-chain-02", [SQL_VULN, CMD_VULN, XSS_VULN])
        body = client.get("/api/v1/kill-chain/scan-chain-02").json()
        assert len(body["kill_chains"]) >= 1

    def test_chains_capped_at_4(self, client, mongo_db):
        vulns = [SQL_VULN, CMD_VULN, XSS_VULN, SECRET_VULN]
        _insert_scan(mongo_db, "scan-chain-03", vulns)
        body = client.get("/api/v1/kill-chain/scan-chain-03").json()
        assert len(body["kill_chains"]) <= 4

    def test_chain_probability_between_0_and_1(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-chain-04", [SQL_VULN, CMD_VULN, XSS_VULN])
        chains = client.get("/api/v1/kill-chain/scan-chain-04").json()["kill_chains"]
        for c in chains:
            assert 0.0 <= c["probability"] <= 1.0


class TestKillChainStats:
    def test_stats_total_vulns_matches(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-stats-01", [SQL_VULN, XSS_VULN])
        body = client.get("/api/v1/kill-chain/scan-stats-01").json()
        assert body["stats"]["total_vulns"] == 2

    def test_stats_stages_hit_is_positive_when_vulns_exist(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-stats-02", [SQL_VULN])
        body = client.get("/api/v1/kill-chain/scan-stats-02").json()
        assert body["stats"]["stages_hit"] >= 1

    def test_stats_zero_for_empty_scan(self, client, mongo_db):
        _insert_scan(mongo_db, "scan-stats-03", [])
        body = client.get("/api/v1/kill-chain/scan-stats-03").json()
        assert body["stats"]["total_vulns"] == 0
        assert body["stats"]["stages_hit"] == 0
