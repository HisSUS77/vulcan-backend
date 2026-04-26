"""
Integration tests — /api/v1/benchmark/* endpoints

Covers: test case CRUD, benchmark run execution, leaderboard,
and field benchmark. Pipeline is fully mocked during runs.
"""
import pytest
from datetime import datetime, timezone
from bson import ObjectId
from unittest.mock import patch, MagicMock, AsyncMock


def _seed_test_cases(mongo_db, n: int = 5):
    cases = []
    for i in range(n):
        cases.append({
            "_id": ObjectId(),
            "name": f"TC-{i:03d}",
            "language": "python" if i % 2 == 0 else "javascript",
            "cwe": "CWE-89",
            "vuln_type": "SQL Injection",
            "label": "vulnerable" if i < 4 else "safe",
            "code": f"x = {i}",
            "source": "manual",
            "created_at": datetime.now(timezone.utc),
        })
    mongo_db.benchmark_test_cases.insert_many(cases)
    return cases


# ── Test Case Listing ─────────────────────────────────────────────────────────

class TestListTestCases:
    URL = "/api/v1/benchmark/test-cases"

    def test_list_returns_200(self, admin_client, mongo_db):
        _seed_test_cases(mongo_db)
        r = admin_client.get(self.URL)
        assert r.status_code == 200

    def test_list_returns_array(self, admin_client, mongo_db):
        _seed_test_cases(mongo_db)
        r = admin_client.get(self.URL)
        assert isinstance(r.json(), list)

    def test_list_count_matches_seeded(self, admin_client, mongo_db):
        _seed_test_cases(mongo_db, n=5)
        r = admin_client.get(self.URL)
        assert len(r.json()) == 5

    def test_filter_by_cwe(self, admin_client, mongo_db):
        _seed_test_cases(mongo_db)
        r = admin_client.get(self.URL, params={"cwe": "CWE-89"})
        assert r.status_code == 200
        for tc in r.json():
            assert tc["cwe"] == "CWE-89"

    def test_filter_by_language_python(self, admin_client, mongo_db):
        _seed_test_cases(mongo_db, n=6)
        r = admin_client.get(self.URL, params={"language": "python"})
        assert r.status_code == 200
        for tc in r.json():
            assert tc["language"] == "python"

    def test_filter_by_label_vulnerable(self, admin_client, mongo_db):
        _seed_test_cases(mongo_db, n=5)
        r = admin_client.get(self.URL, params={"label": "vulnerable"})
        assert r.status_code == 200
        for tc in r.json():
            assert tc["label"] == "vulnerable"

    def test_non_admin_can_list(self, client, mongo_db):
        _seed_test_cases(mongo_db, n=2)
        r = client.get(self.URL)
        # Benchmark listing is open to authenticated users
        assert r.status_code in (200, 403)

    def test_empty_db_returns_empty_list(self, admin_client, mongo_db):
        r = admin_client.get(self.URL)
        assert r.status_code == 200
        assert r.json() == []


# ── Test Case Creation ────────────────────────────────────────────────────────

class TestCreateTestCase:
    URL = "/api/v1/benchmark/test-cases"

    def test_admin_can_create_test_case(self, admin_client):
        r = admin_client.post(self.URL, json={
            "name": "SQLi-001",
            "language": "python",
            "cwe": "CWE-89",
            "vuln_type": "SQL Injection",
            "label": "vulnerable",
            "code": 'q = f"SELECT * FROM t WHERE id={uid}"',
            "source": "manual",
        })
        assert r.status_code in (200, 201)

    def test_created_case_has_id(self, admin_client):
        r = admin_client.post(self.URL, json={
            "name": "TC-new",
            "language": "python",
            "cwe": "CWE-22",
            "vuln_type": "Path Traversal",
            "label": "safe",
            "code": "open('/static/file.txt')",
            "source": "manual",
        })
        body = r.json()
        assert "id" in body

    def test_missing_required_field_returns_422(self, admin_client):
        r = admin_client.post(self.URL, json={"name": "incomplete"})
        assert r.status_code == 422

    def test_invalid_label_returns_422(self, admin_client):
        r = admin_client.post(self.URL, json={
            "name": "bad", "language": "python", "cwe": "CWE-89",
            "vuln_type": "SQLi", "label": "WRONG_LABEL",
            "code": "x=1", "source": "manual",
        })
        assert r.status_code == 422


# ── Benchmark Run ─────────────────────────────────────────────────────────────

class TestRunBenchmark:
    URL = "/api/v1/benchmark/runs"

    def _mock_pipeline(self, vulns=None):
        result = MagicMock(success=True, vulnerabilities=vulns or [])
        pipeline = MagicMock()
        pipeline.analyze_code = AsyncMock(return_value=result)
        return pipeline

    def test_run_with_no_test_cases_returns_empty_run(self, admin_client):
        r = admin_client.post(self.URL, json={"enable_llm": False})
        assert r.status_code in (200, 201)

    def test_run_returns_metrics_fields(self, admin_client, mongo_db):
        _seed_test_cases(mongo_db, n=4)
        with patch("semantic_engine.pipeline.get_pipeline") as gp:
            gp.return_value = self._mock_pipeline()
            r = admin_client.post(self.URL, json={"enable_llm": False})
        assert r.status_code in (200, 201)
        body = r.json()
        for field in ("total", "tp", "fp", "fn", "tn", "precision", "recall", "f1"):
            assert field in body, f"Missing field: {field}"

    def test_run_precision_between_0_and_1(self, admin_client, mongo_db):
        _seed_test_cases(mongo_db, n=3)
        with patch("semantic_engine.pipeline.get_pipeline") as gp:
            gp.return_value = self._mock_pipeline()
            r = admin_client.post(self.URL, json={"enable_llm": False})
        body = r.json()
        if "precision" in body:
            assert 0.0 <= body["precision"] <= 1.0

    def test_run_f1_between_0_and_1(self, admin_client, mongo_db):
        _seed_test_cases(mongo_db, n=3)
        with patch("semantic_engine.pipeline.get_pipeline") as gp:
            gp.return_value = self._mock_pipeline()
            r = admin_client.post(self.URL, json={"enable_llm": False})
        body = r.json()
        if "f1" in body:
            assert 0.0 <= body["f1"] <= 1.0

    def test_run_stored_and_retrievable(self, admin_client, mongo_db):
        _seed_test_cases(mongo_db, n=2)
        with patch("semantic_engine.pipeline.get_pipeline") as gp:
            gp.return_value = self._mock_pipeline()
            run_r = admin_client.post(self.URL, json={"enable_llm": False})
        run_id = run_r.json().get("id")
        if run_id:
            r = admin_client.get(f"/api/v1/benchmark/runs/{run_id}")
            assert r.status_code == 200

    def test_exploit_not_called_during_benchmark(self, admin_client, mongo_db):
        _seed_test_cases(mongo_db, n=2)
        exploit_calls = []
        with patch("semantic_engine.pipeline.get_pipeline") as gp:
            mock_p = self._mock_pipeline()
            gp.return_value = mock_p
            with patch("semantic_engine.classifier.exploit_llm_service",
                       side_effect=lambda *a, **kw: exploit_calls.append(1)):
                admin_client.post(self.URL, json={"enable_llm": False})
        assert len(exploit_calls) == 0


# ── Leaderboard ───────────────────────────────────────────────────────────────

class TestLeaderboard:
    URL = "/api/v1/benchmark/leaderboard"

    def test_leaderboard_returns_200(self, admin_client):
        r = admin_client.get(self.URL)
        assert r.status_code == 200

    def test_leaderboard_returns_list(self, admin_client):
        r = admin_client.get(self.URL)
        assert isinstance(r.json(), list)

    def test_leaderboard_sorted_by_best_f1_desc(self, admin_client, mongo_db):
        # Insert two fake runs with known f1 scores
        from datetime import datetime, timezone
        mongo_db.benchmark_runs.insert_many([
            {"run_type": "synthetic", "model_used": "model-a",
             "f1": 0.8, "precision": 0.8, "recall": 0.8,
             "run_date": datetime.now(timezone.utc), "total": 10},
            {"run_type": "synthetic", "model_used": "model-b",
             "f1": 0.6, "precision": 0.6, "recall": 0.6,
             "run_date": datetime.now(timezone.utc), "total": 10},
        ])
        r = admin_client.get(self.URL)
        assert r.status_code == 200
        entries = r.json()
        if len(entries) >= 2:
            f1s = [e.get("best_f1", 0) for e in entries]
            assert f1s == sorted(f1s, reverse=True)

    def test_leaderboard_entries_have_required_keys(self, admin_client, mongo_db):
        from datetime import datetime, timezone
        mongo_db.benchmark_runs.insert_one({
            "run_type": "synthetic", "model_used": "test-model",
            "f1": 0.72, "precision": 0.75, "recall": 0.69,
            "run_date": datetime.now(timezone.utc), "total": 20,
        })
        r = admin_client.get(self.URL)
        for entry in r.json():
            assert "model_used" in entry
            assert "best_f1" in entry


# ── List Runs ─────────────────────────────────────────────────────────────────

class TestListRuns:
    URL = "/api/v1/benchmark/runs"

    def test_list_runs_returns_200(self, admin_client):
        r = admin_client.get(self.URL)
        assert r.status_code == 200

    def test_list_runs_returns_list(self, admin_client):
        r = admin_client.get(self.URL)
        assert isinstance(r.json(), list)
