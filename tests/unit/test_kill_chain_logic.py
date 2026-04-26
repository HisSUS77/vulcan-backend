"""
Unit tests — app/api/routes/kill_chain.py (pure logic functions)

Covers: _map_stage, _blast_radius, _kill_chains, _narrative.
No database or HTTP layer involved.
"""
import pytest
from app.api.routes.kill_chain import (
    _map_stage,
    _blast_radius,
    _kill_chains,
    _narrative,
)

EMPTY_STAGES = {
    "reconnaissance": [], "initial_access": [], "execution": [],
    "persistence": [], "privilege_escalation": [], "credential_access": [],
    "exfiltration": [], "impact": [],
}


def _stages(**kwargs) -> dict:
    s = dict(EMPTY_STAGES)
    s.update(kwargs)
    return s


# ── _map_stage ────────────────────────────────────────────────────────────────

class TestMapStage:
    def test_sql_injection_maps_to_initial_access(self):
        assert _map_stage("SQL Injection") == "initial_access"

    def test_command_injection_maps_to_execution(self):
        assert _map_stage("Command Injection") == "execution"

    def test_path_traversal_maps_to_persistence(self):
        assert _map_stage("Path Traversal") == "persistence"

    def test_xss_maps_to_exfiltration(self):
        assert _map_stage("Cross-Site Scripting") == "exfiltration"

    def test_hardcoded_secret_maps_to_credential_access(self):
        assert _map_stage("Hardcoded Secret") == "credential_access"

    def test_broken_access_control_maps_to_privilege_escalation(self):
        assert _map_stage("Broken Access Control") == "privilege_escalation"

    def test_sensitive_data_exposure_maps_to_reconnaissance(self):
        assert _map_stage("Sensitive Data Exposure") == "reconnaissance"

    def test_denial_of_service_maps_to_impact(self):
        assert _map_stage("Denial of Service") == "impact"

    def test_ssrf_maps_to_initial_access(self):
        assert _map_stage("Server-Side Request Forgery") == "initial_access"

    def test_ssti_maps_to_execution(self):
        assert _map_stage("Server-Side Template Injection") == "execution"

    def test_unknown_type_defaults_to_reconnaissance(self):
        assert _map_stage("Some Unknown Vuln") == "reconnaissance"

    def test_empty_string_defaults_to_reconnaissance(self):
        assert _map_stage("") == "reconnaissance"

    def test_none_defaults_to_reconnaissance(self):
        assert _map_stage(None) == "reconnaissance"

    def test_case_insensitive(self):
        assert _map_stage("SQL INJECTION") == _map_stage("sql injection")

    def test_partial_match_works(self):
        # "xss" keyword inside longer string
        assert _map_stage("Reflected XSS in search param") == "exfiltration"

    def test_insecure_deserialization_maps_to_execution(self):
        assert _map_stage("Insecure Deserialization") == "execution"

    def test_weak_cryptography_maps_to_credential_access(self):
        assert _map_stage("Weak Cryptography") == "credential_access"


# ── _blast_radius ─────────────────────────────────────────────────────────────

class TestBlastRadius:
    def test_no_vulns_returns_zero(self):
        br = _blast_radius(EMPTY_STAGES, [])
        assert br == 0

    def test_single_critical_vuln(self):
        sv = _stages(initial_access=[{"severity": "critical"}])
        vulns = [{"severity": "critical"}]
        br = _blast_radius(sv, vulns)
        assert br > 0

    def test_execution_stage_adds_bonus(self):
        sv_with_exec = _stages(execution=[{"severity": "high"}])
        sv_without   = _stages(initial_access=[{"severity": "high"}])
        vulns = [{"severity": "high"}]
        assert _blast_radius(sv_with_exec, vulns) > _blast_radius(sv_without, vulns)

    def test_impact_stage_adds_bonus(self):
        sv_with = _stages(impact=[{"severity": "high"}])
        sv_without = _stages(persistence=[{"severity": "high"}])
        vulns = [{"severity": "high"}]
        assert _blast_radius(sv_with, vulns) > _blast_radius(sv_without, vulns)

    def test_more_stages_higher_radius(self):
        one_stage = _stages(initial_access=[{"severity": "medium"}])
        many_stages = _stages(
            initial_access=[{"severity": "medium"}],
            execution=[{"severity": "medium"}],
            credential_access=[{"severity": "medium"}],
            exfiltration=[{"severity": "medium"}],
        )
        vulns = [{"severity": "medium"}]
        assert _blast_radius(many_stages, vulns * 4) > _blast_radius(one_stage, vulns)

    def test_result_capped_at_100(self):
        # Flood every stage with critical vulns
        many = [{"severity": "critical"}] * 20
        sv = {k: many for k in EMPTY_STAGES}
        br = _blast_radius(sv, many)
        assert br <= 100

    def test_result_is_integer(self):
        sv = _stages(initial_access=[{"severity": "high"}])
        br = _blast_radius(sv, [{"severity": "high"}])
        assert isinstance(br, int)

    def test_critical_higher_than_low(self):
        sv_crit = _stages(initial_access=[{"severity": "critical"}])
        sv_low  = _stages(initial_access=[{"severity": "low"}])
        vulns_c = [{"severity": "critical"}]
        vulns_l = [{"severity": "low"}]
        assert _blast_radius(sv_crit, vulns_c) > _blast_radius(sv_low, vulns_l)


# ── _kill_chains ──────────────────────────────────────────────────────────────

class TestKillChains:
    def test_no_active_stages_returns_empty(self):
        chains = _kill_chains(EMPTY_STAGES)
        assert chains == []

    def test_single_stage_returns_empty(self):
        # Need at least 2 matched stages per template
        sv = _stages(initial_access=[{"severity": "high"}])
        chains = _kill_chains(sv)
        assert chains == []

    def test_two_matching_stages_returns_chain(self):
        sv = _stages(
            initial_access=[{"severity": "high"}],
            execution=[{"severity": "critical"}],
        )
        chains = _kill_chains(sv)
        assert len(chains) >= 1

    def test_all_stages_active_returns_up_to_4_chains(self):
        sv = {k: [{"severity": "critical"}] for k in EMPTY_STAGES}
        chains = _kill_chains(sv)
        assert 1 <= len(chains) <= 4

    def test_chains_sorted_by_probability_descending(self):
        sv = {k: [{"severity": "critical"}] for k in EMPTY_STAGES}
        chains = _kill_chains(sv)
        probs = [c["probability"] for c in chains]
        assert probs == sorted(probs, reverse=True)

    def test_each_chain_has_required_keys(self):
        sv = _stages(
            initial_access=[{}], execution=[{}], exfiltration=[{}]
        )
        chains = _kill_chains(sv)
        for c in chains:
            assert "id" in c
            assert "name" in c
            assert "stages" in c
            assert "probability" in c

    def test_probability_between_0_and_1(self):
        sv = {k: [{"severity": "high"}] for k in EMPTY_STAGES}
        chains = _kill_chains(sv)
        for c in chains:
            assert 0.0 <= c["probability"] <= 1.0


# ── _narrative ────────────────────────────────────────────────────────────────

class TestNarrative:
    def test_no_vulns_returns_secure_message(self):
        msg = _narrative(EMPTY_STAGES, 0)
        assert "secure" in msg.lower() or "no exploitable" in msg.lower()

    def test_narrative_includes_blast_radius(self):
        sv = _stages(initial_access=[{"type": "SQL Injection"}])
        msg = _narrative(sv, 45)
        assert "45" in msg

    def test_narrative_mentions_initial_access_vuln_type(self):
        sv = _stages(initial_access=[{"type": "SQL Injection"}])
        msg = _narrative(sv, 30)
        assert "SQL Injection" in msg

    def test_narrative_mentions_execution(self):
        sv = _stages(execution=[{"type": "Command Injection"}])
        msg = _narrative(sv, 70)
        assert "code execution" in msg.lower()

    def test_narrative_mentions_credential_harvesting(self):
        sv = _stages(credential_access=[{"type": "Hardcoded Secret"}])
        msg = _narrative(sv, 40)
        assert "credential" in msg.lower() or "secret" in msg.lower()

    def test_narrative_is_nonempty_string(self):
        sv = _stages(reconnaissance=[{}])
        msg = _narrative(sv, 20)
        assert isinstance(msg, str)
        assert len(msg) > 10

    def test_high_blast_radius_reflected(self):
        sv = _stages(impact=[{"type": "Denial of Service"}])
        msg = _narrative(sv, 95)
        assert "95" in msg
