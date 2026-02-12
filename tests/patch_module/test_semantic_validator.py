import pytest

from app.patch_module.semantic_validator import validate_semantics


def test_semantic_sqli_pass():
    patched = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
    results = validate_semantics(
        vuln_type="SQL Injection",
        sink="cursor.execute",
        source="user_id",
        taint_path=[],
        original_slice="cursor.execute(query)",
        patched_slice=patched,
    )
    assert results[0].passed is True


def test_semantic_sqli_fail():
    patched = 'query = f"SELECT * FROM users WHERE id = {user_id}"\ncur.execute(query)'
    results = validate_semantics(
        vuln_type="SQLi",
        sink="cursor.execute",
        source="user_id",
        taint_path=[],
        original_slice="cur.execute(query)",
        patched_slice=patched,
    )
    assert results[0].passed is False


def test_semantic_xss_pass():
    patched = "element.textContent = userInput"
    results = validate_semantics(
        vuln_type="XSS",
        sink="innerHTML",
        source="req.query.name",
        taint_path=[],
        original_slice="element.innerHTML = userInput",
        patched_slice=patched,
    )
    assert results[0].passed is True


def test_semantic_xss_fail():
    patched = "element.innerHTML = userInput"
    results = validate_semantics(
        vuln_type="XSS",
        sink="innerHTML",
        source="req.query.name",
        taint_path=[],
        original_slice="element.innerHTML = userInput",
        patched_slice=patched,
    )
    assert results[0].passed is False


def test_semantic_command_injection_pass():
    patched = "subprocess.run([\"ping\", \"-c\", \"1\", host], shell=False)"
    results = validate_semantics(
        vuln_type="Command Injection",
        sink="os.system",
        source="host",
        taint_path=[],
        original_slice="os.system(\"ping -c 1 \" + host)",
        patched_slice=patched,
    )
    assert results[0].passed is True


def test_semantic_command_injection_fail():
    patched = "os.system(\"ping -c 1 \" + host)"
    results = validate_semantics(
        vuln_type="Command Injection",
        sink="os.system",
        source="host",
        taint_path=[],
        original_slice="os.system(\"ping -c 1 \" + host)",
        patched_slice=patched,
    )
    assert results[0].passed is False
