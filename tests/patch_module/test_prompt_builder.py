from app.patch_module.prompt_builder import PromptBuilder


def test_prompt_builder_sqli_python():
    prompt = PromptBuilder.build_prompt(
        language="python",
        vuln_type="SQLi",
        cwe="CWE-89",
        owasp="A03",
        vulnerable_slice="cursor.execute(query)",
        context_before_after=None,
        taint_path=["user", "query", "execute"],
        sink="cursor.execute",
        source="request.args",
    )
    assert "YOUR ONLY OUTPUT IS A VALID UNIFIED DIFF" in prompt
    assert "cursor.execute(query)" in prompt  # vulnerable slice present


def test_build_cot_reasoning_prompt_structure():
    prompt = PromptBuilder.build_cot_reasoning_prompt(
        language="python",
        vuln_type="Command Injection",
        cwe="CWE-78",
        owasp="A03",
        vulnerable_slice='os.system("ping " + host)',
        context_before_after=None,
        taint_path=["host", "os.system"],
        sink="os.system",
        source="host",
        file_path="app/utils.py",
    )
    # Must ask for reasoning, not produce a diff
    assert "ROOT CAUSE" in prompt
    assert "ATTACK VECTOR" in prompt
    assert "AFFECTED LINES" in prompt
    assert "SECURE REPLACEMENT" in prompt
    assert "IMPORTS NEEDED" in prompt
    # Must NOT instruct model to output a diff
    assert "--- a/" not in prompt
    assert "+++ b/" not in prompt
    # Vulnerability context must be present
    assert "Command Injection" in prompt
    assert "CWE-78" in prompt
    assert 'os.system("ping " + host)' in prompt


def test_build_cot_reasoning_prompt_no_diff_output():
    """CoT reasoning prompt must never request a unified diff."""
    prompt = PromptBuilder.build_cot_reasoning_prompt(
        language="javascript",
        vuln_type="XSS",
        cwe="CWE-79",
        owasp="A03",
        vulnerable_slice="el.innerHTML = userInput",
        context_before_after=None,
        taint_path=None,
        sink="innerHTML",
        source="userInput",
    )
    assert "no diff" in prompt.lower() or "not a diff" in prompt.lower() or "no diffs" in prompt.lower()
    assert "XSS" in prompt


def test_build_industrial_cot_prompt_four_phases():
    """Industrial CoT prompt must contain all 4 phases and a PATCH_SPEC block."""
    prompt = PromptBuilder.build_industrial_cot_prompt(
        language="python",
        vuln_type="SQL Injection",
        cwe="CWE-89",
        owasp="A03",
        vulnerable_slice="cursor.execute('SELECT * FROM users WHERE id=' + user_id)",
        context_before_after="def get_user(user_id):\n    cursor.execute(...)",
        taint_path=["user_id", "cursor.execute"],
        sink="cursor.execute",
        source="request.args",
        file_path="app/db.py",
    )
    # All four phases present
    assert "PHASE 1" in prompt and "THREAT MODELING" in prompt
    assert "PHASE 2" in prompt and "FIX DESIGN" in prompt
    assert "PHASE 3" in prompt and "ADVERSARIAL" in prompt
    assert "PHASE 4" in prompt and "PATCH SPECIFICATION" in prompt
    # Adversarial sub-sections
    assert "BYPASS ANALYSIS" in prompt
    assert "BYPASS_FOUND" in prompt
    # Formal spec block markers
    assert "PATCH_SPEC_BEGIN" in prompt
    assert "PATCH_SPEC_END" in prompt
    # CVSS estimation requested
    assert "CVSS" in prompt
    # Must NOT request a diff
    assert "--- a/" not in prompt
    assert "+++ b/" not in prompt
    # Vulnerability context embedded
    assert "CWE-89" in prompt
    assert "cursor.execute" in prompt


def test_build_industrial_cot_prompt_exploit_requirement():
    """Prompt must ask for a concrete exploit payload (T1.2)."""
    prompt = PromptBuilder.build_industrial_cot_prompt(
        language="javascript",
        vuln_type="Command Injection",
        cwe="CWE-78",
        owasp="A03",
        vulnerable_slice="exec('ls ' + userInput)",
        context_before_after=None,
        taint_path=["userInput", "exec"],
        sink="exec",
        source="req.query",
    )
    assert "CONCRETE EXPLOIT" in prompt
    assert "ATTACK SURFACE" in prompt
    assert "BREAKAGE_RISK" in prompt
    assert "NEW_IMPORT" in prompt


def test_prompt_builder_xss_js():
    prompt = PromptBuilder.build_prompt(
        language="javascript",
        vuln_type="XSS",
        cwe="CWE-79",
        owasp="A03",
        vulnerable_slice="el.innerHTML = userInput",
        context_before_after=None,
        taint_path=None,
        sink="innerHTML",
        source="req.query.name",
    )
    assert "innerhtml" in prompt.lower()
    assert "dompurify" in prompt.lower() or "textcontent" in prompt.lower()
