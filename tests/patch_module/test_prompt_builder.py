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
