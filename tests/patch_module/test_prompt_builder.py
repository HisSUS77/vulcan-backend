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
    assert "Return ONLY a unified diff" in prompt
    assert "parameterized queries" in prompt.lower()


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
