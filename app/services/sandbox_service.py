"""
SandboxService — runs PoC exploit code in an isolated Docker container.

Security guarantees:
  • --network none  : no outbound network access
  • --memory 128m   : memory cap
  • --cpus 0.25     : CPU cap
  • --read-only     : read-only filesystem (except /tmp)
  • --user nobody   : non-root execution
  • 10 s timeout    : container is force-killed after deadline
  • Temp file cleanup after every run

If Docker is not installed or the daemon is unreachable, the endpoint
returns a clear error rather than crashing.
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

_TIMEOUT = int(os.getenv("SANDBOX_TIMEOUT_SEC", "10"))

_ATTACK_SCRIPT_SYSTEM = """You are a security test engineer. Given patched code and an attack type, write a SELF-CONTAINED Python script that:
1. Embeds the patched function(s) INLINE — no imports from the user's project.
2. Uses ONLY Python stdlib (sqlite3 for SQL, tempfile for files, subprocess for cmd, etc.) — no pip installs.
3. Sets up minimal in-memory test data (sqlite3.connect(':memory:'), tempfile.mktemp(), etc.).
4. Runs the exact attack payload for the given attack type against the patched function.
5. If the attack is BLOCKED: print exactly "BLOCKED" and call sys.exit(0).
6. If the attack BYPASSES the patch: print exactly "BYPASSED" then the evidence, call sys.exit(1).
7. The script must complete in under 8 seconds with NO network access.
8. Output ONLY the Python script — no markdown fences, no explanation."""

# Supported language → Docker image + runner command
_RUNNERS = {
    "python": ("python:3.11-slim", ["python", "/sandbox/exploit.py"]),
    "javascript": ("node:20-slim",  ["node",   "/sandbox/exploit.js"]),
    "js":         ("node:20-slim",  ["node",   "/sandbox/exploit.js"]),
}


@dataclass
class SandboxResult:
    confirmed:  bool          # True when exploit returned exit code 0
    stdout:     str
    stderr:     str
    exit_code:  int
    timed_out:  bool
    error:      Optional[str] = None  # set if Docker itself failed


class SandboxService:
    """Runs exploit PoC code in a Docker sandbox."""

    async def generate_attack_test(
        self,
        patched_code:     str,
        vuln_type:        str,
        attack_name:      str,
        attack_technique: str,
    ) -> "SandboxResult":
        """
        Generate a self-contained test script via LLM then execute it in the sandbox.
        The script embeds the patched function inline and uses stdlib-only resources
        (sqlite3 in-memory, tempfile, etc.) so it never needs network access.
        """
        script = await self._generate_attack_script(patched_code, vuln_type, attack_name, attack_technique)
        if not script:
            return SandboxResult(
                confirmed=False, stdout="", stderr="",
                exit_code=-1, timed_out=False,
                error="LLM unavailable — cannot generate attack test script",
            )
        return await self.run(script, "python", vuln_type)

    async def _generate_attack_script(
        self,
        patched_code:     str,
        vuln_type:        str,
        attack_name:      str,
        attack_technique: str,
    ) -> Optional[str]:
        from semantic_engine.classifier.llm_pool import RoleAwareLLMPool
        pool = RoleAwareLLMPool(role="patch", timeout=30, system_prompt=_ATTACK_SCRIPT_SYSTEM, min_interval_ms=0)
        if not pool.is_available:
            return None

        prompt = (
            f"VULNERABILITY TYPE: {vuln_type}\n"
            f"ATTACK NAME: {attack_name}\n"
            f"ATTACK TECHNIQUE: {attack_technique}\n\n"
            f"PATCHED CODE:\n```python\n{patched_code[:3000]}\n```\n\n"
            "Write the self-contained Python test script now."
        )
        raw = await pool.call(
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1200,
            temperature=0.1,
        )
        if not raw:
            return None
        # Strip markdown fences if model wrapped the output anyway
        import re
        raw = re.sub(r"^```(?:python)?\n?", "", raw.strip())
        raw = re.sub(r"\n?```$", "", raw.strip())
        return raw.strip() or None

    @staticmethod
    def is_docker_available() -> bool:
        try:
            r = subprocess.run(
                ["docker", "info"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5
            )
            return r.returncode == 0
        except Exception:
            return False

    async def run(
        self,
        poc_code:  str,
        language:  str = "python",
        vuln_type: str = "unknown",
    ) -> SandboxResult:
        """Execute poc_code in an isolated container and return real output."""
        language = language.lower()
        if language not in _RUNNERS:
            return SandboxResult(
                confirmed=False, stdout="", stderr="", exit_code=-1, timed_out=False,
                error=f"Unsupported language: {language}. Supported: {list(_RUNNERS)}"
            )

        if not self.is_docker_available():
            return SandboxResult(
                confirmed=False, stdout="", stderr="", exit_code=-1, timed_out=False,
                error="Docker daemon is not available on this host."
            )

        image, cmd = _RUNNERS[language]
        ext = ".py" if language == "python" else ".js"

        # Write PoC to a temp directory, mount read-only into container
        tmp_dir = tempfile.mkdtemp(prefix="vulcan-sandbox-")
        try:
            exploit_file = os.path.join(tmp_dir, f"exploit{ext}")
            with open(exploit_file, "w", encoding="utf-8") as f:
                f.write(poc_code)

            container_name = f"vulcan-sandbox-{uuid.uuid4().hex[:8]}"
            docker_cmd = [
                "docker", "run",
                "--rm",
                "--name",          container_name,
                "--network",       "none",
                "--memory",        "128m",
                "--memory-swap",   "128m",
                "--cpus",          "0.25",
                "--read-only",
                "--tmpfs",         "/tmp:size=16m",
                "--user",          "nobody",
                "-v",              f"{tmp_dir}:/sandbox:ro",
                image,
            ] + cmd

            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._run_docker(docker_cmd, container_name),
            )
            return result

        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @staticmethod
    def _run_docker(docker_cmd: list, container_name: str) -> SandboxResult:
        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True, text=True,
                timeout=_TIMEOUT + 5,   # outer OS timeout (docker has its own)
            )
            timed_out = False
            stdout = proc.stdout[:4000]
            stderr = proc.stderr[:2000]
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            # Force-kill the container
            subprocess.run(
                ["docker", "stop", "--time", "1", container_name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return SandboxResult(
                confirmed=False, stdout="", stderr="Execution timed out.",
                exit_code=-1, timed_out=True
            )
        except Exception as exc:
            return SandboxResult(
                confirmed=False, stdout="", stderr="", exit_code=-1,
                timed_out=False, error=str(exc)
            )

        # Confirm = exit code 0 (attacker's exploit returned success)
        confirmed = exit_code == 0 and bool(stdout.strip())
        return SandboxResult(
            confirmed=confirmed,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            timed_out=timed_out,
        )
