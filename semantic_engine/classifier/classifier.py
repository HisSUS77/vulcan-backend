"""
Slice Classifier - Vulnerability Validation Layer
Orchestrates LLM-based classification of code slices.
Reduces false positives from static analysis.
"""
import logging
import re
from typing import List, Optional
from dataclasses import dataclass

from semantic_engine.query_executor.executor import CodeSlice
from semantic_engine.classifier.llm_service import (
    get_llm_service, 
    LLMClassificationResult,
    Classification
)

logger = logging.getLogger(__name__)

# Rules whose presence alone is sufficient evidence — LLM cannot make them "safe".
# Taint-flow rules (SQL injection, SSRF, path traversal, etc.) are NOT here;
# those still benefit from LLM false-positive filtering.
_PRESENCE_VULN_RULES = {
    "INSECURE_DESERIALIZATION",
    "WEAK_CRYPTO",
    "USE_OF_HARD_CODED_IV",
    "DEBUG_MODE_ENABLED",
    "DISABLED_CERTIFICATE_VALIDATION",
    "JWT_NONE_ALGORITHM",
    "JWT_WEAK_SECRET",
    "HARDCODED_SECRETS",
    "LOGGING_DISABLED",
    "AWS_METADATA_ACCESS",
    "GCP_METADATA_ACCESS",
    "AZURE_METADATA_ACCESS",
    "IMDS_TOKENLESS",
    "A06_NPM_RESOLVED_HTTP",
    "A06_NPM_REGISTRY_HTTP",
    "A06_PYTHON_VCS_DEP",
    "A06_PIPFILE_VCS",
    "VULNERABLE_COMPONENTS",
}


@dataclass
class ClassifiedVulnerability:
    """
    A vulnerability with LLM classification results.
    Combines static analysis detection with AI validation.
    """
    # Original slice data
    slice_id: str
    rule_id: str
    rule_name: str
    owasp: str
    cwe: Optional[str]
    
    # Location and code
    code_snippet: str
    location: dict
    source_label: str
    sink_label: str
    path_nodes: List[str]
    
    # Static analysis results
    static_severity: str
    static_confidence: str
    pattern_type: str
    static_reason: str
    
    # LLM classification results
    llm_classification: Classification
    llm_explanation: str
    llm_severity: str
    llm_exploitability: float
    llm_remediation: str
    llm_confidence: float
    
    # Final combined assessment
    final_severity: str
    final_confidence: float
    is_vulnerable: bool


class SliceClassifier:
    """
    Classifies code slices using LLM to validate static analysis findings.
    Combines pattern-based detection with AI reasoning.
    """

    def __init__(self, enable_llm: bool = True):
        self.enable_llm = enable_llm
        self.llm_service = get_llm_service() if enable_llm else None
        logger.info(f"SliceClassifier initialized (LLM: {enable_llm})")
    
    async def classify_slices(
        self, slices: List[CodeSlice]
    ) -> List[ClassifiedVulnerability]:
        """
        Classify multiple code slices concurrently.

        Spawns LLM_CLASSIFIER_WORKERS independent worker tasks, each with its own
        LLMService instance (own pool + rate limiter), so they run in true parallel.
        When one worker's pool is exhausted it falls back to static; the others
        continue unaffected with their own model cascades.
        """
        import asyncio
        import os
        from semantic_engine.classifier.llm_service import LLMService

        max_llm_calls  = int(os.getenv("MAX_LLM_DETECTION_CALLS", "100"))
        n_workers      = int(os.getenv("LLM_CLASSIFIER_WORKERS", "3"))
        _FALLBACK_EXPL = "LLM unavailable — pattern-based detection only"
        _conf_rank     = {"critical": 4, "high": 3, "medium": 2, "low": 1}

        def _needs_llm(s: "CodeSlice") -> bool:
            return not (s.pattern_type == "REGEX" and s.rule_id in _PRESENCE_VULN_RULES)

        # Sort: high-severity taint-flow slices first so they claim LLM budget
        sorted_slices = sorted(
            slices,
            key=lambda s: _conf_rank.get((s.confidence or "").lower(), 0),
            reverse=True,
        )

        # Separate slices that need LLM from those that don't
        llm_slices    = [s for s in sorted_slices if _needs_llm(s)]
        static_slices = [s for s in sorted_slices if not _needs_llm(s)]

        # ── Static slices (presence rules) — no LLM needed ───────────────────
        static_results: List[ClassifiedVulnerability] = []
        for s in static_slices:
            r = await self.classify_slice(s)
            if r:
                static_results.append(r)

        # ── LLM slices — concurrent workers ──────────────────────────────────
        # Shared queue and counters (protected by asyncio single-thread model)
        queue: asyncio.Queue = asyncio.Queue()
        for s in llm_slices[:max_llm_calls]:
            await queue.put(s)
        # Slices beyond budget go straight to static fallback
        over_budget = llm_slices[max_llm_calls:]

        llm_results: List[Optional[ClassifiedVulnerability]] = []
        counters = {"succeeded": 0, "attempted": 0}

        async def _worker(worker_id: int) -> None:
            # Each worker gets its own LLMService (own pool + rate limiter)
            svc = LLMService()
            svc._pool.reset_soft_exhausted()
            pool_dead = False

            while True:
                try:
                    slice_obj = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

                if pool_dead:
                    r = self._fallback_classify(slice_obj)
                    if r:
                        llm_results.append(r)
                    queue.task_done()
                    continue

                counters["attempted"] += 1

                # Classify using this worker's private LLM service
                r = await self._classify_with_service(slice_obj, svc)
                if r and r.llm_explanation != _FALLBACK_EXPL:
                    counters["succeeded"] += 1
                else:
                    if not svc._pool.is_available:
                        pool_dead = True
                        logger.warning(
                            f"[classifier:worker-{worker_id}] pool exhausted — "
                            "remaining queue items will use static analysis"
                        )

                if r:
                    llm_results.append(r)
                queue.task_done()

        actual_workers = min(n_workers, len(llm_slices)) if llm_slices else 0
        if actual_workers:
            await asyncio.gather(*[_worker(i) for i in range(actual_workers)])

        # Over-budget slices — static only
        for s in over_budget:
            r = self._fallback_classify(s)
            if r:
                llm_results.append(r)

        classified = static_results + [r for r in llm_results if r is not None]
        logger.info(
            f"Classified {len(classified)} vulnerabilities | "
            f"workers={actual_workers} | "
            f"LLM succeeded={counters['succeeded']}/{counters['attempted']} | "
            f"static={len(static_results)} | "
            f"over-budget={len(over_budget)} | "
            f"total slices={len(slices)}"
        )

        # Sort by final severity and confidence
        classified.sort(
            key=lambda v: (
                self._severity_rank(v.final_severity),
                -v.final_confidence
            )
        )

        return classified

    def _fallback_classify(self, slice_obj: "CodeSlice") -> Optional["ClassifiedVulnerability"]:
        """Fast path for slices beyond the LLM cap — static result only."""
        llm_result = self._get_static_only_result(slice_obj)
        final_severity, final_confidence, is_vulnerable = self._combine_results(slice_obj, llm_result)
        if not is_vulnerable:
            return None
        return ClassifiedVulnerability(
            slice_id=slice_obj.slice_id,
            rule_id=slice_obj.rule_id,
            rule_name=slice_obj.rule_name,
            owasp=slice_obj.owasp,
            cwe=slice_obj.cwe,
            code_snippet=slice_obj.code_snippet,
            location=slice_obj.location,
            source_label=slice_obj.source_label,
            sink_label=slice_obj.sink_label,
            path_nodes=slice_obj.path_nodes,
            static_severity=slice_obj.severity,
            static_confidence=slice_obj.confidence,
            pattern_type=slice_obj.pattern_type,
            static_reason=slice_obj.reason,
            llm_classification=llm_result.classification,
            llm_explanation="LLM cap reached — static analysis only",
            llm_severity=llm_result.severity,
            llm_exploitability=llm_result.exploitability_score,
            llm_remediation=llm_result.remediation,
            llm_confidence=llm_result.confidence,
            final_severity=final_severity,
            final_confidence=final_confidence,
            is_vulnerable=is_vulnerable,
        )
    
    async def _classify_with_service(
        self, slice_obj: "CodeSlice", svc
    ) -> Optional["ClassifiedVulnerability"]:
        """Classify one slice using an explicitly supplied LLMService instance."""
        if slice_obj.pattern_type == "REGEX" and slice_obj.rule_id in _PRESENCE_VULN_RULES:
            llm_result = self._get_static_only_result(slice_obj)
        elif self.enable_llm and svc:
            llm_result = await svc.classify_code_slice(
                code_snippet=slice_obj.code_snippet,
                rule_name=slice_obj.rule_name,
                rule_description=slice_obj.reason,
                source_label=slice_obj.source_label,
                sink_label=slice_obj.sink_label,
                owasp=slice_obj.owasp,
                cwe=slice_obj.cwe,
            )
        else:
            llm_result = self._get_static_only_result(slice_obj)

        if llm_result.classification != Classification.SAFE and \
                self._code_is_safe(slice_obj.rule_id, slice_obj.code_snippet):
            from semantic_engine.classifier.llm_service import LLMClassificationResult as _R
            llm_result = _R(
                classification=Classification.SAFE,
                explanation="Safe pattern detected: parameterized query / list args / allowlist / static template.",
                severity="low", exploitability_score=0.0,
                remediation="No action required.", cwe=slice_obj.cwe,
                owasp=slice_obj.owasp, confidence=0.95,
            )

        final_severity, final_confidence, is_vulnerable = self._combine_results(slice_obj, llm_result)
        if not is_vulnerable:
            return None
        return ClassifiedVulnerability(
            slice_id=slice_obj.slice_id, rule_id=slice_obj.rule_id,
            rule_name=slice_obj.rule_name, owasp=slice_obj.owasp, cwe=slice_obj.cwe,
            code_snippet=slice_obj.code_snippet, location=slice_obj.location,
            source_label=slice_obj.source_label, sink_label=slice_obj.sink_label,
            path_nodes=slice_obj.path_nodes, static_severity=slice_obj.severity,
            static_confidence=slice_obj.confidence, pattern_type=slice_obj.pattern_type,
            static_reason=slice_obj.reason, llm_classification=llm_result.classification,
            llm_explanation=llm_result.explanation, llm_severity=llm_result.severity,
            llm_exploitability=llm_result.exploitability_score,
            llm_remediation=llm_result.remediation, llm_confidence=llm_result.confidence,
            final_severity=final_severity, final_confidence=final_confidence,
            is_vulnerable=is_vulnerable,
        )

    async def classify_slice(
        self, slice_obj: CodeSlice
    ) -> Optional[ClassifiedVulnerability]:
        """Classify a single code slice using the default shared LLM service."""
        if slice_obj.pattern_type == "REGEX" and slice_obj.rule_id in _PRESENCE_VULN_RULES:
            llm_result = self._get_static_only_result(slice_obj)
        elif self.enable_llm and self.llm_service:
            llm_result = await self.llm_service.classify_code_slice(
                code_snippet=slice_obj.code_snippet,
                rule_name=slice_obj.rule_name,
                rule_description=slice_obj.reason,
                source_label=slice_obj.source_label,
                sink_label=slice_obj.sink_label,
                owasp=slice_obj.owasp,
                cwe=slice_obj.cwe
            )
        else:
            # Fallback when LLM disabled
            llm_result = self._get_static_only_result(slice_obj)
        
        # Programmatic safe-pattern override — catches well-known FP patterns
        # regardless of what the LLM decided (parameterized SQL, subprocess list, etc.)
        if llm_result.classification != Classification.SAFE and \
                self._code_is_safe(slice_obj.rule_id, slice_obj.code_snippet):
            from semantic_engine.classifier.llm_service import LLMClassificationResult as _R
            llm_result = _R(
                classification=Classification.SAFE,
                explanation="Safe pattern detected: parameterized query / list args / allowlist / static template.",
                severity="low",
                exploitability_score=0.0,
                remediation="No action required.",
                cwe=slice_obj.cwe,
                owasp=slice_obj.owasp,
                confidence=0.95,
            )

        # Combine static + LLM results
        final_severity, final_confidence, is_vulnerable = self._combine_results(
            slice_obj, llm_result
        )

        # Filter out SAFE classifications
        if not is_vulnerable:
            logger.debug(f"Filtered out SAFE slice: {slice_obj.slice_id}")
            return None
        
        # Create classified vulnerability
        return ClassifiedVulnerability(
            slice_id=slice_obj.slice_id,
            rule_id=slice_obj.rule_id,
            rule_name=slice_obj.rule_name,
            owasp=slice_obj.owasp,
            cwe=slice_obj.cwe,
            code_snippet=slice_obj.code_snippet,
            location=slice_obj.location,
            source_label=slice_obj.source_label,
            sink_label=slice_obj.sink_label,
            path_nodes=slice_obj.path_nodes,
            static_severity=slice_obj.severity,
            static_confidence=slice_obj.confidence,
            pattern_type=slice_obj.pattern_type,
            static_reason=slice_obj.reason,
            llm_classification=llm_result.classification,
            llm_explanation=llm_result.explanation,
            llm_severity=llm_result.severity,
            llm_exploitability=llm_result.exploitability_score,
            llm_remediation=llm_result.remediation,
            llm_confidence=llm_result.confidence,
            final_severity=final_severity,
            final_confidence=final_confidence,
            is_vulnerable=is_vulnerable
        )
    
    # Patterns that definitively indicate safe code — override LLM VULNERABLE verdicts.
    # Parameterized SQL: execute/query with %s, ?, or $N placeholder + tuple/array arg
    _PARAMETERIZED_SQL  = re.compile(
        r'(?:execute|query)\s*\(\s*[\'"][^\'"]*(?:%s|\$\d+)[^\'"]*[\'"],\s*[\[\(]',
        re.IGNORECASE,
    )
    _PARAMETERIZED_SQL2 = re.compile(
        r'(?:execute|query)\s*\(\s*[\'"][^\'"]*\?[^\'"]*[\'"],\s*[\[\(]',
        re.IGNORECASE,
    )
    _SUBPROCESS_LIST    = re.compile(r'subprocess\.(?:run|Popen|call|check_output)\s*\(\s*\[', re.IGNORECASE)
    _EXECFILE_ARRAY     = re.compile(r'execFile\s*\(\s*[\'"][^\'"]+[\'"],\s*\[', re.IGNORECASE)
    _DEFUSEDXML         = re.compile(r'(?:import defusedxml|from defusedxml)', re.IGNORECASE)
    # Static template: render_template_string('<literal>', keyword=args) — safe with Jinja2 autoescape
    _STATIC_TEMPLATE    = re.compile(r"render_template_string\s*\(\s*['\"]", re.IGNORECASE)
    _ALLOWLIST_CHECK    = re.compile(r'(?:ALLOWED\w*\.has|allowedHosts|is_safe_url|urlparse)\s*\(', re.IGNORECASE)
    # Path traversal sanitization: normpath + startswith prefix check
    _PATH_NORMPATH_SAFE = re.compile(r'os\.path\.normpath|path\.normalize', re.IGNORECASE)
    _PATH_STARTSWITH    = re.compile(r'startswith\s*\(', re.IGNORECASE)

    _SAFE_RULES_PATTERNS: dict = {}  # populated lazily per rule_id

    def _code_is_safe(self, rule_id: str, code: str) -> bool:
        """Return True when the code snippet contains a definitively safe pattern."""
        if self._DEFUSEDXML.search(code):
            return True
        if rule_id in ("SQL_INJECTION", "NOSQL_INJECTION", "BROKEN_ACCESS_CONTROL"):
            if self._PARAMETERIZED_SQL.search(code) or self._PARAMETERIZED_SQL2.search(code):
                return True
        if rule_id in ("COMMAND_INJECTION", "CODE_INJECTION"):
            if self._SUBPROCESS_LIST.search(code) or self._EXECFILE_ARRAY.search(code):
                return True
        if rule_id == "PATH_TRAVERSAL":
            if self._PATH_NORMPATH_SAFE.search(code) and self._PATH_STARTSWITH.search(code):
                return True
        if rule_id in ("TEMPLATE_INJECTION", "XSS"):
            if self._STATIC_TEMPLATE.search(code):
                return True
        if rule_id in ("SSRF", "UNVALIDATED_REDIRECT"):
            if self._ALLOWLIST_CHECK.search(code):
                return True
        return False

    def _get_static_only_result(self, slice_obj: CodeSlice) -> LLMClassificationResult:
        """
        Get fallback result when LLM is disabled or bypassed.
        Uses static analysis only — treats the finding as VULNERABLE.
        """
        from semantic_engine.classifier.llm_service import LLMClassificationResult
        conf_map = {"high": 0.85, "medium": 0.65, "low": 0.45, "critical": 0.90}
        conf = conf_map.get((slice_obj.confidence or "").lower(), 0.65)
        return LLMClassificationResult(
            classification=Classification.VULNERABLE,
            explanation=slice_obj.reason,
            severity=slice_obj.severity,
            exploitability_score=conf,
            remediation="Apply input validation/sanitization or replace with a safe alternative.",
            cwe=slice_obj.cwe,
            owasp=slice_obj.owasp,
            confidence=conf
        )
    
    def _combine_results(
        self,
        slice_obj: CodeSlice,
        llm_result: LLMClassificationResult
    ) -> tuple[str, float, bool]:
        """
        Combine static analysis and LLM results.
        
        Args:
            slice_obj: Original slice with static analysis
            llm_result: LLM classification result
        
        Returns:
            Tuple of (final_severity, final_confidence, is_vulnerable)
        """
        # Determine if vulnerable
        is_vulnerable = llm_result.classification in [
            Classification.VULNERABLE,
            Classification.LIKELY_VULNERABLE
        ]
        
        # If LLM says SAFE, trust it
        if llm_result.classification == Classification.SAFE:
            return "low", 0.9, False
        
        # If LLM says VULNERABLE, use LLM severity
        if llm_result.classification == Classification.VULNERABLE:
            return llm_result.severity, llm_result.confidence, True
        
        # For LIKELY_VULNERABLE or UNKNOWN, combine assessments
        # Use higher severity between static and LLM
        static_rank = self._severity_rank(slice_obj.severity)
        llm_rank = self._severity_rank(llm_result.severity)
        
        final_severity = (
            slice_obj.severity if static_rank <= llm_rank 
            else llm_result.severity
        )
        
        # Average confidence scores
        static_conf = self._confidence_to_score(slice_obj.confidence)
        final_confidence = (static_conf + llm_result.confidence) / 2
        
        return final_severity, final_confidence, is_vulnerable
    
    def _severity_rank(self, severity: str) -> int:
        """Convert severity to numeric rank (lower = more severe)."""
        ranks = {
            'critical': 0,
            'high': 1,
            'medium': 2,
            'low': 3,
            'info': 4
        }
        return ranks.get(severity.lower(), 5)
    
    def _confidence_to_score(self, confidence: str) -> float:
        """Convert confidence string to numeric score."""
        scores = {
            'high': 0.9,
            'medium': 0.6,
            'low': 0.3
        }
        return scores.get(confidence.lower(), 0.5)


# Global classifier instance
_classifier_instance: Optional[SliceClassifier] = None


def get_classifier(enable_llm: bool = True) -> SliceClassifier:
    """
    Get global classifier instance (singleton).
    Re-creates if enable_llm flag differs from the existing instance.
    """
    global _classifier_instance

    if _classifier_instance is None or _classifier_instance.enable_llm != enable_llm:
        _classifier_instance = SliceClassifier(enable_llm)

    return _classifier_instance
