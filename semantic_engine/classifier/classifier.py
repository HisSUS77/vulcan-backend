"""
Slice Classifier - Vulnerability Validation Layer
Orchestrates LLM-based classification of code slices.
Reduces false positives from static analysis.
"""
import logging
from typing import List, Optional
from dataclasses import dataclass

from semantic_engine.query_executor.executor import CodeSlice
from semantic_engine.classifier.llm_service import (
    get_llm_service, 
    LLMClassificationResult,
    Classification
)

logger = logging.getLogger(__name__)


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
        """
        Initialize classifier.
        
        Args:
            enable_llm: Whether to use LLM classification (True) or skip it (False)
        """
        self.enable_llm = enable_llm
        self.llm_service = get_llm_service() if enable_llm else None
        
        logger.info(f"SliceClassifier initialized (LLM: {enable_llm})")
    
    async def classify_slices(
        self, slices: List[CodeSlice]
    ) -> List[ClassifiedVulnerability]:
        """
        Classify multiple code slices.
        
        Args:
            slices: List of code slices from query executor
        
        Returns:
            List of classified vulnerabilities
        """
        classified = []
        
        for slice_obj in slices:
            result = await self.classify_slice(slice_obj)
            if result:
                classified.append(result)
        
        # Sort by final severity and confidence
        classified.sort(
            key=lambda v: (
                self._severity_rank(v.final_severity),
                -v.final_confidence
            )
        )
        
        logger.info(f"Classified {len(classified)} vulnerabilities")
        return classified
    
    async def classify_slice(
        self, slice_obj: CodeSlice
    ) -> Optional[ClassifiedVulnerability]:
        """
        Classify a single code slice.
        
        Args:
            slice_obj: Code slice to classify
        
        Returns:
            ClassifiedVulnerability or None if filtered out
        """
        # Get LLM classification
        if self.enable_llm and self.llm_service:
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
    
    def _get_static_only_result(self, slice_obj: CodeSlice) -> LLMClassificationResult:
        """
        Get fallback result when LLM is disabled.
        Uses static analysis only.
        """
        from semantic_engine.classifier.llm_service import LLMClassificationResult
        
        return LLMClassificationResult(
            classification=Classification.LIKELY_VULNERABLE,
            explanation=slice_obj.reason,
            severity=slice_obj.severity,
            exploitability_score=0.6,
            remediation="Review code manually and apply input validation/sanitization",
            cwe=slice_obj.cwe,
            owasp=slice_obj.owasp,
            confidence=0.5
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
    
    Args:
        enable_llm: Whether to enable LLM classification
    
    Returns:
        SliceClassifier instance
    """
    global _classifier_instance
    
    if _classifier_instance is None:
        _classifier_instance = SliceClassifier(enable_llm)
    
    return _classifier_instance
