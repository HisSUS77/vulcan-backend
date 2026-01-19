"""
LLM Classifier - AI-Powered Vulnerability Validation
Uses OpenAI/Anthropic/Groq/GitHub Models to classify code slices as SAFE or VULNERABLE.
Reduces false positives from pattern-based detection.
"""
import os
import asyncio
import logging
from typing import Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class Classification(str, Enum):
    """Vulnerability classification levels."""
    SAFE = "SAFE"
    VULNERABLE = "VULNERABLE"
    LIKELY_VULNERABLE = "LIKELY_VULNERABLE"
    UNKNOWN = "UNKNOWN"


class LLMClassificationResult(BaseModel):
    """Result of LLM vulnerability classification."""
    classification: Classification
    explanation: str
    severity: str  # critical, high, medium, low
    exploitability_score: float  # 0.0 to 1.0
    remediation: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    confidence: float  # 0.0 to 1.0


class LLMService:
    """
    LLM integration service supporting multiple providers.
    Handles API calls, retries, and response parsing.
    """
    
    def __init__(
        self,
        provider: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: int = 15
    ):
        """
        Initialize LLM service.
        
        Args:
            provider: LLM provider ('openai', 'anthropic', 'groq', 'github')
            api_key: API key for provider
            model: Model name (e.g., 'gpt-4', 'Llama-4-Scout-17B-Instruct')
            base_url: Base URL for API (for GitHub Models)
            timeout: Request timeout in seconds
        """
        self.provider = provider or os.getenv('LLM_PROVIDER', 'openai')
        self.api_key = api_key or os.getenv('LLM_API_KEY')
        self.model = model or os.getenv('LLM_MODEL_CLASSIFIER', 'gpt-4')
        self.base_url = base_url or os.getenv('LLM_BASE_URL')
        self.timeout = timeout
        
        # Load system prompt
        self.system_prompt = self._load_system_prompt()
        
        if not self.api_key:
            logger.warning("No LLM_API_KEY provided - LLM classification disabled")
        
        # Initialize client
        self.client = None
        if self.api_key:
            self._init_client()
    
    def _load_system_prompt(self) -> str:
        """Load the Vulcan-LLM system prompt from file."""
        try:
            prompt_path = Path(__file__).parent.parent.parent / "app" / "LLM-prompts" / "detect-system-prompt.txt"
            if prompt_path.exists():
                with open(prompt_path, 'r', encoding='utf-8') as f:
                    return f.read().strip()
            else:
                logger.warning(f"System prompt not found at {prompt_path}")
                return "You are a security vulnerability analyzer."
        except Exception as e:
            logger.error(f"Failed to load system prompt: {e}")
            return "You are a security vulnerability analyzer."
    
    def _init_client(self):
        """Initialize provider-specific client."""
        try:
            if self.provider == 'openai':
                from openai import AsyncOpenAI
                self.client = AsyncOpenAI(api_key=self.api_key)
            elif self.provider == 'github':
                # GitHub Models uses OpenAI-compatible API
                from openai import AsyncOpenAI
                self.client = AsyncOpenAI(
                    api_key=self.api_key,
                    base_url=self.base_url or "https://models.github.ai/inference"
                )
                logger.info(f"GitHub Models initialized with {self.model}")
            elif self.provider == 'anthropic':
                from anthropic import AsyncAnthropic
                self.client = AsyncAnthropic(api_key=self.api_key)
            elif self.provider == 'groq':
                from groq import AsyncGroq
                self.client = AsyncGroq(api_key=self.api_key)
            else:
                logger.error(f"Unsupported LLM provider: {self.provider}")
        except ImportError as e:
            logger.error(f"Failed to import {self.provider} library: {e}")
            self.client = None
    
    async def classify_code_slice(
        self,
        code_snippet: str,
        rule_name: str,
        rule_description: str,
        source_label: str,
        sink_label: str,
        owasp: str,
        cwe: Optional[str]
    ) -> LLMClassificationResult:
        """
        Classify a code slice for vulnerability.
        
        Args:
            code_snippet: Code to analyze
            rule_name: Security rule name
            rule_description: Rule description
            source_label: Source node label
            sink_label: Sink node label
            owasp: OWASP category
            cwe: CWE identifier
        
        Returns:
            LLMClassificationResult with classification and details
        """
        if not self.client:
            logger.warning("LLM client not initialized, using fallback classification")
            return self._get_fallback_result()
        
        # Build prompt
        prompt = self._build_classification_prompt(
            code_snippet, rule_name, rule_description,
            source_label, sink_label, owasp, cwe
        )
        
        try:
            # Call LLM with timeout
            response = await asyncio.wait_for(
                self._call_llm(prompt),
                timeout=self.timeout
            )
            
            # Parse response
            result = self._parse_response(response, rule_name, owasp, cwe)
            return result
            
        except asyncio.TimeoutError:
            logger.error(f"LLM request timeout after {self.timeout}s")
            return self._get_fallback_result()
        except Exception as e:
            logger.error(f"LLM classification failed: {e}")
            return self._get_fallback_result()
    
    def _build_classification_prompt(
        self,
        code_snippet: str,
        rule_name: str,
        rule_description: str,
        source_label: str,
        sink_label: str,
        owasp: str,
        cwe: Optional[str]
    ) -> str:
        """Build classification prompt using Vulcan-LLM format."""
        
        # Build context object as per system prompt format
        context = {
            "language": "python",  # TODO: detect from code
            "framework": "FastAPI/Django/Generic",
            "source": source_label,
            "sink": sink_label,
            "description": f"{rule_name}: {rule_description}",
            "owasp": owasp,
            "cwe": cwe or "N/A"
        }
        
        # Build input in the format expected by Vulcan-LLM
        input_data = {
            "code": code_snippet,
            "context": context
        }
        
        return f"""Analyze this code slice for security vulnerabilities.

**Input Data:**
```json
{json.dumps(input_data, indent=2)}
```

**Instructions:**
The code slice above was extracted because the taint tracking engine detected a suspicious dataflow from source '{source_label}' to sink '{sink_label}'.

Your task is to determine if this represents a real exploitable vulnerability.

**Remember to output in this exact JSON format:**
{{
    "vulnerable": true | false,
    "type": "Vulnerability name or 'None'",
    "severity": "Low / Medium / High / Critical",
    "explanation": "Clear explanation why this is or is not a vulnerability.",
    "recommendation": "Specific fix or patch."
}}

Be strict - only mark as vulnerable if the code is actually exploitable based on what you can see.
"""
    
    async def _call_llm(self, prompt: str) -> str:
        """
        Call LLM provider API.
        
        Args:
            prompt: Classification prompt
        
        Returns:
            LLM response text
        """
        if self.provider in ['openai', 'github']:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=1000
            )
            return response.choices[0].message.content
        
        elif self.provider == 'anthropic':
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=1000,
                temperature=0.1,
                system=self.system_prompt,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return response.content[0].text
        
        elif self.provider == 'groq':
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=1000
            )
            return response.choices[0].message.content
        
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
    
    def _parse_response(
        self, response: str, rule_name: str, owasp: str, cwe: Optional[str]
    ) -> LLMClassificationResult:
        """
        Parse LLM response into structured result.
        Handles both old format and new Vulcan-LLM format.
        
        Args:
            response: LLM response text
            rule_name: Rule name (fallback)
            owasp: OWASP category (fallback)
            cwe: CWE identifier (fallback)
        
        Returns:
            LLMClassificationResult
        """
        try:
            # Extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                # Strict=False allows control characters in strings
                data = json.loads(json_str, strict=False)
                
                # Check if this is Vulcan-LLM format (has "vulnerable" field)
                if "vulnerable" in data:
                    # New Vulcan-LLM format
                    is_vulnerable = data.get("vulnerable", False)
                    vuln_type = data.get("type", "Unknown")
                    severity = data.get("severity", "Medium").lower()
                    explanation = data.get("explanation", "No explanation provided")
                    remediation = data.get("recommendation", "Review and fix the code")
                    
                    # Map to classification enum
                    if is_vulnerable and vuln_type != "None":
                        classification = Classification.VULNERABLE
                        confidence = 0.9
                        exploitability = 0.8
                    elif not is_vulnerable:
                        classification = Classification.SAFE
                        confidence = 0.9
                        exploitability = 0.0
                    else:
                        classification = Classification.UNKNOWN
                        confidence = 0.5
                        exploitability = 0.3
                    
                    return LLMClassificationResult(
                        classification=classification,
                        explanation=explanation,
                        severity=severity,
                        exploitability_score=exploitability,
                        remediation=remediation,
                        cwe=cwe,
                        owasp=owasp,
                        confidence=confidence
                    )
                
                else:
                    # Old format compatibility
                    return LLMClassificationResult(
                        classification=Classification(data.get('classification', 'UNKNOWN')),
                        explanation=data.get('explanation', 'No explanation provided'),
                        severity=data.get('severity', 'medium'),
                        exploitability_score=float(data.get('exploitability_score', 0.5)),
                        remediation=data.get('remediation', 'Review code for security issues'),
                        cwe=cwe,
                        owasp=owasp,
                        confidence=float(data.get('confidence', 0.5))
                    )
            else:
                raise ValueError("No JSON found in response")
        
        except Exception as e:
            logger.error(f"Failed to parse LLM response: {e}")
            logger.debug(f"Response was: {response[:500]}")
            return self._get_fallback_result(rule_name, owasp, cwe)
    
    def _get_fallback_result(
        self,
        rule_name: str = "Unknown",
        owasp: str = "Unknown",
        cwe: Optional[str] = None
    ) -> LLMClassificationResult:
        """Get fallback result when LLM is unavailable."""
        return LLMClassificationResult(
            classification=Classification.LIKELY_VULNERABLE,  # Changed from UNKNOWN to actually report issues
            explanation="LLM classification unavailable - using pattern-based detection only",
            severity="medium",
            exploitability_score=0.5,
            remediation="Manual review recommended - verify if user input flows to dangerous sink",
            cwe=cwe,
            owasp=owasp,
            confidence=0.5  # Increased from 0.3 since we have static analysis backing it
        )


# Global LLM service instance
_llm_service_instance: Optional[LLMService] = None


def get_llm_service() -> LLMService:
    """
    Get global LLM service instance (singleton).
    
    Returns:
        LLMService instance
    """
    global _llm_service_instance
    
    if _llm_service_instance is None:
        _llm_service_instance = LLMService()
    
    return _llm_service_instance
