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
    Handles API calls, retries, and response parsing with automatic fallbacks.
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
        Initialize LLM service with fallback support.
        
        Args:
            provider: LLM provider ('openai', 'anthropic', 'groq', 'github')
            api_key: API key for provider
            model: Model name (e.g., 'gpt-4', 'Llama-4-Scout-17B-Instruct')
            base_url: Base URL for API (for GitHub Models)
            timeout: Request timeout in seconds
        """
        self.provider = provider or os.getenv('LLM_PROVIDER', 'github')
        self.api_key = api_key or os.getenv('LLM_API_KEY')
        self.model = model or os.getenv('LLM_MODEL_CLASSIFIER', 'meta/Llama-4-Scout-17B-16E-Instruct')
        self.base_url = base_url or os.getenv('LLM_BASE_URL')
        self.timeout = timeout
        self._response_cache: Dict[str, LLMClassificationResult] = {}
        self._min_interval_sec = float(os.getenv("LLM_MIN_INTERVAL_MS", "250")) / 1000.0
        self._semaphore = asyncio.Semaphore(int(os.getenv("LLM_MAX_CONCURRENCY", "1")))
        self._last_call_ts = 0.0
        self._rate_lock = asyncio.Lock()
        
        # Load system prompt
        self.system_prompt = self._load_system_prompt()
        
        # Initialize fallback providers
        self.fallback_providers = []
        self._setup_fallbacks()
        
        if not self.api_key and not self.fallback_providers:
            logger.warning("No LLM_API_KEY provided - LLM classification disabled")
        
        # Initialize client
        self.client = None
        self.current_provider = self.provider
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
    
    def _setup_fallbacks(self):
        """Setup fallback providers in priority order."""
        # Groq as primary fallback (fast and reliable)
        groq_key = os.getenv('GROQ_API_KEY')
        if groq_key and self.provider != 'groq':
            self.fallback_providers.append({
                'provider': 'groq',
                'api_key': groq_key,
                'model': 'llama-3.3-70b-versatile',
                'base_url': None
            })
            logger.info("Groq configured as fallback provider")
        
        # OpenAI as secondary fallback
        openai_key = os.getenv('OPENAI_API_KEY')
        if openai_key and self.provider != 'openai':
            self.fallback_providers.append({
                'provider': 'openai',
                'api_key': openai_key,
                'model': 'gpt-4o-mini',
                'base_url': None
            })
            logger.info("OpenAI configured as fallback provider")
        
        # Anthropic as tertiary fallback
        anthropic_key = os.getenv('ANTHROPIC_API_KEY')
        if anthropic_key and self.provider != 'anthropic':
            self.fallback_providers.append({
                'provider': 'anthropic',
                'api_key': anthropic_key,
                'model': 'claude-3-haiku-20240307',
                'base_url': None
            })
            logger.info("Anthropic configured as fallback provider")
    
    def _init_client(self, fallback_config: Optional[Dict[str, Any]] = None):
        """Initialize provider-specific client."""
        try:
            # Use fallback config if provided
            if fallback_config:
                provider = fallback_config['provider']
                api_key = fallback_config['api_key']
                base_url = fallback_config.get('base_url')
                model = fallback_config.get('model')
                self.current_provider = provider
                self.model = model
            else:
                provider = self.provider
                api_key = self.api_key
                base_url = self.base_url
            
            if provider == 'openai':
                from openai import AsyncOpenAI
                self.client = AsyncOpenAI(api_key=api_key)
                logger.info(f"Initialized OpenAI client with model {self.model}")
            elif provider == 'github':
                # GitHub Models uses OpenAI-compatible API
                from openai import AsyncOpenAI
                self.client = AsyncOpenAI(
                    api_key=api_key,
                    base_url=base_url or "https://models.github.ai/inference"
                )
                logger.info(f"Initialized GitHub Models with {self.model}")
            elif provider == 'anthropic':
                from anthropic import AsyncAnthropic
                self.client = AsyncAnthropic(api_key=api_key)
                logger.info(f"Initialized Anthropic client with model {self.model}")
            elif provider == 'groq':
                from groq import AsyncGroq
                self.client = AsyncGroq(api_key=api_key)
                logger.info(f"Initialized Groq client with model {self.model}")
            else:
                logger.error(f"Unsupported LLM provider: {provider}")
        except ImportError as e:
            logger.error(f"Failed to import {provider} library: {e}")
            self.client = None
        except Exception as e:
            logger.error(f"Failed to initialize {provider} client: {e}")
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
        Classify a code slice for vulnerability with automatic fallback.
        
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
        if not code_snippet or not code_snippet.strip():
            logger.warning("Empty code snippet - skipping LLM call")
            return self._get_fallback_result(rule_name, owasp, cwe)

        if not self.client:
            logger.warning("LLM client not initialized, trying fallbacks...")
            return await self._try_fallbacks(
                code_snippet, rule_name, rule_description,
                source_label, sink_label, owasp, cwe
            )
        
        # Build prompt
        prompt = self._build_classification_prompt(
            code_snippet, rule_name, rule_description,
            source_label, sink_label, owasp, cwe
        )
        cache_key = self._cache_key(prompt)
        cached = self._response_cache.get(cache_key)
        if cached:
            return cached
        
        try:
            # Call LLM with timeout
            logger.info(f"Calling {self.current_provider} for vulnerability classification...")
            response = await self._call_with_retries(prompt)
            
            # Parse response
            result = self._parse_response(response, rule_name, owasp, cwe)
            logger.info(f"{self.current_provider} classification: {result.classification}")
            self._response_cache[cache_key] = result
            return result
            
        except asyncio.TimeoutError:
            logger.error(f"{self.current_provider} request timeout after {self.timeout}s, trying fallbacks...")
            return await self._try_fallbacks(
                code_snippet, rule_name, rule_description,
                source_label, sink_label, owasp, cwe
            )
        except Exception as e:
            logger.error(f"{self.current_provider} classification failed: {e}, trying fallbacks...")
            return await self._try_fallbacks(
                code_snippet, rule_name, rule_description,
                source_label, sink_label, owasp, cwe
            )
    
    async def _try_fallbacks(
        self,
        code_snippet: str,
        rule_name: str,
        rule_description: str,
        source_label: str,
        sink_label: str,
        owasp: str,
        cwe: Optional[str]
    ) -> LLMClassificationResult:
        """Try fallback providers in order."""
        for fallback in self.fallback_providers:
            try:
                logger.info(f"Trying fallback provider: {fallback['provider']}")
                
                # Initialize fallback client
                self._init_client(fallback)
                
                if not self.client:
                    continue
                
                # Build prompt
                prompt = self._build_classification_prompt(
                    code_snippet, rule_name, rule_description,
                    source_label, sink_label, owasp, cwe
                )
                
                # Call LLM with timeout
                response = await self._call_with_retries(prompt)
                
                # Parse response
                result = self._parse_response(response, rule_name, owasp, cwe)
                logger.info(f"Fallback {self.current_provider} succeeded: {result.classification}")
                cache_key = self._cache_key(prompt)
                self._response_cache[cache_key] = result
                return result
                
            except Exception as e:
                logger.error(f"Fallback {fallback['provider']} failed: {e}")
                continue
        
        # All providers failed, return pattern-based result
        logger.warning("All LLM providers failed, using pattern-based detection")
        return self._get_fallback_result(rule_name, owasp, cwe)

    def _cache_key(self, prompt: str) -> str:
        return str(hash(prompt))

    async def _call_with_retries(self, prompt: str) -> str:
        """
        Call LLM with simple retry/backoff for rate limits/timeouts.
        """
        backoff = 1.0
        last_err: Optional[Exception] = None
        for attempt in range(5):
            try:
                async with self._semaphore:
                    await self._enforce_min_interval()
                    return await asyncio.wait_for(
                        self._call_llm(prompt),
                        timeout=self.timeout
                    )
            except Exception as e:
                last_err = e
                msg = str(e).lower()
                # Retry on rate limit / transient errors
                if "too many requests" in msg or "rate limit" in msg or "429" in msg:
                    logger.warning(f"LLM rate limited, retrying in {backoff:.1f}s (attempt {attempt + 1}/3)")
                    await asyncio.sleep(backoff)
                    backoff *= 2
                    continue
                raise
        if last_err:
            raise last_err
        raise RuntimeError("LLM call failed after retries")

    async def _enforce_min_interval(self):
        """
        Ensure a minimum interval between outbound LLM calls to avoid throttling.
        """
        async with self._rate_lock:
            now = asyncio.get_event_loop().time()
            wait = self._min_interval_sec - (now - self._last_call_ts)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call_ts = asyncio.get_event_loop().time()
    
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
        
        # Auto-detect language from code patterns
        language = self._detect_language(code_snippet)
        
        # Build context object as per system prompt format
        context = {
            "language": language,
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
    
    def _detect_language(self, code: str) -> str:
        """
        Auto-detect programming language from code patterns.
        
        Returns:
            Language identifier ('python', 'javascript', 'typescript', etc.)
        """
        code_lower = code.lower()
        
        # JavaScript/TypeScript indicators
        js_ts_patterns = [
            'const ', 'let ', 'var ', '=>', 'function(',
            'require(', 'import ', 'export ', 'async ',
            'await ', '.then(', 'console.', 'document.'
        ]
        
        # TypeScript specific
        ts_patterns = [': string', ': number', ': boolean', 'interface ', 'type ']
        
        # Python indicators
        python_patterns = [
            'def ', 'import ', 'from ', 'class ', '__init__',
            'self.', 'print(', 'if __name__', '"""', "'''", 
            'async def', 'await '
        ]
        
        # Count matches
        js_ts_score = sum(1 for pattern in js_ts_patterns if pattern in code_lower)
        ts_score = sum(1 for pattern in ts_patterns if pattern in code)
        python_score = sum(1 for pattern in python_patterns if pattern in code_lower)
        
        # TypeScript detection (must have TS-specific patterns + JS patterns)
        if ts_score > 0 and js_ts_score > 0:
            return "typescript"
        
        # JavaScript detection
        if js_ts_score > python_score and js_ts_score >= 2:
            return "javascript"
        
        # Python detection (default)
        if python_score >= js_ts_score or python_score >= 1:
            return "python"
        
        # Default to python if unclear
        return "python"
    
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
