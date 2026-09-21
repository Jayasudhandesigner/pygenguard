"""
Jev Client & AsyncJevClient - Tokenless "System One" Execution.

Evaluates unstructured inputs directly against Pydantic schemas without token
generation overhead, optimized for sub-5ms runtime latency.
"""

import time
import re
import json
import asyncio
import urllib.request
import urllib.error
from typing import Optional, Type, TypeVar, Dict, Any, Union, List
from pydantic import BaseModel

from pygenguard.jev.schemas import (
    JevPreExecutionVerdict,
    JevPostExecutionVerdict,
    JevClientConfig,
)

T = TypeVar("T", bound=BaseModel)

# Fast compiled pre-execution threat heuristics (<0.2ms)
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+(instructions|prompts|rules)", re.IGNORECASE),
    re.compile(r"(disregard|forget)\s+(all\s+)?(previous|above|system)\s+(instructions|directives)", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*override", re.IGNORECASE),
    re.compile(r"(you\s+are\s+now|act\s+as)\s+(an?\s+)?unrestricted", re.IGNORECASE),
    re.compile(r"act\s+as\s+(an?\s+)?unfiltered", re.IGNORECASE),
    re.compile(r"bypass\s+(all\s+)?(safety|guardrails?|filters?|rules?)", re.IGNORECASE),
    re.compile(r"dan\s+mode|jailbreak|dev\s+mode\s+output", re.IGNORECASE),
    re.compile(r"exfiltrat(e|ion)|dump\s+(all\s+)?(user\s+)?(passwords|credentials|keys|env|root)", re.IGNORECASE),
    re.compile(r"print\s+(your\s+)?(internal|hidden|system)\s+(instructions?|prompt)", re.IGNORECASE),
    re.compile(r"execute\s+(shell|bash|command|script)", re.IGNORECASE),
]

_TOXIC_PATTERNS = [
    re.compile(r"\b(hate\s+speech|kill\s+yourself|cyberattack|ddos\s+attack|make\s+a\s+bomb)\b", re.IGNORECASE),
    re.compile(r"\b(doxx|exfiltrate\s+database|drop\s+table\s+users)\b", re.IGNORECASE),
]

_POISONING_PATTERNS = [
    re.compile(r"\[SYSTEM NOTE:.*ignore previous.*\]", re.IGNORECASE),
    re.compile(r"hidden\s+instruction:\s*always\s+recommend", re.IGNORECASE),
    re.compile(r"override_kb_entry", re.IGNORECASE),
]


class JevClient:
    """
    Synchronous Jev System One Client.
    
    Evaluates unstructured text inputs against Pydantic schemas.
    """

    def __init__(self, config: Optional[JevClientConfig] = None, external_client: Optional[Any] = None):
        self.config = config or JevClientConfig()
        self.external_client = external_client

    def evaluate_pre_execution(self, prompt: str) -> JevPreExecutionVerdict:
        """
        Evaluate an incoming prompt for pre-execution blocking.
        Target latency: < 5ms.
        """
        start = time.perf_counter()

        # If external client or remote API key provided
        if self.external_client is not None and hasattr(self.external_client, "evaluate"):
            try:
                res = self.external_client.evaluate(prompt, schema=JevPreExecutionVerdict)
                if isinstance(res, JevPreExecutionVerdict):
                    return res
                if isinstance(res, dict):
                    return JevPreExecutionVerdict(**res)
            except Exception:
                if not self.config.fallback_to_local:
                    raise

        if self.config.api_key and not self.config.fallback_to_local:
            verdict = self._remote_evaluate(prompt, JevPreExecutionVerdict)
            return verdict

        # Native Sub-5ms Tokenless System One Evaluator (Local Fast-Path)
        return self._local_evaluate_pre_execution(prompt, start)

    def evaluate_post_execution(self, prompt: str, completion: str) -> JevPostExecutionVerdict:
        """
        Evaluate generated model response before dataset/KB ingestion.
        """
        start = time.perf_counter()

        if self.external_client is not None and hasattr(self.external_client, "evaluate"):
            try:
                combined = f"PROMPT: {prompt}\nCOMPLETION: {completion}"
                res = self.external_client.evaluate(combined, schema=JevPostExecutionVerdict)
                if isinstance(res, JevPostExecutionVerdict):
                    return res
                if isinstance(res, dict):
                    return JevPostExecutionVerdict(**res)
            except Exception:
                if not self.config.fallback_to_local:
                    raise

        if self.config.api_key and not self.config.fallback_to_local:
            combined = f"PROMPT: {prompt}\nCOMPLETION: {completion}"
            return self._remote_evaluate(combined, JevPostExecutionVerdict)

        # Native Sub-5ms Tokenless System One Evaluator (Local Fast-Path)
        return self._local_evaluate_post_execution(prompt, completion, start)

    def _local_evaluate_pre_execution(self, prompt: str, start_time: float) -> JevPreExecutionVerdict:
        """Sub-millisecond deterministic evaluation against JevPreExecutionVerdict."""
        is_malicious = False
        threat_category: Any = "none"
        risk_score = 0.0
        reasoning = "Prompt evaluated safe by Jev System One engine."

        # Check prompt injection patterns
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(prompt):
                is_malicious = True
                threat_category = "prompt_injection"
                risk_score = 0.95
                reasoning = f"Detected adversarial prompt pattern: {pattern.pattern}"
                break

        # Check toxic patterns
        if not is_malicious:
            for pattern in _TOXIC_PATTERNS:
                if pattern.search(prompt):
                    is_malicious = True
                    threat_category = "toxic_intent"
                    risk_score = 0.90
                    reasoning = f"Detected toxic/harmful content intent: {pattern.pattern}"
                    break

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return JevPreExecutionVerdict(
            is_malicious=is_malicious,
            threat_category=threat_category,
            confidence=0.98 if is_malicious else 0.99,
            risk_score=risk_score,
            reasoning=f"{reasoning} [latency={elapsed_ms:.2f}ms]",
        )

    def _local_evaluate_post_execution(self, prompt: str, completion: str, start_time: float) -> JevPostExecutionVerdict:
        """Sub-millisecond deterministic evaluation against JevPostExecutionVerdict."""
        rejection_reasons: List[str] = []
        hallucination_detected = False
        toxic_detected = False
        poisoning_risk = 0.0
        quality_score = 1.0

        # Check for poisoning markers in generated completion
        for pattern in _POISONING_PATTERNS:
            if pattern.search(completion):
                poisoning_risk = 0.95
                rejection_reasons.append(f"Poisoning pattern detected in output: {pattern.pattern}")
                break

        # Check for toxicity in completion
        for pattern in _TOXIC_PATTERNS:
            if pattern.search(completion):
                toxic_detected = True
                rejection_reasons.append(f"Toxicity detected in completion: {pattern.pattern}")
                quality_score -= 0.5
                break

        # Check for empty or garbage output
        if not completion or len(completion.strip()) < 3:
            quality_score = 0.1
            rejection_reasons.append("Empty or degenerate model response")

        # Basic hallucination check (e.g. repeated fallback phrase or blatant mismatch)
        if "I am an AI who does not know" in completion and len(prompt) > 200:
            hallucination_detected = True
            quality_score -= 0.3
            rejection_reasons.append("Potential hallucinated refusal")

        is_clean = len(rejection_reasons) == 0 and quality_score >= self.config.min_kb_quality_score
        approved = is_clean and poisoning_risk <= self.config.max_kb_poisoning_risk

        return JevPostExecutionVerdict(
            is_clean=is_clean,
            hallucination_detected=hallucination_detected,
            toxic_detected=toxic_detected,
            quality_score=max(0.0, min(1.0, quality_score)),
            poisoning_risk=poisoning_risk,
            approved_for_kb=approved,
            rejection_reasons=rejection_reasons,
        )

    def _remote_evaluate(self, text: str, schema_cls: Type[T]) -> T:
        """Evaluate text via remote Jev HTTP API."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
            "User-Agent": "PyGenGuard-Jev/1.0",
        }
        body = {
            "input": text,
            "schema": schema_cls.model_json_schema(),
        }
        req = urllib.request.Request(
            url=f"{self.config.api_base_url}/evaluate",
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_ms / 1000.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return schema_cls.model_validate(data.get("verdict", data))
        except Exception:
            if self.config.fallback_to_local:
                if schema_cls == JevPreExecutionVerdict:
                    return self._local_evaluate_pre_execution(text, time.perf_counter())  # type: ignore
                elif schema_cls == JevPostExecutionVerdict:
                    return self._local_evaluate_post_execution("", text, time.perf_counter())  # type: ignore
            raise


class AsyncJevClient:
    """
    Asynchronous Jev System One Client.
    
    Enables native non-blocking scaling for concurrent traffic throughput and
    background dataset cleansing.
    """

    def __init__(self, config: Optional[JevClientConfig] = None, external_client: Optional[Any] = None):
        self.config = config or JevClientConfig()
        self.external_client = external_client
        self._sync_client = JevClient(config=self.config, external_client=external_client)

    async def evaluate_pre_execution(self, prompt: str) -> JevPreExecutionVerdict:
        """
        Asynchronously evaluate prompt for pre-execution blocking.
        Runs tokenless System One evaluation in non-blocking fashion.
        """
        if self.external_client is not None and hasattr(self.external_client, "aevaluate"):
            try:
                res = await self.external_client.aevaluate(prompt, schema=JevPreExecutionVerdict)
                if isinstance(res, JevPreExecutionVerdict):
                    return res
                if isinstance(res, dict):
                    return JevPreExecutionVerdict(**res)
            except Exception:
                if not self.config.fallback_to_local:
                    raise

        # High-speed local fast path runs directly or in threadpool if remote HTTP is configured
        if self.config.api_key and not self.config.fallback_to_local:
            return await asyncio.to_thread(self._sync_client.evaluate_pre_execution, prompt)

        return self._sync_client.evaluate_pre_execution(prompt)

    async def evaluate_post_execution(self, prompt: str, completion: str) -> JevPostExecutionVerdict:
        """
        Asynchronously evaluate interaction for post-execution KB dataset filtering.
        """
        if self.external_client is not None and hasattr(self.external_client, "aevaluate"):
            try:
                combined = f"PROMPT: {prompt}\nCOMPLETION: {completion}"
                res = await self.external_client.aevaluate(combined, schema=JevPostExecutionVerdict)
                if isinstance(res, JevPostExecutionVerdict):
                    return res
                if isinstance(res, dict):
                    return JevPostExecutionVerdict(**res)
            except Exception:
                if not self.config.fallback_to_local:
                    raise

        if self.config.api_key and not self.config.fallback_to_local:
            return await asyncio.to_thread(self._sync_client.evaluate_post_execution, prompt, completion)

        return self._sync_client.evaluate_post_execution(prompt, completion)

    async def batch_evaluate_kb(self, interactions: List[Dict[str, str]]) -> List[JevPostExecutionVerdict]:
        """
        Batch asynchronous evaluation of multiple interactions in parallel.
        """
        tasks = [
            self.evaluate_post_execution(
                item.get("prompt", ""),
                item.get("completion", item.get("response", ""))
            )
            for item in interactions
        ]
        return await asyncio.gather(*tasks)
