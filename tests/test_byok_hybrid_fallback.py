"""
Tests for BYOK LLM-as-a-Judge Fallback Engine and HybridGuardEngine.
"""

import json
import pytest
import asyncio
from unittest.mock import patch, MagicMock

from pygenguard import Guard, Session
from pygenguard.byok.judge import BYOKConfig, JudgeVerdict, BYOKLLMJudge
from pygenguard.hybrid import HybridGuardEngine, HybridDecision


class TestBYOKHybridFallback:

    def test_byok_judge_request_builder_openai(self):
        config = BYOKConfig(provider="openai", api_key="sk-test-openai", model="gpt-4o-mini")
        judge = BYOKLLMJudge(config)
        url, headers, body = judge._build_request("Test prompt", context="Reference info")

        assert "api.openai.com" in url
        assert headers["Authorization"] == "Bearer sk-test-openai"
        assert body["model"] == "gpt-4o-mini"
        assert "response_format" in body

    def test_byok_judge_request_builder_anthropic(self):
        config = BYOKConfig(provider="anthropic", api_key="sk-ant-test", model="claude-3-haiku-20240307")
        judge = BYOKLLMJudge(config)
        url, headers, body = judge._build_request("Test prompt", context=None)

        assert "api.anthropic.com" in url
        assert headers["x-api-key"] == "sk-ant-test"
        assert body["model"] == "claude-3-haiku-20240307"

    def test_byok_judge_request_builder_gemini(self):
        config = BYOKConfig(provider="gemini", api_key="gemini-key-123", model="gemini-1.5-flash")
        judge = BYOKLLMJudge(config)
        url, headers, body = judge._build_request("Test prompt", context=None)

        assert "generativelanguage.googleapis.com" in url
        assert "gemini-key-123" in url
        assert "contents" in body

    def test_byok_judge_response_parser(self):
        judge = BYOKLLMJudge()
        raw_openai_resp = json.dumps({
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "allowed": False,
                        "confidence": 0.95,
                        "reasoning": "Detected subtle jailbreak framing",
                        "flagged_categories": ["injection"],
                    })
                }
            }]
        })
        verdict = judge._parse_response(raw_openai_resp)
        assert not verdict.allowed
        assert verdict.confidence == 0.95
        assert "jailbreak" in verdict.reasoning

    def test_hybrid_engine_high_confidence_deterministic_zero_llm(self):
        guard = Guard()
        byok_cfg = BYOKConfig(api_key="sk-mock-key")
        hybrid = HybridGuardEngine(guard, byok_config=byok_cfg)

        session = Session(user_id="hybrid_user_1")
        # Clean prompt has risk 0.0 (< uncertainty_min 0.35) -> Zero LLM tokens used
        res = hybrid.inspect_hybrid("What is the capital of Japan?", session=session)

        assert res.decision.allowed
        assert not res.used_llm_judge
        assert res.confidence_zone == "high_confidence_deterministic"

    def test_hybrid_engine_ambiguous_zone_triggers_byok_judge(self):
        guard = Guard()
        byok_cfg = BYOKConfig(provider="openai", api_key="sk-mock-key")
        hybrid = HybridGuardEngine(guard, byok_config=byok_cfg, uncertainty_min=0.20, uncertainty_max=0.80)

        # Mock deterministic plane to return an ambiguous risk score
        with patch.object(guard, "inspect") as mock_inspect:
            from pygenguard.decision import Decision, PlaneResult
            mock_inspect.return_value = Decision(
                allowed=True,
                action="ALLOW",
                trace_id="test-trace",
                timestamp=MagicMock(),
                rationale="Borderline phrasing",
                plane_results={"intent": PlaneResult(plane_name="intent", passed=True, risk_score=0.45, details="Ambiguous")},
                combined_risk_score=0.45,
            )

            # Mock the BYOK Judge HTTP evaluation
            with patch.object(hybrid.byok_judge, "evaluate") as mock_judge_eval:
                mock_judge_eval.return_value = JudgeVerdict(
                    allowed=True,
                    confidence=0.92,
                    reasoning="LLM Judge confirms prompt is educational context",
                    flagged_categories=[],
                    latency_ms=45.0,
                    provider_used="openai",
                )

                res = hybrid.inspect_hybrid("Explain penetration testing principles", session=Session(user_id="dev1"))

                assert res.used_llm_judge
                assert res.decision.allowed
                assert "LLM Judge confirms" in res.decision.rationale
                assert "byok_judge" in res.decision.plane_results

    @pytest.mark.asyncio
    async def test_async_hybrid_inspection(self):
        guard = Guard()
        session = Session(user_id="async_user")
        res = await guard.ainspect_hybrid("Explain photosynthesis", session=session)
        assert res.decision.allowed
        assert not res.used_llm_judge
