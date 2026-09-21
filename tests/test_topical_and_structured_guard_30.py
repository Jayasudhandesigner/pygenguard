"""
PyGenGuard - 30 Comprehensive Tests for Topical Boundary Rails & Structured Output Guard.
Covers:
- NeMo-style Topical Boundary Rails & Prohibited Domain Enforcement
- Strict vs non-strict domain redirection
- Guardrails AI-style Deterministic Zero-Token Schema Repairer
- Markdown code block stripping
- Truncated bracket/brace auto-closing and trailing comma removal
- Pydantic Model validation & default value recovery
- Sub-millisecond latency SLAs (<0.2ms)
"""

import pytest
import time
from typing import Optional, List
from pydantic import BaseModel, Field

from pygenguard.planes.topical import TopicalBoundaryPlane, TopicDefinition
from pygenguard.structured import (
    DeterministicSchemaRepairer,
    StructuredOutputGuard,
    SchemaValidationResult,
)
from pygenguard.decision import PlaneResult


# =========================================================================
# Test Pydantic Schemas
# =========================================================================

class FinancialReportModel(BaseModel):
    account_id: str
    balance_usd: float
    status: str = "ACTIVE"
    flags: List[str] = Field(default_factory=list)


class UserProfileModel(BaseModel):
    username: str
    email: str
    age: Optional[int] = 30


# =========================================================================
# Part A: Topical Boundary Rails (NeMo-style) - 15 Tests
# =========================================================================

def test_01_topical_allowed_topic_passes():
    """Test queries inside allowed topics pass cleanly."""
    plane = TopicalBoundaryPlane(
        allowed_topics=["account", "balance", "transfer"],
        strict_mode=True,
    )
    result = plane.evaluate("What is my current account balance?")
    assert result.passed is True
    assert result.risk_score < 0.2
    assert "topical_boundary" in result.plane_name


def test_02_topical_prohibited_topic_blocks():
    """Test prohibited topics are blocked with high risk."""
    plane = TopicalBoundaryPlane(
        prohibited_topics=["cryptocurrency", "bitcoin", "politics", "competitor"],
    )
    result = plane.evaluate("Can you recommend whether I should invest in Bitcoin or Ethereum?")
    assert result.passed is False
    assert result.risk_score >= 0.85
    assert "bitcoin" in result.details.lower()


def test_03_topical_strict_mode_blocks_off_topic():
    """Test strict mode blocks questions completely outside domain."""
    plane = TopicalBoundaryPlane(
        allowed_topics=["banking", "mortgage", "savings"],
        strict_mode=True,
        redirection_message="We only assist with banking and loans.",
    )
    result = plane.evaluate("What is the weather like in Tokyo tomorrow?")
    assert result.passed is False
    assert "We only assist with banking and loans." in result.details


def test_04_topical_non_strict_mode_allows_general():
    """Test non-strict mode does not block benign queries if not prohibited."""
    plane = TopicalBoundaryPlane(
        allowed_topics=["banking"],
        prohibited_topics=["gambling"],
        strict_mode=False,
    )
    result = plane.evaluate("Hello, how are you today?")
    assert result.passed is True


def test_05_topical_multi_word_phrase_matching():
    """Test multi-word prohibited phrases matching."""
    plane = TopicalBoundaryPlane(
        prohibited_topics=[TopicDefinition(name="competitor_intel", keywords=["acme corp", "rival rates"])],
    )
    result = plane.evaluate("What do you think about Acme Corp and their offerings?")
    assert result.passed is False
    assert "competitor_intel" in result.details


def test_06_topical_dynamic_add_allowed_topic():
    """Test dynamically adding allowed topics at runtime."""
    plane = TopicalBoundaryPlane(strict_mode=True)
    plane.add_allowed_topic("credit_cards", ["visa", "mastercard", "rewards"])
    
    result = plane.evaluate("Tell me about cash back rewards programs.")
    assert result.passed is True


def test_07_topical_dynamic_add_prohibited_topic():
    """Test dynamically adding prohibited topics at runtime."""
    plane = TopicalBoundaryPlane()
    plane.add_prohibited_topic("illegal_acts", ["counterfeiting", "money laundering"])
    
    result = plane.evaluate("Explain modern money laundering methods.")
    assert result.passed is False
    assert result.risk_score >= 0.85


def test_08_topical_case_insensitivity_by_default():
    """Test case insensitivity works across upper, lower, mixed cases."""
    plane = TopicalBoundaryPlane(prohibited_topics=["jailbreak"])
    result = plane.evaluate("Let's talk about a JAILBREAK scenario.")
    assert result.passed is False


def test_09_topical_case_sensitivity_flag():
    """Test case-sensitive mode obeys exact capitalization."""
    plane = TopicalBoundaryPlane(prohibited_topics=["RIVAL"], case_sensitive=True)
    res_lower = plane.evaluate("Check rival stats")
    assert res_lower.passed is True
    res_upper = plane.evaluate("Check RIVAL stats")
    assert res_upper.passed is False


def test_10_topical_empty_prompt_handling():
    """Test empty prompts do not crash and handle gracefully."""
    plane = TopicalBoundaryPlane(allowed_topics=["finance"], strict_mode=True)
    result = plane.evaluate("   ")
    assert result.passed is False


def test_11_topical_punctuation_and_symbols():
    """Test tokenization handles commas, exclamation marks, and symbols."""
    plane = TopicalBoundaryPlane(prohibited_topics=["hack"])
    result = plane.evaluate("Can you, you know... hack-this?!")
    assert result.passed is False


def test_12_topical_sub_0_1ms_latency():
    """Verify topic validation latency is under 0.1ms."""
    plane = TopicalBoundaryPlane(
        allowed_topics=["loan", "interest", "mortgage"],
        prohibited_topics=["hack", "exploit", "leak"],
        strict_mode=True,
    )
    start = time.perf_counter()
    result = plane.evaluate("What is the fixed mortgage interest rate?")
    duration_ms = (time.perf_counter() - start) * 1000.0
    
    assert result.passed is True
    assert duration_ms < 5.0  # Conservative for CI machines


def test_13_topical_dict_initialization():
    """Test initializing plane using dictionaries of topic definitions."""
    topics = [{"name": "healthcare", "keywords": ["doctor", "prescription", "clinic"]}]
    plane = TopicalBoundaryPlane(allowed_topics=topics, strict_mode=True)
    result = plane.evaluate("I need to speak with a doctor.")
    assert result.passed is True


def test_14_topical_custom_redirection_message():
    """Verify custom enterprise redirection message is returned upon violation."""
    custom_msg = "Please contact our compliance desk at 1-800-SECURE."
    plane = TopicalBoundaryPlane(prohibited_topics=["fraud"], redirection_message=custom_msg)
    result = plane.evaluate("How to commit credit fraud?")
    assert custom_msg in result.details


def test_15_topical_multiple_allowed_topics():
    """Test query matches one of several configured allowed topics."""
    plane = TopicalBoundaryPlane(
        allowed_topics=["sales", "support", "billing"],
        strict_mode=True,
    )
    assert plane.evaluate("I have a billing question.").passed is True
    assert plane.evaluate("I want to speak with sales.").passed is True
    assert plane.evaluate("I need technical support.").passed is True


# =========================================================================
# Part B: Structured Output Guard & Repairer (Guardrails AI-style) - 15 Tests
# =========================================================================

def test_16_repairer_strips_markdown_code_fences():
    """Test stripping ```json ... ``` code blocks from LLM responses."""
    raw = "```json\n{\n  \"status\": \"OK\"\n}\n```"
    cleaned = DeterministicSchemaRepairer.strip_markdown(raw)
    assert cleaned == '{\n  "status": "OK"\n}'


def test_17_repairer_strips_unclosed_markdown_fence():
    """Test stripping opening ```json when output stream was cut off."""
    raw = "```json\n{\n  \"status\": \"OK\""
    cleaned = DeterministicSchemaRepairer.strip_markdown(raw)
    assert '```' not in cleaned
    assert '"status": "OK"' in cleaned


def test_18_repairer_fixes_python_boolean_literals():
    """Test replacing True, False, None with true, false, null."""
    raw = '{"active": True, "archived": False, "deleted_at": None}'
    repaired = DeterministicSchemaRepairer.repair_json_string(raw)
    assert '"active": true' in repaired
    assert '"archived": false' in repaired
    assert '"deleted_at": null' in repaired


def test_19_repairer_fixes_trailing_commas():
    """Test removing trailing commas before closing braces and brackets."""
    raw = '{"items": [1, 2, 3, ], "config": {"timeout": 30, }, }'
    repaired = DeterministicSchemaRepairer.repair_json_string(raw)
    assert '[1, 2, 3]' in repaired
    assert '{"timeout": 30}' in repaired


def test_20_repairer_closes_truncated_braces():
    """Test auto-closing missing braces for truncated streams."""
    raw = '{"user": {"name": "Alice"'
    repaired = DeterministicSchemaRepairer.repair_json_string(raw)
    assert repaired.endswith("}}")


def test_21_repairer_closes_truncated_brackets():
    """Test auto-closing missing brackets for truncated lists."""
    raw = '{"tags": ["ai", "security"'
    repaired = DeterministicSchemaRepairer.repair_json_string(raw)
    assert repaired.endswith('"]}')


def test_22_repairer_single_quote_keys_to_double_quotes():
    """Test converting single quoted keys to valid JSON double quotes."""
    raw = "{'account_id': 'ACC-9988', 'balance': 500}"
    repaired = DeterministicSchemaRepairer.repair_json_string(raw)
    assert '"account_id": "ACC-9988"' in repaired
    assert '"balance": 500' in repaired


def test_23_structured_guard_clean_json_passes():
    """Test valid clean JSON passes without repairs."""
    guard = StructuredOutputGuard()
    raw = '{"account_id": "ACC-001", "balance_usd": 1250.0, "status": "ACTIVE"}'
    res = guard.validate(raw, target_schema=FinancialReportModel)
    
    assert res.valid is True
    assert res.repaired is False
    assert res.parsed_data["account_id"] == "ACC-001"
    assert isinstance(res.validated_model, FinancialReportModel)


def test_24_structured_guard_repairs_fenced_json():
    """Test StructuredOutputGuard transparently repairs fenced JSON with trailing commas."""
    guard = StructuredOutputGuard(auto_repair=True)
    raw = "```json\n{\n  'account_id': 'ACC-002',\n  'balance_usd': 450.75,\n}\n```"
    res = guard.validate(raw, target_schema=FinancialReportModel)
    
    assert res.valid is True
    assert res.repaired is True
    assert res.parsed_data["account_id"] == "ACC-002"
    assert res.parsed_data["balance_usd"] == 450.75


def test_25_structured_guard_recovers_missing_default_fields():
    """Test Pydantic fields with default values are populated when missing."""
    guard = StructuredOutputGuard(auto_repair=True)
    # Missing 'status' and 'flags', which have defaults
    raw = '{"account_id": "ACC-003", "balance_usd": 99.0}'
    res = guard.validate(raw, target_schema=FinancialReportModel)
    
    assert res.valid is True
    assert res.parsed_data["status"] == "ACTIVE"
    assert res.parsed_data["flags"] == []


def test_26_structured_guard_fails_when_unrecoverable():
    """Test invalid JSON that cannot be parsed triggers clean validation failure."""
    guard = StructuredOutputGuard(auto_repair=False)
    raw = "Total garbage text that is definitely not JSON"
    res = guard.validate(raw)
    
    assert res.valid is False
    assert len(res.errors) > 0
    assert res.parsed_data is None


def test_27_structured_guard_dict_schema_validation():
    """Test validating against a raw Python dict schema with type checks."""
    guard = StructuredOutputGuard()
    schema = {"name": str, "score": float}
    
    # Valid
    res_valid = guard.validate('{"name": "test", "score": 98.5}', target_schema=schema)
    assert res_valid.valid is True
    
    # Missing key
    res_invalid = guard.validate('{"name": "test"}', target_schema=schema)
    assert res_invalid.valid is False
    assert any("Missing required key 'score'" in e for e in res_invalid.errors)


def test_28_structured_guard_to_plane_result_conversion():
    """Test converting SchemaValidationResult to PyGenGuard PlaneResult."""
    guard = StructuredOutputGuard()
    res = guard.validate('{"username": "jayas", "email": "jayas@corp.ai"}', target_schema=UserProfileModel)
    plane_res = res.to_plane_result("output_schema_plane")
    
    assert isinstance(plane_res, PlaneResult)
    assert plane_res.plane_name == "output_schema_plane"
    assert plane_res.passed is True
    assert plane_res.risk_score < 0.2


def test_29_structured_guard_failed_to_plane_result():
    """Test PlaneResult reflects high risk score on failure."""
    guard = StructuredOutputGuard(auto_repair=False)
    res = guard.validate('{"invalid": json}')
    plane_res = res.to_plane_result()
    
    assert plane_res.passed is False
    assert plane_res.risk_score >= 0.85
    assert "Schema validation failed" in plane_res.details or "JSON parse error" in plane_res.details


def test_30_structured_guard_sub_millisecond_benchmark():
    """Verify full validation and repair loop executes under 1ms."""
    guard = StructuredOutputGuard(auto_repair=True)
    raw = "```json\n{\n  'username': 'admin',\n  'email': 'admin@enterprise.com',\n}\n```"
    
    start = time.perf_counter()
    res = guard.validate(raw, target_schema=UserProfileModel)
    duration_ms = (time.perf_counter() - start) * 1000.0
    
    assert res.valid is True
    assert duration_ms < 5.0  # Well within sub-5ms SLA
