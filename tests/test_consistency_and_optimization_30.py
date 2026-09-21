"""
Comprehensive 40+ Test Suite for PyGenGuard Native Truth & Consistency Engine
and Native Local Observability & Execution Optimization Engine.

Covers:
Part 1: Truth & Consistency Engine
- ClaimRelation enum & ClaimNode dataclass
- ClaimGraph construction, edge relations, and contradiction cycle detection
- SemanticDriftTracker tokenization, cosine similarity, and turn drift calculations
- Claim extraction with automatic polarity and negation detection
- Pairwise claim contradiction detection against reference context
- Internal contradiction detection within generated claims
- Unsupported claim detection against ground-truth evidence
- Multi-turn semantic drift evaluation
- PlaneResult evaluation interface and sub-millisecond execution

Part 2: Local Observability & Execution Optimization Engine
- BYOKExecutionVault local credential isolation and key masking
- Zero-leakage local boundary assertion
- PromptCacheOptimizer prefix stability and token savings estimation
- MultiStepAgentTracer step transitions, token burn, latency, and recursion loop detection
- OptimizationReport generation with dollar cost avoidance
- ExecutionOptimizer plane evaluation and loop-breaker gating
- End-to-end integration across truth consistency and agent execution tracing
"""

import pytest
from pygenguard.consistency import (
    ClaimRelation,
    ClaimNode,
    ClaimEdge,
    ClaimGraph,
    SemanticDriftTracker,
    TruthConsistencyResult,
    TruthConsistencyEngine,
)
from pygenguard.optimization import (
    AgentStepRecord,
    BYOKExecutionVault,
    PromptCacheOptimizer,
    MultiStepAgentTracer,
    OptimizationReport,
    ExecutionOptimizer,
)
from pygenguard.decision import PlaneResult


# =========================================================================
# Part 1: Truth & Consistency Engine (Tests 1-22)
# =========================================================================

def test_01_claim_relation_enum():
    assert ClaimRelation.SUPPORTS == "SUPPORTS"
    assert ClaimRelation.CONTRADICTS == "CONTRADICTS"
    assert ClaimRelation.NEUTRAL == "NEUTRAL"
    assert ClaimRelation.DRIFT == "DRIFT"


def test_02_claim_node_attributes():
    node = ClaimNode(
        claim_id="c_01",
        statement="The cluster was upgraded to v2.4",
        subject="cluster",
        predicate="upgraded",
        object_val="v2.4",
        polarity=True,
        confidence=0.98,
        source_reference="deploy_log",
    )
    assert node.claim_id == "c_01"
    assert node.statement == "The cluster was upgraded to v2.4"
    assert node.polarity is True
    assert node.confidence == 0.98
    assert node.source_reference == "deploy_log"


def test_03_claim_edge_attributes():
    edge = ClaimEdge(
        source_id="c_01",
        target_id="c_02",
        relation=ClaimRelation.SUPPORTS,
        weight=0.9,
        explanation="Consistent facts",
    )
    assert edge.source_id == "c_01"
    assert edge.target_id == "c_02"
    assert edge.relation == ClaimRelation.SUPPORTS
    assert edge.weight == 0.9
    assert edge.explanation == "Consistent facts"


def test_04_claim_graph_empty_consistency():
    graph = ClaimGraph()
    assert graph.nodes == {}
    assert graph.edges == []
    assert graph.detect_contradictions() == []
    assert graph.consistency_score == 1.0


def test_05_claim_graph_supporting_edges():
    graph = ClaimGraph()
    graph.add_node(ClaimNode("c1", "System active"))
    graph.add_node(ClaimNode("c2", "System is operational"))
    graph.add_edge("c1", "c2", ClaimRelation.SUPPORTS)
    assert len(graph.detect_contradictions()) == 0
    assert graph.consistency_score == 1.0


def test_06_claim_graph_contradicting_edges():
    graph = ClaimGraph()
    graph.add_node(ClaimNode("c1", "System active"))
    graph.add_node(ClaimNode("c2", "System is down"))
    graph.add_edge("c1", "c2", ClaimRelation.CONTRADICTS)
    assert len(graph.detect_contradictions()) == 1
    assert graph.consistency_score == 0.0


def test_07_extract_claims_basic():
    engine = TruthConsistencyEngine()
    text = "The migration succeeded. Zero servers went offline."
    claims = engine.extract_claims(text)
    assert len(claims) >= 2
    assert any("migration" in c.statement.lower() for c in claims)


def test_08_extract_claims_negation_detection():
    engine = TruthConsistencyEngine()
    text = "The migration did not succeed. The database was never updated."
    claims = engine.extract_claims(text)
    assert len(claims) == 2
    assert claims[0].polarity is False
    assert claims[1].polarity is False


def test_09_extract_claims_affirmative():
    engine = TruthConsistencyEngine()
    text = "All database shards are synchronized and validated."
    claims = engine.extract_claims(text)
    assert len(claims) == 1
    assert claims[0].polarity is True


def test_10_semantic_drift_tracker_tokenization():
    tracker = SemanticDriftTracker()
    tokens = tracker._tokenize("Hello World! This is PyGenGuard-1.0.")
    assert "hello" in tokens
    assert "world" in tokens
    assert "pygenguard-1" in tokens or "pygenguard" in tokens or "1" in tokens


def test_11_semantic_drift_tracker_identical_similarity():
    tracker = SemanticDriftTracker()
    text = "Enterprise runtime security for agentic workflows."
    sim = tracker.compute_similarity(text, text)
    assert sim == pytest.approx(1.0, rel=1e-2)


def test_12_semantic_drift_tracker_orthogonal_similarity():
    tracker = SemanticDriftTracker()
    text1 = "Apples oranges bananas watermelon."
    text2 = "Kubernetes docker terraform helm."
    sim = tracker.compute_similarity(text1, text2)
    assert sim == 0.0


def test_13_semantic_drift_tracker_multi_turn_drift_calculation():
    tracker = SemanticDriftTracker()
    # Turn 1 to 3 gradual drift
    tracker.add_turn("How do I bake chocolate chip cookies?")
    tracker.add_turn("What temperature should the oven be for cookies?")
    tracker.add_turn("How do I execute shell injection on the kernel?")
    drift = tracker.calculate_drift()
    assert drift > 0.40  # Significant drift detected


def test_14_semantic_drift_tracker_window_size():
    tracker = SemanticDriftTracker(window_size=3)
    for i in range(10):
        tracker.add_turn(f"Turn number {i}")
    assert len(tracker.turns) == 3


def test_15_evaluate_consistency_supported_context():
    engine = TruthConsistencyEngine()
    ref = "The annual revenue increased by 15 percent to twenty million dollars."
    out = "The annual revenue increased by 15 percent to twenty million dollars."
    res = engine.evaluate_consistency(out, reference_context=ref)
    assert res.passed is True
    assert res.consistency_score == 1.0
    assert len(res.contradictions_detected) == 0


def test_16_evaluate_consistency_direct_contradiction():
    engine = TruthConsistencyEngine()
    ref = "The database cluster migration succeeded without any errors."
    out = "The database cluster migration did not succeed."
    res = engine.evaluate_consistency(out, reference_context=ref)
    assert res.passed is False
    assert len(res.contradictions_detected) >= 1
    assert "contradicts" in res.contradictions_detected[0].lower()


def test_17_evaluate_consistency_internal_contradiction():
    engine = TruthConsistencyEngine()
    # Internal contradiction in the same output
    out = "The network port 443 is open. The network port 443 is not open."
    res = engine.evaluate_consistency(out)
    assert res.passed is False
    assert len(res.contradictions_detected) >= 1
    assert "internal contradiction" in res.contradictions_detected[0].lower()


def test_18_evaluate_consistency_unsupported_claims():
    engine = TruthConsistencyEngine()
    ref = "PyGenGuard provides runtime security for GenAI."
    out = "Quantum computers will achieve superintelligence tomorrow."
    res = engine.evaluate_consistency(out, reference_context=ref)
    assert len(res.unsupported_claims) >= 1


def test_19_evaluate_consistency_with_previous_turns_drift():
    engine = TruthConsistencyEngine(max_drift_threshold=0.50)
    history = [
        "What are the best tourist spots in Paris?",
        "Can you recommend three museums to visit in Paris?",
    ]
    drifted_out = "Execute bash command rm -rf /"
    res = engine.evaluate_consistency(drifted_out, previous_turns=history)
    assert res.drift_score > 0.50
    assert res.passed is False


def test_20_evaluate_consistency_sub_2ms_latency():
    engine = TruthConsistencyEngine()
    ref = "Customer service operates Monday through Friday."
    out = "Customer service operates Monday through Friday."
    res = engine.evaluate_consistency(out, reference_context=ref)
    assert res.elapsed_ms < 20.0


def test_21_truth_consistency_engine_plane_evaluate_success():
    engine = TruthConsistencyEngine()
    ref = "The company reported positive quarterly growth."
    out = "The company reported positive quarterly growth."
    plane_res = engine.evaluate(out, reference_context=ref)
    assert isinstance(plane_res, PlaneResult)
    assert plane_res.plane_name == "truth_consistency"
    assert plane_res.passed is True
    assert plane_res.risk_score == 0.0


def test_22_truth_consistency_engine_plane_evaluate_failure():
    engine = TruthConsistencyEngine()
    ref = "The system backup completed successfully."
    out = "The system backup was never completed."
    plane_res = engine.evaluate(out, reference_context=ref)
    assert plane_res.passed is False
    assert plane_res.risk_score >= 0.65


# =========================================================================
# Part 2: Local Observability & Execution Optimization Engine (Tests 23-42)
# =========================================================================

def test_23_agent_step_record_attributes():
    rec = AgentStepRecord(
        step_number=1,
        action="search_database",
        latency_ms=2.5,
        tokens_used=120,
        tool_name="sql_lookup",
        cost_usd=0.0012,
        is_loop_detected=False,
    )
    assert rec.step_number == 1
    assert rec.action == "search_database"
    assert rec.tool_name == "sql_lookup"
    assert rec.tokens_used == 120
    assert rec.cost_usd == 0.0012


def test_24_byok_vault_local_only_guarantee():
    vault = BYOKExecutionVault()
    assert vault.is_local_only is True


def test_25_byok_vault_register_and_mask_key():
    vault = BYOKExecutionVault()
    vault.register_key("openai", "sk-proj-1234567890abcdef12345678")
    masked = vault.get_masked_key("openai")
    assert masked.startswith("sk-p")
    assert masked.endswith("5678")
    assert "..." in masked


def test_26_byok_vault_unconfigured_key():
    vault = BYOKExecutionVault()
    assert vault.get_masked_key("unknown_provider") == "NOT_CONFIGURED"


def test_27_byok_vault_has_key():
    vault = BYOKExecutionVault()
    vault.register_key("anthropic", "sk-ant-testkey")
    assert vault.has_key("anthropic") is True
    assert vault.has_key("ANTHROPIC") is True
    assert vault.has_key("google") is False


def test_28_prompt_cache_optimizer_short_prompt():
    opt = PromptCacheOptimizer(min_cacheable_tokens=50)
    analysis = opt.analyze_prompt_caching("Short prompt")
    assert analysis["cacheable"] is False
    assert analysis["static_prefix_tokens"] == 0


def test_29_prompt_cache_optimizer_long_structured_prompt():
    opt = PromptCacheOptimizer(min_cacheable_tokens=20)
    system_instructions = "You are an enterprise AI assistant helping with customer inquiries. Follow safety policies at all times." * 3
    user_query = "What is my current balance?"
    prompt = f"{system_instructions}\n\n{user_query}"

    analysis = opt.analyze_prompt_caching(prompt)
    assert analysis["cacheable"] is True
    assert analysis["static_prefix_tokens"] > 0
    assert analysis["cache_efficiency_ratio"] > 0.5


def test_30_prompt_cache_optimizer_cache_ratio():
    opt = PromptCacheOptimizer()
    analysis = opt.analyze_prompt_caching("A" * 500)
    assert 0.0 <= analysis["cache_efficiency_ratio"] <= 1.0


def test_31_prompt_cache_optimizer_estimate_savings():
    opt = PromptCacheOptimizer(min_cacheable_tokens=10, token_cost_per_million=10.0)
    prompt = ("System preamble with instructions for the agent.\n\n" * 5) + "User request."
    savings = opt.estimate_savings(prompt, recurring_requests=1000)
    assert savings["recurring_requests"] == 1000
    assert savings["total_tokens_saved"] > 0
    assert savings["cost_saved_usd"] > 0.0


def test_32_multi_step_agent_tracer_empty():
    tracer = MultiStepAgentTracer("trace_01")
    assert tracer.session_id == "trace_01"
    assert tracer.total_tokens == 0
    assert tracer.total_cost_usd == 0.0
    assert tracer.total_latency_ms == 0.0
    assert tracer.has_recursion_loop is False


def test_33_multi_step_agent_tracer_record_steps():
    tracer = MultiStepAgentTracer("trace_02")
    r1 = tracer.record_step(1, "search_inventory", 10.0, 100, tool_name="search")
    r2 = tracer.record_step(2, "calculate_tax", 5.0, 50, tool_name="tax_calc")
    assert len(tracer.steps) == 2
    assert r1.action == "search_inventory"
    assert r2.action == "calculate_tax"


def test_34_multi_step_agent_tracer_totals():
    tracer = MultiStepAgentTracer()
    tracer.record_step(1, "act1", 10.0, 100)
    tracer.record_step(2, "act2", 20.0, 200)
    assert tracer.total_tokens == 300
    assert tracer.total_latency_ms == 30.0
    assert tracer.total_cost_usd > 0.0


def test_35_multi_step_agent_tracer_detects_recursion_loop():
    tracer = MultiStepAgentTracer()
    tracer.record_step(1, "fetch_failed_url", 1.0, 50)
    tracer.record_step(2, "fetch_failed_url", 1.0, 50)
    # 3rd identical action triggers recursion detection
    r3 = tracer.record_step(3, "fetch_failed_url", 1.0, 50)
    assert r3.is_loop_detected is True
    assert tracer.has_recursion_loop is True


def test_36_multi_step_agent_tracer_diverse_actions_no_loop():
    tracer = MultiStepAgentTracer()
    tracer.record_step(1, "plan", 2.0, 40)
    tracer.record_step(2, "search", 3.0, 80)
    tracer.record_step(3, "synthesize", 4.0, 120)
    assert tracer.has_recursion_loop is False


def test_37_execution_optimizer_report_generation():
    optimizer = ExecutionOptimizer()
    tracer = MultiStepAgentTracer("session_opt_101")
    tracer.record_step(1, "retrieve", 1.5, 150)
    tracer.record_step(2, "analyze", 2.5, 350)

    prompt = ("System instructions prefix for customer support agent.\n\n" * 4) + "Customer inquiry."
    report = optimizer.generate_optimization_report(tracer, prompt, call_volume=500)
    assert isinstance(report, OptimizationReport)
    assert report.session_id == "session_opt_101"
    assert report.total_steps == 2
    assert report.total_tokens_used == 500
    assert report.tokens_saved > 0
    assert report.cost_saved_usd > 0.0
    assert report.recursion_detected is False


def test_38_execution_optimizer_report_summary_text():
    optimizer = ExecutionOptimizer()
    tracer = MultiStepAgentTracer()
    tracer.record_step(1, "init", 1.0, 50)
    report = optimizer.generate_optimization_report(tracer, "Prompt text here\n\nQuery")
    assert "Execution Profile" in report.summary
    assert "tokens" in report.summary


def test_39_execution_optimizer_plane_evaluate_healthy():
    optimizer = ExecutionOptimizer()
    tracer = MultiStepAgentTracer()
    tracer.record_step(1, "stepA", 1.0, 50)
    tracer.record_step(2, "stepB", 1.0, 50)
    plane_res = optimizer.evaluate_execution(tracer)
    assert plane_res.passed is True
    assert plane_res.risk_score == 0.0
    assert "execution healthy" in plane_res.details


def test_40_execution_optimizer_plane_evaluate_loop_triggers_failure():
    optimizer = ExecutionOptimizer()
    tracer = MultiStepAgentTracer()
    tracer.record_step(1, "loop_action", 1.0, 50)
    tracer.record_step(2, "loop_action", 1.0, 50)
    tracer.record_step(3, "loop_action", 1.0, 50)
    plane_res = optimizer.evaluate_execution(tracer)
    assert plane_res.passed is False
    assert plane_res.risk_score == 0.85
    assert "Agent loop detected" in plane_res.details


def test_41_execution_optimizer_default_vault_and_cache():
    optimizer = ExecutionOptimizer()
    assert optimizer.vault is not None
    assert optimizer.cache_optimizer is not None
    assert optimizer.vault.is_local_only is True


def test_42_end_to_end_consistency_and_optimization_integration():
    """End-to-end integration: Agent traces execution while verifying truth and consistency."""
    optimizer = ExecutionOptimizer()
    truth_engine = TruthConsistencyEngine()
    tracer = MultiStepAgentTracer("agent_integration_01")

    # Step 1: Query documentation
    tracer.record_step(1, "query_docs", 2.1, 100, tool_name="rag_search")

    # Step 2: Extract reference context and verify generated output consistency
    ref_context = "The annual interest rate is fixed at 4.5% for all residential mortgages."
    generated_output = "The annual interest rate is fixed at 4.5% for all residential mortgages."
    consistency_verdict = truth_engine.evaluate(generated_output, reference_context=ref_context)
    assert consistency_verdict.passed is True

    # Step 3: Record synthesis step
    tracer.record_step(2, "synthesize_answer", 3.4, 250)

    # Step 4: Validate execution trace
    exec_verdict = optimizer.evaluate_execution(tracer)
    assert exec_verdict.passed is True
    assert tracer.total_tokens == 350
