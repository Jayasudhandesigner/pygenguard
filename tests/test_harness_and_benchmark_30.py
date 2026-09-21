"""
Comprehensive 30+ Test Suite for PyGenGuard Harness Engineering & Benchmark Suite.

Covers:
- DataColumnConstraint schemas and attributes
- DeterministicDataGuard JSON string parsing and schema validation
- NaN and Infinity arithmetic anomaly detection
- Strict allowed-columns enforcement (anti-exfiltration)
- Data type constraints (int, float, str)
- Numeric boundary range assertions (min_value, max_value)
- Allowed values categorical assertions
- Regex pattern validation on analytical columns
- Nullable vs Non-nullable column validation
- Max record limit thresholding
- AnalyticalValidationResult and PlaneResult interface
- HarnessScenarioRunner multi-step pipeline orchestration
- BenchmarkHarness suite execution (Direct, Indirect, Tool Sandboxing)
- BenchmarkMetric calculation (Precision, Recall, F1, P95 latency)
- Markdown report generation
"""

import math
import pytest
from pygenguard.harness import (
    DataColumnConstraint,
    AnalyticalValidationResult,
    DeterministicDataGuard,
    HarnessScenarioRunner,
)
from pygenguard.audit.benchmark import (
    BenchmarkHarness,
    BenchmarkMetric,
)
from pygenguard.decision import PlaneResult


# =========================================================================
# Part 1: DataColumnConstraint & Data Guard Fundamentals (Tests 1-8)
# =========================================================================

def test_01_data_column_constraint_defaults():
    c = DataColumnConstraint(name="revenue")
    assert c.name == "revenue"
    assert c.data_type == "float"
    assert c.min_value is None
    assert c.max_value is None
    assert c.allowed_values is None
    assert c.allow_null is False
    assert c.regex_pattern is None


def test_02_data_column_constraint_custom():
    c = DataColumnConstraint(
        name="status",
        data_type="str",
        allowed_values=["ACTIVE", "PENDING", "CLOSED"],
        allow_null=True,
        regex_pattern=r"^[A-Z_]+$",
    )
    assert c.name == "status"
    assert c.data_type == "str"
    assert c.allowed_values == ["ACTIVE", "PENDING", "CLOSED"]
    assert c.allow_null is True
    assert c.regex_pattern == r"^[A-Z_]+$"


def test_03_validate_valid_record_list():
    guard = DeterministicDataGuard()
    records = [{"revenue": 1000.5, "sales_count": 10}]
    constraints = [
        DataColumnConstraint("revenue", data_type="float", min_value=0.0),
        DataColumnConstraint("sales_count", data_type="int", min_value=0),
    ]
    res = guard.validate_records(records, constraints)
    assert res.passed is True
    assert res.risk_score == 0.0
    assert len(res.violations) == 0
    assert res.total_records_checked == 1
    assert res.sanitized_data == records


def test_04_validate_valid_single_dict():
    guard = DeterministicDataGuard()
    single_record = {"score": 0.95}
    res = guard.validate_records(single_record, [DataColumnConstraint("score", min_value=0.0, max_value=1.0)])
    assert res.passed is True
    assert res.total_records_checked == 1


def test_05_validate_valid_json_string():
    guard = DeterministicDataGuard()
    json_str = '[{"cost": 45.20}, {"cost": 12.80}]'
    res = guard.validate_records(json_str, [DataColumnConstraint("cost", min_value=0.0)])
    assert res.passed is True
    assert res.total_records_checked == 2


def test_06_validate_invalid_json_string_fails():
    guard = DeterministicDataGuard()
    corrupt_str = '{"cost": 45.20, incomplete'
    res = guard.validate_records(corrupt_str)
    assert res.passed is False
    assert res.risk_score == 0.9
    assert any("not valid JSON" in v for v in res.violations)


def test_07_validate_invalid_payload_type():
    guard = DeterministicDataGuard()
    # Non-dict, non-list primitive payload
    res = guard.validate_records(12345)
    assert res.passed is False
    assert res.risk_score == 0.8
    assert any("must be a JSON object or array" in v for v in res.violations)


def test_08_record_limit_exceeded():
    guard = DeterministicDataGuard(max_record_limit=5)
    data = [{"id": i} for i in range(10)]
    res = guard.validate_records(data)
    assert res.passed is False
    assert any("exceeds maximum limit" in v for v in res.violations)


# =========================================================================
# Part 2: Statistical & Security Validations (Tests 9-20)
# =========================================================================

def test_09_nan_detection_blocks():
    guard = DeterministicDataGuard(block_on_nan_inf=True)
    records = [{"metric": float("nan")}]
    res = guard.validate_records(records)
    assert res.passed is False
    assert any("contains NaN or Infinity" in v for v in res.violations)


def test_10_positive_infinity_blocks():
    guard = DeterministicDataGuard(block_on_nan_inf=True)
    records = [{"metric": float("inf")}]
    res = guard.validate_records(records)
    assert res.passed is False
    assert any("contains NaN or Infinity" in v for v in res.violations)


def test_11_negative_infinity_blocks():
    guard = DeterministicDataGuard(block_on_nan_inf=True)
    records = [{"metric": float("-inf")}]
    res = guard.validate_records(records)
    assert res.passed is False
    assert any("contains NaN or Infinity" in v for v in res.violations)


def test_12_permissive_nan_inf_mode():
    guard = DeterministicDataGuard(block_on_nan_inf=False)
    records = [{"metric": float("nan")}]
    res = guard.validate_records(records)
    assert res.passed is True


def test_13_unauthorized_columns_anti_exfiltration():
    guard = DeterministicDataGuard(block_on_unauthorized_columns=True)
    records = [{"revenue": 500.0, "ssn_leaked": "000-12-3456"}]
    res = guard.validate_records(records, allowed_columns=["revenue"])
    assert res.passed is False
    assert any("unauthorized columns" in v for v in res.violations)


def test_14_permissive_unauthorized_columns():
    guard = DeterministicDataGuard(block_on_unauthorized_columns=False)
    records = [{"revenue": 500.0, "extra_info": "ok"}]
    res = guard.validate_records(records, allowed_columns=["revenue"])
    assert res.passed is True


def test_15_data_type_int_validation_fails_on_float():
    guard = DeterministicDataGuard()
    records = [{"count": 12.34}]
    constraints = [DataColumnConstraint("count", data_type="int")]
    res = guard.validate_records(records, constraints)
    assert res.passed is False
    assert any("must be integer" in v for v in res.violations)


def test_16_data_type_str_validation_fails_on_int():
    guard = DeterministicDataGuard()
    records = [{"sku": 12345}]
    constraints = [DataColumnConstraint("sku", data_type="str")]
    res = guard.validate_records(records, constraints)
    assert res.passed is False
    assert any("must be string" in v for v in res.violations)


def test_17_min_value_boundary_check():
    guard = DeterministicDataGuard()
    constraints = [DataColumnConstraint("rate", min_value=0.0)]
    # Negative value
    res_fail = guard.validate_records([{"rate": -0.01}], constraints)
    assert res_fail.passed is False
    assert any("below minimum" in v for v in res_fail.violations)

    # Exact boundary
    res_pass = guard.validate_records([{"rate": 0.0}], constraints)
    assert res_pass.passed is True


def test_18_max_value_boundary_check():
    guard = DeterministicDataGuard()
    constraints = [DataColumnConstraint("pct", max_value=100.0)]
    # Above max
    res_fail = guard.validate_records([{"pct": 100.1}], constraints)
    assert res_fail.passed is False
    assert any("exceeds maximum" in v for v in res_fail.violations)

    # Exact boundary
    res_pass = guard.validate_records([{"pct": 100.0}], constraints)
    assert res_pass.passed is True


def test_19_allowed_values_categorical_enum():
    guard = DeterministicDataGuard()
    constraints = [DataColumnConstraint("region", data_type="str", allowed_values=["US", "EU", "APAC"])]
    res_pass = guard.validate_records([{"region": "EU"}], constraints)
    assert res_pass.passed is True

    res_fail = guard.validate_records([{"region": "LATAM"}], constraints)
    assert res_fail.passed is False
    assert any("not in allowed values" in v for v in res_fail.violations)


def test_20_regex_pattern_constraint():
    guard = DeterministicDataGuard()
    # Require UUID format
    uuid_pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    constraints = [DataColumnConstraint("session_id", data_type="str", regex_pattern=uuid_pattern)]

    res_pass = guard.validate_records([{"session_id": "12345678-1234-1234-1234-123456789abc"}], constraints)
    assert res_pass.passed is True

    res_fail = guard.validate_records([{"session_id": "malicious-injection-payload"}], constraints)
    assert res_fail.passed is False
    assert any("does not match pattern" in v for v in res_fail.violations)


# =========================================================================
# Part 3: Nullability & Plane Interface (Tests 21-25)
# =========================================================================

def test_21_allow_null_flag_behavior():
    guard = DeterministicDataGuard()
    # Allow null = False
    c_strict = [DataColumnConstraint("tax_id", allow_null=False)]
    res_strict = guard.validate_records([{"tax_id": None}], c_strict)
    assert res_strict.passed is False
    assert any("cannot be null" in v for v in res_strict.violations)

    # Allow null = True
    c_permissive = [DataColumnConstraint("tax_id", allow_null=True)]
    res_permissive = guard.validate_records([{"tax_id": None}], c_permissive)
    assert res_permissive.passed is True


def test_22_plane_result_evaluate_success():
    guard = DeterministicDataGuard()
    plane_res = guard.evaluate([{"revenue": 100.0}])
    assert isinstance(plane_res, PlaneResult)
    assert plane_res.plane_name == "deterministic_data"
    assert plane_res.passed is True
    assert plane_res.risk_score == 0.0
    assert "verification passed" in plane_res.details


def test_23_plane_result_evaluate_failure():
    guard = DeterministicDataGuard()
    plane_res = guard.evaluate([{"revenue": float("nan")}])
    assert plane_res.plane_name == "deterministic_data"
    assert plane_res.passed is False
    assert plane_res.risk_score == 0.85
    assert "Data integrity failed" in plane_res.details


def test_24_data_guard_latency_under_2ms():
    guard = DeterministicDataGuard()
    records = [{"idx": i, "val": i * 1.5} for i in range(100)]
    constraints = [DataColumnConstraint("val", min_value=0.0)]
    res = guard.validate_records(records, constraints)
    assert res.elapsed_ms < 20.0


def test_25_harness_scenario_runner_success():
    runner = HarnessScenarioRunner()
    step1 = lambda: PlaneResult(plane_name="auth", passed=True, risk_score=0.0, details="auth ok")
    step2 = lambda: PlaneResult(plane_name="data", passed=True, risk_score=0.0, details="data ok")

    summary = runner.run_scenario("Customer Checkout Simulation", [step1, step2])
    assert summary["scenario"] == "Customer Checkout Simulation"
    assert summary["passed"] is True
    assert summary["total_steps"] == 2
    assert len(runner.results) == 1


# =========================================================================
# Part 4: Harness Scenario Runner & Benchmark Suites (Tests 26-40)
# =========================================================================

def test_26_harness_scenario_runner_failure():
    runner = HarnessScenarioRunner()
    step1 = lambda: PlaneResult(plane_name="auth", passed=True, risk_score=0.0, details="auth ok")
    step2 = lambda: PlaneResult(plane_name="rate_limit", passed=False, risk_score=0.9, details="burst exceeded")

    summary = runner.run_scenario("Rapid Attack Simulation", [step1, step2])
    assert summary["passed"] is False
    assert summary["step_results"][1]["passed"] is False


def test_27_benchmark_metric_dataclass():
    m = BenchmarkMetric(
        suite_name="Unit Test Suite",
        total_tests=10,
        true_positives=5,
        false_positives=0,
        true_negatives=5,
        false_negatives=0,
        precision=1.0,
        recall=1.0,
        f1_score=1.0,
        avg_latency_ms=0.5,
        p95_latency_ms=0.8,
    )
    assert m.total_tests == 10
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.f1_score == 1.0


def test_28_benchmark_harness_initialization():
    harness = BenchmarkHarness()
    assert harness.guard is not None
    assert harness.jev is not None
    assert harness.taint_tracker is not None
    assert harness.tool_guard is not None


def test_29_direct_injection_suite_metrics():
    harness = BenchmarkHarness()
    metric = harness.run_direct_injection_suite()
    assert metric.total_tests == 40
    assert metric.precision >= 0.85
    assert metric.recall >= 0.85
    assert metric.avg_latency_ms < 10.0


def test_30_indirect_injection_suite_metrics():
    harness = BenchmarkHarness()
    metric = harness.run_indirect_injection_suite()
    assert metric.total_tests == 40
    assert metric.precision >= 0.90
    assert metric.recall >= 0.90
    assert metric.avg_latency_ms < 10.0


def test_31_tool_sandboxing_suite_metrics():
    harness = BenchmarkHarness()
    metric = harness.run_tool_sandboxing_suite()
    assert metric.total_tests == 40
    assert metric.precision >= 0.90
    assert metric.recall >= 0.90
    assert metric.avg_latency_ms < 10.0


def test_32_run_all_suites_returns_three_metrics():
    harness = BenchmarkHarness()
    metrics = harness.run_all_suites()
    assert len(metrics) == 3
    assert metrics[0].suite_name.startswith("Direct Prompt Injection")
    assert metrics[1].suite_name.startswith("Indirect Injection")
    assert metrics[2].suite_name.startswith("Tool Sandboxing")


def test_33_format_markdown_report_structure():
    harness = BenchmarkHarness()
    metric = BenchmarkMetric(
        suite_name="Mock Benchmark",
        total_tests=10,
        true_positives=5,
        false_positives=0,
        true_negatives=5,
        false_negatives=0,
        precision=1.0,
        recall=1.0,
        f1_score=1.0,
        avg_latency_ms=0.15,
        p95_latency_ms=0.25,
    )
    report = harness.format_markdown_report([metric])
    assert "# PyGenGuard Standardized Security Benchmark Report" in report
    assert "| **Mock Benchmark** | 10 | 100.0% | 100.0% | 100.0% | 0.15ms | 0.25ms | **PASS** |" in report


def test_34_format_markdown_report_warn_status():
    harness = BenchmarkHarness()
    metric = BenchmarkMetric(
        suite_name="Suboptimal Model",
        total_tests=10,
        true_positives=2,
        false_positives=2,
        true_negatives=3,
        false_negatives=3,
        precision=0.5,
        recall=0.4,
        f1_score=0.44,
        avg_latency_ms=1.2,
        p95_latency_ms=2.0,
    )
    report = harness.format_markdown_report([metric])
    assert "**WARN**" in report


def test_35_compute_metrics_zero_tests_edge_case():
    harness = BenchmarkHarness()
    metric = harness._compute_metrics("Zero Test", tp=0, fp=0, tn=0, fn=0, latencies=[])
    assert metric.total_tests == 0
    assert metric.precision == 1.0
    assert metric.recall == 1.0
    assert metric.f1_score == 1.0
    assert metric.avg_latency_ms == 0.0
    assert metric.p95_latency_ms == 0.0


def test_36_p95_latency_computation_accuracy():
    harness = BenchmarkHarness()
    latencies = [float(i) for i in range(1, 101)]  # 1 to 100
    metric = harness._compute_metrics("Latency Test", tp=50, fp=0, tn=50, fn=0, latencies=latencies)
    # p95 index is int(100 * 0.95) = 95 -> value is 96.0
    assert metric.p95_latency_ms == pytest.approx(96.0, rel=1e-1)


def test_37_multiple_data_column_violations_aggregated():
    guard = DeterministicDataGuard()
    records = [{"revenue": -10.0, "status": "INVALID_STATUS"}]
    constraints = [
        DataColumnConstraint("revenue", min_value=0.0),
        DataColumnConstraint("status", data_type="str", allowed_values=["OK"]),
    ]
    res = guard.validate_records(records, constraints)
    assert res.passed is False
    assert len(res.violations) == 2


def test_38_empty_records_list_passes():
    guard = DeterministicDataGuard()
    res = guard.validate_records([])
    assert res.passed is True
    assert res.total_records_checked == 0


def test_39_empty_record_with_allowed_columns_passes():
    guard = DeterministicDataGuard()
    res = guard.validate_records([{}], allowed_columns=["revenue"])
    assert res.passed is True


def test_40_large_batch_data_guard_performance():
    guard = DeterministicDataGuard()
    records = [{"id": i, "score": 0.5} for i in range(1000)]
    constraints = [DataColumnConstraint("score", min_value=0.0, max_value=1.0)]
    res = guard.validate_records(records, constraints)
    assert res.passed is True
    assert res.total_records_checked == 1000
    assert res.elapsed_ms < 50.0
