"""
Harness Engineering & Deterministic Data Analysis Guard for PyGenGuard.

Provides:
1. Deterministic schema enforcement for LLM analytical outputs (SQL, JSON, tabular metrics).
2. Numeric sanity and statistical integrity validation (preventing hallucinated data anomalies).
3. Data column exfiltration and sensitive attribute leakage prevention in analytical results.
4. Standardized test harness runner for multi-scenario agent verification.
"""

import re
import json
import time
import math
from typing import Dict, Any, List, Optional, Union, Callable
from dataclasses import dataclass, field

from pygenguard.decision import PlaneResult


@dataclass
class DataColumnConstraint:
    """Constraints for a single column/field in an analytical dataset."""
    name: str
    data_type: str = "float"  # float, int, str, bool, list
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    allowed_values: Optional[List[Any]] = None
    allow_null: bool = False
    regex_pattern: Optional[str] = None


@dataclass
class AnalyticalValidationResult:
    """Outcome of deterministic data analysis validation."""
    passed: bool
    risk_score: float
    violations: List[str]
    sanitized_data: Optional[Any]
    total_records_checked: int
    elapsed_ms: float


class DeterministicDataGuard:
    """
    Guards analytical and tabular LLM responses for data science and harness workflows.

    Usage:
        guard = DeterministicDataGuard()
        constraints = [
            DataColumnConstraint("revenue", min_value=0.0),
            DataColumnConstraint("conversion_rate", min_value=0.0, max_value=1.0)
        ]
        res = guard.validate_records(data, constraints)
    """

    def __init__(
        self,
        block_on_nan_inf: bool = True,
        block_on_unauthorized_columns: bool = True,
        max_record_limit: int = 50_000,
    ):
        self.block_on_nan_inf = block_on_nan_inf
        self.block_on_unauthorized_columns = block_on_unauthorized_columns
        self.max_record_limit = max_record_limit

    def validate_records(
        self,
        data: Union[List[Dict[str, Any]], Dict[str, Any], str],
        constraints: Optional[List[DataColumnConstraint]] = None,
        allowed_columns: Optional[List[str]] = None,
    ) -> AnalyticalValidationResult:
        """
        Validate analytical records against deterministic constraints.
        Target execution latency: < 2.0ms.
        """
        start = time.perf_counter()
        violations: List[str] = []

        # Parse JSON if string input
        if isinstance(data, str):
            try:
                parsed_data = json.loads(data)
            except Exception as e:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                return AnalyticalValidationResult(
                    passed=False,
                    risk_score=0.9,
                    violations=[f"Data is not valid JSON format: {str(e)}"],
                    sanitized_data=None,
                    total_records_checked=0,
                    elapsed_ms=elapsed_ms,
                )
        else:
            parsed_data = data

        # Normalize to list of records
        records: List[Dict[str, Any]]
        if isinstance(parsed_data, dict):
            records = [parsed_data]
        elif isinstance(parsed_data, list):
            records = [r for r in parsed_data if isinstance(r, dict)]
        else:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return AnalyticalValidationResult(
                passed=False,
                risk_score=0.8,
                violations=["Input data must be a JSON object or array of objects"],
                sanitized_data=None,
                total_records_checked=0,
                elapsed_ms=elapsed_ms,
            )

        if len(records) > self.max_record_limit:
            violations.append(f"Record count {len(records)} exceeds maximum limit {self.max_record_limit}")

        constraint_map = {c.name: c for c in (constraints or [])}
        allowed_set = set(allowed_columns) if allowed_columns else None

        for idx, rec in enumerate(records):
            # Check unauthorized columns
            if allowed_set is not None:
                extra_cols = set(rec.keys()) - allowed_set
                if extra_cols and self.block_on_unauthorized_columns:
                    violations.append(f"Record #{idx} contains unauthorized columns: {extra_cols}")

            # Check individual column constraints
            for col_name, val in rec.items():
                # NaN / Inf validation
                if isinstance(val, float):
                    if math.isnan(val) or math.isinf(val):
                        if self.block_on_nan_inf:
                            violations.append(f"Record #{idx} column '{col_name}' contains NaN or Infinity")

                c = constraint_map.get(col_name)
                if c is not None:
                    if val is None:
                        if not c.allow_null:
                            violations.append(f"Record #{idx} column '{col_name}' cannot be null")
                        continue

                    # Type checks
                    if c.data_type == "int" and not isinstance(val, int):
                        violations.append(f"Record #{idx} column '{col_name}' must be integer, got {type(val).__name__}")
                    elif c.data_type == "float" and not isinstance(val, (int, float)):
                        violations.append(f"Record #{idx} column '{col_name}' must be numeric, got {type(val).__name__}")
                    elif c.data_type == "str" and not isinstance(val, str):
                        violations.append(f"Record #{idx} column '{col_name}' must be string, got {type(val).__name__}")

                    # Min / Max range checks
                    if isinstance(val, (int, float)):
                        if c.min_value is not None and val < c.min_value:
                            violations.append(f"Record #{idx} column '{col_name}' value {val} is below minimum {c.min_value}")
                        if c.max_value is not None and val > c.max_value:
                            violations.append(f"Record #{idx} column '{col_name}' value {val} exceeds maximum {c.max_value}")

                    # Allowed values enum check
                    if c.allowed_values is not None and val not in c.allowed_values:
                        violations.append(f"Record #{idx} column '{col_name}' value '{val}' not in allowed values: {c.allowed_values}")

                    # Regex pattern
                    if c.regex_pattern is not None and isinstance(val, str):
                        if not re.search(c.regex_pattern, val):
                            violations.append(f"Record #{idx} column '{col_name}' value does not match pattern: {c.regex_pattern}")

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        passed = len(violations) == 0
        risk_score = 0.85 if not passed else 0.0

        return AnalyticalValidationResult(
            passed=passed,
            risk_score=risk_score,
            violations=violations,
            sanitized_data=records if passed else None,
            total_records_checked=len(records),
            elapsed_ms=elapsed_ms,
        )

    def evaluate(
        self,
        data: Union[List[Dict[str, Any]], Dict[str, Any], str],
        constraints: Optional[List[DataColumnConstraint]] = None,
        allowed_columns: Optional[List[str]] = None,
    ) -> PlaneResult:
        """Evaluate as a standard PyGenGuard PlaneResult."""
        res = self.validate_records(data, constraints, allowed_columns)
        details = (
            f"Deterministic data verification passed across {res.total_records_checked} records."
            if res.passed else
            f"Data integrity failed with {len(res.violations)} violations: {'; '.join(res.violations[:3])}"
        )
        return PlaneResult(
            plane_name="deterministic_data",
            passed=res.passed,
            risk_score=res.risk_score,
            details=details,
            latency_ms=res.elapsed_ms,
        )


class HarnessScenarioRunner:
    """
    Executes multi-step test harness scenarios for agents and workflows.
    """

    def __init__(self):
        self.results: List[Dict[str, Any]] = []

    def run_scenario(
        self,
        scenario_name: str,
        steps: List[Callable[[], PlaneResult]],
    ) -> Dict[str, Any]:
        """Execute an automated harness scenario."""
        t0 = time.perf_counter()
        step_results = []
        all_passed = True

        for i, step_fn in enumerate(steps):
            res = step_fn()
            step_results.append({
                "step": i + 1,
                "plane": res.plane_name,
                "passed": res.passed,
                "risk": res.risk_score,
                "details": res.details,
                "latency_ms": res.latency_ms,
            })
            if not res.passed:
                all_passed = False

        total_ms = (time.perf_counter() - t0) * 1000.0
        summary = {
            "scenario": scenario_name,
            "passed": all_passed,
            "total_steps": len(steps),
            "step_results": step_results,
            "total_latency_ms": total_ms,
        }
        self.results.append(summary)
        return summary
