"""
OpenTelemetry Tracing Integration for PyGenGuard.

Generates distributed trace spans for security evaluations with OpenTelemetry attributes.
Falls back to zero-overhead no-op when OpenTelemetry is not installed.
"""

from typing import Optional, Dict, Any
from contextlib import contextmanager
from pygenguard.decision import Decision


class PyGenGuardTracer:
    """
    OpenTelemetry tracer adapter for PyGenGuard.
    
    Usage:
    ```python
    from pygenguard.telemetry import PyGenGuardTracer
    
    tracer = PyGenGuardTracer()
    with tracer.trace_inspection("chat_prompt", user_id="user_123") as span:
        decision = guard.inspect(prompt, session)
        tracer.record_decision_to_span(span, decision)
    ```
    """
    
    def __init__(self, tracer_name: str = "pygenguard"):
        self.tracer_name = tracer_name
        self._has_otel = False
        self._tracer = None
        
        try:
            from opentelemetry import trace
            self._tracer = trace.get_tracer(tracer_name)
            self._has_otel = True
        except ImportError:
            self._has_otel = False
            self._tracer = None
            
    @property
    def is_otel_available(self) -> bool:
        """Check if OpenTelemetry is active."""
        return self._has_otel
        
    @contextmanager
    def trace_inspection(self, operation_name: str = "pygenguard.inspect", **attributes):
        """Context manager to trace an inspection operation."""
        if self._has_otel and self._tracer:
            with self._tracer.start_as_current_span(operation_name) as span:
                for k, v in attributes.items():
                    span.set_attribute(f"genai.security.{k}", str(v))
                yield span
        else:
            # No-op fallback
            yield None
            
    def record_decision(self, decision: Decision, span: Any = None) -> None:
        """Record decision attributes onto an active OpenTelemetry span."""
        if not self._has_otel or span is None:
            return
            
        try:
            span.set_attribute("genai.security.action", decision.action)
            span.set_attribute("genai.security.allowed", decision.allowed)
            span.set_attribute("genai.security.trace_id", decision.trace_id)
            span.set_attribute("genai.security.risk_score", decision.combined_risk_score)
            span.set_attribute("genai.security.rationale", decision.rationale)
            
            for plane_name, pr in decision.plane_results.items():
                span.set_attribute(f"genai.security.plane.{plane_name}.passed", pr.passed)
                span.set_attribute(f"genai.security.plane.{plane_name}.risk_score", pr.risk_score)
                span.set_attribute(f"genai.security.plane.{plane_name}.latency_ms", pr.latency_ms)
        except Exception:
            pass


_global_tracer = PyGenGuardTracer()

def get_tracer() -> PyGenGuardTracer:
    """Get the global tracer instance."""
    return _global_tracer
