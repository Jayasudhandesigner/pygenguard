"""
Metrics Collector for PyGenGuard.

Tracks telemetry, request counts, latencies, and threat statistics.
Exports in standard Prometheus text format with zero external dependencies.
"""

import threading
import time
from typing import Dict, List, Tuple, Any
from collections import defaultdict


class MetricsCollector:
    """
    Thread-safe metrics collector and Prometheus text exporter for PyGenGuard.
    
    Usage:
    ```python
    from pygenguard.metrics import get_metrics_collector
    
    collector = get_metrics_collector()
    # In your FastAPI endpoint:
    @app.get("/metrics")
    def metrics():
        return Response(collector.generate_prometheus_text(), media_type="text/plain")
    ```
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __init__(self):
        self._lock = threading.Lock()
        # Counts: (plane, action) -> count
        self._inspections_total: Dict[Tuple[str, str], int] = defaultdict(int)
        # Latency sum (ms) and count: plane -> (sum_ms, count)
        self._latency_sums: Dict[str, float] = defaultdict(float)
        self._latency_counts: Dict[str, int] = defaultdict(int)
        # Threat counts: (plane, threat_type) -> count
        self._threats_total: Dict[Tuple[str, str], int] = defaultdict(int)
        # Risk score sums: plane -> (sum_risk, count)
        self._risk_sums: Dict[str, float] = defaultdict(float)
        self._risk_counts: Dict[str, int] = defaultdict(int)
        
    @classmethod
    def get_instance(cls) -> "MetricsCollector":
        """Singleton accessor for metrics collector."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance
    
    def record_decision(self, decision: Any) -> None:
        """Record metrics from a Decision object."""
        with self._lock:
            for plane_name, pr in decision.plane_results.items():
                action = "allow" if pr.passed else "block"
                self._inspections_total[(plane_name, action)] += 1
                self._latency_sums[plane_name] += pr.latency_ms
                self._latency_counts[plane_name] += 1
                self._risk_sums[plane_name] += pr.risk_score
                self._risk_counts[plane_name] += 1
                
                if not pr.passed or pr.risk_score > 0.3:
                    # Extract threat keywords from details
                    self._threats_total[(plane_name, "flagged")] += 1
    
    def record_inspection(self, plane_name: str, action: str, latency_ms: float, risk_score: float) -> None:
        """Record a single plane inspection."""
        with self._lock:
            self._inspections_total[(plane_name, action.lower())] += 1
            self._latency_sums[plane_name] += latency_ms
            self._latency_counts[plane_name] += 1
            self._risk_sums[plane_name] += risk_score
            self._risk_counts[plane_name] += 1
            
    def record_threat(self, plane_name: str, threat_category: str) -> None:
        """Record a specific threat hit."""
        with self._lock:
            self._threats_total[(plane_name, threat_category)] += 1
            
    def reset(self) -> None:
        """Reset all metrics (useful for test isolation)."""
        with self._lock:
            self._inspections_total.clear()
            self._latency_sums.clear()
            self._latency_counts.clear()
            self._threats_total.clear()
            self._risk_sums.clear()
            self._risk_counts.clear()
            
    def generate_prometheus_text(self) -> str:
        """Export metrics formatted for Prometheus scraping."""
        lines = [
            "# HELP pygenguard_inspections_total Total number of inspections evaluated by PyGenGuard",
            "# TYPE pygenguard_inspections_total counter"
        ]
        
        with self._lock:
            for (plane, action), count in sorted(self._inspections_total.items()):
                lines.append(f'pygenguard_inspections_total{{plane="{plane}",action="{action}"}} {count}')
                
            lines.append("# HELP pygenguard_inspection_latency_seconds_total Total latency spent in plane evaluation")
            lines.append("# TYPE pygenguard_inspection_latency_seconds_total summary")
            for plane, sum_ms in sorted(self._latency_sums.items()):
                cnt = self._latency_counts.get(plane, 1)
                lines.append(f'pygenguard_inspection_latency_seconds_sum{{plane="{plane}"}} {sum_ms / 1000.0:.6f}')
                lines.append(f'pygenguard_inspection_latency_seconds_count{{plane="{plane}"}} {cnt}')
                
            lines.append("# HELP pygenguard_threats_detected_total Total count of detected security threats")
            lines.append("# TYPE pygenguard_threats_detected_total counter")
            for (plane, threat), count in sorted(self._threats_total.items()):
                lines.append(f'pygenguard_threats_detected_total{{plane="{plane}",category="{threat}"}} {count}')
                
            lines.append("# HELP pygenguard_average_risk_score Average risk score evaluated per plane")
            lines.append("# TYPE pygenguard_average_risk_score gauge")
            for plane, r_sum in sorted(self._risk_sums.items()):
                cnt = self._risk_counts.get(plane, 1)
                avg = r_sum / max(1, cnt)
                lines.append(f'pygenguard_average_risk_score{{plane="{plane}"}} {avg:.4f}')
                
        return "\n".join(lines) + "\n"


def get_metrics_collector() -> MetricsCollector:
    """Convenience getter for the global metrics collector."""
    return MetricsCollector.get_instance()
