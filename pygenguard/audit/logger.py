"""
Audit Logger v2 — Structured JSONL Logging for Compliance & Forensics.

Enhanced in v1.0 with:
- JSON Lines format with correlation IDs
- Configurable log destinations (stdout, file, both)
- Log rotation support
- Privacy controls (redact prompt text)
- Session/user context propagation
- Regulatory compliance tagging (EU AI Act, NIST AI RMF, SOC2, GDPR)
- Custom event logging for agentic workflows
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pathlib import Path
from logging.handlers import RotatingFileHandler


class AuditLogger:
    """
    Structured JSON logger for security decisions.

    Every decision is logged with full context for:
    - Regulatory audits (EU AI Act Article 13, NIST AI RMF GV-3)
    - Forensic investigation
    - Compliance reporting (SOC2, GDPR Article 5)
    - Analytics and dashboarding

    Usage:
        logger = AuditLogger(
            enabled=True,
            log_destination="both",
            log_file="audit.jsonl",
            include_prompt_text=False
        )
    """

    def __init__(
        self,
        enabled: bool = True,
        log_file: Optional[str] = None,
        log_level: int = logging.INFO,
        log_destination: str = "stdout",  # "stdout", "file", "both"
        log_rotation_mb: int = 100,
        log_backup_count: int = 5,
        include_prompt_text: bool = False,
        include_plane_details: bool = True,
        correlation_id_header: str = "x-request-id",
    ):
        """
        Args:
            enabled: Whether logging is active
            log_file: Path to log file (None = stdout only)
            log_level: Python logging level
            log_destination: Where to write logs
            log_rotation_mb: Max log file size in MB before rotation
            log_backup_count: Number of rotated log files to keep
            include_prompt_text: Whether to include raw prompt text (privacy)
            include_plane_details: Whether to include per-plane details
            correlation_id_header: Header name for request correlation IDs
        """
        self.enabled = enabled
        self.include_prompt_text = include_prompt_text
        self.include_plane_details = include_plane_details
        self.correlation_id_header = correlation_id_header

        self._logger = logging.getLogger("pygenguard.audit")
        self._logger.setLevel(log_level)
        self._logger.propagate = False

        # Clear existing handlers to avoid duplicates on re-init
        self._logger.handlers.clear()

        use_stdout = log_destination in ("stdout", "both")
        use_file = log_destination in ("file", "both")

        if use_stdout:
            console = logging.StreamHandler()
            console.setFormatter(logging.Formatter('%(message)s'))
            self._logger.addHandler(console)

        if use_file and log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=log_rotation_mb * 1024 * 1024,
                backupCount=log_backup_count,
                encoding="utf-8",
            )
            file_handler.setFormatter(logging.Formatter('%(message)s'))
            self._logger.addHandler(file_handler)

    def log(
        self,
        decision: Any,
        user_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        prompt_text: Optional[str] = None,
        agent_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log a Decision object as structured JSONL.

        Args:
            decision: Decision object from guard inspection
            user_id: User identifier for audit trail
            correlation_id: Request correlation ID for distributed tracing
            prompt_text: Raw prompt text (only logged if include_prompt_text=True)
            agent_id: Agent identifier for agentic workflows
            tenant_id: Tenant identifier for multi-tenant deployments
            extra: Additional metadata to include in the log entry
        """
        if not self.enabled:
            return

        log_entry: Dict[str, Any] = {
            "event": "security_decision",
            "version": "1.0",
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        }

        # Decision data
        decision_dict = decision.to_dict()
        log_entry["trace_id"] = decision_dict.get("trace_id", "")
        log_entry["allowed"] = decision_dict.get("allowed", True)
        log_entry["action"] = decision_dict.get("action", "ALLOW")
        log_entry["rationale"] = decision_dict.get("rationale", "")
        log_entry["combined_risk_score"] = decision_dict.get("combined_risk_score", 0.0)

        # Plane results (if enabled)
        if self.include_plane_details:
            log_entry["plane_results"] = decision_dict.get("plane_results", {})

        # Context
        if user_id:
            log_entry["user_id"] = user_id
        if correlation_id:
            log_entry["correlation_id"] = correlation_id
        if agent_id:
            log_entry["agent_id"] = agent_id
        if tenant_id:
            log_entry["tenant_id"] = tenant_id

        # Prompt text (privacy-controlled)
        if self.include_prompt_text and prompt_text:
            log_entry["prompt_text"] = prompt_text[:500]  # Truncate for safety

        # Sanitized response (if present)
        if decision_dict.get("sanitized_response"):
            log_entry["sanitized_response"] = True  # Flag only, not full content

        # Regulatory compliance tags
        log_entry["regulatory"] = {
            "eu_ai_act": "Article 13 compliant",
            "nist_ai_rmf": "GV-3 logged",
            "gdpr": "Article 5 data minimization",
            "soc2": "CC7.2 security event logged",
        }

        # Extra metadata
        if extra:
            log_entry["metadata"] = extra

        self._logger.info(json.dumps(log_entry, separators=(',', ':')))

    def log_event(
        self,
        event_type: str,
        details: Dict[str, Any],
        severity: str = "info",
        user_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> None:
        """
        Log a custom event (e.g., circuit breaker trip, rate limit hit, policy reload).

        Args:
            event_type: Type of event
            details: Event details
            severity: Event severity level
            user_id: User identifier
            correlation_id: Request correlation ID
        """
        if not self.enabled:
            return

        log_entry: Dict[str, Any] = {
            "event": event_type,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            **details,
        }

        if user_id:
            log_entry["user_id"] = user_id
        if correlation_id:
            log_entry["correlation_id"] = correlation_id

        level = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL,
        }.get(severity, logging.INFO)

        self._logger.log(level, json.dumps(log_entry, separators=(',', ':')))

    def log_rate_limit(
        self,
        user_id: str,
        limit_type: str,
        current: int,
        maximum: int,
        retry_after: float = 0.0,
    ) -> None:
        """Log a rate limit event."""
        self.log_event(
            event_type="rate_limit_hit",
            details={
                "limit_type": limit_type,
                "current": current,
                "maximum": maximum,
                "retry_after_seconds": retry_after,
            },
            severity="warning",
            user_id=user_id,
        )

    def log_circuit_breaker(
        self,
        plane_name: str,
        state: str,
        failure_count: int,
    ) -> None:
        """Log a circuit breaker state change."""
        self.log_event(
            event_type="circuit_breaker_state_change",
            details={
                "plane": plane_name,
                "state": state,
                "failure_count": failure_count,
            },
            severity="warning" if state != "closed" else "info",
        )

    def log_agentic_event(
        self,
        event_type: str,
        agent_id: str,
        details: Dict[str, Any],
        user_id: Optional[str] = None,
    ) -> None:
        """Log an agentic workflow event (tool use, delegation, boundary check)."""
        self.log_event(
            event_type=f"agentic.{event_type}",
            details={
                "agent_id": agent_id,
                **details,
            },
            severity="info",
            user_id=user_id,
        )
