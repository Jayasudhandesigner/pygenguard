"""
Multi-Agent Consensus & Quorum Gate Plane for PyGenGuard.

Enforces Byzantine and threshold quorum verification across multi-agent swarms
before executing critical or high-privilege actions (financial transactions,
schema modifications, external emails, deployment triggers).
"""

import time
from typing import Optional, List, Dict, Any, Union
from pygenguard.decision import PlaneResult


class ConsensusGate:
    """
    Evaluates multi-agent consensus and quorum votes.

    Usage:
        gate = ConsensusGate(default_quorum_ratio=0.67)
        result = gate.evaluate(
            action_name="delete_production_table",
            agent_votes=[
                {"agent_id": "auditor_1", "approved": True},
                {"agent_id": "security_lead", "approved": False, "reason": "Requires VP approval"},
                {"agent_id": "dba_agent", "approved": False, "reason": "Backup not verified"},
            ],
            quorum_ratio=0.67
        )
    """

    def __init__(self, default_quorum_ratio: float = 0.67):
        self.default_quorum_ratio = default_quorum_ratio

    def evaluate(
        self,
        action_name: str,
        agent_votes: Union[List[Dict[str, Any]], Dict[str, bool]],
        quorum_ratio: Optional[float] = None,
    ) -> PlaneResult:
        """
        Evaluate quorum approval for an action.

        Args:
            action_name: Name of privileged action
            agent_votes: List of vote dicts or mapping of agent_id -> bool
            quorum_ratio: Minimum approval ratio (defaults to 0.67, i.e. 2/3)

        Returns:
            PlaneResult
        """
        start = time.perf_counter()
        ratio_threshold = quorum_ratio if quorum_ratio is not None else self.default_quorum_ratio

        total_votes = 0
        approvals = 0
        dissenting_reasons: List[str] = []

        if isinstance(agent_votes, dict):
            total_votes = len(agent_votes)
            for agent_id, approved in agent_votes.items():
                if approved:
                    approvals += 1
                else:
                    dissenting_reasons.append(f"{agent_id}: vote=REJECT")
        elif isinstance(agent_votes, list):
            total_votes = len(agent_votes)
            for v in agent_votes:
                if v.get("approved"):
                    approvals += 1
                else:
                    agent = v.get("agent_id", "unknown_agent")
                    reason = v.get("reason", "no reason provided")
                    dissenting_reasons.append(f"{agent}: {reason}")

        if total_votes == 0:
            return PlaneResult(
                plane_name="consensus",
                passed=False,
                risk_score=0.9,
                details=f"Consensus failed: 0 votes collected for action '{action_name}'",
                latency_ms=0.0,
            )

        actual_ratio = approvals / total_votes
        passed = actual_ratio >= ratio_threshold
        elapsed = (time.perf_counter() - start) * 1000.0

        if passed:
            details = f"Consensus approved for '{action_name}': {approvals}/{total_votes} ({actual_ratio:.1%}) >= {ratio_threshold:.1%}"
            risk_score = 0.0
        else:
            dissent_text = "; ".join(dissenting_reasons) if dissenting_reasons else "Quorum not met"
            details = f"Consensus REJECTED for '{action_name}': {approvals}/{total_votes} ({actual_ratio:.1%}) < {ratio_threshold:.1%}. Dissent: {dissent_text}"
            risk_score = 0.85

        return PlaneResult(
            plane_name="consensus",
            passed=passed,
            risk_score=risk_score,
            details=details,
            latency_ms=elapsed,
        )
