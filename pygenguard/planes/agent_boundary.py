"""
Agent Boundary Guard Plane for PyGenGuard v1.0.

Enforces security boundaries in multi-agent systems.

Protections:
- Agent identity verification and security context
- Inter-agent message inspection for injection attacks
- Privilege propagation control (prevent low-trust agent escalation)
- Delegation depth limits (max chain length)
- Cross-agent data isolation (prevent unauthorized data sharing)
"""

import re
import time
from typing import Optional, List, Dict, Set, Any, Tuple
from pygenguard.decision import PlaneResult
from pygenguard.utils.decoders import get_normalized_variants


# Patterns indicating prompt injection in inter-agent messages
INTER_AGENT_INJECTION_PATTERNS = [
    r"ignore\s+(?:your|previous|all)\s+(?:instructions|rules|guidelines)",
    r"you\s+are\s+now\s+(?:a|an)\s+(?:different|new|unrestricted)",
    r"forget\s+(?:your|everything|all)\s+(?:instructions|context|rules)",
    r"(?:override|bypass)\s+(?:your|the)\s+(?:security|safety|restrictions)",
    r"(?:pretend|act\s+as\s+if)\s+you\s+(?:are|were)\s+(?:admin|root|system)",
    r"transfer\s+all\s+(?:data|information|context)\s+to\s+(?:me|this\s+agent)",
    r"(?:share|send|transmit)\s+(?:user|private|confidential|secret)\s+(?:data|information|keys)",
]


class AgentSecurityContext:
    """
    Security context for an agent in a multi-agent system.

    Tracks the agent's identity, trust level, permissions,
    and delegation chain for privilege propagation control.
    """

    def __init__(
        self,
        agent_id: str,
        agent_role: str = "worker",
        trust_level: int = 50,  # 0-100
        permissions: Optional[Set[str]] = None,
        delegation_chain: Optional[List[str]] = None,
        max_delegation_depth: int = 5,
        allowed_delegate_to: Optional[Set[str]] = None,
        data_classification: str = "internal",  # public, internal, confidential, restricted
    ):
        self.agent_id = agent_id
        self.agent_role = agent_role
        self.trust_level = trust_level
        self.permissions = permissions or set()
        self.delegation_chain = delegation_chain or []
        self.max_delegation_depth = max_delegation_depth
        self.allowed_delegate_to = allowed_delegate_to  # None = can delegate to any
        self.data_classification = data_classification

    @property
    def delegation_depth(self) -> int:
        """Current depth of the delegation chain."""
        return len(self.delegation_chain)

    def can_delegate_to(self, target_agent_id: str) -> bool:
        """Check if this agent can delegate to a target agent."""
        if self.delegation_depth >= self.max_delegation_depth:
            return False
        if self.allowed_delegate_to is not None:
            return target_agent_id in self.allowed_delegate_to
        return True

    def create_delegated_context(
        self, target_agent_id: str, target_role: str = "worker"
    ) -> "AgentSecurityContext":
        """
        Create a security context for a delegated agent.
        The delegated agent inherits a reduced trust level and
        the delegation chain is extended.
        """
        return AgentSecurityContext(
            agent_id=target_agent_id,
            agent_role=target_role,
            trust_level=max(0, self.trust_level - 10),  # Trust degrades on delegation
            permissions=self.permissions.copy(),
            delegation_chain=self.delegation_chain + [self.agent_id],
            max_delegation_depth=self.max_delegation_depth,
            data_classification=self.data_classification,
        )


# Trust level hierarchy
TRUST_HIERARCHY = {
    "orchestrator": 90,
    "supervisor": 80,
    "specialist": 60,
    "worker": 50,
    "external": 20,
    "untrusted": 0,
}

# Data classification hierarchy (higher = more sensitive)
DATA_CLASSIFICATION_LEVELS = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
}


class AgentBoundaryGuard:
    """
    Enforces security boundaries in multi-agent systems.

    Ensures that:
    - Agents can only communicate within allowed boundaries
    - Low-trust agents cannot escalate privileges through high-trust agents
    - Inter-agent messages are scanned for injection attempts
    - Delegation chains don't exceed configured depth
    - Data classification levels are respected in cross-agent communication

    Usage:
        boundary_guard = AgentBoundaryGuard(
            max_delegation_depth=3,
            block_privilege_escalation=True,
        )

        # When Agent A sends a message to Agent B:
        result = boundary_guard.evaluate(
            source_context=agent_a_context,
            target_context=agent_b_context,
            message="Please search for user data..."
        )
    """

    def __init__(
        self,
        max_delegation_depth: int = 5,
        min_trust_for_delegation: int = 30,
        block_privilege_escalation: bool = True,
        block_data_leakage: bool = True,
        scan_inter_agent_messages: bool = True,
    ):
        self.max_delegation_depth = max_delegation_depth
        self.min_trust = min_trust_for_delegation
        self.block_escalation = block_privilege_escalation
        self.block_data_leakage = block_data_leakage
        self.scan_messages = scan_inter_agent_messages

    def evaluate(
        self,
        source_context: AgentSecurityContext,
        target_context: Optional[AgentSecurityContext] = None,
        message: Optional[str] = None,
        requested_permissions: Optional[Set[str]] = None,
    ) -> PlaneResult:
        """
        Evaluate an inter-agent interaction for security violations.

        Args:
            source_context: Security context of the sending/delegating agent
            target_context: Security context of the receiving agent (if applicable)
            message: The message being sent between agents
            requested_permissions: Permissions the source is requesting

        Returns:
            PlaneResult with pass/fail and threat details
        """
        start = time.perf_counter()
        threats: List[str] = []
        risk_score = 0.0
        should_block = False

        # 1. Delegation depth check
        if source_context.delegation_depth >= self.max_delegation_depth:
            threats.append(
                f"Delegation depth exceeded: {source_context.delegation_depth}"
                f"/{self.max_delegation_depth}"
            )
            risk_score = max(risk_score, 0.8)
            should_block = True

        # 2. Circular delegation detection
        if target_context:
            if target_context.agent_id in source_context.delegation_chain:
                threats.append(
                    f"Circular delegation detected: {target_context.agent_id} "
                    f"already in chain {source_context.delegation_chain}"
                )
                risk_score = max(risk_score, 0.9)
                should_block = True

        # 3. Trust level check
        if source_context.trust_level < self.min_trust:
            threats.append(
                f"Agent '{source_context.agent_id}' trust level too low: "
                f"{source_context.trust_level} < {self.min_trust}"
            )
            risk_score = max(risk_score, 0.7)
            should_block = True

        # 4. Privilege escalation detection
        if self.block_escalation and target_context:
            if source_context.trust_level < target_context.trust_level:
                # Lower trust agent trying to use higher trust agent
                trust_gap = target_context.trust_level - source_context.trust_level
                if trust_gap > 20:  # Significant trust gap
                    threats.append(
                        f"Privilege escalation attempt: "
                        f"'{source_context.agent_id}' (trust: {source_context.trust_level}) → "
                        f"'{target_context.agent_id}' (trust: {target_context.trust_level})"
                    )
                    risk_score = max(risk_score, 0.85)
                    should_block = True

        # 5. Data classification check
        if self.block_data_leakage and target_context:
            source_level = DATA_CLASSIFICATION_LEVELS.get(
                source_context.data_classification, 1
            )
            target_level = DATA_CLASSIFICATION_LEVELS.get(
                target_context.data_classification, 1
            )
            if source_level > target_level:
                threats.append(
                    f"Data leakage risk: '{source_context.data_classification}' data "
                    f"flowing to '{target_context.data_classification}' agent"
                )
                risk_score = max(risk_score, 0.9)
                should_block = True

        # 6. Delegation allowlist check
        if target_context and not source_context.can_delegate_to(target_context.agent_id):
            threats.append(
                f"Agent '{source_context.agent_id}' cannot delegate to "
                f"'{target_context.agent_id}'"
            )
            risk_score = max(risk_score, 0.7)
            should_block = True

        # 7. Inter-agent message injection scan
        if self.scan_messages and message:
            injection_threats = self._scan_message(message)
            if injection_threats:
                threats.extend(injection_threats)
                risk_score = max(risk_score, 0.95)
                should_block = True

        # 8. Permission validation
        if requested_permissions:
            unauthorized = requested_permissions - source_context.permissions
            if unauthorized:
                threats.append(
                    f"Unauthorized permissions requested: {unauthorized}"
                )
                risk_score = max(risk_score, 0.8)
                should_block = True

        passed = not should_block
        details = (
            "; ".join(threats)
            if threats
            else f"Agent boundary check passed for '{source_context.agent_id}'"
        )

        return PlaneResult(
            plane_name="agent_boundary",
            passed=passed,
            risk_score=risk_score,
            details=details,
            latency_ms=(time.perf_counter() - start) * 1000,
        )

    def _scan_message(self, message: str) -> List[str]:
        """Scan an inter-agent message for injection patterns."""
        threats = []
        variants = get_normalized_variants(message[:5000])

        for variant in variants:
            v_lower = variant.lower()
            for pattern in INTER_AGENT_INJECTION_PATTERNS:
                if re.search(pattern, v_lower):
                    threats.append("Prompt injection detected in inter-agent message")
                    return threats  # One injection is enough to block

        return threats

    def validate_delegation_chain(
        self, chain: List[str], agent_contexts: Dict[str, AgentSecurityContext]
    ) -> PlaneResult:
        """
        Validate an entire delegation chain for security.

        Args:
            chain: List of agent IDs in delegation order
            agent_contexts: Map of agent_id → AgentSecurityContext

        Returns:
            PlaneResult for the chain validation
        """
        start = time.perf_counter()
        threats: List[str] = []
        max_risk = 0.0

        if len(chain) > self.max_delegation_depth:
            threats.append(f"Chain length {len(chain)} exceeds max {self.max_delegation_depth}")
            max_risk = 0.8

        # Check for circular references
        if len(chain) != len(set(chain)):
            threats.append("Circular delegation in chain")
            max_risk = max(max_risk, 0.95)

        # Validate trust levels don't escalate
        for i in range(len(chain) - 1):
            source_id = chain[i]
            target_id = chain[i + 1]
            source_ctx = agent_contexts.get(source_id)
            target_ctx = agent_contexts.get(target_id)

            if source_ctx and target_ctx:
                if source_ctx.trust_level < target_ctx.trust_level - 20:
                    threats.append(
                        f"Trust escalation at step {i + 1}: "
                        f"{source_id}({source_ctx.trust_level}) → "
                        f"{target_id}({target_ctx.trust_level})"
                    )
                    max_risk = max(max_risk, 0.85)

        passed = len(threats) == 0
        details = "; ".join(threats) if threats else f"Delegation chain of {len(chain)} agents verified"

        return PlaneResult(
            plane_name="agent_boundary",
            passed=passed,
            risk_score=max_risk,
            details=details,
            latency_ms=(time.perf_counter() - start) * 1000,
        )
