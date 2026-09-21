"""
CrewAI Integration for PyGenGuard v1.0.

Provides agent-level security guards for CrewAI multi-agent workflows.
"""

from typing import Any, Optional, Dict, Set
from pygenguard.guard import Guard
from pygenguard.session import Session
from pygenguard.decision import Decision
from pygenguard.planes.tool_use import ToolUsePlane
from pygenguard.planes.agent_boundary import AgentBoundaryGuard, AgentSecurityContext


class PyGenGuardAgentGuard:
    """
    Security guard for CrewAI agents.

    Wraps agent execution with input/output/tool inspection.

    Usage:
    ```python
    from crewai import Agent
    from pygenguard.integrations.crewai import PyGenGuardAgentGuard

    guard = PyGenGuardAgentGuard(
        guard=Guard(mode="strict"),
        agent_id="researcher",
        allowed_tools=["search", "scrape"]
    )

    # Use guard in agent lifecycle
    agent = Agent(
        role="researcher",
        goal="Find information",
        backstory="...",
        step_callback=guard.step_callback,
    )
    ```
    """

    def __init__(
        self,
        guard: Optional[Guard] = None,
        agent_id: str = "crewai_agent",
        agent_role: str = "worker",
        allowed_tools: Optional[Set[str]] = None,
        blocked_tools: Optional[Set[str]] = None,
        max_tool_calls: int = 20,
        raise_on_block: bool = True,
    ):
        self.guard = guard or Guard(mode="balanced")
        self.agent_id = agent_id
        self.raise_on_block = raise_on_block
        self._session = Session.create(user_id=f"crewai:{agent_id}")
        self._tool_call_count = 0
        self._tool_guard = ToolUsePlane(
            allowed_tools=list(allowed_tools) if allowed_tools else None,
            blocked_tools=list(blocked_tools) if blocked_tools else None,
            max_tool_calls_per_session=max_tool_calls,
        )
        self._security_context = AgentSecurityContext(
            agent_id=agent_id,
            agent_role=agent_role,
        )

    def inspect_task_input(self, task_description: str) -> Decision:
        """Inspect task description before agent starts working."""
        return self.guard.inspect(task_description, self._session)

    def inspect_task_output(self, output: str, task_description: str = "") -> Decision:
        """Inspect agent's task output."""
        return self.guard.inspect_output(
            output, prompt=task_description, session=self._session
        )

    def inspect_tool_call(
        self,
        tool_name: str,
        tool_args: Optional[Dict[str, Any]] = None,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> Decision:
        """Inspect a tool call before execution."""
        self._tool_call_count += 1
        effective_args = arguments if arguments is not None else tool_args
        result = self._tool_guard.evaluate(
            tool_name=tool_name,
            tool_args=effective_args,
            agent_id=self.agent_id,
            call_count_this_session=self._tool_call_count,
        )

        if result.passed:
            return Decision.create_allow(
                trace_id="",
                plane_results={"tool_use": result},
                rationale=result.details,
            )
        else:
            return Decision.create_block(
                trace_id="",
                plane_results={"tool_use": result},
                rationale=result.details,
                safe_response="Tool call blocked by security policy.",
            )

    def step_callback(self, step_output: Any) -> None:
        """
        Callback for CrewAI agent steps.
        Can be passed as step_callback to Agent constructor.
        """
        if hasattr(step_output, "output") and isinstance(step_output.output, str):
            decision = self.guard.inspect_output(
                step_output.output, session=self._session
            )
            if not decision.allowed and self.raise_on_block:
                raise SecurityBlockError(decision)

    @property
    def security_context(self) -> AgentSecurityContext:
        """Get the agent's security context."""
        return self._security_context

    def reset(self) -> None:
        """Reset tool call counters."""
        self._tool_call_count = 0


class SecurityBlockError(Exception):
    """Raised when PyGenGuard blocks a CrewAI operation."""
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"PyGenGuard blocked: {decision.rationale}")


CrewAIAgentGuard = PyGenGuardAgentGuard

