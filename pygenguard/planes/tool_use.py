"""
Tool-Use Guard Plane for PyGenGuard v1.0.

Validates tool/function calls in agentic workflows before execution.

Protections:
- Tool name allowlist/denylist enforcement
- Argument injection detection (SQL injection, path traversal, command injection)
- Tool call frequency limiting (prevent infinite loops)
- Sensitive tool escalation (flag tools accessing PII, financial data, external APIs)
- Argument schema validation
"""

import re
import time
from typing import Optional, List, Dict, Set, Any, Tuple
from pygenguard.decision import PlaneResult


# Dangerous argument patterns that indicate injection attempts
SQL_INJECTION_PATTERNS = [
    r"(?:--|;)\s*(?:DROP|DELETE|UPDATE|INSERT|ALTER|EXEC|UNION)\s",
    r"'\s*OR\s+'?\d+'?\s*=\s*'?\d+'?",
    r"'\s*;\s*--",
    r"(?:UNION\s+ALL\s+SELECT|SELECT\s+\*\s+FROM)",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"/etc/(?:passwd|shadow|hosts)",
    r"[A-Za-z]:\\\\(?:Windows|System32)",
    r"~/.ssh",
    r"/proc/self",
]

COMMAND_INJECTION_PATTERNS = [
    r";\s*(?:rm|cat|curl|wget|nc|bash|sh|powershell|cmd)\s",
    r"\$\(.*\)",
    r"`.*`",
    r"\|\s*(?:bash|sh|python|perl|ruby|node)\s",
    r">\s*/dev/(?:tcp|udp)/",
]

# Tools that access sensitive resources and should require elevated permissions
SENSITIVE_TOOL_CATEGORIES = {
    "database": ["database_query", "db_query", "sql_execute", "db_write", "db_delete"],
    "filesystem": ["file_write", "file_delete", "file_create", "file_move", "shell_exec"],
    "network": ["http_request", "send_email", "send_sms", "api_call", "webhook_send"],
    "financial": ["payment_api", "transfer_funds", "create_invoice", "charge_card"],
    "auth": ["create_user", "delete_user", "reset_password", "grant_permission"],
}


class ToolUsePlane:
    """
    Validates tool/function calls before execution in agentic workflows.

    Usage:
        tool_guard = ToolUsePlane(
            allowed_tools=["search", "calculator", "code_interpreter"],
            blocked_tools=["shell_exec", "file_delete"],
            max_tool_calls_per_turn=5,
            require_approval_for=["database_query", "payment_api"]
        )

        result = tool_guard.evaluate(
            tool_name="database_query",
            tool_args={"query": "SELECT * FROM users WHERE id = 1"},
            agent_id="research_agent",
            call_count_this_turn=3
        )
    """

    def __init__(
        self,
        allowed_tools: Optional[List[str]] = None,
        blocked_tools: Optional[List[str]] = None,
        max_tool_calls_per_turn: int = 10,
        max_tool_calls_per_session: int = 100,
        require_approval_for: Optional[List[str]] = None,
        block_argument_injection: bool = True,
        block_sensitive_without_permission: bool = True,
        sensitive_categories: Optional[Dict[str, List[str]]] = None,
    ):
        self.allowed_tools = set(allowed_tools) if allowed_tools else None
        self.blocked_tools = set(blocked_tools or [])
        self.max_per_turn = max_tool_calls_per_turn
        self.max_per_session = max_tool_calls_per_session
        self.require_approval = set(require_approval_for or [])
        self.block_injection = block_argument_injection
        self.block_sensitive = block_sensitive_without_permission
        self.sensitive_categories = sensitive_categories or SENSITIVE_TOOL_CATEGORIES

    def evaluate(
        self,
        tool_name: str,
        tool_args: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
        call_count_this_turn: int = 0,
        call_count_this_session: int = 0,
        agent_permissions: Optional[Set[str]] = None,
    ) -> PlaneResult:
        """
        Evaluate a tool call for security violations.

        Args:
            tool_name: Name of the tool being called
            tool_args: Arguments passed to the tool
            agent_id: ID of the agent making the call
            call_count_this_turn: Number of tool calls so far in this turn
            call_count_this_session: Total tool calls in this session
            agent_permissions: Set of permission strings the agent has

        Returns:
            PlaneResult with pass/fail and threat details
        """
        start = time.perf_counter()
        threats: List[str] = []
        risk_score = 0.0
        should_block = False

        tool_args = tool_args or {}
        agent_permissions = agent_permissions or set()

        # 1. Denylist check
        if tool_name in self.blocked_tools or "*" in self.blocked_tools:
            threats.append(f"Tool '{tool_name}' is in the denylist")
            risk_score = max(risk_score, 0.95)
            should_block = True

        # 2. Allowlist check (if configured)
        if self.allowed_tools is not None and tool_name not in self.allowed_tools:
            threats.append(f"Tool '{tool_name}' is not in the allowlist")
            risk_score = max(risk_score, 0.9)
            should_block = True

        # 3. Frequency limiting
        if call_count_this_turn >= self.max_per_turn:
            threats.append(
                f"Tool call frequency exceeded: {call_count_this_turn}/{self.max_per_turn} per turn"
            )
            risk_score = max(risk_score, 0.7)
            should_block = True

        if call_count_this_session >= self.max_per_session:
            threats.append(
                f"Session tool call limit exceeded: {call_count_this_session}/{self.max_per_session}"
            )
            risk_score = max(risk_score, 0.8)
            should_block = True

        # 4. Approval requirement check
        if tool_name in self.require_approval:
            if "approval_granted" not in agent_permissions:
                threats.append(
                    f"Tool '{tool_name}' requires explicit approval"
                )
                risk_score = max(risk_score, 0.6)
                should_block = True

        # 5. Sensitive tool category check
        if self.block_sensitive:
            for category, tools in self.sensitive_categories.items():
                if tool_name in tools:
                    permission_key = f"access_{category}"
                    if permission_key not in agent_permissions:
                        threats.append(
                            f"Tool '{tool_name}' is a sensitive {category} tool — "
                            f"requires '{permission_key}' permission"
                        )
                        risk_score = max(risk_score, 0.8)
                        should_block = True
                    break

        # 6. Argument injection detection
        if self.block_injection and tool_args:
            injection_threats = self._check_argument_injection(tool_name, tool_args)
            if injection_threats:
                threats.extend(injection_threats)
                risk_score = max(risk_score, 0.95)
                should_block = True

        passed = not should_block
        details = "; ".join(threats) if threats else f"Tool '{tool_name}' call approved"

        return PlaneResult(
            plane_name="tool_use",
            passed=passed,
            risk_score=risk_score,
            details=details,
            latency_ms=(time.perf_counter() - start) * 1000,
        )

    def _check_argument_injection(
        self, tool_name: str, args: Dict[str, Any]
    ) -> List[str]:
        """Check tool arguments for injection patterns."""
        threats = []

        for arg_name, arg_value in args.items():
            if not isinstance(arg_value, str):
                continue

            # SQL injection
            for pattern in SQL_INJECTION_PATTERNS:
                if re.search(pattern, arg_value, re.IGNORECASE):
                    threats.append(
                        f"SQL injection detected in arg '{arg_name}': pattern match"
                    )
                    break

            # Path traversal
            for pattern in PATH_TRAVERSAL_PATTERNS:
                if re.search(pattern, arg_value, re.IGNORECASE):
                    threats.append(
                        f"Path traversal detected in arg '{arg_name}'"
                    )
                    break

            # Command injection
            for pattern in COMMAND_INJECTION_PATTERNS:
                if re.search(pattern, arg_value, re.IGNORECASE):
                    threats.append(
                        f"Command injection detected in arg '{arg_name}'"
                    )
                    break

        return threats

    def evaluate_batch(
        self,
        tool_calls: List[Dict[str, Any]],
        agent_id: Optional[str] = None,
        agent_permissions: Optional[Set[str]] = None,
    ) -> PlaneResult:
        """
        Evaluate a batch of tool calls (e.g., parallel tool use in a single turn).

        Args:
            tool_calls: List of {"name": str, "args": dict} tool call definitions
            agent_id: Agent making the calls
            agent_permissions: Agent's permissions

        Returns:
            PlaneResult covering all tool calls
        """
        start = time.perf_counter()
        all_threats: List[str] = []
        max_risk = 0.0
        any_blocked = False

        for i, call in enumerate(tool_calls):
            result = self.evaluate(
                tool_name=call.get("name", "unknown"),
                tool_args=call.get("args", {}),
                agent_id=agent_id,
                call_count_this_turn=i,
                call_count_this_session=i,
                agent_permissions=agent_permissions,
            )
            if not result.passed:
                any_blocked = True
                all_threats.append(f"[{call.get('name', '?')}] {result.details}")
            max_risk = max(max_risk, result.risk_score)

        passed = not any_blocked
        details = "; ".join(all_threats) if all_threats else f"All {len(tool_calls)} tool calls approved"

        return PlaneResult(
            plane_name="tool_use",
            passed=passed,
            risk_score=max_risk,
            details=details,
            latency_ms=(time.perf_counter() - start) * 1000,
        )
