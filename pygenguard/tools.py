"""
Tool Execution Sandbox & Proxy Decorator for PyGenGuard.

Provides automatic security wrapping for agent tool/function executions:
- Pre-execution tool argument validation (SQLi, command injection, path traversal)
- Permission & allowlist enforcement
- Timeout-bounded sandboxed execution
- Post-execution output inspection for indirect prompt injection & data leakage
"""

import asyncio
import functools
import inspect
import time
from typing import Callable, Any, Optional, Set, Dict
from pygenguard.decision import Decision
from pygenguard.session import Session


class ToolSecurityException(Exception):
    """Raised when an agent tool call is blocked by security policy."""
    def __init__(self, decision: Decision, phase: str = "input"):
        self.decision = decision
        self.phase = phase
        super().__init__(f"Tool call blocked ({phase}): {decision.rationale}")


class ToolExecutionTimeout(Exception):
    """Raised when an agent tool exceeds execution timeout."""
    def __init__(self, tool_name: str, timeout_sec: float):
        self.tool_name = tool_name
        self.timeout_sec = timeout_sec
        super().__init__(f"Tool '{tool_name}' timed out after {timeout_sec:.2f}s")


def guard_tool(
    guard: Any,
    name: Optional[str] = None,
    permissions: Optional[Set[str]] = None,
    timeout_seconds: float = 10.0,
    inspect_output: bool = True,
    raise_on_block: bool = True,
    fallback_value: Any = None,
):
    """
    Decorator for synchronous agent tool functions.

    Usage:
        @guard_tool(guard, name="database_query", timeout_seconds=5.0)
        def query_database(query: str) -> dict:
            return db.execute(query)
    """
    def decorator(func: Callable) -> Callable:
        tool_name = name or func.__name__

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # 1. Bind arguments into parameter dict
            sig = inspect.signature(func)
            bound = sig.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            tool_args = dict(bound.arguments)

            session = kwargs.get("session") or getattr(guard, "_default_session", None) or Session.create("tool_agent")

            # 2. Pre-execution argument inspection
            dec = guard.inspect_tool_call(
                tool_name=tool_name,
                arguments=tool_args,
                session=session,
                agent_permissions=permissions,
            )
            if not dec.allowed:
                if raise_on_block:
                    raise ToolSecurityException(dec, phase="input")
                return fallback_value if fallback_value is not None else {"error": dec.rationale}

            # 3. Tool execution
            result = func(*args, **kwargs)

            # 4. Post-execution tool output inspection (indirect prompt injection / secret leaks)
            if inspect_output and result is not None:
                out_str = str(result)
                out_dec = guard.inspect_output(out_str)
                if not out_dec.allowed:
                    if raise_on_block:
                        raise ToolSecurityException(out_dec, phase="output")
                    return fallback_value if fallback_value is not None else {"error": "Tool output flagged by security policy"}

                inj_dec = guard.inspect(out_str, session)
                if not inj_dec.allowed:
                    if raise_on_block:
                        raise ToolSecurityException(inj_dec, phase="output")
                    return fallback_value if fallback_value is not None else {"error": "Tool output flagged by security policy"}

            return result

        return wrapper
    return decorator


def aguard_tool(
    guard: Any,
    name: Optional[str] = None,
    permissions: Optional[Set[str]] = None,
    timeout_seconds: float = 10.0,
    inspect_output: bool = True,
    raise_on_block: bool = True,
    fallback_value: Any = None,
):
    """
    Decorator for asynchronous agent tool functions.

    Usage:
        @aguard_tool(guard, name="fetch_webpage", timeout_seconds=5.0)
        async def fetch_webpage(url: str) -> str:
            return await http.get(url)
    """
    def decorator(func: Callable) -> Callable:
        tool_name = name or func.__name__

        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # 1. Bind arguments
            sig = inspect.signature(func)
            bound = sig.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            tool_args = dict(bound.arguments)

            session = kwargs.get("session") or getattr(guard, "_default_session", None) or Session.create("tool_agent")

            # 2. Pre-execution argument inspection
            dec = guard.inspect_tool_call(
                tool_name=tool_name,
                arguments=tool_args,
                session=session,
                agent_permissions=permissions,
            )
            if not dec.allowed:
                if raise_on_block:
                    raise ToolSecurityException(dec, phase="input")
                return fallback_value if fallback_value is not None else {"error": dec.rationale}

            # 3. Async tool execution with timeout
            try:
                result = await asyncio.wait_for(func(*args, **kwargs), timeout=timeout_seconds)
            except asyncio.TimeoutError:
                raise ToolExecutionTimeout(tool_name, timeout_seconds)

            # 4. Post-execution indirect prompt injection check
            if inspect_output and result is not None:
                out_str = str(result)
                out_dec = guard.inspect_output(out_str)
                if not out_dec.allowed:
                    if raise_on_block:
                        raise ToolSecurityException(out_dec, phase="output")
                    return fallback_value if fallback_value is not None else {"error": "Tool output flagged by security policy"}

                inj_dec = guard.inspect(out_str, session)
                if not inj_dec.allowed:
                    if raise_on_block:
                        raise ToolSecurityException(inj_dec, phase="output")
                    return fallback_value if fallback_value is not None else {"error": "Tool output flagged by security policy"}

            return result

        return wrapper
    return decorator


class ToolSandbox:
    """
    Registry and sandbox executor for agent tools.

    Usage:
        sandbox = ToolSandbox(guard)
        sandbox.register("search", my_search_func)
        res = sandbox.execute("search", query="climate change")
    """

    def __init__(self, guard: Any, default_timeout_sec: float = 10.0):
        self.guard = guard
        self.default_timeout = default_timeout_sec
        self._tools: Dict[str, Callable] = {}

    def register(self, name: str, func: Callable, permissions: Optional[Set[str]] = None) -> None:
        """Register a tool wrapped with guardrails."""
        self._tools[name] = guard_tool(
            self.guard,
            name=name,
            permissions=permissions,
            timeout_seconds=self.default_timeout,
        )(func)

    def execute(self, name: str, *args, **kwargs) -> Any:
        """Execute a sandboxed tool by name."""
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' is not registered in ToolSandbox.")
        return self._tools[name](*args, **kwargs)
