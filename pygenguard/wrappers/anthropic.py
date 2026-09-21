"""
Anthropic SDK Wrapper for PyGenGuard v1.0.

Provides 1-line security wrapping for Anthropic clients (Claude).
"""

import functools
from typing import Any, Optional
from pygenguard.guard import Guard
from pygenguard.session import Session
from pygenguard.streaming.guard import StreamingOutputGuard
from pygenguard.decision import Decision


class PyGenGuardSecurityException(Exception):
    """Raised when an LLM call is blocked by security policy."""
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"Request blocked by PyGenGuard: {decision.rationale}")


def _extract_prompt_from_anthropic(kwargs: dict) -> str:
    """Extract prompt text from Anthropic messages API kwargs."""
    messages = kwargs.get("messages", [])
    if isinstance(messages, list):
        for msg in reversed(messages):
            if isinstance(msg, dict) and msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    return content
                elif isinstance(content, list):
                    return " ".join(
                        block.get("text", "")
                        for block in content
                        if isinstance(block, dict) and block.get("type") == "text"
                    )
    return ""


def wrap_anthropic(
    client: Any,
    guard: Optional[Guard] = None,
    raise_on_block: bool = True,
) -> Any:
    """
    Wrap an Anthropic client with PyGenGuard runtime security.

    Usage:
    ```python
    from anthropic import Anthropic
    from pygenguard.wrappers import wrap_anthropic

    client = Anthropic()
    client = wrap_anthropic(client)

    # Automatically inspected before and after execution!
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Hello"}]
    )
    ```
    """
    sync_guard = guard or Guard(mode="balanced")
    stream_guard = StreamingOutputGuard()

    if hasattr(client, "messages") and hasattr(client.messages, "create"):
        orig_create = client.messages.create

        import inspect
        if inspect.iscoroutinefunction(orig_create):
            @functools.wraps(orig_create)
            async def async_wrapped(*args, **kwargs):
                prompt = _extract_prompt_from_anthropic(kwargs)
                user_id = kwargs.pop("genguard_user_id", "anthropic_user")
                session = kwargs.pop("genguard_session", None) or Session.create(user_id=user_id)

                if prompt:
                    decision = sync_guard.inspect(prompt, session)
                    if not decision.allowed:
                        if raise_on_block:
                            raise PyGenGuardSecurityException(decision)
                        return decision.safe_response

                result = await orig_create(*args, **kwargs)

                # Inspect output
                if hasattr(result, "content") and result.content:
                    for block in result.content:
                        if hasattr(block, "text") and block.text:
                            out_dec = sync_guard.inspect_output(block.text, prompt=prompt, session=session)
                            if not out_dec.allowed and raise_on_block:
                                raise PyGenGuardSecurityException(out_dec)
                            if out_dec.sanitized_response:
                                block.text = out_dec.sanitized_response

                return result

            client.messages.create = async_wrapped
        else:
            @functools.wraps(orig_create)
            def sync_wrapped(*args, **kwargs):
                prompt = _extract_prompt_from_anthropic(kwargs)
                user_id = kwargs.pop("genguard_user_id", "anthropic_user")
                session = kwargs.pop("genguard_session", None) or Session.create(user_id=user_id)

                if prompt:
                    decision = sync_guard.inspect(prompt, session)
                    if not decision.allowed:
                        if raise_on_block:
                            raise PyGenGuardSecurityException(decision)
                        return decision.safe_response

                result = orig_create(*args, **kwargs)

                # Inspect output
                if hasattr(result, "content") and result.content:
                    for block in result.content:
                        if hasattr(block, "text") and block.text:
                            out_dec = sync_guard.inspect_output(block.text, prompt=prompt, session=session)
                            if not out_dec.allowed and raise_on_block:
                                raise PyGenGuardSecurityException(out_dec)
                            if out_dec.sanitized_response:
                                block.text = out_dec.sanitized_response

                return result

            client.messages.create = sync_wrapped

    return client
