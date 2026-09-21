"""
OpenAI SDK Drop-in Wrapper for PyGenGuard.

Provides 1-line security wrapping for OpenAI clients.
"""

import functools
import types
from typing import Any, Optional, Callable
from pygenguard.guard import Guard
from pygenguard.async_guard.guard import AsyncGuard
from pygenguard.session import Session
from pygenguard.streaming.guard import StreamingOutputGuard
from pygenguard.decision import Decision


class PyGenGuardSecurityException(Exception):
    """Raised when an LLM call is blocked by security policy."""
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"Request blocked by PyGenGuard: {decision.rationale}")


def _extract_prompt_from_kwargs(kwargs: dict) -> str:
    """Extract prompt text from chat completion kwargs."""
    if "messages" in kwargs and isinstance(kwargs["messages"], list):
        for msg in reversed(kwargs["messages"]):
            if isinstance(msg, dict) and msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    return content
                elif isinstance(content, list):
                    return " ".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text")
    if "prompt" in kwargs and isinstance(kwargs["prompt"], str):
        return kwargs["prompt"]
    return ""


def wrap_openai(
    client: Any,
    guard: Optional[Guard] = None,
    async_guard: Optional[AsyncGuard] = None,
    raise_on_block: bool = True
) -> Any:
    """
    Wrap an OpenAI or AsyncOpenAI client with PyGenGuard runtime security.
    
    Usage:
    ```python
    from openai import OpenAI
    from pygenguard.wrappers import wrap_openai
    
    client = OpenAI()
    client = wrap_openai(client)
    
    # Automatically inspected before and after execution!
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello world"}]
    )
    ```
    """
    sync_guard = guard or Guard(mode="balanced")
    a_guard = async_guard or AsyncGuard(mode="balanced")
    stream_guard = StreamingOutputGuard()
    
    if hasattr(client, "chat") and hasattr(client.chat, "completions"):
        orig_create = client.chat.completions.create
        
        # Check if async
        import inspect
        if inspect.iscoroutinefunction(orig_create):
            @functools.wraps(orig_create)
            async def async_wrapped_create(*args, **kwargs):
                prompt = _extract_prompt_from_kwargs(kwargs)
                user_id = kwargs.get("user", "openai_user")
                session = kwargs.pop("genguard_session", None) or Session.create(user_id=user_id)
                
                # 1. Input Inspection
                if prompt:
                    decision = await a_guard.inspect(prompt, session)
                    if not decision.allowed:
                        if raise_on_block:
                            raise PyGenGuardSecurityException(decision)
                        # Return synthetic mock response if not raising
                        return decision.safe_response
                        
                # 2. Call original API
                result = await orig_create(*args, **kwargs)
                
                # 3. Handle Streaming vs Non-Streaming Output
                if kwargs.get("stream", False):
                    return stream_guard.wrap_async_stream(result, prompt=prompt)
                    
                # Inspect complete output
                if hasattr(result, "choices") and result.choices:
                    content = result.choices[0].message.content
                    if content:
                        out_decision = await a_guard.inspect_output(content, prompt=prompt, session=session)
                        if not out_decision.allowed and raise_on_block:
                            raise PyGenGuardSecurityException(out_decision)
                        if out_decision.sanitized_response:
                            result.choices[0].message.content = out_decision.sanitized_response
                            
                return result
                
            client.chat.completions.create = async_wrapped_create
        else:
            @functools.wraps(orig_create)
            def sync_wrapped_create(*args, **kwargs):
                prompt = _extract_prompt_from_kwargs(kwargs)
                user_id = kwargs.get("user", "openai_user")
                session = kwargs.pop("genguard_session", None) or Session.create(user_id=user_id)
                
                # 1. Input Inspection
                if prompt:
                    decision = sync_guard.inspect(prompt, session)
                    if not decision.allowed:
                        if raise_on_block:
                            raise PyGenGuardSecurityException(decision)
                        return decision.safe_response
                        
                # 2. Call original API
                result = orig_create(*args, **kwargs)
                
                # 3. Handle Streaming vs Non-Streaming Output
                if kwargs.get("stream", False):
                    return stream_guard.wrap_sync_stream(result, prompt=prompt)
                    
                # Inspect complete output
                if hasattr(result, "choices") and result.choices:
                    content = result.choices[0].message.content
                    if content:
                        out_decision = sync_guard.inspect_output(content, prompt=prompt, session=session)
                        if not out_decision.allowed and raise_on_block:
                            raise PyGenGuardSecurityException(out_decision)
                        if out_decision.sanitized_response:
                            result.choices[0].message.content = out_decision.sanitized_response
                            
                return result
                
            client.chat.completions.create = sync_wrapped_create
            
    return client
