"""
LiteLLM Wrapper for PyGenGuard v1.0.

Provides security wrapping for LiteLLM's universal LLM interface.
"""

import functools
from typing import Any, Optional
from pygenguard.guard import Guard
from pygenguard.session import Session
from pygenguard.decision import Decision


class PyGenGuardSecurityException(Exception):
    """Raised when an LLM call is blocked by security policy."""
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"Request blocked by PyGenGuard: {decision.rationale}")


def _extract_prompt_from_litellm(kwargs: dict) -> str:
    """Extract prompt from LiteLLM completion kwargs."""
    messages = kwargs.get("messages", [])
    if isinstance(messages, list):
        for msg in reversed(messages):
            if isinstance(msg, dict) and msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    return content
    prompt = kwargs.get("prompt", "")
    if isinstance(prompt, str):
        return prompt
    return ""


def wrap_litellm(
    litellm_module: Any,
    guard: Optional[Guard] = None,
    raise_on_block: bool = True,
) -> Any:
    """
    Wrap LiteLLM's completion/acompletion with PyGenGuard security.

    Usage:
    ```python
    import litellm
    from pygenguard.wrappers import wrap_litellm

    litellm = wrap_litellm(litellm)

    # Automatically inspected!
    response = litellm.completion(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello"}]
    )
    ```
    """
    sync_guard = guard or Guard(mode="balanced")

    # Wrap synchronous completion
    if hasattr(litellm_module, "completion"):
        orig_completion = litellm_module.completion

        @functools.wraps(orig_completion)
        def wrapped_completion(*args, **kwargs):
            prompt = _extract_prompt_from_litellm(kwargs)
            user_id = kwargs.pop("genguard_user_id", "litellm_user")
            session = kwargs.pop("genguard_session", None) or Session.create(user_id=user_id)

            if prompt:
                decision = sync_guard.inspect(prompt, session)
                if not decision.allowed:
                    if raise_on_block:
                        raise PyGenGuardSecurityException(decision)
                    return decision.safe_response

            result = orig_completion(*args, **kwargs)

            # Inspect output
            if hasattr(result, "choices") and result.choices:
                msg = result.choices[0].message
                if hasattr(msg, "content") and msg.content:
                    out_dec = sync_guard.inspect_output(msg.content, prompt=prompt, session=session)
                    if not out_dec.allowed and raise_on_block:
                        raise PyGenGuardSecurityException(out_dec)
                    if out_dec.sanitized_response:
                        msg.content = out_dec.sanitized_response

            return result

        litellm_module.completion = wrapped_completion

    # Wrap async completion
    if hasattr(litellm_module, "acompletion"):
        orig_acompletion = litellm_module.acompletion

        @functools.wraps(orig_acompletion)
        async def wrapped_acompletion(*args, **kwargs):
            prompt = _extract_prompt_from_litellm(kwargs)
            user_id = kwargs.pop("genguard_user_id", "litellm_user")
            session = kwargs.pop("genguard_session", None) or Session.create(user_id=user_id)

            if prompt:
                decision = sync_guard.inspect(prompt, session)
                if not decision.allowed:
                    if raise_on_block:
                        raise PyGenGuardSecurityException(decision)
                    return decision.safe_response

            result = await orig_acompletion(*args, **kwargs)

            if hasattr(result, "choices") and result.choices:
                msg = result.choices[0].message
                if hasattr(msg, "content") and msg.content:
                    out_dec = sync_guard.inspect_output(msg.content, prompt=prompt, session=session)
                    if not out_dec.allowed and raise_on_block:
                        raise PyGenGuardSecurityException(out_dec)
                    if out_dec.sanitized_response:
                        msg.content = out_dec.sanitized_response

            return result

        litellm_module.acompletion = wrapped_acompletion

    return litellm_module
