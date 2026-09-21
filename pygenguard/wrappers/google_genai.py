"""
Google GenAI SDK Wrapper for PyGenGuard v1.0.

Provides 1-line security wrapping for Google's generativeai (Gemini) clients.
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


def _extract_prompt_from_gemini(args: tuple, kwargs: dict) -> str:
    """Extract prompt from Gemini generate_content args."""
    # generate_content(contents=...) or generate_content("prompt text")
    if args:
        first_arg = args[0]
        if isinstance(first_arg, str):
            return first_arg
        elif isinstance(first_arg, list):
            texts = []
            for item in first_arg:
                if isinstance(item, str):
                    texts.append(item)
                elif isinstance(item, dict) and "text" in item:
                    texts.append(item["text"])
            return " ".join(texts)

    contents = kwargs.get("contents", "")
    if isinstance(contents, str):
        return contents
    elif isinstance(contents, list):
        texts = []
        for item in contents:
            if isinstance(item, str):
                texts.append(item)
            elif isinstance(item, dict) and "text" in item:
                texts.append(item["text"])
        return " ".join(texts)

    return ""


def wrap_google(
    model: Any,
    guard: Optional[Guard] = None,
    raise_on_block: bool = True,
) -> Any:
    """
    Wrap a Google GenerativeModel with PyGenGuard runtime security.

    Usage:
    ```python
    import google.generativeai as genai
    from pygenguard.wrappers import wrap_google

    genai.configure(api_key="...")
    model = genai.GenerativeModel("gemini-1.5-pro")
    model = wrap_google(model)

    # Automatically inspected!
    response = model.generate_content("Hello")
    ```
    """
    sync_guard = guard or Guard(mode="balanced")

    if hasattr(model, "generate_content"):
        orig_generate = model.generate_content

        import inspect
        if inspect.iscoroutinefunction(orig_generate):
            @functools.wraps(orig_generate)
            async def async_wrapped(*args, **kwargs):
                prompt = _extract_prompt_from_gemini(args, kwargs)
                user_id = kwargs.pop("genguard_user_id", "gemini_user")
                session = kwargs.pop("genguard_session", None) or Session.create(user_id=user_id)

                if prompt:
                    decision = sync_guard.inspect(prompt, session)
                    if not decision.allowed:
                        if raise_on_block:
                            raise PyGenGuardSecurityException(decision)
                        return decision.safe_response

                result = await orig_generate(*args, **kwargs)

                # Inspect output text
                if hasattr(result, "text") and result.text:
                    out_dec = sync_guard.inspect_output(result.text, prompt=prompt, session=session)
                    if not out_dec.allowed and raise_on_block:
                        raise PyGenGuardSecurityException(out_dec)

                return result

            model.generate_content = async_wrapped
        else:
            @functools.wraps(orig_generate)
            def sync_wrapped(*args, **kwargs):
                prompt = _extract_prompt_from_gemini(args, kwargs)
                user_id = kwargs.pop("genguard_user_id", "gemini_user")
                session = kwargs.pop("genguard_session", None) or Session.create(user_id=user_id)

                if prompt:
                    decision = sync_guard.inspect(prompt, session)
                    if not decision.allowed:
                        if raise_on_block:
                            raise PyGenGuardSecurityException(decision)
                        return decision.safe_response

                result = orig_generate(*args, **kwargs)

                if hasattr(result, "text") and result.text:
                    out_dec = sync_guard.inspect_output(result.text, prompt=prompt, session=session)
                    if not out_dec.allowed and raise_on_block:
                        raise PyGenGuardSecurityException(out_dec)

                return result

            model.generate_content = sync_wrapped

    return model
