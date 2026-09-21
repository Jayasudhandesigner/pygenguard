"""
PyGenGuard SDK Wrappers - Drop-in security for LLM provider SDKs.
"""

from pygenguard.wrappers.openai import wrap_openai, PyGenGuardSecurityException

# Lazy imports to avoid requiring SDK dependencies
def wrap_anthropic(client, **kwargs):
    """Wrap an Anthropic client with PyGenGuard security."""
    from pygenguard.wrappers.anthropic import wrap_anthropic as _wrap
    return _wrap(client, **kwargs)

def wrap_google(model, **kwargs):
    """Wrap a Google GenerativeModel with PyGenGuard security."""
    from pygenguard.wrappers.google_genai import wrap_google as _wrap
    return _wrap(model, **kwargs)

def wrap_litellm(litellm_module, **kwargs):
    """Wrap LiteLLM with PyGenGuard security."""
    from pygenguard.wrappers.litellm import wrap_litellm as _wrap
    return _wrap(litellm_module, **kwargs)

__all__ = [
    "wrap_openai",
    "wrap_anthropic",
    "wrap_google",
    "wrap_litellm",
    "PyGenGuardSecurityException",
]
