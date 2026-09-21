"""
PyGenGuard Framework Integrations.
"""

from pygenguard.integrations.fastapi import PyGenGuardMiddleware

# Lazy imports for optional framework dependencies
def get_langchain_handler(**kwargs):
    """Get LangChain callback handler."""
    from pygenguard.integrations.langchain import PyGenGuardCallbackHandler
    return PyGenGuardCallbackHandler(**kwargs)

def get_llamaindex_handler(**kwargs):
    """Get LlamaIndex callback handler."""
    from pygenguard.integrations.llamaindex import PyGenGuardCallbackHandler
    return PyGenGuardCallbackHandler(**kwargs)

def get_crewai_guard(**kwargs):
    """Get CrewAI agent guard."""
    from pygenguard.integrations.crewai import PyGenGuardAgentGuard
    return PyGenGuardAgentGuard(**kwargs)

__all__ = [
    "PyGenGuardMiddleware",
    "get_langchain_handler",
    "get_llamaindex_handler",
    "get_crewai_guard",
]
