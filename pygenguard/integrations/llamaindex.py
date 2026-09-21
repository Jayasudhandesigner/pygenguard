"""
LlamaIndex Integration for PyGenGuard v1.0.

Provides callback-based security integration for LlamaIndex queries and retrievals.
"""

from typing import Any, Optional, Dict, List
from pygenguard.guard import Guard
from pygenguard.session import Session
from pygenguard.decision import Decision


class PyGenGuardCallbackHandler:
    """
    LlamaIndex callback handler for security inspection.

    Usage:
    ```python
    from llama_index.core import Settings
    from pygenguard.integrations.llamaindex import PyGenGuardCallbackHandler

    guard_handler = PyGenGuardCallbackHandler(guard=Guard(mode="strict"))
    Settings.callback_manager.add_handler(guard_handler)
    ```
    """

    def __init__(
        self,
        guard: Optional[Guard] = None,
        user_id: str = "llamaindex_user",
        raise_on_block: bool = True,
        inspect_retrieval: bool = True,
    ):
        self.guard = guard or Guard(mode="balanced")
        self.user_id = user_id
        self.raise_on_block = raise_on_block
        self.inspect_retrieval = inspect_retrieval
        self._session = Session.create(user_id=user_id)

    def on_query_start(self, query: str, **kwargs: Any) -> Decision:
        """Inspect query before processing."""
        decision = self.guard.inspect(query, self._session)
        if not decision.allowed and self.raise_on_block:
            raise SecurityBlockError(decision)
        return decision

    def on_query_end(self, response: Any, **kwargs: Any) -> None:
        """Inspect query response."""
        if hasattr(response, "response") and isinstance(response.response, str):
            out_dec = self.guard.inspect_output(
                response.response, session=self._session
            )
            if not out_dec.allowed and self.raise_on_block:
                raise SecurityBlockError(out_dec)

    def on_retrieve_start(self, query: str, **kwargs: Any) -> None:
        """Inspect retrieval query."""
        if self.inspect_retrieval:
            decision = self.guard.inspect(query, self._session)
            if not decision.allowed and self.raise_on_block:
                raise SecurityBlockError(decision)

    def on_retrieve_end(self, nodes: List[Any], **kwargs: Any) -> None:
        """Inspect retrieved nodes for poisoning."""
        if not self.inspect_retrieval:
            return
        for node in nodes:
            text = ""
            if hasattr(node, "text"):
                text = node.text
            elif hasattr(node, "get_content"):
                text = node.get_content()
            if text:
                dec = self.guard.inspect_training_data(text)
                if not dec.allowed and self.raise_on_block:
                    raise SecurityBlockError(dec)


class SecurityBlockError(Exception):
    """Raised when PyGenGuard blocks a LlamaIndex operation."""
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"PyGenGuard blocked: {decision.rationale}")


PyGenGuardLlamaIndexHandler = PyGenGuardCallbackHandler

