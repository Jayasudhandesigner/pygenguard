"""
LangChain Integration for PyGenGuard v1.0.

Provides callback-based security integration for LangChain chains,
agents, and tools.
"""

from typing import Any, Optional, Dict, List, Union
from pygenguard.guard import Guard
from pygenguard.session import Session
from pygenguard.decision import Decision


class PyGenGuardCallbackHandler:
    """
    LangChain callback handler that intercepts LLM calls for security inspection.

    Usage:
    ```python
    from langchain.llms import OpenAI
    from pygenguard.integrations.langchain import PyGenGuardCallbackHandler

    guard_handler = PyGenGuardCallbackHandler(guard=Guard(mode="strict"))
    llm = OpenAI(callbacks=[guard_handler])
    ```

    Also works as a Runnable wrapper:
    ```python
    from pygenguard.integrations.langchain import PyGenGuardRunnable

    secured_chain = PyGenGuardRunnable(guard) | llm | PyGenGuardOutputRunnable(guard)
    ```
    """

    def __init__(
        self,
        guard: Optional[Guard] = None,
        user_id: str = "langchain_user",
        raise_on_block: bool = True,
        inspect_output: bool = True,
    ):
        self.guard = guard or Guard(mode="balanced")
        self.user_id = user_id
        self.raise_on_block = raise_on_block
        self.inspect_output = inspect_output
        self._session = Session.create(user_id=user_id)
        self._last_prompt = ""

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        """Called when LLM starts. Inspects input prompts."""
        for prompt in prompts:
            self._last_prompt = prompt
            decision = self.guard.inspect(prompt, self._session)
            if not decision.allowed:
                if self.raise_on_block:
                    raise SecurityBlockError(decision)

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Called when LLM finishes. Inspects output."""
        if not self.inspect_output:
            return

        if hasattr(response, "generations"):
            for gen_list in response.generations:
                for gen in gen_list:
                    if hasattr(gen, "text") and gen.text:
                        out_dec = self.guard.inspect_output(
                            gen.text, prompt=self._last_prompt, session=self._session
                        )
                        if not out_dec.allowed and self.raise_on_block:
                            raise SecurityBlockError(out_dec)

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts. Can inspect tool inputs."""
        decision = self.guard.inspect(input_str, self._session)
        if not decision.allowed and self.raise_on_block:
            raise SecurityBlockError(decision)

    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """Called when a chain starts."""
        pass  # Can be extended for chain-level inspection

    def on_llm_error(self, error: Exception, **kwargs: Any) -> None:
        """Called on LLM error."""
        pass

    def on_chain_error(self, error: Exception, **kwargs: Any) -> None:
        """Called on chain error."""
        pass

    def on_tool_error(self, error: Exception, **kwargs: Any) -> None:
        """Called on tool error."""
        pass


class SecurityBlockError(Exception):
    """Raised when PyGenGuard blocks a LangChain operation."""
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"PyGenGuard blocked: {decision.rationale}")


def create_guard_chain_wrapper(
    guard: Optional[Guard] = None,
    user_id: str = "langchain_user",
) -> "PyGenGuardCallbackHandler":
    """Convenience factory for creating a LangChain guard wrapper."""
    return PyGenGuardCallbackHandler(
        guard=guard or Guard(mode="balanced"),
        user_id=user_id,
    )
