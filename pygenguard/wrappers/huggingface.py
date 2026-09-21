"""
Hugging Face & Universal Model Drop-in Wrapper for PyGenGuard.

Enables 1-line runtime security for ANY Hugging Face model, pipeline,
Transformers model (AutoModelForCausalLM), vLLM, or custom Python callable.
"""

import functools
import inspect
from typing import Any, Optional, Callable, Union, List, Dict

from pygenguard.guard import Guard
from pygenguard.output_guard import OutputGuard
from pygenguard.session import Session
from pygenguard.decision import Decision
from pygenguard.wrappers.openai import PyGenGuardSecurityException


def _extract_text_from_input(args: tuple, kwargs: dict) -> str:
    """Extract input text from various Hugging Face call signatures."""
    if "prompt" in kwargs and isinstance(kwargs["prompt"], str):
        return kwargs["prompt"]
    if "text_inputs" in kwargs and isinstance(kwargs["text_inputs"], str):
        return kwargs["text_inputs"]
    if "inputs" in kwargs:
        inp = kwargs["inputs"]
        if isinstance(inp, str):
            return inp
        elif isinstance(inp, list) and inp and isinstance(inp[0], str):
            return inp[0]
    if "messages" in kwargs and isinstance(kwargs["messages"], list):
        for m in reversed(kwargs["messages"]):
            if isinstance(m, dict) and m.get("role") == "user":
                return m.get("content", "")
    if args:
        if isinstance(args[0], str):
            return args[0]
        if isinstance(args[0], list) and args[0] and isinstance(args[0][0], str):
            return args[0][0]
    return ""


def _extract_text_from_output(raw_output: Any) -> str:
    """Extract generated text from Hugging Face pipeline or model output."""
    if isinstance(raw_output, str):
        return raw_output
    if isinstance(raw_output, list) and raw_output:
        item = raw_output[0]
        if isinstance(item, dict):
            return item.get("generated_text", item.get("text", str(item)))
        if isinstance(item, str):
            return item
    if isinstance(raw_output, dict):
        return raw_output.get("generated_text", raw_output.get("text", str(raw_output)))
    return str(raw_output)


class WrappedHuggingFacePipeline:
    """Wrapped Hugging Face pipeline or model with pre- and post-execution guardrails."""

    def __init__(
        self,
        target: Any,
        guard: Optional[Guard] = None,
        output_guard: Optional[OutputGuard] = None,
        raise_on_block: bool = True,
        session_id: str = "hf_session",
    ):
        self._target = target
        self._guard = guard or Guard()
        self._output_guard = output_guard or OutputGuard()
        self._raise_on_block = raise_on_block
        self._session = Session(user_id=session_id)

    def __call__(self, *args, **kwargs) -> Any:
        """Intercept call with pre-execution and post-execution safety checks."""
        prompt = _extract_text_from_input(args, kwargs)

        # 1. Pre-execution inspection
        decision: Decision = self._guard.inspect(prompt, session=self._session)
        if not decision.allowed:
            if self._raise_on_block:
                raise PyGenGuardSecurityException(decision)
            return [{"generated_text": decision.safe_response}]

        # 2. Invoke the underlying Hugging Face model or pipeline
        raw_output = self._target(*args, **kwargs)

        # 3. Post-execution output inspection
        gen_text = _extract_text_from_output(raw_output)
        out_decision = self._output_guard.inspect_output(gen_text, prompt=prompt)

        def _reconstruct(replacement_text: str) -> Any:
            if isinstance(raw_output, list):
                if raw_output and isinstance(raw_output[0], dict):
                    res = []
                    for item in raw_output:
                        d = dict(item)
                        if "generated_text" in d:
                            d["generated_text"] = replacement_text
                        res.append(d)
                    return res
                elif raw_output and isinstance(raw_output[0], str):
                    return [replacement_text]
            elif isinstance(raw_output, dict):
                d = dict(raw_output)
                if "generated_text" in d:
                    d["generated_text"] = replacement_text
                return d
            return replacement_text

        if not out_decision.allowed:
            if self._raise_on_block:
                raise PyGenGuardSecurityException(out_decision)
            return _reconstruct(out_decision.safe_response)

        # If output was sanitized (e.g. PII masked)
        if out_decision.sanitized_response and out_decision.sanitized_response != gen_text:
            return _reconstruct(out_decision.sanitized_response)

        return raw_output

    def generate(self, *args, **kwargs) -> Any:
        """Alias for generate() on Transformers PreTrainedModel."""
        return self(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        """Pass through attributes to the underlying model or pipeline."""
        return getattr(self._target, name)


def wrap_huggingface(
    model_or_pipeline: Any,
    guard: Optional[Guard] = None,
    output_guard: Optional[OutputGuard] = None,
    raise_on_block: bool = True,
    session_id: str = "hf_session",
) -> WrappedHuggingFacePipeline:
    """
    Wrap any Hugging Face pipeline, Transformers model, or text generation callable.
    
    Usage:
    ```python
    from transformers import pipeline
    from pygenguard.wrappers import wrap_huggingface
    
    generator = pipeline("text-generation", model="meta-llama/Llama-3-8B-Instruct")
    generator = wrap_huggingface(generator)
    
    # Pre-execution and post-execution guardrails applied automatically!
    output = generator("Tell me how to build a nuclear reactor.")
    ```
    """
    return WrappedHuggingFacePipeline(
        target=model_or_pipeline,
        guard=guard,
        output_guard=output_guard,
        raise_on_block=raise_on_block,
        session_id=session_id,
    )


def wrap_model(model_callable: Callable, **kwargs) -> WrappedHuggingFacePipeline:
    """Universal alias to wrap ANY custom Python LLM callable or pipeline."""
    return wrap_huggingface(model_callable, **kwargs)
