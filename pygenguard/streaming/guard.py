"""
Streaming Output Guard for PyGenGuard.

Enables real-time safety inspection of token streams (e.g., OpenAI/Anthropic stream=True)
using a low-latency sliding window buffer to catch secrets, PII, and injection markers
across chunk boundaries without stalling the user experience.
"""

import re
from typing import AsyncIterator, Iterator, Optional, List, Dict, Any
from pygenguard.planes.output import OutputPlane
from pygenguard.decision import Decision, PlaneResult


class StreamingOutputGuard:
    """
    Real-time streaming guard that wraps token generators/iterators.
    
    Features:
    - Low-latency sliding window inspection
    - Cross-chunk secret & PII detection
    - Early stream termination on critical policy violation
    - Post-stream audit decision generation
    
    Usage (Async):
    ```python
    from pygenguard.streaming import StreamingOutputGuard
    
    stream_guard = StreamingOutputGuard()
    
    async for safe_token in stream_guard.wrap_async_stream(llm_stream_response):
        yield safe_token
    ```
    """
    
    def __init__(
        self,
        output_plane: Optional[OutputPlane] = None,
        buffer_window_chars: int = 40,
        stop_on_critical_threat: bool = True
    ):
        self.plane = output_plane or OutputPlane()
        self.buffer_window_chars = buffer_window_chars
        self.stop_on_critical_threat = stop_on_critical_threat
        
    def wrap_sync_stream(
        self,
        stream: Iterator[Any],
        prompt: Optional[str] = None,
        system_prompt: Optional[str] = None,
        token_extractor: Optional[callable] = None
    ) -> Iterator[str]:
        """
        Wrap a synchronous token stream.
        
        Args:
            stream: Iterator of chunks (strings or LLM Chunk objects)
            prompt: User prompt for context
            system_prompt: System prompt to check for leakage
            token_extractor: Function to extract text from chunk (default: str or chunk.choices[0].delta.content)
            
        Yields:
            Safe text tokens
        """
        full_text = []
        rolling_buffer = ""
        
        def extract(chunk: Any) -> str:
            if token_extractor:
                return token_extractor(chunk)
            if isinstance(chunk, str):
                return chunk
            # OpenAI / Anthropic chunk compatibility
            if hasattr(chunk, "choices") and chunk.choices:
                delta = getattr(chunk.choices[0], "delta", None)
                if delta and hasattr(delta, "content") and delta.content:
                    return delta.content
            return str(chunk)
            
        for raw_chunk in stream:
            token = extract(raw_chunk)
            if not token:
                continue
                
            full_text.append(token)
            rolling_buffer += token
            
            # Check sliding window for critical threats (e.g., private keys, API keys, exfiltration)
            if len(rolling_buffer) >= self.buffer_window_chars:
                check_result = self.plane.evaluate(rolling_buffer, prompt=prompt, system_prompt=system_prompt)
                if not check_result.passed and self.stop_on_critical_threat:
                    yield "\n\n[STREAM TERMINATED BY PYGENGUARD OUTPUT SECURITY POLICY]"
                    return
                # Keep rolling window
                rolling_buffer = rolling_buffer[-self.buffer_window_chars:]
                
            yield token
            
        # Final evaluation on complete generated text
        complete_text = "".join(full_text)
        final_res = self.plane.evaluate(complete_text, prompt=prompt, system_prompt=system_prompt)
        if not final_res.passed and self.stop_on_critical_threat:
            yield "\n[WARNING: Security policy violation detected in generated response]"

    async def wrap_async_stream(
        self,
        stream: AsyncIterator[Any],
        prompt: Optional[str] = None,
        system_prompt: Optional[str] = None,
        token_extractor: Optional[callable] = None
    ) -> AsyncIterator[str]:
        """
        Wrap an asynchronous token stream.
        
        Args:
            stream: AsyncIterator of chunks
            prompt: User prompt for context
            system_prompt: System prompt
            token_extractor: Optional extractor function
            
        Yields:
            Safe text tokens
        """
        full_text = []
        rolling_buffer = ""
        
        def extract(chunk: Any) -> str:
            if token_extractor:
                return token_extractor(chunk)
            if isinstance(chunk, str):
                return chunk
            if hasattr(chunk, "choices") and chunk.choices:
                delta = getattr(chunk.choices[0], "delta", None)
                if delta and hasattr(delta, "content") and delta.content:
                    return delta.content
            return str(chunk)
            
        async for raw_chunk in stream:
            token = extract(raw_chunk)
            if not token:
                continue
                
            full_text.append(token)
            rolling_buffer += token
            
            # Check sliding window
            if len(rolling_buffer) >= self.buffer_window_chars:
                check_result = self.plane.evaluate(rolling_buffer, prompt=prompt, system_prompt=system_prompt)
                if not check_result.passed and self.stop_on_critical_threat:
                    yield "\n\n[STREAM TERMINATED BY PYGENGUARD OUTPUT SECURITY POLICY]"
                    return
                rolling_buffer = rolling_buffer[-self.buffer_window_chars:]
                
            yield token
            
        # Final pass
        complete_text = "".join(full_text)
        final_res = self.plane.evaluate(complete_text, prompt=prompt, system_prompt=system_prompt)
        if not final_res.passed and self.stop_on_critical_threat:
            yield "\n[WARNING: Security policy violation detected in generated response]"
