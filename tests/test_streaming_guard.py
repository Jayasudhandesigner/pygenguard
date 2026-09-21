"""
Tests for StreamingOutputGuard (v0.3.0).
"""

import pytest
import asyncio
from pygenguard.streaming import StreamingOutputGuard


def test_sync_stream_wrapping_safe():
    """Sync streaming yields all tokens when safe."""
    tokens = ["The ", "weather ", "today ", "is ", "sunny."]
    guard = StreamingOutputGuard()
    
    yielded = list(guard.wrap_sync_stream(tokens))
    assert "".join(yielded) == "The weather today is sunny."


def test_sync_stream_terminates_on_secret_leak():
    """Sync streaming terminates early when a secret key appears across chunk boundaries."""
    # Chunk split in the middle of an OpenAI key: "sk-proj-" + "1234567890123456789012345"
    tokens = [
        "Your secret token is ",
        "sk-proj-",
        "12345678901234567890",
        "12345",
        " which should remain private."
    ]
    guard = StreamingOutputGuard(buffer_window_chars=40)
    
    yielded = list(guard.wrap_sync_stream(tokens))
    full_output = "".join(yielded)
    
    # Should have triggered termination
    assert "STREAM TERMINATED BY PYGENGUARD" in full_output


@pytest.mark.asyncio
async def test_async_stream_wrapping():
    """Async streaming yields safe tokens and handles async generator streams."""
    async def async_token_generator():
        for t in ["AI ", "safety ", "is ", "paramount."]:
            await asyncio.sleep(0.001)
            yield t
            
    guard = StreamingOutputGuard()
    collected = []
    
    async for token in guard.wrap_async_stream(async_token_generator()):
        collected.append(token)
        
    assert "".join(collected) == "AI safety is paramount."
