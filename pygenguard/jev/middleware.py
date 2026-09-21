"""
FastAPI & ASGI Gateway Middleware for Jev Tokenless Pre-Execution Blocking.

Intercepts requests at the network gateway layer to block malicious inputs in <5ms
before consuming LLM inference tokens. Optionally enqueues outputs to Jev Post-Execution
KB filtering for continuous dataset cleansing.
"""

import json
from typing import Optional, List, Callable, Dict, Any, Union

from pygenguard.jev.engine import DualLayerGovernanceEngine
from pygenguard.jev.schemas import JevClientConfig


class JevGatewayMiddleware:
    """
    High-speed ASGI Middleware enforcing Jev Pre-Execution Blocking at gateway layer.
    
    Usage with FastAPI:
    ```python
    from fastapi import FastAPI
    from pygenguard.jev import JevGatewayMiddleware, DualLayerGovernanceEngine
    
    app = FastAPI()
    jev_engine = DualLayerGovernanceEngine()
    
    app.add_middleware(
        JevGatewayMiddleware,
        engine=jev_engine,
        protected_paths=["/chat", "/v1/chat/completions"],
        auto_kb_cleansing=True
    )
    ```
    """

    def __init__(
        self,
        app: Any,
        engine: Optional[DualLayerGovernanceEngine] = None,
        protected_paths: Optional[List[str]] = None,
        prompt_extractor: Optional[Callable[[Dict[str, Any]], Optional[str]]] = None,
        auto_kb_cleansing: bool = False,
    ):
        self.app = app
        self.engine = engine or DualLayerGovernanceEngine()
        self.protected_paths = set(protected_paths or ["/chat", "/v1/chat/completions", "/api/chat", "/v1/completions"])
        self.prompt_extractor = prompt_extractor or self._default_extract_prompt
        self.auto_kb_cleansing = auto_kb_cleansing

    def _default_extract_prompt(self, body: Dict[str, Any]) -> Optional[str]:
        """Extract prompt from common GenAI request payload structures."""
        if not isinstance(body, dict):
            return None
        if "prompt" in body and isinstance(body["prompt"], str):
            return body["prompt"]
        if "query" in body and isinstance(body["query"], str):
            return body["query"]
        if "message" in body and isinstance(body["message"], str):
            return body["message"]
        if "messages" in body and isinstance(body["messages"], list):
            for msg in reversed(body["messages"]):
                if isinstance(msg, dict) and msg.get("role") == "user":
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        return content
                    elif isinstance(content, list):
                        parts = [p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text"]
                        return " ".join(parts)
        return None

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path not in self.protected_paths:
            await self.app(scope, receive, send)
            return

        # Receive body
        body_chunks = []
        more_body = True
        while more_body:
            message = await receive()
            body_chunks.append(message.get("body", b""))
            more_body = message.get("more_body", False)

        body_bytes = b"".join(body_chunks)

        # Parse JSON
        prompt: Optional[str] = None
        try:
            body_json = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            prompt = self.prompt_extractor(body_json)
        except Exception:
            body_json = {}

        if prompt:
            # Layer 1: Tokenless Pre-Execution Blocking via Jev (<5ms target)
            decision = await self.engine.apre_execution_block(prompt)
            if not decision.allowed:
                response_payload = {
                    "error": "SecurityException",
                    "status": "blocked",
                    "governance": "Jev System One Pre-Execution Blocking",
                    "safe_response": decision.safe_response,
                    "rationale": decision.rationale,
                    "trace_id": decision.trace_id,
                }
                body_resp = json.dumps(response_payload).encode("utf-8")
                await send({
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body_resp)).encode("latin-1")),
                        (b"x-pygenguard-blocked", b"true"),
                        (b"x-pygenguard-gateway", b"jev-system-one"),
                    ],
                })
                await send({
                    "type": "http.response.body",
                    "body": body_resp,
                })
                return

        # Request allowed: pass to application
        async def custom_receive() -> Dict[str, Any]:
            return {"type": "http.request", "body": body_bytes, "more_body": False}

        await self.app(scope, custom_receive, send)
