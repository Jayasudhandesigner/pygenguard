"""
FastAPI & ASGI Middleware for PyGenGuard.

Provides drop-in security interception for FastAPI, Starlette, and ASGI applications.
"""

import json
from typing import Optional, List, Callable, Dict, Any, Union
from pygenguard.session import Session
from pygenguard.async_guard.guard import AsyncGuard
from pygenguard.decision import Decision


class PyGenGuardMiddleware:
    """
    ASGI Middleware that intercepts chat/LLM endpoints to enforce PyGenGuard security rules.
    
    Usage with FastAPI:
    ```python
    from fastapi import FastAPI
    from pygenguard import AsyncGuard
    from pygenguard.integrations.fastapi import PyGenGuardMiddleware
    
    app = FastAPI()
    guard = AsyncGuard(mode="strict")
    
    app.add_middleware(
        PyGenGuardMiddleware,
        guard=guard,
        protected_paths=["/chat", "/v1/chat/completions"],
        user_id_header="X-User-ID"
    )
    ```
    """
    
    def __init__(
        self,
        app: Any,
        guard: Optional[AsyncGuard] = None,
        protected_paths: Optional[List[str]] = None,
        user_id_header: str = "x-user-id",
        user_id_extractor: Optional[Callable[[Dict[str, Any]], str]] = None,
        prompt_extractor: Optional[Callable[[Dict[str, Any]], Optional[str]]] = None,
        inspect_output: bool = False
    ):
        self.app = app
        self.guard = guard or AsyncGuard(mode="balanced")
        self.protected_paths = set(protected_paths or ["/chat", "/v1/chat/completions", "/api/chat"])
        self.user_id_header = user_id_header.lower()
        self.user_id_extractor = user_id_extractor
        self.prompt_extractor = prompt_extractor or self._default_extract_prompt
        self.inspect_output = inspect_output
    
    def _default_extract_prompt(self, body: Dict[str, Any]) -> Optional[str]:
        """Extract prompt from common GenAI request payload structures."""
        if not isinstance(body, dict):
            return None
            
        # Direct prompt / query
        if "prompt" in body and isinstance(body["prompt"], str):
            return body["prompt"]
        if "query" in body and isinstance(body["query"], str):
            return body["query"]
        if "message" in body and isinstance(body["message"], str):
            return body["message"]
            
        # OpenAI chat completions messages list: [{"role": "user", "content": "..."}]
        if "messages" in body and isinstance(body["messages"], list):
            for msg in reversed(body["messages"]):
                if isinstance(msg, dict) and msg.get("role") == "user":
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        return content
                    elif isinstance(content, list):
                        # Multi-part content
                        parts = [p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text"]
                        return " ".join(parts)
        return None
    
    def _extract_ip(self, headers: Dict[str, str], client_host: Optional[str]) -> str:
        """Extract client IP handling load balancers and CDNs."""
        for header in ["cf-connecting-ip", "x-forwarded-for", "x-real-ip"]:
            if header in headers:
                val = headers[header].split(",")[0].strip()
                if val:
                    return val
        return client_host or "0.0.0.0"
    
    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        """ASGI handler."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
            
        path = scope.get("path", "")
        # Check if path is protected
        is_protected = any(path == p or path.startswith(p.rstrip("/") + "/") for p in self.protected_paths)
        if not is_protected:
            await self.app(scope, receive, send)
            return
            
        # Parse headers
        headers: Dict[str, str] = {}
        for k, v in scope.get("headers", []):
            headers[k.decode("latin1").lower()] = v.decode("latin1")
            
        client = scope.get("client")
        client_host = client[0] if client else None
        ip_address = self._extract_ip(headers, client_host)
        user_agent = headers.get("user-agent", "")
        
        # Determine User ID
        user_id = "anonymous"
        if self.user_id_extractor:
            try:
                user_id = self.user_id_extractor(headers)
            except Exception:
                user_id = "anonymous"
        elif self.user_id_header in headers:
            user_id = headers[self.user_id_header]
            
        # Read the request body
        body_bytes = b""
        more_body = True
        
        # Buffer incoming body chunks
        while more_body:
            message = await receive()
            body_bytes += message.get("body", b"")
            more_body = message.get("more_body", False)
            
        # Create a receiver to replay the body to downstream app
        body_sent = False
        async def replay_receive():
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": body_bytes, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}
            
        # Parse body and inspect
        prompt_text = None
        if body_bytes:
            try:
                body_json = json.loads(body_bytes.decode("utf-8"))
                prompt_text = self.prompt_extractor(body_json)
            except Exception:
                prompt_text = None
                
        if prompt_text:
            session = Session(
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            decision = await self.guard.inspect(prompt_text, session)
            
            if not decision.allowed:
                # Intercept and return 403 Forbidden
                error_body = json.dumps({
                    "error": {
                        "message": decision.safe_response,
                        "type": "security_violation",
                        "code": "pygenguard_blocked",
                        "trace_id": decision.trace_id,
                        "rationale": decision.rationale
                    }
                }).encode("utf-8")
                
                response_headers = [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(error_body)).encode("ascii")),
                    (b"x-genguard-decision", decision.action.encode("ascii")),
                    (b"x-genguard-trace-id", decision.trace_id.encode("ascii")),
                    (b"x-genguard-risk", str(round(decision.combined_risk_score, 2)).encode("ascii")),
                ]
                
                await send({
                    "type": "http.response.start",
                    "status": 403,
                    "headers": response_headers
                })
                await send({
                    "type": "http.response.body",
                    "body": error_body,
                    "more_body": False
                })
                return
                
            # Store decision in scope state
            if "state" not in scope:
                scope["state"] = {}
            scope["state"]["pygenguard_decision"] = decision
            scope["state"]["pygenguard_session"] = session
            
        # Forward request downstream with replayed body
        await self.app(scope, replay_receive, send)
