"""
Session - Request context for security evaluation.

v1.0: Extended with agentic orchestration context (agent IDs, tool tracking,
delegation depth, step counts, and tenant multi-tenancy).
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import hashlib


@dataclass
class ChatTurn:
    """A single conversation turn."""
    role: str  # "user" or "assistant"
    content: str
    timestamp: float


@dataclass
class ToolCallRecord:
    """Record of a tool call made during an agent session."""
    tool_name: str
    arguments: Dict[str, Any]
    timestamp: float = field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    result: Optional[Any] = None
    blocked: bool = False


@dataclass
class Session:
    """
    Encapsulates all request context needed for security evaluation.
    
    This is the main input alongside the prompt for Guard.inspect().
    """
    
    # User identification
    user_id: str
    
    # Network signals
    ip_address: str = "0.0.0.0"
    user_agent: str = ""
    tls_fingerprint: str = "unknown"
    
    # Conversation history (for context plane)
    history: List[ChatTurn] = field(default_factory=list)
    
    # Token tracking (for economics plane)
    tokens_used_session: int = 0
    session_start_time: float = field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ==========================================
    # v1.0: Agentic & Multi-Tenancy Context
    # ==========================================
    tenant_id: Optional[str] = None
    role: Optional[str] = None
    agent_id: Optional[str] = None
    allowed_tools: Optional[List[str]] = None
    tool_calls: List[ToolCallRecord] = field(default_factory=list)
    current_step: int = 0
    max_steps: int = 50
    delegation_depth: int = 0
    max_delegation_depth: int = 5
    
    @classmethod
    def from_request(
        cls,
        request: Any,
        user_id: str,
        history: Optional[List[Dict]] = None,
        tenant_id: Optional[str] = None,
        role: Optional[str] = None,
    ) -> "Session":
        """
        Factory to create Session from a web framework request object.
        
        Works with FastAPI, Flask, Django, or any framework with standard attributes.
        """
        # Extract IP (handle proxies)
        ip = "0.0.0.0"
        if hasattr(request, "client") and request.client:
            ip = getattr(request.client, "host", "0.0.0.0")
        elif hasattr(request, "headers"):
            ip = request.headers.get("X-Forwarded-For", "0.0.0.0").split(",")[0].strip()
        
        # Extract User-Agent
        user_agent = ""
        if hasattr(request, "headers"):
            user_agent = request.headers.get("User-Agent", "")
        
        # Convert history dicts to ChatTurn objects
        chat_history = []
        if history:
            for turn in history:
                chat_history.append(ChatTurn(
                    role=turn.get("role", "user"),
                    content=turn.get("content", ""),
                    timestamp=turn.get("timestamp", datetime.now(timezone.utc).timestamp())
                ))
        
        return cls(
            user_id=user_id,
            ip_address=ip,
            user_agent=user_agent,
            history=chat_history,
            tenant_id=tenant_id,
            role=role,
        )
    
    @classmethod
    def create(cls, user_id: str, **kwargs) -> "Session":
        """Simple factory for manual session creation."""
        return cls(user_id=user_id, **kwargs)

    @classmethod
    def create_agent_session(
        cls,
        agent_id: str,
        user_id: str = "agent_system",
        allowed_tools: Optional[List[str]] = None,
        tenant_id: Optional[str] = None,
        role: Optional[str] = "agent",
        max_steps: int = 50,
        delegation_depth: int = 0,
        **kwargs,
    ) -> "Session":
        """Factory for agentic orchestration sessions."""
        return cls(
            user_id=user_id,
            agent_id=agent_id,
            allowed_tools=allowed_tools,
            tenant_id=tenant_id,
            role=role,
            max_steps=max_steps,
            delegation_depth=delegation_depth,
            **kwargs,
        )

    def is_agent_session(self) -> bool:
        """Check if this session represents an autonomous agent."""
        return self.agent_id is not None
    
    def get_fingerprint(self) -> str:
        """Generate a cryptographic fingerprint of the session."""
        raw = f"{self.ip_address}|{self.user_agent}|{self.tls_fingerprint}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
    
    def add_turn(self, role: str, content: str) -> None:
        """Add a conversation turn to history."""
        self.history.append(ChatTurn(
            role=role,
            content=content,
            timestamp=datetime.now(timezone.utc).timestamp()
        ))
    
    def get_full_context(self) -> str:
        """Concatenate all history for context analysis."""
        return " ".join(turn.content for turn in self.history)
    
    def increment_tokens(self, count: int) -> None:
        """Track token usage for economics plane."""
        self.tokens_used_session += count
    
    def get_burn_rate(self) -> float:
        """Calculate tokens per second for this session."""
        elapsed = datetime.now(timezone.utc).timestamp() - self.session_start_time
        if elapsed < 1.0:
            # During the first second of a session, use 1.0s window minimum
            # to avoid false token/sec spikes on instant single-turn prompts
            return float(self.tokens_used_session)
        return self.tokens_used_session / elapsed

    def record_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        result: Optional[Any] = None,
        blocked: bool = False,
    ) -> ToolCallRecord:
        """Record a tool call during agent execution."""
        record = ToolCallRecord(
            tool_name=tool_name,
            arguments=arguments,
            result=result,
            blocked=blocked,
        )
        self.tool_calls.append(record)
        return record

    def increment_step(self) -> int:
        """Advance agent execution step count."""
        self.current_step += 1
        return self.current_step

    def has_exceeded_steps(self) -> bool:
        """Check if agent exceeded maximum allowed iteration steps."""
        return self.current_step >= self.max_steps
