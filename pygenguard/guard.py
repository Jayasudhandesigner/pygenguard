"""
Guard - The single entry point for PyGenGuard security evaluation.

v1.0: Enhanced with Policy Engine, Circuit Breakers, Rate Limiting,
Shadow Mode, Content Safety, and Agentic Guardrails integration.
"""

import uuid
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Optional, Literal, List, Any, Set, Tuple
from dataclasses import dataclass

from pygenguard.session import Session
from pygenguard.decision import Decision, PlaneResult
from pygenguard.cache import SecurityCache
from pygenguard.batch import BatchScanner, BatchScanResult
from pygenguard.planes.identity import IdentityPlane
from pygenguard.planes.intent import IntentPlane
from pygenguard.planes.context import ContextPlane
from pygenguard.planes.economics import EconomicsPlane
from pygenguard.planes.compliance import CompliancePlane
from pygenguard.planes.output import OutputPlane
from pygenguard.planes.phishing import PhishingDetectorPlane
from pygenguard.planes.content_safety import ContentSafetyPlane
from pygenguard.planes.tool_use import ToolUsePlane
from pygenguard.planes.chain_of_thought import ChainOfThoughtGuard
from pygenguard.planes.memory import AgentMemoryGuard
from pygenguard.planes.grounding import GroundingPlane
from pygenguard.planes.consensus import ConsensusGate
from pygenguard.planes.extraction import ModelExtractionGuard
from pygenguard.rag import RAGRetrievalGuard
from pygenguard.canary import CanaryManager
from pygenguard.audit.logger import AuditLogger
from pygenguard.policy import Policy, GuardMode, FailAction, PolicyWatcher
from pygenguard.resilience import CircuitBreakerRegistry, CircuitBreakerConfig
from pygenguard.rate_limiter import RateLimiter
from pygenguard.rbac import RBACPolicy
from pygenguard.utils.pii import PIIMaskingEngine
from pygenguard.budget import BudgetManager
from pygenguard.routing import ModelRouter, RouteDecision
from pygenguard.sanitizer import PromptSanitizer
from pygenguard.adaptive import AdaptiveRuleLearner, AdaptiveRule
from pygenguard.utils.decoders import decode_and_inspect, adecode_and_inspect
from pygenguard.planes.pricing import PricingPlane
from pygenguard.planes.contact import ContactPlane
from pygenguard.planes.confidential import ConfidentialPlane
from pygenguard.byok.judge import BYOKConfig, JudgeVerdict, BYOKLLMJudge
from pygenguard.hybrid import HybridGuardEngine, HybridDecision
from pygenguard.saas.tenant import TenantConfig, TenantManager
from pygenguard.saas.cluster import ClusterManager, ClusterNodeInfo
from pygenguard.jev.engine import DualLayerGovernanceEngine
from pygenguard.jev.schemas import JevClientConfig


@dataclass
class GuardConfig:
    """Configuration for Guard behavior."""

    # Trust thresholds for identity plane
    trust_thresholds: Dict[str, int] = None

    # Intent detection sensitivity
    intent_sensitivity: float = 0.5

    # Economics thresholds
    max_burn_rate: float = 1000.0  # tokens/sec

    # Audit settings
    audit_enabled: bool = True

    # Output guard settings
    output_guard_enabled: bool = True
    mask_output_pii: bool = True
    canary_tokens: Optional[List[str]] = None

    # Phishing & Training Integrity settings
    block_phishing: bool = True

    # Content safety
    content_safety_enabled: bool = True

    def __post_init__(self):
        if self.trust_thresholds is None:
            self.trust_thresholds = {"full": 70, "degraded": 40}


class Guard:
    """
    The single entry point for PyGenGuard security evaluation.

    v1.0 supports:
    - Policy-as-Code configuration
    - Circuit breaker fault tolerance
    - Rate limiting per user/tenant
    - Shadow/canary mode (log-only)
    - Content safety plane
    - Agentic tool-use and chain-of-thought guardrails
    - RBAC-based plane bypassing

    Usage:
        # Simple (backward compatible)
        guard = Guard(mode="strict")

        # With policy engine
        policy = Policy.from_yaml("policy.yaml")
        guard = Guard(policy=policy)

        # Shadow mode (log-only, never blocks)
        guard = Guard(mode="shadow")

        # With RBAC
        guard = Guard(mode="strict", rbac=rbac_policy)

        # Input inspection
        decision = guard.inspect(prompt, session)
        if not decision.allowed:
            return decision.safe_response

        model_response = run_model(prompt)

        # Output inspection
        output_decision = guard.inspect_output(model_response, prompt=prompt)
        return output_decision.sanitized_response or model_response
    """

    def __init__(
        self,
        mode: Literal["strict", "balanced", "permissive", "shadow"] = "balanced",
        trust_thresholds: Optional[Dict[str, int]] = None,
        intent_sensitivity: Optional[float] = None,
        max_burn_rate: Optional[float] = None,
        audit_enabled: bool = True,
        canary_tokens: Optional[List[str]] = None,
        policy: Optional[Policy] = None,
        rbac: Optional[RBACPolicy] = None,
        rate_limiter: Optional[RateLimiter] = None,
        jev_engine: Optional[DualLayerGovernanceEngine] = None,
    ):
        """
        Initialize Guard with configuration.

        Args:
            mode: Security mode preset
            trust_thresholds: Custom identity plane thresholds
            intent_sensitivity: Custom intent plane sensitivity
            max_burn_rate: Max tokens/sec before economics throttling
            audit_enabled: Whether to log decisions
            canary_tokens: Custom canary tokens for output leak detection
            policy: Full policy object (overrides mode-based config)
            rbac: Role-based access control policy
            rate_limiter: Custom rate limiter instance
        """
        # Policy takes precedence over mode-based config
        if policy:
            self._policy = policy
        else:
            self._policy = Policy.preset(mode)

        self._shadow_mode = self._policy.mode == GuardMode.SHADOW
        self._rbac = rbac

        # Build GuardConfig from policy or mode
        config = self._build_config(mode, trust_thresholds, intent_sensitivity, max_burn_rate, audit_enabled, canary_tokens)
        self.config = config

        # Initialize core planes
        self._identity_plane = IdentityPlane(config.trust_thresholds)
        self._intent_plane = IntentPlane(config.intent_sensitivity)
        self._phishing_plane = PhishingDetectorPlane(block_on_phishing_urls=True, block_on_lures=True)
        self._context_plane = ContextPlane()
        self._economics_plane = EconomicsPlane(config.max_burn_rate)
        self._compliance_plane = CompliancePlane()
        self._output_plane = OutputPlane(
            block_on_secrets=True,
            block_on_dangerous_code=True,
            block_on_system_leak=True,
            mask_pii_enabled=config.mask_output_pii,
            custom_canary_tokens=config.canary_tokens,
        )

        # v1.0: Content Safety Plane
        cs_policy = self._policy.content_safety
        self._content_safety_plane = ContentSafetyPlane(
            block_categories=cs_policy.block_categories if cs_policy.enabled else [],
            severity_threshold=cs_policy.severity_threshold,
        )
        self._content_safety_enabled = cs_policy.enabled

        # v1.0: Agentic Guardrails
        self._tool_use_plane = ToolUsePlane()
        self._cot_guard = ChainOfThoughtGuard()

        # v1.0: Circuit Breaker Registry
        self._circuit_breakers = CircuitBreakerRegistry(
            default_config=CircuitBreakerConfig(
                failure_threshold=5,
                recovery_timeout_sec=30.0,
                fail_open=False,
            )
        )

        # v1.0: Rate Limiter
        rl = self._policy.rate_limits
        self._rate_limiter = rate_limiter or (
            RateLimiter(
                requests_per_minute=rl.requests_per_minute,
                requests_per_hour=rl.requests_per_hour,
                tokens_per_minute=rl.tokens_per_minute,
                tokens_per_hour=rl.tokens_per_hour,
                burst_multiplier=rl.burst_allowance,
            ) if rl.enabled else None
        )

        # Audit logger
        audit_policy = self._policy.audit
        self._audit = AuditLogger(
            enabled=config.audit_enabled,
            log_destination=audit_policy.log_destination,
            log_file=audit_policy.log_file_path,
            include_prompt_text=audit_policy.include_prompt_text,
            include_plane_details=audit_policy.include_plane_details,
        )

        # Performance: Security Cache & Batch Scanner
        self._cache = SecurityCache()
        self._batch_scanner = BatchScanner(self)

        # RAG, Memory, and Canary security
        self._rag_guard = RAGRetrievalGuard(self)
        self._memory_guard = AgentMemoryGuard()
        self._canary_mgr = CanaryManager()

        # Grounding, Consensus, and Extraction planes
        self._grounding_plane = GroundingPlane()
        self._consensus_gate = ConsensusGate()
        self._extraction_guard = ModelExtractionGuard()

        # Privacy, Budget & Routing engines
        self._pii_engine = PIIMaskingEngine()
        self._budget_mgr = BudgetManager()
        self._router = ModelRouter()

        # Sanitization, Adaptive Rules & Dynamic Defense
        self._sanitizer = PromptSanitizer()
        self._adaptive_learner = AdaptiveRuleLearner()
        self._policy_watcher: Optional[PolicyWatcher] = None

        # Enterprise Commercial & Data Security Planes
        self._pricing_plane = PricingPlane()
        self._contact_plane = ContactPlane()
        self._confidential_plane = ConfidentialPlane()

        # BYOK Hybrid Engine & SaaS Clustered Infrastructure
        self._hybrid_engine = HybridGuardEngine(self)
        self._tenant_mgr = TenantManager()
        self._cluster_mgr = ClusterManager()

        # Jev Tokenless System One & Dual-Layer Governance Engine
        self._jev_engine = jev_engine or DualLayerGovernanceEngine()

    def _build_config(self, mode, trust_thresholds, intent_sensitivity, max_burn_rate, audit_enabled, canary_tokens):
        """Build GuardConfig from mode or explicit overrides."""
        config = self._get_mode_config(mode)
        if trust_thresholds:
            config.trust_thresholds = trust_thresholds
        if intent_sensitivity is not None:
            config.intent_sensitivity = intent_sensitivity
        if max_burn_rate is not None:
            config.max_burn_rate = max_burn_rate
        config.audit_enabled = audit_enabled
        if canary_tokens:
            config.canary_tokens = canary_tokens
        return config

    def _get_mode_config(self, mode: str) -> GuardConfig:
        """Get preset configuration for a mode."""
        if mode == "strict":
            return GuardConfig(
                trust_thresholds={"full": 80, "degraded": 50},
                intent_sensitivity=0.3,
                max_burn_rate=500.0,
            )
        elif mode == "permissive":
            return GuardConfig(
                trust_thresholds={"full": 50, "degraded": 20},
                intent_sensitivity=0.7,
                max_burn_rate=2000.0,
            )
        else:  # balanced / shadow
            return GuardConfig()

    def _should_skip_plane(self, plane_name: str, user_id: Optional[str] = None) -> bool:
        """Check if a plane should be skipped (disabled or RBAC bypass)."""
        if not self._policy.is_plane_enabled(plane_name):
            return True
        if user_id and self._rbac and self._rbac.should_bypass_plane(user_id, plane_name):
            return True
        return False

    def _process_plane_result(
        self,
        plane_name: str,
        result: PlaneResult,
        trace_id: str,
        plane_results: Dict[str, PlaneResult],
        block_response: str,
    ) -> Optional[Decision]:
        """
        Process a plane result through the policy engine.
        Returns a Decision if the request should be blocked/degraded, or None to continue.
        """
        plane_results[plane_name] = result

        if result.passed:
            return None

        # In shadow mode, log but don't block
        effective_action = self._policy.get_effective_action(plane_name)

        if effective_action == FailAction.LOG_ONLY:
            # Shadow mode — log the would-have-blocked but continue
            return None

        if effective_action == FailAction.DEGRADE:
            decision = Decision.create_degrade(
                trace_id=trace_id,
                plane_results=plane_results,
                rationale=f"{plane_name} check flagged: {result.details}",
            )
            self._audit.log(decision)
            return decision

        # Default: BLOCK
        decision = Decision.create_block(
            trace_id=trace_id,
            plane_results=plane_results,
            rationale=f"{plane_name} check failed: {result.details}",
            safe_response=block_response,
        )
        self._audit.log(decision)
        return decision

    def inspect(self, prompt: str, session: Session) -> Decision:
        """
        Evaluate a prompt against all input security planes.

        Args:
            prompt: The user's input text
            session: Session context (identity, history, etc.)

        Returns:
            Decision object with allowed/blocked status and full audit trail
        """
        trace_id = str(uuid.uuid4())
        plane_results: Dict[str, PlaneResult] = {}
        user_id = getattr(session, "user_id", None)

        # ========================================
        # PRE-CHECK: RATE LIMITING
        # ========================================
        if self._rate_limiter and user_id:
            rl_result = self._rate_limiter.check_request(user_id, token_count=len(prompt))
            plane_results["rate_limiter"] = rl_result
            if not rl_result.passed:
                decision = Decision.create_degrade(
                    trace_id=trace_id,
                    plane_results=plane_results,
                    rationale=f"Rate limit exceeded: {rl_result.details}",
                )
                self._audit.log(decision)
                return decision

        # ========================================
        # PLANE 1: IDENTITY
        # ========================================
        if not self._should_skip_plane("identity", user_id):
            cb = self._circuit_breakers.get_or_create("identity")
            identity_result = cb.call(
                self._identity_plane.evaluate, session,
                timeout_ms=self._policy.get_plane_policy("identity").timeout_ms,
            )
            block = self._process_plane_result(
                "identity", identity_result, trace_id, plane_results,
                "Session verification required.",
            )
            if block:
                return block

        # ========================================
        # PLANE 2: INTENT (Cognitive Threat Detection)
        # ========================================
        if not self._should_skip_plane("intent", user_id):
            cb = self._circuit_breakers.get_or_create("intent")
            intent_result = cb.call(
                self._intent_plane.evaluate, prompt,
                timeout_ms=self._policy.get_plane_policy("intent").timeout_ms,
            )
            block = self._process_plane_result(
                "intent", intent_result, trace_id, plane_results,
                "I can't help with that request.",
            )
            if block:
                return block

        # ========================================
        # PLANE 3: CONTENT SAFETY
        # ========================================
        if self._content_safety_enabled and not self._should_skip_plane("content_safety", user_id):
            cb = self._circuit_breakers.get_or_create("content_safety")
            safety_result = cb.call(
                self._content_safety_plane.evaluate, prompt,
                timeout_ms=self._policy.get_plane_policy("content_safety").timeout_ms,
            )
            block = self._process_plane_result(
                "content_safety", safety_result, trace_id, plane_results,
                "This content violates safety policies.",
            )
            if block:
                return block

        # ========================================
        # PLANE 4: PHISHING & DATA INTEGRITY
        # ========================================
        if not self._should_skip_plane("phishing", user_id):
            cb = self._circuit_breakers.get_or_create("phishing")
            phishing_result = cb.call(
                self._phishing_plane.evaluate, prompt,
                timeout_ms=self._policy.get_plane_policy("phishing").timeout_ms,
            )
            block = self._process_plane_result(
                "phishing", phishing_result, trace_id, plane_results,
                "Request contains suspicious phishing or unverified links.",
            )
            if block:
                return block

        # ========================================
        # PLANE 5: CONTEXT
        # ========================================
        if not self._should_skip_plane("context", user_id):
            full_context = session.get_full_context() + " " + prompt
            cb = self._circuit_breakers.get_or_create("context")
            context_result = cb.call(
                self._context_plane.evaluate, full_context, session.history,
                timeout_ms=self._policy.get_plane_policy("context").timeout_ms,
            )
            block = self._process_plane_result(
                "context", context_result, trace_id, plane_results,
                "This conversation cannot continue.",
            )
            if block:
                return block

        # ========================================
        # PLANE 6: ECONOMICS
        # ========================================
        if not self._should_skip_plane("economics", user_id):
            session.increment_tokens(len(prompt))
            cb = self._circuit_breakers.get_or_create("economics")
            economics_result = cb.call(
                self._economics_plane.evaluate, session,
                timeout_ms=self._policy.get_plane_policy("economics").timeout_ms,
            )
            plane_results["economics"] = economics_result
            if not economics_result.passed:
                decision = Decision.create_degrade(
                    trace_id=trace_id,
                    plane_results=plane_results,
                    rationale=f"Rate limiting applied: {economics_result.details}",
                )
                self._audit.log(decision)
                if not self._shadow_mode:
                    return decision

        # ========================================
        # PLANE 7: COMPLIANCE (always runs, for audit)
        # ========================================
        if not self._should_skip_plane("compliance", user_id):
            compliance_result = self._compliance_plane.evaluate(prompt)
            plane_results["compliance"] = compliance_result

        # ========================================
        # PLANE 8: PRICING & COMMERCIAL LEAKS
        # ========================================
        if not self._should_skip_plane("pricing", user_id):
            pricing_result = self._pricing_plane.evaluate(prompt)
            plane_results["pricing"] = pricing_result
            if not pricing_result.passed:
                block = self._process_plane_result(
                    "pricing", pricing_result, trace_id, plane_results,
                    "Commercial pricing or rate card information blocked by security policy.",
                )
                if block:
                    self._cluster_mgr.record_inspection(allowed=False)
                    return block

        # ========================================
        # PLANE 9: CONTACT & CRM DISCLOSURE
        # ========================================
        if not self._should_skip_plane("contact", user_id):
            contact_result = self._contact_plane.evaluate(prompt)
            plane_results["contact"] = contact_result
            if not contact_result.passed:
                block = self._process_plane_result(
                    "contact", contact_result, trace_id, plane_results,
                    "Direct contact information blocked by security policy.",
                )
                if block:
                    self._cluster_mgr.record_inspection(allowed=False)
                    return block

        # ========================================
        # PLANE 10: CONFIDENTIAL ASSETS & TRADE SECRETS
        # ========================================
        if not self._should_skip_plane("confidential", user_id):
            conf_result = self._confidential_plane.evaluate(prompt)
            plane_results["confidential"] = conf_result
            if not conf_result.passed:
                block = self._process_plane_result(
                    "confidential", conf_result, trace_id, plane_results,
                    "Confidential corporate assets or trade secret data blocked by security policy.",
                )
                if block:
                    self._cluster_mgr.record_inspection(allowed=False)
                    return block

        # ========================================
        # FINAL: ALL PASSED
        # ========================================
        decision = Decision.create_allow(
            trace_id=trace_id,
            plane_results=plane_results,
            rationale="All security planes passed.",
        )
        self._audit.log(decision)
        self._cluster_mgr.record_inspection(allowed=True)
        return decision

    def cached_inspect(self, prompt: str, session: Session, ttl: Optional[float] = None) -> Decision:
        """
        Inspect with sub-millisecond LRU/TTL caching for repeated queries.
        Returns cached Decision in ~0.01ms on cache hit.
        """
        user_id = getattr(session, "user_id", None)
        cached = self._cache.get(prompt, user_id=user_id)
        if cached is not None:
            return cached
        decision = self.inspect(prompt, session)
        self._cache.set(prompt, decision, user_id=user_id, custom_ttl=ttl)
        return decision

    async def acached_inspect(self, prompt: str, session: Session, ttl: Optional[float] = None) -> Decision:
        """Asynchronous cached inspection."""
        return self.cached_inspect(prompt, session, ttl=ttl)

    def inspect_parallel(self, prompt: str, session: Session, max_workers: int = 5) -> Decision:
        """
        Execute independent planes (Identity, Intent, Content Safety, Phishing) in parallel
        threads with early-exit on first block, minimizing pre-inference latency.
        """
        trace_id = str(uuid.uuid4())
        plane_results: Dict[str, PlaneResult] = {}
        user_id = getattr(session, "user_id", None)

        # Pre-check: rate limiting
        if self._rate_limiter and user_id:
            rl_result = self._rate_limiter.check_request(user_id, token_count=len(prompt))
            plane_results["rate_limiter"] = rl_result
            if not rl_result.passed:
                decision = Decision.create_degrade(
                    trace_id=trace_id,
                    plane_results=plane_results,
                    rationale=f"Rate limit exceeded: {rl_result.details}",
                )
                self._audit.log(decision)
                return decision

        tasks = {}
        if not self._should_skip_plane("identity", user_id):
            tasks["identity"] = lambda: self._circuit_breakers.get_or_create("identity").call(
                self._identity_plane.evaluate, session,
                timeout_ms=self._policy.get_plane_policy("identity").timeout_ms,
            )
        if not self._should_skip_plane("intent", user_id):
            tasks["intent"] = lambda: self._circuit_breakers.get_or_create("intent").call(
                self._intent_plane.evaluate, prompt,
                timeout_ms=self._policy.get_plane_policy("intent").timeout_ms,
            )
        if self._content_safety_enabled and not self._should_skip_plane("content_safety", user_id):
            tasks["content_safety"] = lambda: self._circuit_breakers.get_or_create("content_safety").call(
                self._content_safety_plane.evaluate, prompt,
                timeout_ms=self._policy.get_plane_policy("content_safety").timeout_ms,
            )
        if not self._should_skip_plane("phishing", user_id):
            tasks["phishing"] = lambda: self._circuit_breakers.get_or_create("phishing").call(
                self._phishing_plane.evaluate, prompt,
                timeout_ms=self._policy.get_plane_policy("phishing").timeout_ms,
            )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_plane = {executor.submit(fn): name for name, fn in tasks.items()}
            first_block_decision = None
            for future in as_completed(future_to_plane):
                plane_name = future_to_plane[future]
                res = future.result()
                plane_results[plane_name] = res
                if not res.passed and not first_block_decision and not self._shadow_mode:
                    first_block_decision = Decision.create_block(
                        trace_id=trace_id,
                        plane_results=plane_results,
                        rationale=f"{plane_name} check failed: {res.details}",
                    )

            if first_block_decision:
                self._audit.log(first_block_decision)
                return first_block_decision

        # Context plane (needs history)
        if not self._should_skip_plane("context", user_id):
            full_context = session.get_full_context() + " " + prompt
            cb = self._circuit_breakers.get_or_create("context")
            context_result = cb.call(
                self._context_plane.evaluate, full_context, session.history,
                timeout_ms=self._policy.get_plane_policy("context").timeout_ms,
            )
            block = self._process_plane_result("context", context_result, trace_id, plane_results, "This conversation cannot continue.")
            if block:
                return block

        # Economics plane
        if not self._should_skip_plane("economics", user_id):
            session.increment_tokens(len(prompt))
            cb = self._circuit_breakers.get_or_create("economics")
            econ_res = cb.call(
                self._economics_plane.evaluate, session,
                timeout_ms=self._policy.get_plane_policy("economics").timeout_ms,
            )
            plane_results["economics"] = econ_res
            if not econ_res.passed and not self._shadow_mode:
                decision = Decision.create_degrade(trace_id=trace_id, plane_results=plane_results, rationale=f"Rate limiting applied: {econ_res.details}")
                self._audit.log(decision)
                return decision

        # Compliance plane
        if not self._should_skip_plane("compliance", user_id):
            plane_results["compliance"] = self._compliance_plane.evaluate(prompt)

        decision = Decision.create_allow(trace_id=trace_id, plane_results=plane_results, rationale="All security planes passed.")
        self._audit.log(decision)
        return decision

    async def ainspect_parallel(self, prompt: str, session: Session) -> Decision:
        """Asynchronously execute parallel inspection without blocking event loop."""
        return await asyncio.to_thread(self.inspect_parallel, prompt, session)

    def scan_batch(self, prompts: List[str], session: Optional[Session] = None, max_workers: int = 8) -> BatchScanResult:
        """Batch scan prompts synchronously using worker thread pool."""
        return self._batch_scanner.scan_batch(prompts, session, max_workers=max_workers)

    async def ascan_batch(self, prompts: List[str], session: Optional[Session] = None, concurrency: int = 50) -> BatchScanResult:
        """Batch scan prompts asynchronously with bounded concurrency."""
        return await self._batch_scanner.ascan_batch(prompts, session, concurrency=concurrency)

    def guard_tool(self, name: Optional[str] = None, **kwargs):
        """Decorator to guard a synchronous agent tool function."""
        from pygenguard.tools import guard_tool as _guard_tool
        return _guard_tool(self, name=name, **kwargs)

    def aguard_tool(self, name: Optional[str] = None, **kwargs):
        """Decorator to guard an asynchronous agent tool function."""
        from pygenguard.tools import aguard_tool as _aguard_tool
        return _aguard_tool(self, name=name, **kwargs)

    def intercept_stream(self, stream, prompt: Optional[str] = None, system_prompt: Optional[str] = None):
        """Wrap and filter a synchronous token stream in real time."""
        from pygenguard.streaming.guard import StreamingOutputGuard
        stream_guard = StreamingOutputGuard(output_plane=self._output_plane)
        return stream_guard.wrap_sync_stream(stream, prompt=prompt, system_prompt=system_prompt)

    def aintercept_stream(self, stream, prompt: Optional[str] = None, system_prompt: Optional[str] = None):
        """Wrap and filter an asynchronous token stream in real time."""
        from pygenguard.streaming.guard import StreamingOutputGuard
        stream_guard = StreamingOutputGuard(output_plane=self._output_plane)
        return stream_guard.wrap_async_stream(stream, prompt=prompt, system_prompt=system_prompt)

    def inspect_retrieval(self, chunks: List[Any], session: Optional[Session] = None, strip_flagged: bool = True):
        """Scan retrieved RAG document chunks for indirect prompt injection and poisoning."""
        return self._rag_guard.inspect_retrieval(chunks, session=session, strip_flagged=strip_flagged)

    async def ainspect_retrieval(self, chunks: List[Any], session: Optional[Session] = None, strip_flagged: bool = True):
        """Asynchronously scan retrieved RAG document chunks."""
        return await self._rag_guard.ainspect_retrieval(chunks, session=session, strip_flagged=strip_flagged)

    def inspect_memory(self, memory_entries: Any, agent_id: Optional[str] = None) -> Decision:
        """Inspect persistent agent memory for poisoned instructions or backdoors."""
        trace_id = str(uuid.uuid4())
        res = self._memory_guard.evaluate(memory_entries, agent_id=agent_id)
        if res.passed:
            return Decision.create_allow(trace_id=trace_id, plane_results={"memory": res}, rationale=res.details)
        return Decision.create_block(trace_id=trace_id, plane_results={"memory": res}, rationale=res.details)

    async def ainspect_memory(self, memory_entries: Any, agent_id: Optional[str] = None) -> Decision:
        """Asynchronously inspect persistent agent memory."""
        return await asyncio.to_thread(self.inspect_memory, memory_entries, agent_id)

    def inject_canary(self, system_prompt: str, session: Session) -> str:
        """Inject an ephemeral canary honey-token into system prompt."""
        return self._canary_mgr.inject(system_prompt, session)

    def verify_canary(self, output_text: str, session: Session) -> Decision:
        """Verify whether the session canary leaked in model output."""
        trace_id = str(uuid.uuid4())
        res = self._canary_mgr.verify(output_text, session)
        if res.passed:
            return Decision.create_allow(trace_id=trace_id, plane_results={"canary": res}, rationale=res.details)
        return Decision.create_block(trace_id=trace_id, plane_results={"canary": res}, rationale=res.details, safe_response="System prompt extraction detected.")

    def inspect_grounding(self, output_text: str, reference_context: str) -> Decision:
        """Inspect generated text for factual grounding and hallucinations against context."""
        trace_id = str(uuid.uuid4())
        res = self._grounding_plane.evaluate(output_text, reference_context)
        if res.passed:
            return Decision.create_allow(trace_id=trace_id, plane_results={"grounding": res}, rationale=res.details)
        return Decision.create_block(trace_id=trace_id, plane_results={"grounding": res}, rationale=res.details, safe_response="Response contains ungrounded or hallucinated claims.")

    async def ainspect_grounding(self, output_text: str, reference_context: str) -> Decision:
        """Asynchronously inspect factual grounding."""
        return await asyncio.to_thread(self.inspect_grounding, output_text, reference_context)

    def inspect_consensus(self, action_name: str, agent_votes: Any, quorum_ratio: Optional[float] = None) -> Decision:
        """Evaluate multi-agent votes for quorum authorization on critical actions."""
        trace_id = str(uuid.uuid4())
        res = self._consensus_gate.evaluate(action_name, agent_votes, quorum_ratio=quorum_ratio)
        if res.passed:
            return Decision.create_allow(trace_id=trace_id, plane_results={"consensus": res}, rationale=res.details)
        return Decision.create_block(trace_id=trace_id, plane_results={"consensus": res}, rationale=res.details, safe_response=f"Consensus quorum not met for '{action_name}'.")

    async def ainspect_consensus(self, action_name: str, agent_votes: Any, quorum_ratio: Optional[float] = None) -> Decision:
        """Asynchronously evaluate multi-agent consensus."""
        return await asyncio.to_thread(self.inspect_consensus, action_name, agent_votes, quorum_ratio)

    def inspect_extraction(self, prompt: str, session: Session) -> Decision:
        """Detect automated model extraction, distillation, and boundary-probing attacks."""
        trace_id = str(uuid.uuid4())
        res = self._extraction_guard.evaluate(prompt, session)
        if res.passed:
            return Decision.create_allow(trace_id=trace_id, plane_results={"extraction": res}, rationale=res.details)
        return Decision.create_block(trace_id=trace_id, plane_results={"extraction": res}, rationale=res.details, safe_response="Automated model extraction probing detected.")

    async def ainspect_extraction(self, prompt: str, session: Session) -> Decision:
        """Asynchronously detect model extraction probing."""
        return await asyncio.to_thread(self.inspect_extraction, prompt, session)

    def mask_pii(self, text: str) -> Tuple[str, Dict[str, str]]:
        """Mask PII entities with reversible synthetic tokens."""
        return self._pii_engine.mask_pii(text)

    def unmask_pii(self, text: str, mapping: Dict[str, str]) -> str:
        """Restore original PII entities from token mapping."""
        return self._pii_engine.unmask_pii(text, mapping)

    async def amask_pii(self, text: str) -> Tuple[str, Dict[str, str]]:
        """Asynchronously mask PII entities."""
        return await self._pii_engine.amask_pii(text)

    async def aunmask_pii(self, text: str, mapping: Dict[str, str]) -> str:
        """Asynchronously restore original PII entities."""
        return await self._pii_engine.aunmask_pii(text, mapping)

    def inspect_budget(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        session: Session,
    ) -> Decision:
        """Inspect and enforce financial USD token cost budget per session."""
        trace_id = str(uuid.uuid4())
        res = self._budget_mgr.inspect_cost(model, input_tokens, output_tokens, session)
        if res.passed:
            return Decision.create_allow(trace_id=trace_id, plane_results={"budget": res}, rationale=res.details)
        return Decision.create_block(trace_id=trace_id, plane_results={"budget": res}, rationale=res.details, safe_response="Financial budget limit exceeded for session.")

    async def ainspect_budget(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        session: Session,
    ) -> Decision:
        """Asynchronously evaluate session token cost budget."""
        return await asyncio.to_thread(self.inspect_budget, model, input_tokens, output_tokens, session)

    def route_safe(
        self,
        prompt: str,
        risk_score: float = 0.0,
        preferred_model: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> RouteDecision:
        """Safely select model destination based on risk score and circuit breaker status."""
        return self._router.route_safe(prompt, risk_score=risk_score, preferred_model=preferred_model, metadata=metadata)

    async def aroute_safe(
        self,
        prompt: str,
        risk_score: float = 0.0,
        preferred_model: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> RouteDecision:
        """Asynchronously route prompt safely based on risk score and health."""
        return await self._router.aroute_safe(prompt, risk_score=risk_score, preferred_model=preferred_model, metadata=metadata)

    def sanitize_prompt(
        self,
        prompt: str,
        strip_delimiters: bool = True,
        normalize_homoglyphs: bool = True,
    ) -> str:
        """Sanitize prompt text, stripping invisible unicode, control characters, delimiters, and homoglyphs."""
        return self._sanitizer.sanitize_prompt(prompt, strip_delimiters=strip_delimiters, normalize_homoglyphs_override=normalize_homoglyphs)

    async def asanitize_prompt(
        self,
        prompt: str,
        strip_delimiters: bool = True,
        normalize_homoglyphs: bool = True,
    ) -> str:
        """Asynchronously sanitize prompt text."""
        return await self._sanitizer.asanitize_prompt(prompt, strip_delimiters=strip_delimiters, normalize_homoglyphs_override=normalize_homoglyphs)

    def learn_adaptive_rule(
        self,
        rule_id: str,
        pattern: str,
        reason: str,
        ttl_sec: float = 3600.0,
        risk_score: float = 0.9,
    ) -> AdaptiveRule:
        """Dynamically register a temporary adaptive defense rule."""
        return self._adaptive_learner.learn_rule(rule_id, pattern, reason, ttl_sec=ttl_sec, risk_score=risk_score)

    async def alearn_adaptive_rule(
        self,
        rule_id: str,
        pattern: str,
        reason: str,
        ttl_sec: float = 3600.0,
        risk_score: float = 0.9,
    ) -> AdaptiveRule:
        """Asynchronously dynamically register an adaptive defense rule."""
        return await self._adaptive_learner.alearn_rule(rule_id, pattern, reason, ttl_sec=ttl_sec, risk_score=risk_score)

    def inspect_adaptive(self, prompt: str, session: Optional[Session] = None) -> Decision:
        """Inspect prompt against active dynamically learned adaptive defense rules."""
        trace_id = str(uuid.uuid4())
        res = self._adaptive_learner.evaluate(prompt, session)
        if res.passed:
            return Decision.create_allow(trace_id=trace_id, plane_results={"adaptive": res}, rationale=res.details)
        return Decision.create_block(trace_id=trace_id, plane_results={"adaptive": res}, rationale=res.details, safe_response="Request blocked by dynamic adaptive defense rule.")

    async def ainspect_adaptive(self, prompt: str, session: Optional[Session] = None) -> Decision:
        """Asynchronously inspect prompt against dynamically learned adaptive rules."""
        return await asyncio.to_thread(self.inspect_adaptive, prompt, session)

    def decode_and_inspect(self, prompt: str, session: Optional[Session] = None, max_depth: int = 2) -> Decision:
        """Recursively unwraps multi-level ciphers / obfuscations (Base64, Hex, ROT13, Binary, Reversed) and inspects."""
        trace_id = str(uuid.uuid4())
        effective_session = session or Session(user_id="anonymous")
        passed, triggered_variant, dec = decode_and_inspect(
            prompt,
            inspect_fn=lambda text: self.inspect(text, session=effective_session),
            max_depth=max_depth,
        )
        if passed:
            return Decision.create_allow(trace_id=trace_id, plane_results={}, rationale="Multi-level obfuscation unwrap inspection passed.")
        return Decision.create_block(
            trace_id=trace_id,
            plane_results=dec.plane_results if dec else {},
            rationale=f"Obfuscated threat detected in payload variant: {triggered_variant[:60]}...",
            safe_response="Obfuscated evasion attempt blocked by security policy.",
        )

    async def adecode_and_inspect(self, prompt: str, session: Optional[Session] = None, max_depth: int = 2) -> Decision:
        """Asynchronously unwrap multi-level obfuscations and inspect."""
        return await asyncio.to_thread(self.decode_and_inspect, prompt, session, max_depth)

    def reload_policy(self, new_policy: Policy) -> None:
        """Hot-reload policy configuration at runtime."""
        self._policy = new_policy
        self._shadow_mode = self._policy.mode == GuardMode.SHADOW
        cs_policy = self._policy.content_safety
        self._content_safety_plane = ContentSafetyPlane(
            block_categories=cs_policy.block_categories if cs_policy.enabled else [],
            severity_threshold=cs_policy.severity_threshold,
        )
        self._content_safety_enabled = cs_policy.enabled

    def enable_policy_watcher(self, policy_path: str) -> PolicyWatcher:
        """Enable live file watching for policy hot-reload."""
        self._policy_watcher = PolicyWatcher(policy_path, on_reload=self.reload_policy)
        return self._policy_watcher

    def inspect_pricing(self, text: str) -> Decision:
        """Inspect text for commercial price leaks, quotes, and rate cards."""
        trace_id = str(uuid.uuid4())
        res = self._pricing_plane.evaluate(text)
        if res.passed:
            return Decision.create_allow(trace_id=trace_id, plane_results={"pricing": res}, rationale=res.details)
        return Decision.create_block(trace_id=trace_id, plane_results={"pricing": res}, rationale=res.details, safe_response="Commercial pricing or rate card information blocked.")

    async def ainspect_pricing(self, text: str) -> Decision:
        """Asynchronously inspect text for pricing leaks."""
        return await asyncio.to_thread(self.inspect_pricing, text)

    def inspect_contact(self, text: str) -> Decision:
        """Inspect text for direct contact information (emails, phones, LinkedIn, CRM IDs)."""
        trace_id = str(uuid.uuid4())
        res = self._contact_plane.evaluate(text)
        if res.passed:
            return Decision.create_allow(trace_id=trace_id, plane_results={"contact": res}, rationale=res.details)
        return Decision.create_block(trace_id=trace_id, plane_results={"contact": res}, rationale=res.details, safe_response="Direct contact details blocked by privacy policy.")

    async def ainspect_contact(self, text: str) -> Decision:
        """Asynchronously inspect text for contact information."""
        return await asyncio.to_thread(self.inspect_contact, text)

    def sanitize_contacts(self, text: str) -> Tuple[str, Dict[str, str]]:
        """Sanitize contact entities into reversible synthetic placeholders."""
        return self._contact_plane.sanitize_contacts(text)

    def unmask_contacts(self, text: str, mapping: Dict[str, str]) -> str:
        """Restore original contact entities from mapping."""
        return self._contact_plane.unmask_contacts(text, mapping)

    def inspect_confidential(self, text: str) -> Decision:
        """Inspect text for proprietary trade secrets, unreleased roadmaps, M&A, and compensation figures."""
        trace_id = str(uuid.uuid4())
        res = self._confidential_plane.evaluate(text)
        if res.passed:
            return Decision.create_allow(trace_id=trace_id, plane_results={"confidential": res}, rationale=res.details)
        return Decision.create_block(trace_id=trace_id, plane_results={"confidential": res}, rationale=res.details, safe_response="Confidential corporate intelligence blocked.")

    async def ainspect_confidential(self, text: str) -> Decision:
        """Asynchronously inspect text for confidential trade secrets."""
        return await asyncio.to_thread(self.inspect_confidential, text)

    def inspect_hybrid(
        self,
        prompt: str,
        session: Optional[Session] = None,
        context: Optional[str] = None,
        tenant_id: Optional[str] = None,
        byok_config: Optional[BYOKConfig] = None,
    ) -> HybridDecision:
        """
        Execute deterministic Zero-LLM fast inspection with conditional BYOK LLM-as-a-Judge fallback
        only when confidence falls in the ambiguous zone.
        """
        # Resolve tenant BYOK config if tenant_id provided
        effective_byok = byok_config
        if not effective_byok and tenant_id:
            tenant = self._tenant_mgr.get_tenant(tenant_id)
            if tenant and tenant.byok_config:
                effective_byok = tenant.byok_config

        return self._hybrid_engine.inspect_hybrid(
            prompt=prompt,
            session=session,
            context=context,
            byok_config_override=effective_byok,
        )

    async def ainspect_hybrid(
        self,
        prompt: str,
        session: Optional[Session] = None,
        context: Optional[str] = None,
        tenant_id: Optional[str] = None,
        byok_config: Optional[BYOKConfig] = None,
    ) -> HybridDecision:
        """Asynchronously execute hybrid inspection with BYOK LLM judge fallback."""
        return await asyncio.to_thread(
            self.inspect_hybrid,
            prompt,
            session,
            context,
            tenant_id,
            byok_config,
        )

    def register_tenant(self, tenant_config: TenantConfig) -> None:
        """Register a SaaS tenant configuration with isolated BYOK credentials."""
        self._tenant_mgr.register_tenant(tenant_config)

    def get_tenant(self, tenant_id: str) -> Optional[TenantConfig]:
        """Get SaaS tenant configuration."""
        return self._tenant_mgr.get_tenant(tenant_id)

    def get_cluster_health(self) -> ClusterNodeInfo:
        """Get server farm node telemetry and health metrics."""
        return self._cluster_mgr.get_node_health()

    def inspect_training_data(
        self,
        sample_text: str,
        source: Optional[str] = None,
    ) -> Decision:
        """
        Verify whether a training sample, scraped article, or fine-tuning record
        is safe to feed into LLM training / RAG pipelines (checking for phishing,
        credential harvesters, and backdoor poisoning triggers).

        Args:
            sample_text: Text content of training sample
            source: Identifier of the source dataset / document

        Returns:
            Decision object
        """
        trace_id = str(uuid.uuid4())
        plane_results: Dict[str, PlaneResult] = {}

        # 1. Phishing & Poisoning Check
        phishing_res = self._phishing_plane.evaluate(sample_text)
        plane_results["phishing"] = phishing_res

        # 2. Output & Secrets Check
        out_res = self._output_plane.evaluate(sample_text)
        plane_results["output"] = out_res

        # 3. Compliance Check
        comp_res = self._compliance_plane.evaluate(sample_text)
        plane_results["compliance"] = comp_res

        # 4. Content Safety Check
        if self._content_safety_enabled:
            safety_res = self._content_safety_plane.evaluate(sample_text)
            plane_results["content_safety"] = safety_res
        else:
            safety_res = PlaneResult(plane_name="content_safety", passed=True, risk_score=0.0, details="Disabled")

        passed = phishing_res.passed and out_res.passed and safety_res.passed

        if not passed:
            reasons = []
            if not phishing_res.passed:
                reasons.append(phishing_res.details)
            if not out_res.passed:
                reasons.append(out_res.details)
            if not safety_res.passed:
                reasons.append(safety_res.details)

            decision = Decision.create_block(
                trace_id=trace_id,
                plane_results=plane_results,
                rationale=f"Training data integrity check failed: {'; '.join(reasons)}",
                safe_response="Sample rejected from training dataset.",
            )
        else:
            decision = Decision.create_allow(
                trace_id=trace_id,
                plane_results=plane_results,
                rationale="Training sample verified safe for model ingestion.",
            )

        self._audit.log(decision)
        return decision

    def inspect_output(
        self,
        output_text: str,
        prompt: Optional[str] = None,
        system_prompt: Optional[str] = None,
        session: Optional[Session] = None,
        sanitize: bool = True,
    ) -> Decision:
        """
        Evaluate generated model response against output security policies.
        """
        trace_id = str(uuid.uuid4())
        plane_results: Dict[str, PlaneResult] = {}

        if session:
            session.increment_tokens(len(output_text))

        out_result = self._output_plane.evaluate(
            output_text=output_text,
            prompt=prompt,
            system_prompt=system_prompt,
        )
        plane_results["output"] = out_result

        # Also verify no phishing links generated in output
        phishing_result = self._phishing_plane.evaluate(output_text)
        plane_results["phishing"] = phishing_result

        # Content safety on output
        if self._content_safety_enabled:
            safety_result = self._content_safety_plane.evaluate(output_text)
            plane_results["content_safety"] = safety_result
        else:
            safety_result = PlaneResult(plane_name="content_safety", passed=True, risk_score=0.0, details="Disabled")

        passed = out_result.passed and phishing_result.passed and safety_result.passed
        sanitized = self._output_plane.sanitize(output_text) if sanitize else None

        if not passed:
            details = out_result.details if not out_result.passed else (
                phishing_result.details if not phishing_result.passed else safety_result.details
            )
            decision = Decision.create_block(
                trace_id=trace_id,
                plane_results=plane_results,
                rationale=f"Output security check failed: {details}",
                safe_response="I cannot output the requested response as it violates output security policies.",
                sanitized_response=sanitized,
            )
        else:
            decision = Decision.create_allow(
                trace_id=trace_id,
                plane_results=plane_results,
                rationale="Output security verification passed.",
                sanitized_response=sanitized,
            )

        self._audit.log(decision)
        return decision

    def inspect_tool_call(
        self,
        tool_name: str,
        tool_args: Optional[Dict[str, Any]] = None,
        arguments: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
        session: Optional[Session] = None,
        agent_permissions: Optional[Set[str]] = None,
    ) -> Decision:
        """
        Evaluate a tool/function call before execution in agentic workflows.

        Args:
            tool_name: Name of the tool being called
            tool_args: Arguments passed to the tool
            arguments: Alias for tool_args
            agent_id: ID of the agent making the call
            session: Session context
            agent_permissions: Permission set for the agent

        Returns:
            Decision object
        """
        trace_id = str(uuid.uuid4())
        effective_args = arguments if arguments is not None else tool_args
        effective_agent_id = agent_id or (session.agent_id if session else None)

        result = self._tool_use_plane.evaluate(
            tool_name=tool_name,
            tool_args=effective_args,
            agent_id=effective_agent_id,
            agent_permissions=agent_permissions,
        )

        if session and hasattr(session, "record_tool_call"):
            session.record_tool_call(
                tool_name=tool_name,
                arguments=effective_args or {},
                blocked=not result.passed,
            )

        if result.passed:
            decision = Decision.create_allow(
                trace_id=trace_id,
                plane_results={"tool_use": result},
                rationale=result.details,
            )
        else:
            decision = Decision.create_block(
                trace_id=trace_id,
                plane_results={"tool_use": result},
                rationale=result.details,
                safe_response="Tool call blocked by security policy.",
            )

        self._audit.log(decision)
        return decision

    def inspect_reasoning(
        self,
        reasoning_text: str,
        step_number: int = 1,
        total_steps: int = 1,
        original_task: Optional[str] = None,
        previous_steps: Optional[List[str]] = None,
    ) -> Decision:
        """
        Inspect a chain-of-thought reasoning step for security threats.

        Args:
            reasoning_text: The reasoning/thinking text to inspect
            step_number: Current step number
            total_steps: Total steps so far
            original_task: The original user task
            previous_steps: List of previous reasoning steps

        Returns:
            Decision object
        """
        trace_id = str(uuid.uuid4())

        result = self._cot_guard.evaluate(
            reasoning_text=reasoning_text,
            step_number=step_number,
            total_steps=total_steps,
            original_task=original_task,
            previous_steps=previous_steps,
        )

        if result.passed:
            decision = Decision.create_allow(
                trace_id=trace_id,
                plane_results={"chain_of_thought": result},
                rationale=result.details,
            )
        else:
            decision = Decision.create_block(
                trace_id=trace_id,
                plane_results={"chain_of_thought": result},
                rationale=result.details,
                safe_response="Reasoning step blocked due to security concern.",
            )

        self._audit.log(decision)
        return decision

    def get_session_trust(self, session: Session) -> int:
        """Get current trust score for a session (utility method)."""
        return self._identity_plane.get_trust_score(session)

    def get_health(self) -> Dict[str, Any]:
        """Get health status of all circuit breakers and rate limiters."""
        health: Dict[str, Any] = {
            "policy": self._policy.name,
            "mode": self._policy.mode.value,
            "shadow_mode": self._shadow_mode,
            "circuit_breakers": self._circuit_breakers.get_all_health(),
        }
        if self._rate_limiter:
            health["rate_limiter"] = "active"
        return health

    def inspect_with_jev(self, prompt: str, session: Optional[Session] = None) -> Decision:
        """
        Tokenless "System One" Execution using Jev.
        
        Evaluates unstructured inputs directly against Pydantic schemas in <5ms.
        Halts malicious prompts at pre-execution before expensive inference tokens are consumed.
        """
        return self._jev_engine.pre_execution_block(prompt, session=session)

    def filter_kb_with_jev(
        self,
        prompt: str,
        completion: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Any]:
        """
        Post-Execution KB Filtering using Jev.
        
        Evaluates generated interactions before knowledge base or vector store ingestion
        to strip hallucinations, toxic content, and poisoning attacks.
        """
        return self._jev_engine.filter_kb_interaction(prompt, completion, metadata=metadata)
