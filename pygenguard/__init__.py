"""
PyGenGuard - Production-Grade Runtime Security & Governance for GenAI & Agentic AI.

A deterministic, zero-dependency security layer that enforces trust, intent,
cost, compliance, output safety, content safety, and agentic guardrails
before and after model execution.

v1.0.0 Features:
- Policy-as-Code Engine (Python dict, YAML, JSON)
- 20 Security Planes across Core, Agentic, and Enterprise domains
- Tokenless System One Execution & Dual-Layer Governance (Jev Engine)
- Circuit Breaker pattern for resilient plane evaluation
- Rate Limiting (sliding window + token bucket)
- RBAC & Multi-Tenancy support
- Context Taint & Provenance Tracking (Instruction Hierarchy & InjecAgent)
- Compound Multi-Plane Risk Correlator (Swiss Cheese Model)
- Deterministic Data Analysis Guard & Test Harness Engineering
- Standardized Benchmark Suite in CLI
- OutputGuard & StreamingOutputGuard for post-generation verification
- Drop-in SDK wrappers: OpenAI, Anthropic, Google GenAI, LiteLLM
- Framework integrations: LangChain, LlamaIndex, CrewAI, FastAPI
- AsyncGuard for high-concurrency applications
- Prometheus metrics & OpenTelemetry tracing
"""

__version__ = "1.0.0"
__author__ = "PyGenGuard Contributors"

# Core exports
from pygenguard.guard import Guard, GuardConfig
from pygenguard.output_guard import OutputGuard
from pygenguard.session import Session, ChatTurn
from pygenguard.decision import Decision, PlaneResult

# Policy engine
from pygenguard.policy import Policy, PlanePolicy, GuardMode, FailAction

# Resilience
from pygenguard.resilience import CircuitBreaker, CircuitBreakerRegistry, CircuitState, CircuitBreakerConfig

# Rate limiting
from pygenguard.rate_limiter import RateLimiter, SlidingWindowCounter, TokenBucket, RateLimitResult

# RBAC
from pygenguard.rbac import RBACPolicy, Role, Tenant

# Alerts
from pygenguard.alerts import AlertManager, WebhookAlert, LogAlert, CallbackAlert

# Async support
from pygenguard.async_guard import AsyncGuard

# Streaming guard
from pygenguard.streaming import StreamingOutputGuard

# SDK Wrappers
from pygenguard.wrappers import wrap_openai, wrap_anthropic, wrap_google, wrap_litellm
from pygenguard.wrappers import PyGenGuardSecurityException

# Planes — Core
from pygenguard.planes import (
    IdentityPlane, IntentPlane, ContextPlane, EconomicsPlane,
    CompliancePlane, OutputPlane, PhishingDetectorPlane, MultiModalPlane,
)

# Planes — Agentic & Advanced
from pygenguard.planes import (
    ToolUsePlane, ChainOfThoughtGuard, AgentBoundaryGuard,
    AgentSecurityContext, ContentSafetyPlane,
    GroundingPlane, ConsensusGate, ModelExtractionGuard, AgentMemoryGuard,
    PricingPlane, ContactPlane, ConfidentialPlane,
)

# Plugins
from pygenguard.plugins import BasePlane, PlaneRegistry, plane_plugin, PlanePhase, PlaneConfig

# Integrations
from pygenguard.integrations import PyGenGuardMiddleware

# Observability
from pygenguard.metrics import MetricsCollector, get_metrics_collector
from pygenguard.telemetry import PyGenGuardTracer, get_tracer

# Performance, Caching & Batching
from pygenguard.cache import SecurityCache
from pygenguard.batch import BatchScanner, BatchScanResult

# Tool Sandboxing
from pygenguard.tools import guard_tool, aguard_tool, ToolSandbox

# RAG & Canary
from pygenguard.rag import RAGRetrievalGuard
from pygenguard.canary import CanaryManager

# Privacy, Cost & Routing
from pygenguard.utils.pii import PIIMaskingEngine
from pygenguard.budget import BudgetManager
from pygenguard.routing import ModelRouter, RouteDecision

# Sanitization & Adaptive Learning
from pygenguard.sanitizer import PromptSanitizer
from pygenguard.adaptive import AdaptiveRuleLearner, AdaptiveRule
from pygenguard.policy import PolicyWatcher
from pygenguard.utils.decoders import (
    decode_and_inspect,
    adecode_and_inspect,
    unwrap_multilevel_obfuscation,
    decode_rot13,
    decode_caesar,
    decode_binary,
)

# BYOK & Hybrid LLM Judge
from pygenguard.byok import BYOKConfig, JudgeVerdict, BYOKLLMJudge
from pygenguard.hybrid import HybridGuardEngine, HybridDecision

# SaaS Multi-Tenancy & Server Farms
from pygenguard.saas import (
    TenantConfig, TenantManager, ClusterNodeInfo,
    DistributedStateStore, InMemoryStateStore, ClusterManager,
)

# Jev Tokenless System One & Dual-Layer Governance
from pygenguard.jev import (
    JevPreExecutionVerdict,
    JevPostExecutionVerdict,
    JevClientConfig,
    JevClient,
    AsyncJevClient,
    DualLayerGovernanceEngine,
    KBDatasetReviewResult,
    JevGatewayMiddleware,
)

# Provenance & Context Taint Tracking (OpenAI Instruction Hierarchy & InjecAgent)
from pygenguard.provenance import (
    ProvenanceTier, ProvenanceChunk, TaintAnalysisResult, ContextTaintTracker
)

# Compound Multi-Plane Risk Correlation (CSIRO Swiss Cheese Model)
from pygenguard.correlator import (
    CompoundRiskCorrelator, CompoundThreatVerdict
)

# Harness Engineering & Deterministic Data Analysis Guard
from pygenguard.harness import (
    DeterministicDataGuard, DataColumnConstraint, AnalyticalValidationResult, HarnessScenarioRunner
)

# Standardized Benchmark Harness
from pygenguard.audit.benchmark import (
    BenchmarkHarness, BenchmarkMetric
)


# Truth & Consistency Engine
from pygenguard.consistency import (
    ClaimRelation, ClaimNode, ClaimEdge, ClaimGraph,
    SemanticDriftTracker, TruthConsistencyResult, TruthConsistencyEngine,
)

# Execution & Cost Optimization Engine
from pygenguard.optimization import (
    AgentStepRecord, BYOKExecutionVault, PromptCacheOptimizer,
    MultiStepAgentTracer, OptimizationReport, ExecutionOptimizer,
)

__all__ = [
    # Version
    "__version__",
    # Core
    "Guard", "GuardConfig", "OutputGuard",
    "Session", "ChatTurn", "Decision", "PlaneResult",
    # Policy
    "Policy", "PlanePolicy", "GuardMode", "FailAction", "PolicyWatcher",
    # Resilience
    "CircuitBreaker", "CircuitBreakerRegistry", "CircuitState", "CircuitBreakerConfig",
    # Rate Limiting
    "RateLimiter", "SlidingWindowCounter", "TokenBucket", "RateLimitResult",
    # RBAC
    "RBACPolicy", "Role", "Tenant",
    # Alerts
    "AlertManager", "WebhookAlert", "LogAlert", "CallbackAlert",
    # Async
    "AsyncGuard",
    # Streaming
    "StreamingOutputGuard",
    # Wrappers
    "wrap_openai", "wrap_anthropic", "wrap_google", "wrap_litellm",
    "PyGenGuardSecurityException",
    # Planes — Core
    "IdentityPlane", "IntentPlane", "ContextPlane", "EconomicsPlane",
    "CompliancePlane", "OutputPlane", "PhishingDetectorPlane", "MultiModalPlane",
    # Planes — Agentic & Advanced
    "ToolUsePlane", "ChainOfThoughtGuard", "AgentBoundaryGuard",
    "AgentSecurityContext", "ContentSafetyPlane",
    "GroundingPlane", "ConsensusGate", "ModelExtractionGuard", "AgentMemoryGuard",
    "PricingPlane", "ContactPlane", "ConfidentialPlane",
    # Plugins
    "BasePlane", "PlaneRegistry", "plane_plugin", "PlanePhase", "PlaneConfig",
    # Integrations
    "PyGenGuardMiddleware",
    # Observability
    "MetricsCollector", "get_metrics_collector",
    "PyGenGuardTracer", "get_tracer",
    # High-Performance, Batch & Cache
    "SecurityCache", "BatchScanner", "BatchScanResult",
    # Tool Sandboxing
    "guard_tool", "aguard_tool", "ToolSandbox",
    # RAG & Canary
    "RAGRetrievalGuard", "CanaryManager",
    # Privacy, Cost & Routing
    "PIIMaskingEngine", "BudgetManager", "ModelRouter", "RouteDecision",
    # Sanitization & Adaptive Learning
    "PromptSanitizer", "AdaptiveRuleLearner", "AdaptiveRule",
    # Decoders & Obfuscation
    "decode_and_inspect", "adecode_and_inspect", "unwrap_multilevel_obfuscation",
    "decode_rot13", "decode_caesar", "decode_binary",
    # BYOK & Hybrid LLM Judge
    "BYOKConfig", "JudgeVerdict", "BYOKLLMJudge",
    "HybridGuardEngine", "HybridDecision",
    # SaaS Multi-Tenancy & Server Farms
    "TenantConfig", "TenantManager", "ClusterNodeInfo",
    "DistributedStateStore", "InMemoryStateStore", "ClusterManager",
    # Jev Tokenless System One & Dual-Layer Governance
    "JevPreExecutionVerdict", "JevPostExecutionVerdict", "JevClientConfig",
    "JevClient", "AsyncJevClient", "DualLayerGovernanceEngine",
    "KBDatasetReviewResult", "JevGatewayMiddleware",
    # Provenance, Correlator, Harness & Benchmark
    "ProvenanceTier", "ProvenanceChunk", "TaintAnalysisResult", "ContextTaintTracker",
    "CompoundRiskCorrelator", "CompoundThreatVerdict",
    "DeterministicDataGuard", "DataColumnConstraint", "AnalyticalValidationResult", "HarnessScenarioRunner",
    "BenchmarkHarness", "BenchmarkMetric",
    # Truth & Consistency Engine
    "ClaimRelation", "ClaimNode", "ClaimEdge", "ClaimGraph",
    "SemanticDriftTracker", "TruthConsistencyResult", "TruthConsistencyEngine",
    # Execution & Cost Optimization
    "AgentStepRecord", "BYOKExecutionVault", "PromptCacheOptimizer",
    "MultiStepAgentTracer", "OptimizationReport", "ExecutionOptimizer",
]
