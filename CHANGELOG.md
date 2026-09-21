# Changelog

All notable changes to **PyGenGuard** will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-09-15

### Added
- **20 Advanced Production-Grade Capabilities (Dual Sync & Async APIs)**:
  1. **Parallel Plane Evaluation**: `inspect_parallel` & `ainspect_parallel` using thread pool / asyncio gathering.
  2. **Security Result Caching**: `cached_inspect` & `acached_inspect` with normalized hashing, LRU eviction, and TTL.
  3. **High-Throughput Batch Scanning**: `scan_batch` & `ascan_batch` with `BatchScanner`.
  4. **Chunk-Level Streaming Interception**: `intercept_stream` & `aintercept_stream` with 40-char sliding buffer window.
  5. **Agent Tool Sandboxing**: `@guard_tool` & `@aguard_tool` decorators with pre/post inspection and `ToolSandbox`.
  6. **RAG Retrieval Security**: `inspect_retrieval` & `ainspect_retrieval` with `RAGRetrievalGuard`.
  7. **Agent Memory Poisoning Guard**: `inspect_memory` & `ainspect_memory` with `AgentMemoryGuard`.
  8. **Ephemeral Canary Honey-Tokens**: `inject_canary` & `verify_canary` with `CanaryManager`.
  9. **Deterministic Grounding Guard**: `inspect_grounding` & `ainspect_grounding` with `GroundingPlane`.
  10. **Multi-Agent Consensus Quorum Gate**: `inspect_consensus` & `ainspect_consensus` with `ConsensusGate`.
  11. **Model Extraction & Distillation Probing Guard**: `inspect_extraction` & `ainspect_extraction` with `ModelExtractionGuard`.
  12. **Reversible PII Pseudonymization Engine**: `mask_pii` / `unmask_pii` & `amask_pii` / `aunmask_pii` with `PIIMaskingEngine`.
  13. **Financial Dollar Token Budget Enforcement**: `inspect_budget` & `ainspect_budget` with `BudgetManager`.
  14. **Cross-Model Safe Routing & Cascade**: `route_safe` & `aroute_safe` with `ModelRouter`.
  15. **Prompt Sanitization & Boundary Delimiter Stripping**: `sanitize_prompt` & `asanitize_prompt` with `PromptSanitizer`.
  16. **Self-Learning Adaptive Defense Rules**: `learn_adaptive_rule` & `alearn_adaptive_rule` with `AdaptiveRuleLearner`.
  17. **Multi-Level Recursive Cipher Decoders**: `decode_and_inspect` & `adecode_and_inspect` with ROT13, Caesar, binary, reversed.
  18. **Policy-as-Code Live Hot-Reloading**: `enable_policy_watcher`, `reload_policy`, and `PolicyWatcher`.
  19. **Data Poisoning & Training Integrity**: `inspect_training_data` and CLI `scan-data`.
  20. **CLI Power Tools**: `pygenguard scan-batch`, `pygenguard route`, and `pygenguard sanitize`.
- **Complete Test Coverage**: 200+ unit and integration tests passing across all suites.

---

## [1.0.0] - 2026-09-15

### Added
- **Policy-as-Code Engine (`policy.py`)**:
  - Declarative policy definitions in YAML, JSON, or Python dicts.
  - Built-in presets: `strict`, `balanced`, `permissive`, and `shadow`.
  - Fine-grained fail actions per plane: `BLOCK`, `DEGRADE`, `CHALLENGE`, `LOG_ONLY`.
  - `Policy.from_file`, `Policy.from_json`, `Policy.from_yaml`, `Policy.save`, and `Policy.merge`.
- **Resilience & Circuit Breakers (`resilience.py`)**:
  - Per-plane `CircuitBreaker` state machine (`CLOSED` → `OPEN` → `HALF_OPEN` → `CLOSED`).
  - Configurable failure threshold, recovery timeouts, and fail-open/fail-closed behaviors.
  - Centralized `CircuitBreakerRegistry` with aggregated health status reporting.
- **Composite Rate Limiting (`rate_limiter.py`)**:
  - Sliding-window counter for requests/min, requests/hour, tokens/min, and tokens/hour.
  - Token-bucket algorithm for burst allowance without false positives.
- **Agentic Orchestration Guardrails**:
  - `ToolUsePlane`: Validates tool/function calls before execution; catches SQL injection, command injection, path traversal, and enforces tool allowlists and frequency limits.
  - `ChainOfThoughtGuard`: Analyzes reasoning steps in ReAct/CoT workflows for deception, covert goal hijacking, and infinite iteration loops.
  - `AgentBoundaryGuard`: Multi-agent boundary enforcement, delegation depth limits, and inter-agent injection defense.
- **Role-Based Access Control & Multi-Tenancy (`rbac.py`)**:
  - Per-role plane bypasses, custom token quotas, and per-role tool authorizations.
  - Multi-tenant policy isolation with hierarchical role inheritance.
- **Deterministic Content Safety Plane (`planes/content_safety.py`)**:
  - Zero-ML, deterministic classification for hate speech, self-harm, violence, sexual exploitation, and illicit instruction vectors.
- **1-Line SDK Wrappers**:
  - `wrap_anthropic(client)`: Drop-in security wrapper for Anthropic Claude.
  - `wrap_google(model)`: Drop-in security wrapper for Google Gemini GenerativeModel.
  - `wrap_litellm(litellm)`: Universal wrapper for LiteLLM synchronous and asynchronous completion.
- **Framework Integrations**:
  - `PyGenGuardCallbackHandler`: LangChain callback integration.
  - `PyGenGuardLlamaIndexHandler`: LlamaIndex callback integration.
  - `CrewAIAgentGuard`: CrewAI step and tool callback guard.
- **Alerting & Webhook Dispatcher (`alerts.py`)**:
  - Webhook delivery (Slack, Discord, PagerDuty), structured JSONL logging, and custom callback backends.
  - Sliding-window alert rate-limiting and deduplication.
- **Production CLI Tooling (`cli/main.py`)**:
  - Commands: `scan`, `scan-data`, `inspect-tool`, `validate-policy`, `audit`, `benchmark`, `version`.
- **Extended Test Suite**:
  - Over 155 automated unit and integration tests with zero external test service requirements.

---

## [0.3.0] - 2026-09-14

### Added
- **Post-Generation Output Guard (`OutputGuard` & `inspect_output`)**:
  - Intercepts secret and credential leaks (OpenAI, AWS, GitHub PAT, JWT, Private Keys).
  - Detects system prompt regurgitation and secret canary token leakage.
  - Blocks dangerous executable code payloads and markdown image data exfiltration.
  - Automatic PII and credential sanitization (`decision.sanitized_response`).
- **Advanced Obfuscation & Evasion Decoders (`utils/decoders.py`)**:
  - Base64, Hex, and URL-encoded injection decoders.
  - Leetspeak and Unicode homoglyph normalization.
  - Zero-width and invisible character stripping.
- **FastAPI & ASGI Middleware (`PyGenGuardMiddleware`)**:
  - Drop-in ASGI middleware for FastAPI, Starlette, and LiteStar.
- **Metrics & Telemetry**:
  - Prometheus metrics exporter and OpenTelemetry distributed tracing spans.

---

## [0.2.0] - 2026-06-29

### Added
- Asynchronous Guard runtime (`AsyncGuard`).
- Distributed session store adapter framework (`BaseSessionStore`, `InMemorySessionStore`, `RedisSessionStore`).
- Extensible Plugin Architecture (`BasePlane`, `PlaneRegistry`).

---

## [0.1.0] - 2026-06-25

### Initial Release
- Deterministic multi-plane security engine: Identity, Intent, Context, Economics, and Compliance planes.
- Client Trust Score (CTS) dynamic drift detection.
- Core `Guard` and `Session` APIs.
