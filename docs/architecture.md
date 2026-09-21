# PyGenGuard Architecture & System One Design

## Overview

Traditional LLM guardrails suffer from a fundamental architectural bottleneck: they use secondary LLMs or slow natural language classifiers to evaluate user prompts. Generating validation text introduces 200ms–1500ms of latency, multiplying API costs and adding non-deterministic failure modes.

PyGenGuard solves this with **Tokenless "System One" Execution**:

```
+-----------------------------------------------------------------------------------+
|                               INCOMING USER PROMPT                                |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                         LAYER 1: PRE-EXECUTION GATEWAY                            |
|  - Tokenless System One Classification (<5ms)                                     |
|  - Delimiter / Zero-Width / Homoglyph Sanitization                                |
|  - Continuous Trust Scoring (IdentityPlane)                                       |
|  - Intent, Compliance, Content Safety, Phishing Planes                            |
|  - Multi-Tenancy & RBAC Plane Bypass Check                                        |
+-----------------------------------------------------------------------------------+
          |                                                    |
     [IF BLOCKED]                                         [IF ALLOWED]
          |                                                    |
          v                                                    v
+------------------------+                           +--------------------+
| Return Safe Response / |                           |  Upstream LLM /    |
| Zero Tokens Billed     |                           |  Agent Execution   |
+------------------------+                           +--------------------+
                                                               |
                                                               v
+-----------------------------------------------------------------------------------+
|                        LAYER 2: POST-EXECUTION FILTERING                          |
|  - OutputGuard: Leakage, PII Redaction, Honey-Token Verification                  |
|  - Knowledge Base (KB) Anti-Poisoning Filter                                      |
|  - Synthetic Hallucination & Toxicity Sanitization                                |
|  - Asynchronous Continuous Learning Ingestion Queue                               |
+-----------------------------------------------------------------------------------+
          |                                                    |
    [CLEAN DATA]                                         [POISONED DATA]
          |                                                    |
          v                                                    v
+------------------------+                           +--------------------+
| Ingest to Vector DB /  |                           | Quarantine Log /   |
| Knowledge Base Cache   |                           | Security Alert     |
+------------------------+                           +--------------------+
```

---

## Tokenless "System One" Execution

System One execution is inspired by cognitive dual-process theory: fast, instinctive, sub-conscious filtering before rational deliberative thought.

1. **Zero Token Generation Overhead**: Rather than prompting an LLM to generate conversational tokens like `"Yes, this is an injection because..."`, the Jev engine evaluates unstructured input strings directly against typed Pydantic models (`JevPreExecutionVerdict`).
2. **Deterministic Classification**: High-speed compiled automata classify inputs into structured threat categories:
   - `prompt_injection`
   - `jailbreak`
   - `data_exfiltration`
   - `toxic_intent`
   - `system_prompt_override`
3. **Strict Latency Budget**: The entire evaluation pipeline executes in less than 5 milliseconds, making it invisible to downstream users while saving 100% of LLM inference tokens on malicious attacks.

---

## Dual-Layer Governance Engine

### Layer 1: Pre-Execution Threat Mitigation
Runs synchronously or asynchronously at your API gateway, reverse proxy, or application router:
- Inspects incoming prompts before model inference.
- Enforces rate limits, sliding window quotas, and token bucket burst allowances.
- Validates identity trust drift and context drift across multi-turn sessions.
- Blocks malicious payloads before they consume expensive cloud resources.

### Layer 2: Post-Execution Knowledge Base Filtering
Operates on the response stream and database ingestion pipelines:
- Inspects LLM-generated completions before they are written to vector databases (e.g. Pinecone, Chroma, Qdrant) or used for fine-tuning datasets.
- Identifies and strips persistent poisoning payloads (e.g., hidden prompt instructions injected into training data).
- Detects hallucinations, toxic outputs, and accidental credential leakage.
- Buffers reviews into an asynchronous non-blocking background queue to guarantee zero throughput degradation.

---

## Fault Tolerance & Circuit Breakers

Security guardrails must never become a single point of failure that downs production services. PyGenGuard integrates stateful **Circuit Breakers** across every plane:

- **State Closed**: Normal operation. All evaluations pass through.
- **State Open**: If a plane fails consecutively beyond `failure_threshold` (e.g. 5 failures), the breaker trips. Calls are short-circuited in 0.0ms.
  - In `fail_open=True` mode: Requests pass through with a warning log.
  - In `fail_open=False` mode: Requests are safely blocked.
- **State Half-Open**: After `recovery_timeout_sec`, a single recovery probe is allowed through. If successful, the circuit automatically resets to `CLOSED`.
