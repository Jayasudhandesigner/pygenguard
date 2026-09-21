# Resilience, Rate Limiting & Streaming Guard

## Resilience & Fault Tolerance

Security controls should never cause unexpected cascading downtime in production systems. PyGenGuard builds resilience directly into the core execution pipeline.

### Circuit Breakers (`pygenguard.resilience`)

Each security plane is guarded by an individual circuit breaker implementing the classic Three-State Pattern:

```
      +-------------+
      |   CLOSED    | <---------------+
      | (Pass-thru) |                 |
      +-------------+                 |
             |                        |
     [Threshold Failures]       [Probe Succeeds]
             |                        |
             v                        |
      +-------------+          +-------------+
      |    OPEN     | -------> |  HALF_OPEN  |
      | (Tripped)   | [Timeout]|   (Probe)   |
      +-------------+          +-------------+
```

```python
from pygenguard.resilience import CircuitBreaker, CircuitBreakerConfig

config = CircuitBreakerConfig(
    failure_threshold=5,         # Consecutive failures to trip
    recovery_timeout_sec=30.0,   # Wait time before probing recovery
    fail_open=True,              # True = ALLOW requests when tripped; False = BLOCK
)

breaker = CircuitBreaker("intent", config)
result = breaker.call(plane.evaluate, user_prompt)
```

---

## Rate Limiting Algorithms (`pygenguard.rate_limiter`)

### 1. Sliding Window Counter (`SlidingWindowCounter`)
Provides smooth, edge-free rate limiting per user, tenant, or API key:

```python
from pygenguard.rate_limiter import SlidingWindowCounter

limiter = SlidingWindowCounter(window_seconds=60, max_requests=100)
result = limiter.check_and_increment("user_123")

if not result.allowed:
    print(f"Rate limited. Retry after {result.retry_after_seconds:.1f}s")
```

### 2. Token Bucket (`TokenBucket`)
Allows burst-tolerant operations where short bursts of requests are permitted while maintaining a steady average rate:

```python
from pygenguard.rate_limiter import TokenBucket

bucket = TokenBucket(rate_per_second=10.0, burst_size=25)
result = bucket.consume("api_key_456", count=5)
```

---

## Streaming Output Guard (`pygenguard.streaming`)

For applications utilizing streaming token generators (e.g., `stream=True` in OpenAI or Anthropic SDKs), buffering the entire response defeats low-latency UX. 

`StreamingOutputGuard` inspects tokens in real-time across a sliding character buffer window, detecting secrets, PII, and system leaks across chunk boundaries:

```python
from pygenguard.streaming import StreamingOutputGuard

stream_guard = StreamingOutputGuard(buffer_window_chars=40, stop_on_critical_threat=True)

# Asynchronous streaming generator wrapping
async def stream_chat_response():
    async for safe_token in stream_guard.wrap_async_stream(llm_token_generator):
        yield safe_token
```

---

## Dynamic Honey-Tokens & Canary Manager (`pygenguard.canary`)

`CanaryManager` injects session-unique, cryptographically salted honey-tokens into system prompts. If an attacker successfully tricks an LLM into leaking its system instructions, the presence of the canary token in the output guarantees 100% false-positive-free detection:

```python
from pygenguard.canary import CanaryManager
from pygenguard.session import Session

canary_mgr = CanaryManager()
session = Session(user_id="alice")

# 1. Inject canary into system prompt
secured_sys_prompt = canary_mgr.inject("You are a financial advisor.", session)

# 2. Verify model output post-generation
result = canary_mgr.verify(model_response_text, session)
if not result.passed:
    print("CRITICAL: System prompt exfiltration detected via canary token!")
```
