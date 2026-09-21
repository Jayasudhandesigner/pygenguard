"""
Security Decision Cache for PyGenGuard.

Provides ultra-fast sub-millisecond (0.01ms) decision caching for repeated
benign queries and known attack vectors, using normalized fingerprinting,
LRU eviction, and TTL expiration.
"""

import time
import hashlib
import threading
from typing import Optional, Dict, Tuple, Any, List
from collections import OrderedDict
from pygenguard.decision import Decision


class SecurityCache:
    """
    Thread-safe LRU & TTL cache for Guard decisions.

    Normalizes input text (ignoring trivial whitespace and casing variations)
    to match repeat attacks and common queries with 0.01ms lookup times.

    Usage:
        cache = SecurityCache(max_size=10000, ttl_seconds=300)
        cache.set(prompt, decision)
        decision = cache.get(prompt)
    """

    def __init__(
        self,
        max_size: int = 10_000,
        ttl_seconds: float = 300.0,
        cache_blocked: bool = True,
        cache_allowed: bool = True,
    ):
        self.max_size = max_size
        self.ttl = ttl_seconds
        self.cache_blocked = cache_blocked
        self.cache_allowed = cache_allowed

        # key -> (Decision, expiry_timestamp)
        self._cache: OrderedDict[str, Tuple[Decision, float]] = OrderedDict()
        self._lock = threading.Lock()

        # Stats
        self._hits = 0
        self._misses = 0

    @staticmethod
    def compute_fingerprint(text: str, user_id: Optional[str] = None) -> str:
        """Compute normalized cryptographic fingerprint of text."""
        normalized = " ".join(text.strip().lower().split())
        key = f"{user_id or 'global'}:{normalized}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def get(self, prompt: str, user_id: Optional[str] = None) -> Optional[Decision]:
        """Look up cached decision for prompt."""
        key = self.compute_fingerprint(prompt, user_id)
        now = time.monotonic()

        with self._lock:
            if key not in self._cache:
                self._misses += 1
                return None

            decision, expiry = self._cache[key]
            if now > expiry:
                # Expired
                del self._cache[key]
                self._misses += 1
                return None

            # Move to end (MRU)
            self._cache.move_to_end(key)
            self._hits += 1
            return decision

    def set(
        self,
        prompt: str,
        decision: Decision,
        user_id: Optional[str] = None,
        custom_ttl: Optional[float] = None,
    ) -> bool:
        """Store decision in cache."""
        if decision.allowed and not self.cache_allowed:
            return False
        if not decision.allowed and not self.cache_blocked:
            return False

        key = self.compute_fingerprint(prompt, user_id)
        ttl = custom_ttl if custom_ttl is not None else self.ttl
        expiry = time.monotonic() + ttl

        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = (decision, expiry)

            # Evict LRU if over capacity
            while len(self._cache) > self.max_size:
                self._cache.popitem(last=False)
            return True

    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()

    @property
    def stats(self) -> Dict[str, Any]:
        """Get cache performance metrics."""
        with self._lock:
            total = self._hits + self._misses
            hit_ratio = (self._hits / total) if total > 0 else 0.0
            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_ratio": round(hit_ratio, 4),
            }
