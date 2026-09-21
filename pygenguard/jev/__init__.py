"""
Jev Tokenless "System One" Execution & Dual-Layer Governance Module for PyGenGuard.

Provides:
- Tokenless System One Execution via direct Pydantic schemas.
- Dual-Layer Governance: Pre-Execution Blocking & Post-Execution KB Filtering.
- High-concurrency scaling with AsyncJevClient.
"""

from pygenguard.jev.schemas import (
    JevPreExecutionVerdict,
    JevPostExecutionVerdict,
    JevClientConfig,
)
from pygenguard.jev.client import JevClient, AsyncJevClient
from pygenguard.jev.engine import DualLayerGovernanceEngine, KBDatasetReviewResult
from pygenguard.jev.middleware import JevGatewayMiddleware

__all__ = [
    "JevPreExecutionVerdict",
    "JevPostExecutionVerdict",
    "JevClientConfig",
    "JevClient",
    "AsyncJevClient",
    "DualLayerGovernanceEngine",
    "KBDatasetReviewResult",
    "JevGatewayMiddleware",
]
