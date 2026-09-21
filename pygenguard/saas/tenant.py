"""
SaaS Multi-Tenant Configuration & BYOK Vault Manager for PyGenGuard.

Provides isolated policy scopes, tenant-specific rate limits and token quotas,
and customer-managed BYOK credential vaulting for server farm deployments.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, Any, List
from pygenguard.policy import Policy
from pygenguard.byok.judge import BYOKConfig


@dataclass
class TenantConfig:
    """Isolated security configuration for a single SaaS customer/tenant."""
    tenant_id: str
    name: str = ""
    policy: Optional[Policy] = None
    byok_config: Optional[BYOKConfig] = None
    max_requests_per_minute: int = 1200
    monthly_token_quota: int = 50_000_000
    metadata: Dict[str, Any] = field(default_factory=dict)


class TenantManager:
    """
    Registry for SaaS multi-tenancy and BYOK key management.

    Usage:
        tenants = TenantManager()
        tenants.register_tenant(TenantConfig(
            tenant_id="org_acme_corp",
            name="Acme Corp",
            byok_config=BYOKConfig(provider="openai", api_key="sk-..."),
        ))
        cfg = tenants.get_tenant("org_acme_corp")
    """

    def __init__(self):
        self._tenants: Dict[str, TenantConfig] = {}

    def register_tenant(self, config: TenantConfig) -> None:
        """Register or update a tenant's security scope and BYOK configuration."""
        self._tenants[config.tenant_id] = config

    def get_tenant(self, tenant_id: str) -> Optional[TenantConfig]:
        """Retrieve tenant configuration by tenant_id."""
        return self._tenants.get(tenant_id)

    def set_tenant_byok(self, tenant_id: str, byok_config: BYOKConfig) -> bool:
        """Update or register BYOK credentials for a specific tenant."""
        tenant = self._tenants.get(tenant_id)
        if not tenant:
            tenant = TenantConfig(tenant_id=tenant_id, byok_config=byok_config)
            self._tenants[tenant_id] = tenant
            return True
        tenant.byok_config = byok_config
        return True

    def delete_tenant(self, tenant_id: str) -> bool:
        """Remove a tenant from the registry."""
        if tenant_id in self._tenants:
            del self._tenants[tenant_id]
            return True
        return False

    def list_tenants(self) -> List[str]:
        """List all active tenant IDs."""
        return list(self._tenants.keys())
