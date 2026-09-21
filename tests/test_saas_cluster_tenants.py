"""
Tests for SaaS Multi-Tenancy, Tenant BYOK Vaults, and Server Farm Cluster Management.
"""

import pytest
import time
from unittest.mock import patch

from pygenguard import Guard, Session
from pygenguard.saas.tenant import TenantConfig, TenantManager
from pygenguard.saas.cluster import ClusterManager, InMemoryStateStore
from pygenguard.byok.judge import BYOKConfig, JudgeVerdict


class TestSaaSClusterTenants:

    def test_tenant_manager_crud(self):
        manager = TenantManager()

        # 1. Register tenant
        cfg = TenantConfig(
            tenant_id="tenant_fintech_1",
            name="FinTech Corp",
            max_requests_per_minute=2000,
            byok_config=BYOKConfig(provider="openai", api_key="sk-fintech-key"),
        )
        manager.register_tenant(cfg)

        # 2. Retrieve tenant
        retrieved = manager.get_tenant("tenant_fintech_1")
        assert retrieved is not None
        assert retrieved.name == "FinTech Corp"
        assert retrieved.byok_config.api_key == "sk-fintech-key"

        # 3. Update BYOK
        manager.set_tenant_byok("tenant_fintech_1", BYOKConfig(provider="anthropic", api_key="sk-ant-new"))
        assert manager.get_tenant("tenant_fintech_1").byok_config.provider == "anthropic"

        # 4. List and Delete
        assert "tenant_fintech_1" in manager.list_tenants()
        assert manager.delete_tenant("tenant_fintech_1")
        assert manager.get_tenant("tenant_fintech_1") is None

    def test_in_memory_state_store_and_ttls(self):
        store = InMemoryStateStore()
        store.set("session_counter", "10")
        assert store.get("session_counter") == "10"

        # Atomic increment
        new_val = store.incr("session_counter", 5)
        assert new_val == 15
        assert store.get("session_counter") == "15"

        # TTL expiration
        store.set("temp_token", "abc123xyz", ttl_sec=0.1)
        assert store.get("temp_token") == "abc123xyz"
        time.sleep(0.15)
        assert store.get("temp_token") is None

    def test_cluster_manager_telemetry(self):
        cluster = ClusterManager(node_id="worker_east_1")
        cluster.record_inspection(allowed=True)
        cluster.record_inspection(allowed=False)
        cluster.record_inspection(allowed=True)

        health = cluster.get_node_health()
        assert health.node_id == "worker_east_1"
        assert health.total_inspections == 3
        assert health.blocked_count == 1
        assert health.status == "HEALTHY"
        assert abs(health.metadata["block_rate_percent"] - 33.33) < 0.1

    def test_guard_with_tenant_and_cluster_integration(self):
        guard = Guard()

        # Register tenant with BYOK
        guard.register_tenant(TenantConfig(
            tenant_id="tenant_alpha",
            name="Alpha Corp",
            byok_config=BYOKConfig(provider="openai", api_key="sk-alpha-vault-key"),
        ))

        # Check tenant retrieval
        tenant = guard.get_tenant("tenant_alpha")
        assert tenant is not None
        assert tenant.byok_config.api_key == "sk-alpha-vault-key"

        # Run inspect to verify cluster metrics increment
        session = Session(user_id="user_alpha_1", tenant_id="tenant_alpha")
        guard.inspect("Hello from Alpha tenant", session=session)

        cluster_health = guard.get_cluster_health()
        assert cluster_health.total_inspections >= 1
