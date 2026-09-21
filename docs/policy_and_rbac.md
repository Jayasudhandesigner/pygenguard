# Policy-as-Code & Role-Based Access Control (RBAC)

## Policy-as-Code

PyGenGuard replaces hardcoded safety constants with a declarative, composable **Policy Engine**. Policies can be authored in Python dictionaries, YAML, or JSON, and support hierarchical inheritance and runtime hot-reloading.

### Guard Modes

- `strict`: Lowest tolerance. Higher threshold sensitivity; fails closed on any ambiguity.
- `balanced` (default): Production balance between security protection and low friction.
- `permissive`: Higher tolerance; only blocks critical high-confidence attacks.
- `shadow`: Audit/canary mode. Evaluates all security planes and logs results, but never blocks user prompts.

---

## Defining Policies

### 1. YAML Configuration

```yaml
version: "1.0"
name: "enterprise_production"
mode: "balanced"

planes:
  intent:
    enabled: true
    action_on_fail: "BLOCK"
    timeout_ms: 50.0
    fail_open: false

  compliance:
    enabled: true
    action_on_fail: "BLOCK"
    config:
      enforce_hipaa: true
      enforce_pci: true

  economics:
    enabled: true
    action_on_fail: "DEGRADE"
    timeout_ms: 20.0
    fail_open: true

rate_limits:
  enabled: true
  requests_per_minute: 120
  tokens_per_minute: 200000
  burst_allowance: 1.5

content_safety:
  enabled: true
  block_categories:
    - "hate_speech"
    - "self_harm"
    - "violence"
    - "sexual_content"
    - "illegal_activity"
  severity_threshold: 0.75
```

### 2. Loading & Merging in Python

```python
from pygenguard.policy import Policy

# Load from file
policy = Policy.from_file("policy.yaml")

# Override with environment or tenant customizations
tenant_override = Policy.from_dict({
    "rate_limits": {"requests_per_minute": 500}
})
effective_policy = policy.merge(tenant_override)
```

---

## Role-Based Access Control (RBAC) & Multi-Tenancy

PyGenGuard supports granular role definitions, role inheritance, and multi-tenant isolation.

```python
from pygenguard.rbac import RBACPolicy, Role, Tenant

rbac = RBACPolicy()

# Define Base Role
analyst_role = Role(
    name="analyst",
    max_tokens_per_session=200_000,
    allowed_tools={"query_analytics", "generate_chart"},
    blocked_tools={"execute_bash", "delete_records"},
)
rbac.add_role(analyst_role)

# Role Inheritance (Senior Analyst inherits Analyst permissions)
senior_analyst = Role(
    name="senior_analyst",
    inherits_from="analyst",
    max_tokens_per_session=1_000_000,
    allowed_tools={"query_analytics", "generate_chart", "export_dataset"},
)
rbac.add_role(senior_analyst)

# Admin Role with Plane Bypasses
admin_role = Role(
    name="admin",
    bypass_planes={"economics", "rate_limiter"},
    max_tokens_per_session=10_000_000,
    allowed_tools=None,  # All tools permitted
)
rbac.add_role(admin_role)

# Tenant Isolation
tenant_acme = Tenant(
    tenant_id="acme_corp",
    max_requests_per_minute=2000,
    max_tokens_per_minute=1_000_000,
)
rbac.add_tenant(tenant_acme)
```
