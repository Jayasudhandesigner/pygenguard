"""
RBAC (Role-Based Access Control) & Multi-Tenancy for PyGenGuard v1.0.

Provides:
- Role-based plane bypass and configuration
- Per-role token limits, tool permissions, and content restrictions
- Multi-tenant policy isolation
- Hierarchical role inheritance
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, List, Set, Any


@dataclass
class Role:
    """
    Definition of a security role with permissions and limits.

    Usage:
        admin_role = Role(
            name="admin",
            bypass_planes={"economics"},
            max_tokens_per_session=1_000_000,
            allowed_tools=None,  # None = all tools allowed
        )
    """
    name: str
    description: str = ""

    # Planes that this role can bypass (not evaluated)
    bypass_planes: Set[str] = field(default_factory=set)

    # Token limits
    max_tokens_per_session: int = 100_000
    max_tokens_per_minute: int = 50_000

    # Rate limits (overrides global rate limits)
    max_requests_per_minute: Optional[int] = None

    # Tool permissions for agentic workflows
    allowed_tools: Optional[Set[str]] = None    # None = all allowed
    blocked_tools: Set[str] = field(default_factory=set)

    # Content restrictions
    blocked_content_categories: Set[str] = field(default_factory=set)

    # Custom metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Role inheritance
    inherits_from: Optional[str] = None

    def can_bypass_plane(self, plane_name: str) -> bool:
        """Check if this role bypasses a specific plane."""
        return plane_name in self.bypass_planes

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check if a tool is allowed for this role."""
        if tool_name in self.blocked_tools:
            return False
        if self.allowed_tools is not None:
            return tool_name in self.allowed_tools
        return True  # All tools allowed by default


@dataclass
class Tenant:
    """
    Tenant configuration for multi-tenant deployments.

    Each tenant can have its own policy overrides and role definitions.
    """
    tenant_id: str
    name: str = ""
    enabled: bool = True

    # Tenant-specific role overrides
    roles: Dict[str, Role] = field(default_factory=dict)

    # Global limits for this tenant
    max_requests_per_minute: int = 1000
    max_tokens_per_minute: int = 500_000

    # Policy overrides (merged with global policy)
    policy_overrides: Dict[str, Any] = field(default_factory=dict)

    # Custom metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


class RBACPolicy:
    """
    Role-Based Access Control policy manager.

    Usage:
        rbac = RBACPolicy()
        rbac.add_role(Role(name="admin", bypass_planes={"economics"}, max_tokens_per_session=1_000_000))
        rbac.add_role(Role(name="user", max_tokens_per_session=100_000))
        rbac.add_role(Role(name="guest", max_tokens_per_session=10_000, blocked_tools={"*"}))

        role = rbac.get_role("admin")
        if role.can_bypass_plane("economics"):
            # Skip economics plane for admins
    """

    def __init__(self, roles: Optional[Dict[str, Dict[str, Any]]] = None):
        self._roles: Dict[str, Role] = {}
        self._tenants: Dict[str, Tenant] = {}
        self._user_roles: Dict[str, str] = {}  # user_id -> role_name

        if roles:
            for role_name, role_config in roles.items():
                self.add_role(Role(
                    name=role_name,
                    bypass_planes=set(role_config.get("bypass_planes", [])),
                    max_tokens_per_session=role_config.get("max_tokens", 100_000),
                    max_tokens_per_minute=role_config.get("max_tokens_per_minute", 50_000),
                    max_requests_per_minute=role_config.get("max_requests_per_minute"),
                    allowed_tools=set(role_config["allowed_tools"]) if "allowed_tools" in role_config else None,
                    blocked_tools=set(role_config.get("blocked_tools", [])),
                    blocked_content_categories=set(role_config.get("blocked_content_categories", [])),
                    inherits_from=role_config.get("inherits_from"),
                ))

    def add_role(self, role: Role) -> None:
        """Register a role."""
        self._roles[role.name] = role

    def get_role(self, role_name: str) -> Optional[Role]:
        """Get a role by name, resolving inheritance."""
        role = self._roles.get(role_name)
        if role is None:
            return None

        if role.inherits_from and role.inherits_from in self._roles:
            parent = self._roles[role.inherits_from]
            # Merge parent into child (child overrides parent)
            merged = Role(
                name=role.name,
                description=role.description or parent.description,
                bypass_planes=parent.bypass_planes | role.bypass_planes,
                max_tokens_per_session=role.max_tokens_per_session or parent.max_tokens_per_session,
                max_tokens_per_minute=role.max_tokens_per_minute or parent.max_tokens_per_minute,
                max_requests_per_minute=role.max_requests_per_minute or parent.max_requests_per_minute,
                allowed_tools=role.allowed_tools if role.allowed_tools is not None else parent.allowed_tools,
                blocked_tools=parent.blocked_tools | role.blocked_tools,
                blocked_content_categories=parent.blocked_content_categories | role.blocked_content_categories,
                metadata={**parent.metadata, **role.metadata},
            )
            return merged

        return role

    def assign_role(self, user_id: str, role_name: str) -> None:
        """Assign a role to a user."""
        if role_name not in self._roles:
            raise ValueError(f"Role '{role_name}' not found")
        self._user_roles[user_id] = role_name

    def get_user_role(self, user_id: str) -> Optional[Role]:
        """Get the role assigned to a user."""
        role_name = self._user_roles.get(user_id)
        if role_name:
            return self.get_role(role_name)
        return None

    def should_bypass_plane(self, user_id: str, plane_name: str) -> bool:
        """Check if a user's role allows bypassing a specific plane."""
        role = self.get_user_role(user_id)
        if role:
            return role.can_bypass_plane(plane_name)
        return False

    def is_tool_allowed_for_user(self, user_id: str, tool_name: str) -> bool:
        """Check if a tool is allowed for a user based on their role."""
        role = self.get_user_role(user_id)
        if role:
            return role.is_tool_allowed(tool_name)
        return True  # Default: all tools allowed

    def add_tenant(self, tenant: Tenant) -> None:
        """Register a tenant."""
        self._tenants[tenant.tenant_id] = tenant

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Get tenant configuration."""
        return self._tenants.get(tenant_id)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RBACPolicy":
        """Create an RBAC policy from a dictionary."""
        return cls(roles=data.get("roles", {}))

    def list_roles(self) -> List[str]:
        """List all registered role names."""
        return list(self._roles.keys())

    def list_tenants(self) -> List[str]:
        """List all registered tenant IDs."""
        return list(self._tenants.keys())
