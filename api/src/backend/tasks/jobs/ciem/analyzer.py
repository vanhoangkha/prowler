"""CIEM - Effective Permission Analyzer.

Computes effective permissions for cloud identities by evaluating
policy chains (identity policies + resource policies + SCPs + boundaries).
"""

from dataclasses import dataclass, field
from enum import Enum
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Permission:
    action: str
    resource: str
    effect: str  # Allow or Deny
    condition: dict | None = None
    source: str = ""  # policy ARN/name that grants this


@dataclass
class IdentityProfile:
    identity_id: str
    identity_type: str  # user, role, service_account, service_principal
    provider: str
    name: str
    granted_permissions: list[Permission] = field(default_factory=list)
    used_permissions: list[str] = field(default_factory=list)
    unused_permissions: list[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    is_over_privileged: bool = False
    last_activity: str | None = None
    recommendations: list[str] = field(default_factory=list)


@dataclass
class BlastRadius:
    identity_id: str
    accessible_resources: list[str] = field(default_factory=list)
    accessible_services: list[str] = field(default_factory=list)
    cross_account_access: list[str] = field(default_factory=list)
    sensitive_data_access: bool = False
    admin_access: bool = False
    score: float = 0.0  # 0-10


class PermissionAnalyzer:
    """Analyzes effective permissions and detects over-privileged identities."""

    ADMIN_ACTIONS = {'*', 'iam:*', 'sts:*', 'organizations:*'}
    SENSITIVE_ACTIONS = {
        's3:GetObject', 's3:PutObject', 'kms:Decrypt',
        'secretsmanager:GetSecretValue', 'ssm:GetParameter',
    }

    def analyze_identity(self, profile: IdentityProfile) -> IdentityProfile:
        """Analyze an identity's permissions and compute risk."""
        granted_actions = {p.action for p in profile.granted_permissions if p.effect == 'Allow'}

        # Check for admin access
        has_admin = bool(granted_actions & self.ADMIN_ACTIONS)

        # Check for sensitive data access
        has_sensitive = bool(granted_actions & self.SENSITIVE_ACTIONS)

        # Compute unused permissions
        used_set = set(profile.used_permissions)
        all_granted = granted_actions - {'*'}  # exclude wildcard for comparison
        profile.unused_permissions = sorted(all_granted - used_set)

        # Determine over-privileged status
        if profile.used_permissions:
            usage_ratio = len(used_set) / max(len(all_granted), 1)
            profile.is_over_privileged = usage_ratio < 0.3  # using less than 30%
        else:
            profile.is_over_privileged = len(all_granted) > 5

        # Compute risk level
        if has_admin and profile.is_over_privileged:
            profile.risk_level = RiskLevel.CRITICAL
        elif has_admin:
            profile.risk_level = RiskLevel.HIGH
        elif has_sensitive and profile.is_over_privileged:
            profile.risk_level = RiskLevel.HIGH
        elif profile.is_over_privileged:
            profile.risk_level = RiskLevel.MEDIUM

        # Generate recommendations
        profile.recommendations = self._generate_recommendations(profile, has_admin)

        return profile

    def compute_blast_radius(self, profile: IdentityProfile) -> BlastRadius:
        """Compute blast radius if identity is compromised."""
        granted_actions = {p.action for p in profile.granted_permissions if p.effect == 'Allow'}
        resources = {p.resource for p in profile.granted_permissions if p.effect == 'Allow'}

        services = set()
        for action in granted_actions:
            if ':' in action:
                services.add(action.split(':')[0])

        has_admin = bool(granted_actions & self.ADMIN_ACTIONS)
        has_sensitive = bool(granted_actions & self.SENSITIVE_ACTIONS)

        # Cross-account detection
        cross_account = [r for r in resources if ':' in r and 'arn:' in r]

        score = 0.0
        if has_admin:
            score += 5.0
        if has_sensitive:
            score += 2.0
        score += min(len(services) * 0.3, 2.0)
        score += min(len(cross_account) * 0.5, 1.0)
        score = min(score, 10.0)

        return BlastRadius(
            identity_id=profile.identity_id,
            accessible_resources=sorted(resources)[:50],
            accessible_services=sorted(services),
            cross_account_access=cross_account[:20],
            sensitive_data_access=has_sensitive,
            admin_access=has_admin,
            score=round(score, 1),
        )

    def _generate_recommendations(self, profile: IdentityProfile, has_admin: bool) -> list[str]:
        """Generate least-privilege recommendations."""
        recs = []
        if has_admin and profile.is_over_privileged:
            recs.append("Remove admin/wildcard permissions - identity uses only a subset of granted actions")
        if profile.unused_permissions and len(profile.unused_permissions) > 10:
            recs.append(f"Remove {len(profile.unused_permissions)} unused permissions to follow least-privilege")
        if not profile.last_activity:
            recs.append("No recent activity detected - consider disabling or removing this identity")
        if profile.used_permissions:
            recs.append(f"Create scoped policy with only the {len(profile.used_permissions)} actions actually used")
        return recs
