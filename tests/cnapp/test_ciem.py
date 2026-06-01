"""Tests for CIEM permission analyzer."""

import sys
sys.path.insert(0, "api/src/backend")

from tasks.jobs.ciem.analyzer import (
    PermissionAnalyzer,
    IdentityProfile,
    Permission,
    RiskLevel,
)


def _make_profile(actions: list[str], used: list[str] | None = None) -> IdentityProfile:
    permissions = [
        Permission(action=a, resource="*", effect="Allow", source="test-policy")
        for a in actions
    ]
    return IdentityProfile(
        identity_id="arn:aws:iam::123:user/test",
        identity_type="user",
        provider="aws",
        name="test",
        granted_permissions=permissions,
        used_permissions=used or [],
    )


def test_admin_over_privileged_is_critical():
    analyzer = PermissionAnalyzer()
    profile = _make_profile(["*", "s3:GetObject", "ec2:DescribeInstances"], used=["s3:GetObject"])
    result = analyzer.analyze_identity(profile)
    assert result.risk_level == RiskLevel.CRITICAL
    assert result.is_over_privileged


def test_minimal_permissions_is_low_risk():
    analyzer = PermissionAnalyzer()
    profile = _make_profile(["s3:GetObject", "s3:ListBucket"], used=["s3:GetObject", "s3:ListBucket"])
    result = analyzer.analyze_identity(profile)
    assert result.risk_level == RiskLevel.LOW
    assert not result.is_over_privileged


def test_blast_radius_admin():
    analyzer = PermissionAnalyzer()
    profile = _make_profile(["*"])
    blast = analyzer.compute_blast_radius(profile)
    assert blast.admin_access
    assert blast.score >= 5.0


def test_blast_radius_readonly():
    analyzer = PermissionAnalyzer()
    profile = _make_profile(["s3:GetObject", "ec2:Describe*"])
    blast = analyzer.compute_blast_radius(profile)
    assert not blast.admin_access
    assert blast.score < 5.0


def test_recommendations_generated():
    analyzer = PermissionAnalyzer()
    profile = _make_profile(
        ["*", "iam:*", "s3:*", "ec2:*", "rds:*", "lambda:*"],
        used=["s3:GetObject"],
    )
    result = analyzer.analyze_identity(profile)
    assert len(result.recommendations) > 0


def test_unused_permissions_detected():
    analyzer = PermissionAnalyzer()
    profile = _make_profile(
        ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "ec2:RunInstances"],
        used=["s3:GetObject"],
    )
    result = analyzer.analyze_identity(profile)
    assert "s3:PutObject" in result.unused_permissions
    assert "s3:GetObject" not in result.unused_permissions
