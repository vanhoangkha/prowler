"""Tests for the risk scoring engine."""

import sys
sys.path.insert(0, "api/src/backend")

from api.attack_paths.scoring import compute_risk_score, Severity, RiskScore


def test_zero_score_no_risk():
    score = compute_risk_score()
    assert score.total == 0.0
    assert score.exploitability == 0.0
    assert score.impact == 0.0


def test_critical_vuln_exposed_privileged():
    score = compute_risk_score(
        is_internet_exposed=True,
        has_vulnerabilities=True,
        vulnerability_severity=Severity.CRITICAL,
        has_high_privileges=True,
        has_sensitive_data_access=True,
    )
    assert score.total > 0
    assert score.exploitability == 1.0
    assert score.impact == 1.0
    assert score.exposure > 0


def test_medium_vuln_no_exposure():
    score = compute_risk_score(
        has_vulnerabilities=True,
        vulnerability_severity=Severity.MEDIUM,
    )
    assert score.total == 0.0  # no exposure = 0 total
    assert score.exploitability > 0


def test_internet_exposed_only():
    score = compute_risk_score(is_internet_exposed=True)
    assert score.exploitability == 0.3
    assert score.exposure == 0.4


def test_hop_count_increases_exposure():
    score1 = compute_risk_score(is_internet_exposed=True, has_high_privileges=True, hop_count=1)
    score2 = compute_risk_score(is_internet_exposed=True, has_high_privileges=True, hop_count=3)
    assert score2.exposure > score1.exposure


def test_score_capped_at_10():
    score = compute_risk_score(
        is_internet_exposed=True,
        has_vulnerabilities=True,
        vulnerability_severity=Severity.CRITICAL,
        has_high_privileges=True,
        has_sensitive_data_access=True,
        hop_count=10,
        finding_count=50,
    )
    assert score.total <= 10.0
