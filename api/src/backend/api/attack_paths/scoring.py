"""Risk scoring engine for attack paths and toxic combinations.

Scoring formula: Risk = Exploitability × Impact × Exposure

Each factor is scored 0.0-1.0, final score is 0-10.
"""

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.2,
    Severity.INFO: 0.0,
}


@dataclass
class RiskScore:
    total: float  # 0-10
    exploitability: float  # 0-1
    impact: float  # 0-1
    exposure: float  # 0-1
    factors: dict  # explanation of scoring


def compute_risk_score(
    is_internet_exposed: bool = False,
    has_vulnerabilities: bool = False,
    vulnerability_severity: Severity = Severity.INFO,
    has_high_privileges: bool = False,
    has_sensitive_data_access: bool = False,
    hop_count: int = 0,
    finding_count: int = 0,
) -> RiskScore:
    """Compute weighted risk score for an attack path."""
    factors = {}

    # Exploitability: how easy to exploit
    exploitability = 0.0
    if has_vulnerabilities:
        exploitability += SEVERITY_WEIGHTS.get(vulnerability_severity, 0.0) * 0.7
        factors["vulnerability"] = vulnerability_severity.value
    if is_internet_exposed:
        exploitability += 0.3
        factors["internet_exposed"] = True
    exploitability = min(exploitability, 1.0)

    # Impact: what damage can be done
    impact = 0.0
    if has_high_privileges:
        impact += 0.5
        factors["high_privileges"] = True
    if has_sensitive_data_access:
        impact += 0.5
        factors["sensitive_data"] = True
    impact = min(impact, 1.0)

    # Exposure: blast radius
    exposure = 0.0
    if is_internet_exposed:
        exposure += 0.4
    if hop_count > 0:
        exposure += min(hop_count * 0.15, 0.4)
        factors["hop_count"] = hop_count
    if finding_count > 0:
        exposure += min(finding_count * 0.05, 0.2)
        factors["finding_count"] = finding_count
    exposure = min(exposure, 1.0)

    total = round(exploitability * impact * exposure * 10, 1)

    return RiskScore(
        total=total,
        exploitability=round(exploitability, 2),
        impact=round(impact, 2),
        exposure=round(exposure, 2),
        factors=factors,
    )
