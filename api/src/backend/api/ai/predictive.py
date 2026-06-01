"""Predictive Risk Engine.

Analyzes infrastructure change trends to predict future risk exposure.
Uses historical scan data to forecast security posture degradation.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


@dataclass
class RiskTrend:
    metric: str
    current_value: float
    previous_value: float
    change_percent: float
    direction: str  # increasing, decreasing, stable
    prediction_7d: float
    risk_impact: str  # positive, negative, neutral


@dataclass
class PredictiveReport:
    generated_at: str
    overall_risk_score: float  # 0-10
    predicted_risk_7d: float
    risk_direction: str
    trends: list[RiskTrend] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)


def compute_risk_trend(current: float, previous: float) -> RiskTrend:
    """Compute trend between two data points."""
    if previous == 0:
        change = 100.0 if current > 0 else 0.0
    else:
        change = ((current - previous) / previous) * 100

    direction = "increasing" if change > 5 else "decreasing" if change < -5 else "stable"
    # Simple linear projection
    prediction = current + (current - previous)

    return RiskTrend(
        metric="",
        current_value=current,
        previous_value=previous,
        change_percent=round(change, 1),
        direction=direction,
        prediction_7d=round(max(0, prediction), 1),
        risk_impact="negative" if change > 5 else "positive" if change < -5 else "neutral",
    )


def generate_predictive_report(
    current_findings: int = 0,
    previous_findings: int = 0,
    current_critical: int = 0,
    previous_critical: int = 0,
    current_public_resources: int = 0,
    previous_public_resources: int = 0,
    current_admin_identities: int = 0,
    previous_admin_identities: int = 0,
    current_unencrypted: int = 0,
    previous_unencrypted: int = 0,
) -> PredictiveReport:
    """Generate predictive risk report from scan metrics."""
    trends = []
    alerts = []
    actions = []

    # Findings trend
    t = compute_risk_trend(current_findings, previous_findings)
    t.metric = "total_findings"
    trends.append(t)
    if t.direction == "increasing" and t.change_percent > 20:
        alerts.append(f"Findings increasing rapidly (+{t.change_percent}% week-over-week)")

    # Critical findings
    t = compute_risk_trend(current_critical, previous_critical)
    t.metric = "critical_findings"
    trends.append(t)
    if t.direction == "increasing":
        alerts.append(f"Critical findings growing: {int(t.current_value)} → predicted {int(t.prediction_7d)} in 7 days")
        actions.append("URGENT: Address critical findings before they compound")

    # Public resources
    t = compute_risk_trend(current_public_resources, previous_public_resources)
    t.metric = "public_resources"
    trends.append(t)
    if t.direction == "increasing":
        alerts.append(f"Attack surface expanding: {int(t.change_percent)}% more public resources")
        actions.append("Review newly public resources — apply network restrictions")

    # Admin identities
    t = compute_risk_trend(current_admin_identities, previous_admin_identities)
    t.metric = "admin_identities"
    trends.append(t)
    if t.direction == "increasing":
        alerts.append(f"Privilege creep detected: {int(t.current_value)} admin identities (+{int(t.change_percent)}%)")
        actions.append("Audit new admin roles — apply least privilege")

    # Unencrypted
    t = compute_risk_trend(current_unencrypted, previous_unencrypted)
    t.metric = "unencrypted_stores"
    trends.append(t)
    if current_unencrypted > 0:
        actions.append(f"Encrypt {current_unencrypted} unencrypted data stores")

    # Overall score (weighted)
    score = min(10.0, (
        (current_critical * 2.0) +
        (current_public_resources * 0.5) +
        (current_admin_identities * 0.3) +
        (current_unencrypted * 0.4)
    ))

    # Predicted score
    negative_trends = sum(1 for t in trends if t.risk_impact == "negative")
    predicted = min(10.0, score + (negative_trends * 0.5))

    risk_direction = "worsening" if predicted > score else "improving" if predicted < score else "stable"

    if not actions:
        actions.append("Maintain current security posture — no immediate action needed")

    return PredictiveReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        overall_risk_score=round(score, 1),
        predicted_risk_7d=round(predicted, 1),
        risk_direction=risk_direction,
        trends=trends,
        alerts=alerts,
        recommended_actions=actions,
    )
