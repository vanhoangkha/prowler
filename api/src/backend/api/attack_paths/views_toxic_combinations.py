"""API views for toxic combination detection."""

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from api.attack_paths.toxic_combinations import (
    TOXIC_COMBINATIONS,
    get_toxic_combinations_for_provider,
    get_toxic_combination_by_id,
)
from api.attack_paths.scoring import Severity, compute_risk_score


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_toxic_combinations(request: Request) -> Response:
    """List all available toxic combination patterns.

    Query params:
        provider: Filter by provider (aws, azure, gcp)
    """
    provider = request.query_params.get("provider")

    if provider:
        combinations = get_toxic_combinations_for_provider(provider)
    else:
        combinations = TOXIC_COMBINATIONS

    data = [
        {
            "id": tc.id,
            "name": tc.name,
            "description": tc.description,
            "severity": tc.severity,
            "providers": tc.providers,
            "conditions": tc.conditions,
        }
        for tc in combinations
    ]

    return Response({"data": data, "count": len(data)})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def compute_score(request: Request) -> Response:
    """Compute risk score for given parameters.

    Body:
        is_internet_exposed: bool
        has_vulnerabilities: bool
        vulnerability_severity: str (critical/high/medium/low/info)
        has_high_privileges: bool
        has_sensitive_data_access: bool
        hop_count: int
        finding_count: int
    """
    data = request.data
    severity_str = data.get("vulnerability_severity", "info")
    try:
        severity = Severity(severity_str)
    except ValueError:
        severity = Severity.INFO

    score = compute_risk_score(
        is_internet_exposed=data.get("is_internet_exposed", False),
        has_vulnerabilities=data.get("has_vulnerabilities", False),
        vulnerability_severity=severity,
        has_high_privileges=data.get("has_high_privileges", False),
        has_sensitive_data_access=data.get("has_sensitive_data_access", False),
        hop_count=data.get("hop_count", 0),
        finding_count=data.get("finding_count", 0),
    )

    return Response({
        "score": score.total,
        "exploitability": score.exploitability,
        "impact": score.impact,
        "exposure": score.exposure,
        "factors": score.factors,
    })
