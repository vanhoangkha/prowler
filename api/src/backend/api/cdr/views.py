"""API views for CDR - Cloud Detection & Response."""

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework import status

from tasks.jobs.cdr.engine import BUILTIN_RULES, AlertSeverity


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_alerts(request: Request) -> Response:
    """List security alerts."""
    severity = request.query_params.get("severity")
    alert_status = request.query_params.get("status", "open")
    # TODO: Query from database
    return Response({"alerts": [], "total": 0, "filters": {"severity": severity, "status": alert_status}})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_detection_rules(request: Request) -> Response:
    """List detection rules."""
    provider = request.query_params.get("provider")
    rules = BUILTIN_RULES
    if provider:
        rules = [r for r in rules if r.provider in (provider, "all")]
    data = [{
        "id": r.id, "name": r.name, "description": r.description,
        "severity": r.severity.value, "provider": r.provider,
        "mitre_tactic": r.mitre_tactic, "mitre_technique": r.mitre_technique,
        "enabled": r.enabled,
    } for r in rules]
    return Response({"rules": data, "total": len(data)})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def acknowledge_alert(request: Request) -> Response:
    """Acknowledge or resolve an alert."""
    alert_id = request.data.get("alert_id")
    new_status = request.data.get("status")  # acknowledged, resolved, false_positive
    if not alert_id or not new_status:
        return Response({"error": "alert_id and status required"}, status=status.HTTP_400_BAD_REQUEST)
    return Response({"alert_id": alert_id, "status": new_status, "message": "Alert updated"})
