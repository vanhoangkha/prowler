"""API views for DSPM - Data Security Posture Management."""

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework import status


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def data_inventory(request: Request) -> Response:
    """Get data store inventory with classification."""
    return Response({"data_stores": [], "total": 0})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def trigger_classification_scan(request: Request) -> Response:
    """Trigger data classification scan."""
    provider_id = request.data.get("provider_id")
    if not provider_id:
        return Response({"error": "provider_id required"}, status=status.HTTP_400_BAD_REQUEST)
    return Response({"status": "queued", "provider_id": provider_id}, status=status.HTTP_202_ACCEPTED)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def data_risk_findings(request: Request) -> Response:
    """Get data risk findings (public + sensitive, unencrypted, over-permissioned)."""
    return Response({"findings": [], "total": 0})
