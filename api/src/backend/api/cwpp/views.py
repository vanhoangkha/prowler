"""API views for CWPP agentless scanning."""

from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle
from rest_framework import status

from api.cnapp_permissions import validate_provider_access, validate_string_param


class ScanRateThrottle(UserRateThrottle):
    rate = '10/hour'


@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([ScanRateThrottle])
def trigger_vm_scan(request: Request) -> Response:
    """Trigger agentless VM scan."""
    provider_id = request.data.get("provider_id")
    if not provider_id:
        return Response({"error": "provider_id is required"}, status=status.HTTP_400_BAD_REQUEST)

    # Tenant isolation: verify user owns this provider
    provider = validate_provider_access(request, provider_id)

    instance_ids = request.data.get("instance_ids")
    scan_types = request.data.get("scan_types", ["vulnerability", "secret"])

    # Validate scan_types
    allowed_types = {"vulnerability", "secret", "malware", "sbom"}
    if not all(t in allowed_types for t in scan_types):
        return Response({"error": f"scan_types must be subset of {allowed_types}"}, status=status.HTTP_400_BAD_REQUEST)

    return Response({
        "status": "queued",
        "provider_id": str(provider.id),
        "scan_types": scan_types,
    }, status=status.HTTP_202_ACCEPTED)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([ScanRateThrottle])
def trigger_container_scan(request: Request) -> Response:
    """Trigger container image scan."""
    provider_id = request.data.get("provider_id")
    if not provider_id:
        return Response({"error": "provider_id is required"}, status=status.HTTP_400_BAD_REQUEST)

    provider = validate_provider_access(request, provider_id)
    repositories = request.data.get("repositories")

    return Response({
        "status": "queued",
        "provider_id": str(provider.id),
    }, status=status.HTTP_202_ACCEPTED)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def scan_status(request: Request) -> Response:
    """Get scan status (scoped to user's providers)."""
    return Response({"scans": [], "total": 0})
