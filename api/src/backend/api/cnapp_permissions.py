"""CNAPP tenant isolation permissions.

Ensures users can only access providers belonging to their tenant.
Prevents cross-tenant data access (Critical security control).
"""

from uuid import UUID

from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.request import Request

from api.models import Provider


def validate_provider_access(request: Request, provider_id: str) -> Provider:
    """Validate that the authenticated user has access to the given provider.

    Args:
        request: DRF request with authenticated user
        provider_id: Provider UUID string from request data

    Returns:
        Provider instance if access is granted

    Raises:
        ValidationError: If provider_id is not a valid UUID
        NotFound: If provider doesn't exist or user has no access
    """
    # Validate UUID format
    try:
        UUID(provider_id)
    except (ValueError, TypeError):
        raise ValidationError({"provider_id": "Must be a valid UUID"})

    # Query with tenant scoping (RLS ensures user can only see their own)
    try:
        provider = Provider.objects.get(id=provider_id)
    except Provider.DoesNotExist:
        raise NotFound("Provider not found")

    # Additional check: verify provider belongs to user's tenant
    if hasattr(request, 'tenant_id') and hasattr(provider, 'tenant_id'):
        if str(provider.tenant_id) != str(request.tenant_id):
            raise NotFound("Provider not found")

    return provider


def validate_uuid_param(value: str, field_name: str = "id") -> str:
    """Validate a string is a valid UUID."""
    try:
        return str(UUID(value))
    except (ValueError, TypeError):
        raise ValidationError({field_name: "Must be a valid UUID"})


def validate_string_param(value: str | None, field_name: str, max_length: int = 2048) -> str | None:
    """Validate and sanitize a string parameter."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError({field_name: "Must be a string"})
    if len(value) > max_length:
        raise ValidationError({field_name: f"Must be at most {max_length} characters"})
    return value
