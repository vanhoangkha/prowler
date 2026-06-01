"""API views for AI-Native Security features."""

from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle
from rest_framework import status

from api.ai.query_engine import (
    match_query_template,
    build_llm_prompt,
    generate_risk_summary,
    generate_recommendations,
    QUERY_TEMPLATES,
)
from api.ai.remediation import (
    generate_remediation,
    generate_pr_body,
    REMEDIATION_TEMPLATES,
)


class AIQueryThrottle(UserRateThrottle):
    rate = '30/hour'


@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([AIQueryThrottle])
def ask_security_question(request: Request) -> Response:
    """Ask a natural language security question.

    Body:
        question: str - Natural language security question
        provider_uid: str (optional) - Scope to specific provider
    """
    question = request.data.get("question", "").strip()
    if not question or len(question) > 500:
        return Response(
            {"error": "question required (max 500 chars)"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Try template matching first (fast, no LLM needed)
    template = match_query_template(question)

    if template:
        return Response({
            "method": "template",
            "question": question,
            "cypher": template["cypher"].strip(),
            "explanation": template["explanation"],
            "results": [],  # TODO: Execute against Neo4j
            "recommendations": [],
            "note": "Execute this query against your Neo4j graph for results.",
        })

    # Fall back to LLM prompt generation
    prompt = build_llm_prompt(question)
    return Response({
        "method": "llm_required",
        "question": question,
        "llm_prompt": prompt,
        "note": "Send this prompt to your LLM (Claude/GPT via Bedrock) to generate the Cypher query.",
        "supported_templates": list(QUERY_TEMPLATES.keys()),
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_query_templates(request: Request) -> Response:
    """List available pre-built security query templates."""
    templates = [
        {
            "id": tid,
            "patterns": t["patterns"],
            "explanation": t["explanation"],
            "example_questions": t["patterns"][:2],
        }
        for tid, t in QUERY_TEMPLATES.items()
    ]
    return Response({"templates": templates, "total": len(templates)})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def generate_fix(request: Request) -> Response:
    """Generate IaC remediation for a finding.

    Body:
        finding_type: str - e.g., "s3_bucket_public_access"
        context: dict - Resource details (bucket_name, sg_id, etc.)
    """
    finding_type = request.data.get("finding_type", "")
    context = request.data.get("context", {})

    if not finding_type:
        return Response(
            {"error": "finding_type required"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if finding_type not in REMEDIATION_TEMPLATES:
        return Response({
            "error": f"Unknown finding_type. Available: {list(REMEDIATION_TEMPLATES.keys())}",
        }, status=status.HTTP_400_BAD_REQUEST)

    patch = generate_remediation(finding_type, context)
    if not patch:
        return Response({"error": "Could not generate remediation"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({
        "finding_type": finding_type,
        "patch": {
            "iac_type": patch.iac_type,
            "code": patch.patch_code,
            "explanation": patch.explanation,
            "risk_of_change": patch.risk_of_change,
            "requires_downtime": patch.requires_downtime,
            "auto_applicable": patch.auto_applicable,
        },
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_remediations(request: Request) -> Response:
    """List available auto-remediation templates."""
    remediations = [
        {
            "finding_type": ftype,
            "explanation": t["explanation"],
            "risk": t.get("risk", "medium"),
            "requires_downtime": t.get("downtime", False),
            "iac_types": [k for k in t.keys() if k not in ("explanation", "risk", "downtime")],
        }
        for ftype, t in REMEDIATION_TEMPLATES.items()
    ]
    return Response({"remediations": remediations, "total": len(remediations)})
