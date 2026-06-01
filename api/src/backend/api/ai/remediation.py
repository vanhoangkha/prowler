"""AI Auto-Remediation Engine.

Generates Infrastructure-as-Code patches (Terraform/CloudFormation)
for security findings and can create PRs automatically.
"""

from dataclasses import dataclass, field
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@dataclass
class RemediationPatch:
    finding_id: str
    finding_title: str
    severity: str
    resource_id: str
    resource_type: str
    iac_type: str  # terraform, cloudformation, cli
    patch_code: str
    explanation: str
    risk_of_change: str  # low, medium, high
    requires_downtime: bool = False
    auto_applicable: bool = True


# Remediation templates for common findings
REMEDIATION_TEMPLATES: dict[str, dict] = {
    "s3_bucket_public_access": {
        "terraform": '''resource "aws_s3_bucket_public_access_block" "{resource_name}" {{
  bucket                  = "{bucket_name}"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}''',
        "cli": 'aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
        "explanation": "Blocks all public access to the S3 bucket. Existing public objects will become private.",
        "risk": "medium",
        "downtime": False,
    },
    "security_group_open_ssh": {
        "terraform": '''# Remove the 0.0.0.0/0 SSH rule and replace with VPN CIDR
resource "aws_vpc_security_group_ingress_rule" "{resource_name}_ssh" {{
  security_group_id = "{sg_id}"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  cidr_ipv4         = "{vpn_cidr}"  # Replace with your VPN CIDR
  description       = "SSH from VPN only"
}}''',
        "cli": 'aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port 22 --cidr 0.0.0.0/0',
        "explanation": "Restricts SSH access to VPN CIDR only. Removes internet-wide SSH access.",
        "risk": "high",
        "downtime": False,
    },
    "rds_not_encrypted": {
        "terraform": '''resource "aws_rds_cluster" "{resource_name}" {{
  # ... existing config ...
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}}

resource "aws_kms_key" "rds" {{
  description         = "RDS encryption key"
  enable_key_rotation = true
}}''',
        "explanation": "Enables encryption at rest for RDS. Requires creating a new encrypted cluster and migrating data.",
        "risk": "high",
        "downtime": True,
    },
    "iam_user_no_mfa": {
        "terraform": '''resource "aws_iam_user_policy" "{resource_name}_enforce_mfa" {{
  name = "enforce-mfa"
  user = "{user_name}"
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Sid       = "DenyAllExceptMFASetup"
      Effect    = "Deny"
      NotAction = ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "iam:ListMFADevices", "iam:ResyncMFADevice", "sts:GetSessionToken"]
      Resource  = "*"
      Condition = {{ Bool = {{ "aws:MultiFactorAuthPresent" = "false" }} }}
    }}]
  }})
}}''',
        "cli": 'echo "User {user_name} must enable MFA. Send notification."',
        "explanation": "Enforces MFA by denying all actions (except MFA setup) when MFA is not present.",
        "risk": "medium",
        "downtime": False,
    },
    "cloudtrail_not_enabled": {
        "terraform": '''resource "aws_cloudtrail" "security_trail" {{
  name                          = "security-audit-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn
}}''',
        "explanation": "Enables CloudTrail with multi-region coverage, log validation, and encryption.",
        "risk": "low",
        "downtime": False,
    },
    "ec2_imdsv1_enabled": {
        "terraform": '''resource "aws_instance" "{resource_name}" {{
  # ... existing config ...
  metadata_options {{
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # Enforces IMDSv2
    http_put_response_hop_limit = 1
  }}
}}''',
        "cli": 'aws ec2 modify-instance-metadata-options --instance-id {instance_id} --http-tokens required --http-endpoint enabled',
        "explanation": "Enforces IMDSv2, preventing SSRF-based credential theft from instance metadata.",
        "risk": "low",
        "downtime": False,
    },
}


def generate_remediation(finding_type: str, context: dict) -> RemediationPatch | None:
    """Generate a remediation patch for a finding."""
    template = REMEDIATION_TEMPLATES.get(finding_type)
    if not template:
        return None

    # Format template with context
    terraform_code = template.get("terraform", "")
    try:
        terraform_code = terraform_code.format(**context)
    except KeyError:
        pass  # Leave unformatted placeholders

    return RemediationPatch(
        finding_id=context.get("finding_id", ""),
        finding_title=finding_type.replace("_", " ").title(),
        severity=context.get("severity", "high"),
        resource_id=context.get("resource_id", ""),
        resource_type=context.get("resource_type", ""),
        iac_type="terraform",
        patch_code=terraform_code,
        explanation=template["explanation"],
        risk_of_change=template.get("risk", "medium"),
        requires_downtime=template.get("downtime", False),
    )


def generate_pr_body(patches: list[RemediationPatch]) -> str:
    """Generate a PR description for a batch of remediations."""
    body = "## 🔒 Security Auto-Remediation\n\n"
    body += "This PR was automatically generated by Prowler CNAPP AI.\n\n"
    body += "### Changes\n\n"

    for patch in patches:
        risk_emoji = {"low": "🟢", "medium": "🟡", "high": "🔴"}.get(patch.risk_of_change, "⚪")
        body += f"- {risk_emoji} **{patch.finding_title}** ({patch.resource_id})\n"
        body += f"  - {patch.explanation}\n"
        if patch.requires_downtime:
            body += f"  - ⚠️ **Requires downtime**\n"
        body += "\n"

    body += "### Risk Assessment\n\n"
    high_risk = sum(1 for p in patches if p.risk_of_change == "high")
    if high_risk:
        body += f"⚠️ {high_risk} change(s) are high-risk. Review carefully before merging.\n"
    else:
        body += "✅ All changes are low/medium risk. Safe to merge after review.\n"

    return body
