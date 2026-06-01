"""Django models for CNAPP modules (CWPP, CIEM, DSPM, CDR).

These models persist scan results, findings, and alerts
for the CNAPP platform capabilities.
"""

from django.db import models
from django.utils import timezone


class CWPPScan(models.Model):
    """Agentless workload scan record."""
    id = models.UUIDField(primary_key=True, editable=False)
    provider = models.ForeignKey("api.Provider", on_delete=models.CASCADE, related_name="cwpp_scans")
    scan_type = models.CharField(max_length=20, choices=[("vm", "VM"), ("container", "Container")])
    status = models.CharField(max_length=20, default="pending", choices=[
        ("pending", "Pending"), ("running", "Running"),
        ("completed", "Completed"), ("failed", "Failed"),
    ])
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.FloatField(null=True, blank=True)
    targets_count = models.IntegerField(default=0)
    findings_count = models.IntegerField(default=0)
    error_message = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "cnapp_cwpp_scans"
        ordering = ["-created_at"]


class CWPPFinding(models.Model):
    """Vulnerability/secret finding from agentless scan."""
    id = models.UUIDField(primary_key=True, editable=False)
    scan = models.ForeignKey(CWPPScan, on_delete=models.CASCADE, related_name="findings")
    finding_type = models.CharField(max_length=20, choices=[
        ("vulnerability", "Vulnerability"), ("secret", "Secret"),
        ("malware", "Malware"), ("sbom", "SBOM"),
    ])
    severity = models.CharField(max_length=10)
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    resource_id = models.CharField(max_length=500)
    resource_type = models.CharField(max_length=50)
    package_name = models.CharField(max_length=200, blank=True, default="")
    package_version = models.CharField(max_length=100, blank=True, default="")
    cve_id = models.CharField(max_length=50, blank=True, default="")
    fix_version = models.CharField(max_length=100, blank=True, default="")
    file_path = models.CharField(max_length=1000, blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "cnapp_cwpp_findings"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["severity"]),
            models.Index(fields=["cve_id"]),
            models.Index(fields=["resource_id"]),
        ]


class CIEMIdentity(models.Model):
    """Analyzed cloud identity with risk assessment."""
    id = models.UUIDField(primary_key=True, editable=False)
    provider = models.ForeignKey("api.Provider", on_delete=models.CASCADE, related_name="ciem_identities")
    identity_arn = models.CharField(max_length=500, db_index=True)
    identity_type = models.CharField(max_length=30)  # user, role, service_account
    name = models.CharField(max_length=200)
    risk_level = models.CharField(max_length=10, default="low")
    is_over_privileged = models.BooleanField(default=False)
    granted_permissions_count = models.IntegerField(default=0)
    used_permissions_count = models.IntegerField(default=0)
    unused_permissions_count = models.IntegerField(default=0)
    blast_radius_score = models.FloatField(default=0.0)
    has_admin_access = models.BooleanField(default=False)
    has_sensitive_data_access = models.BooleanField(default=False)
    last_activity = models.DateTimeField(null=True, blank=True)
    recommendations = models.JSONField(default=list)
    analyzed_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "cnapp_ciem_identities"
        ordering = ["-blast_radius_score"]
        indexes = [
            models.Index(fields=["risk_level"]),
            models.Index(fields=["is_over_privileged"]),
        ]


class DSPMDataStore(models.Model):
    """Discovered and classified data store."""
    id = models.UUIDField(primary_key=True, editable=False)
    provider = models.ForeignKey("api.Provider", on_delete=models.CASCADE, related_name="dspm_stores")
    store_id = models.CharField(max_length=500, db_index=True)
    store_type = models.CharField(max_length=30)  # s3, blob, gcs, rds
    region = models.CharField(max_length=50, blank=True)
    is_public = models.BooleanField(default=False)
    is_encrypted = models.BooleanField(default=True)
    highest_sensitivity = models.CharField(max_length=10, default="low")
    categories = models.JSONField(default=list)  # ["pii", "phi", "pci"]
    findings_count = models.IntegerField(default=0)
    scanned_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "cnapp_dspm_stores"
        ordering = ["-scanned_at"]
        indexes = [
            models.Index(fields=["is_public", "highest_sensitivity"]),
        ]


class CDRAlert(models.Model):
    """Security alert from CDR detection engine."""
    id = models.CharField(max_length=64, primary_key=True)
    provider = models.ForeignKey("api.Provider", on_delete=models.CASCADE, related_name="cdr_alerts", null=True)
    rule_id = models.CharField(max_length=100, db_index=True)
    rule_name = models.CharField(max_length=200)
    severity = models.CharField(max_length=10)
    status = models.CharField(max_length=20, default="open", choices=[
        ("open", "Open"), ("acknowledged", "Acknowledged"),
        ("resolved", "Resolved"), ("false_positive", "False Positive"),
    ])
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    account_id = models.CharField(max_length=100)
    region = models.CharField(max_length=50, blank=True)
    principal = models.CharField(max_length=500)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    resources = models.JSONField(default=list)
    mitre_tactic = models.CharField(max_length=50, blank=True)
    mitre_technique = models.CharField(max_length=20, blank=True)
    event_time = models.DateTimeField()
    created_at = models.DateTimeField(default=timezone.now)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "cnapp_cdr_alerts"
        ordering = ["-event_time"]
        indexes = [
            models.Index(fields=["severity", "status"]),
            models.Index(fields=["rule_id"]),
            models.Index(fields=["account_id"]),
        ]


class IntegrationChannel(models.Model):
    """Configured alert notification channel."""
    id = models.UUIDField(primary_key=True, editable=False)
    name = models.CharField(max_length=100)
    channel_type = models.CharField(max_length=20, choices=[
        ("slack", "Slack"), ("pagerduty", "PagerDuty"),
        ("email", "Email"), ("webhook", "Webhook"),
        ("jira", "Jira"), ("servicenow", "ServiceNow"),
    ])
    config = models.JSONField(default=dict)  # encrypted in production
    severity_filter = models.JSONField(default=list, blank=True)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "cnapp_integration_channels"
