"""URL configuration for CNAPP modules (attack paths, CWPP, CIEM, DSPM, CDR)."""

from django.urls import path

from api.attack_paths.views_toxic_combinations import list_toxic_combinations, compute_score
from api.cwpp.views import trigger_vm_scan, trigger_container_scan, scan_status
from api.ciem.views import (
    identity_risk_dashboard,
    analyze_identity,
    blast_radius,
    unused_credentials,
    recommendations,
)
from api.dspm.views import data_inventory, trigger_classification_scan, data_risk_findings
from api.cdr.views import list_alerts, list_detection_rules, acknowledge_alert
from api.ai.views import (
    ask_security_question,
    list_query_templates,
    generate_fix,
    list_remediations,
)

urlpatterns = [
    # Attack Paths & Toxic Combinations
    path("attack-paths/toxic-combinations/", list_toxic_combinations, name="toxic-combinations"),
    path("attack-paths/score/", compute_score, name="attack-paths-score"),

    # CWPP - Agentless Scanning
    path("cwpp/vm-scan/", trigger_vm_scan, name="cwpp-vm-scan"),
    path("cwpp/container-scan/", trigger_container_scan, name="cwpp-container-scan"),
    path("cwpp/status/", scan_status, name="cwpp-status"),

    # CIEM - Identity Intelligence
    path("ciem/dashboard/", identity_risk_dashboard, name="ciem-dashboard"),
    path("ciem/analyze/", analyze_identity, name="ciem-analyze"),
    path("ciem/blast-radius/", blast_radius, name="ciem-blast-radius"),
    path("ciem/unused-credentials/", unused_credentials, name="ciem-unused-credentials"),
    path("ciem/recommendations/", recommendations, name="ciem-recommendations"),

    # DSPM - Data Security
    path("dspm/inventory/", data_inventory, name="dspm-inventory"),
    path("dspm/scan/", trigger_classification_scan, name="dspm-scan"),
    path("dspm/findings/", data_risk_findings, name="dspm-findings"),

    # CDR - Detection & Response
    path("cdr/alerts/", list_alerts, name="cdr-alerts"),
    path("cdr/rules/", list_detection_rules, name="cdr-rules"),
    path("cdr/alerts/acknowledge/", acknowledge_alert, name="cdr-acknowledge"),

    # AI-Native Security
    path("ai/ask/", ask_security_question, name="ai-ask"),
    path("ai/templates/", list_query_templates, name="ai-templates"),
    path("ai/fix/", generate_fix, name="ai-fix"),
    path("ai/remediations/", list_remediations, name="ai-remediations"),
]
