"""Prometheus metrics for CNAPP modules.

Exposes key metrics for monitoring CNAPP platform health and performance.
"""

from prometheus_client import Counter, Histogram, Gauge

# CWPP Metrics
CWPP_SCANS_TOTAL = Counter(
    "cnapp_cwpp_scans_total",
    "Total CWPP scans executed",
    ["provider", "scan_type", "status"],
)
CWPP_SCAN_DURATION = Histogram(
    "cnapp_cwpp_scan_duration_seconds",
    "CWPP scan duration in seconds",
    ["provider", "scan_type"],
    buckets=[30, 60, 120, 300, 600, 1200, 3600],
)
CWPP_FINDINGS_TOTAL = Counter(
    "cnapp_cwpp_findings_total",
    "Total CWPP findings discovered",
    ["provider", "severity", "finding_type"],
)

# CIEM Metrics
CIEM_IDENTITIES_ANALYZED = Counter(
    "cnapp_ciem_identities_analyzed_total",
    "Total identities analyzed",
    ["provider", "risk_level"],
)
CIEM_OVER_PRIVILEGED = Gauge(
    "cnapp_ciem_over_privileged_count",
    "Current count of over-privileged identities",
    ["provider"],
)

# DSPM Metrics
DSPM_STORES_SCANNED = Counter(
    "cnapp_dspm_stores_scanned_total",
    "Total data stores scanned",
    ["provider", "store_type"],
)
DSPM_SENSITIVE_DATA_FOUND = Counter(
    "cnapp_dspm_sensitive_data_found_total",
    "Sensitive data findings",
    ["provider", "category", "sensitivity"],
)

# CDR Metrics
CDR_EVENTS_PROCESSED = Counter(
    "cnapp_cdr_events_processed_total",
    "Total cloud events processed",
    ["provider"],
)
CDR_ALERTS_GENERATED = Counter(
    "cnapp_cdr_alerts_generated_total",
    "Total alerts generated",
    ["provider", "severity", "rule_id"],
)
CDR_ALERTS_OPEN = Gauge(
    "cnapp_cdr_alerts_open_count",
    "Current count of open alerts",
    ["severity"],
)

# Integration Metrics
INTEGRATION_DISPATCHES = Counter(
    "cnapp_integration_dispatches_total",
    "Total alert dispatches",
    ["channel_type", "status"],
)
INTEGRATION_DISPATCH_DURATION = Histogram(
    "cnapp_integration_dispatch_duration_seconds",
    "Alert dispatch duration",
    ["channel_type"],
    buckets=[0.1, 0.5, 1, 2, 5, 10],
)
