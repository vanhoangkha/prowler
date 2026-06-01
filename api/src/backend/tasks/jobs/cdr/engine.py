"""CDR Detection Engine - real-time cloud threat detection.

Processes cloud events (CloudTrail, Activity Log, Audit Log)
and matches against detection rules to identify threats.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


class AlertSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class DetectionRule:
    id: str
    name: str
    description: str
    severity: AlertSeverity
    provider: str  # aws, azure, gcp, all
    event_source: str  # e.g., cloudtrail, activity_log
    conditions: dict  # matching conditions
    mitre_tactic: str = ""
    mitre_technique: str = ""
    enabled: bool = True


@dataclass
class CloudEvent:
    event_id: str
    event_time: str
    event_source: str
    event_name: str
    provider: str
    region: str
    account_id: str
    principal: str
    source_ip: str | None = None
    user_agent: str | None = None
    resources: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


@dataclass
class Alert:
    id: str
    rule_id: str
    rule_name: str
    severity: AlertSeverity
    status: AlertStatus
    title: str
    description: str
    provider: str
    account_id: str
    region: str
    principal: str
    event_time: str
    source_ip: str | None = None
    resources: list[str] = field(default_factory=list)
    mitre_tactic: str = ""
    mitre_technique: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# Built-in detection rules
BUILTIN_RULES: list[DetectionRule] = [
    DetectionRule(
        id="cdr-aws-root-login",
        name="Root Account Login",
        description="AWS root account was used to sign in",
        severity=AlertSeverity.CRITICAL,
        provider="aws",
        event_source="cloudtrail",
        conditions={"event_name": "ConsoleLogin", "principal_contains": "root"},
        mitre_tactic="Initial Access",
        mitre_technique="T1078.004",
    ),
    DetectionRule(
        id="cdr-aws-iam-user-created",
        name="IAM User Created",
        description="New IAM user created - potential persistence",
        severity=AlertSeverity.HIGH,
        provider="aws",
        event_source="cloudtrail",
        conditions={"event_name": "CreateUser"},
        mitre_tactic="Persistence",
        mitre_technique="T1136.003",
    ),
    DetectionRule(
        id="cdr-aws-security-group-open",
        name="Security Group Opened to Internet",
        description="Security group rule added allowing 0.0.0.0/0",
        severity=AlertSeverity.HIGH,
        provider="aws",
        event_source="cloudtrail",
        conditions={"event_name": "AuthorizeSecurityGroupIngress"},
        mitre_tactic="Defense Evasion",
        mitre_technique="T1562.007",
    ),
    DetectionRule(
        id="cdr-aws-cloudtrail-stopped",
        name="CloudTrail Logging Stopped",
        description="CloudTrail logging was disabled - covering tracks",
        severity=AlertSeverity.CRITICAL,
        provider="aws",
        event_source="cloudtrail",
        conditions={"event_name": "StopLogging"},
        mitre_tactic="Defense Evasion",
        mitre_technique="T1562.008",
    ),
    DetectionRule(
        id="cdr-aws-kms-key-deleted",
        name="KMS Key Scheduled for Deletion",
        description="KMS key scheduled for deletion - potential ransomware",
        severity=AlertSeverity.CRITICAL,
        provider="aws",
        event_source="cloudtrail",
        conditions={"event_name": "ScheduleKeyDeletion"},
        mitre_tactic="Impact",
        mitre_technique="T1485",
    ),
    DetectionRule(
        id="cdr-aws-unusual-region",
        name="API Call from Unusual Region",
        description="API activity detected from a region not normally used",
        severity=AlertSeverity.MEDIUM,
        provider="aws",
        event_source="cloudtrail",
        conditions={"unusual_region": True},
        mitre_tactic="Discovery",
        mitre_technique="T1580",
    ),
    DetectionRule(
        id="cdr-aws-crypto-mining",
        name="Potential Cryptomining Activity",
        description="Large EC2 instances launched - possible cryptomining",
        severity=AlertSeverity.HIGH,
        provider="aws",
        event_source="cloudtrail",
        conditions={"event_name": "RunInstances", "instance_type_prefix": ["p3", "p4", "g4", "g5"]},
        mitre_tactic="Impact",
        mitre_technique="T1496",
    ),
    DetectionRule(
        id="cdr-aws-s3-public",
        name="S3 Bucket Made Public",
        description="S3 bucket ACL or policy changed to allow public access",
        severity=AlertSeverity.HIGH,
        provider="aws",
        event_source="cloudtrail",
        conditions={"event_name": ["PutBucketAcl", "PutBucketPolicy"]},
        mitre_tactic="Exfiltration",
        mitre_technique="T1537",
    ),
]


class DetectionEngine:
    """Matches cloud events against detection rules to generate alerts."""

    def __init__(self, rules: list[DetectionRule] | None = None):
        self.rules = [r for r in (rules or BUILTIN_RULES) if r.enabled]

    def process_event(self, event: CloudEvent) -> list[Alert]:
        """Process a single cloud event against all rules."""
        alerts = []
        for rule in self.rules:
            if rule.provider not in (event.provider, "all"):
                continue
            if self._matches(rule, event):
                alert = self._create_alert(rule, event)
                alerts.append(alert)
        return alerts

    def process_events(self, events: list[CloudEvent]) -> list[Alert]:
        """Process batch of events."""
        alerts = []
        for event in events:
            alerts.extend(self.process_event(event))
        return alerts

    def _matches(self, rule: DetectionRule, event: CloudEvent) -> bool:
        """Check if event matches rule conditions."""
        conditions = rule.conditions

        # Match event_name
        if "event_name" in conditions:
            expected = conditions["event_name"]
            if isinstance(expected, list):
                if event.event_name not in expected:
                    return False
            elif event.event_name != expected:
                return False

        # Match principal contains
        if "principal_contains" in conditions:
            if conditions["principal_contains"] not in event.principal:
                return False

        return True

    def _create_alert(self, rule: DetectionRule, event: CloudEvent) -> Alert:
        """Create alert from matched rule and event."""
        import hashlib
        alert_id = hashlib.sha256(f"{rule.id}:{event.event_id}".encode()).hexdigest()[:16]

        return Alert(
            id=alert_id,
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            status=AlertStatus.OPEN,
            title=f"{rule.name}: {event.event_name} by {event.principal}",
            description=rule.description,
            provider=event.provider,
            account_id=event.account_id,
            region=event.region,
            principal=event.principal,
            event_time=event.event_time,
            source_ip=event.source_ip,
            resources=event.resources,
            mitre_tactic=rule.mitre_tactic,
            mitre_technique=rule.mitre_technique,
        )
