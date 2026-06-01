"""DSPM Data Classifier - discovers and classifies sensitive data.

Scans cloud data stores (S3/Blob/GCS, RDS/SQL/CloudSQL) using
sampling + regex/pattern matching to detect PII, PHI, PCI data.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


class DataCategory(Enum):
    PII = "pii"
    PHI = "phi"
    PCI = "pci"
    CREDENTIALS = "credentials"
    INTERNAL = "internal"
    PUBLIC = "public"


class Sensitivity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ClassificationRule:
    name: str
    category: DataCategory
    sensitivity: Sensitivity
    pattern: str
    description: str


@dataclass
class DataFinding:
    data_store: str
    data_store_type: str  # s3, rds, blob, gcs
    category: DataCategory
    sensitivity: Sensitivity
    rule_name: str
    sample_count: int
    location: str  # path/table/container
    provider: str
    region: str


@dataclass
class DataStoreProfile:
    store_id: str
    store_type: str
    provider: str
    region: str
    is_public: bool = False
    is_encrypted: bool = True
    findings: list[DataFinding] = field(default_factory=list)
    highest_sensitivity: Sensitivity = Sensitivity.LOW
    categories: list[DataCategory] = field(default_factory=list)


# Built-in classification rules
DEFAULT_RULES: list[ClassificationRule] = [
    ClassificationRule("SSN", DataCategory.PII, Sensitivity.CRITICAL, r"\b\d{3}-\d{2}-\d{4}\b", "US Social Security Number"),
    ClassificationRule("Credit Card", DataCategory.PCI, Sensitivity.CRITICAL, r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", "Credit card number"),
    ClassificationRule("Email", DataCategory.PII, Sensitivity.MEDIUM, r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email address"),
    ClassificationRule("Phone", DataCategory.PII, Sensitivity.MEDIUM, r"\b(?:\+?1[-.]?)?\(?[0-9]{3}\)?[-.]?[0-9]{3}[-.]?[0-9]{4}\b", "Phone number"),
    ClassificationRule("AWS Key", DataCategory.CREDENTIALS, Sensitivity.CRITICAL, r"\bAKIA[0-9A-Z]{16}\b", "AWS Access Key ID"),
    ClassificationRule("Private Key", DataCategory.CREDENTIALS, Sensitivity.CRITICAL, r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private key"),
    ClassificationRule("IP Address", DataCategory.INTERNAL, Sensitivity.LOW, r"\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b", "Internal IP"),
    ClassificationRule("MRN", DataCategory.PHI, Sensitivity.HIGH, r"\bMRN[:\s]?\d{6,10}\b", "Medical Record Number"),
    ClassificationRule("DOB", DataCategory.PHI, Sensitivity.HIGH, r"\b(?:DOB|Date of Birth)[:\s]?\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", "Date of Birth"),
]


class DataClassifier:
    """Classifies data in cloud storage using pattern matching."""

    def __init__(self, rules: list[ClassificationRule] | None = None):
        self.rules = rules or DEFAULT_RULES
        self._compiled = [(r, re.compile(r.pattern, re.IGNORECASE)) for r in self.rules]

    def classify_text(self, text: str, source: str = "") -> list[DataFinding]:
        """Classify a text sample against all rules."""
        findings = []
        for rule, pattern in self._compiled:
            matches = pattern.findall(text)
            if matches:
                findings.append(DataFinding(
                    data_store=source,
                    data_store_type="",
                    category=rule.category,
                    sensitivity=rule.sensitivity,
                    rule_name=rule.name,
                    sample_count=len(matches),
                    location=source,
                    provider="",
                    region="",
                ))
        return findings

    def scan_s3_bucket(self, boto3_session, bucket_name: str, sample_size: int = 10) -> DataStoreProfile:
        """Scan S3 bucket by sampling objects."""
        s3 = boto3_session.client("s3")
        profile = DataStoreProfile(
            store_id=bucket_name, store_type="s3", provider="aws", region="",
        )

        # Check public access
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") in [
                    "http://acs.amazonaws.com/groups/global/AllUsers",
                    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                ]:
                    profile.is_public = True
        except Exception:
            pass

        # Check encryption
        try:
            s3.get_bucket_encryption(Bucket=bucket_name)
            profile.is_encrypted = True
        except s3.exceptions.ClientError:
            profile.is_encrypted = False

        # Sample objects
        try:
            objects = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=sample_size)
            for obj in objects.get("Contents", [])[:sample_size]:
                if obj["Size"] > 10 * 1024 * 1024:  # skip >10MB
                    continue
                try:
                    response = s3.get_object(Bucket=bucket_name, Key=obj["Key"], Range="bytes=0-65535")
                    content = response["Body"].read().decode("utf-8", errors="ignore")
                    findings = self.classify_text(content, source=f"s3://{bucket_name}/{obj['Key']}")
                    for f in findings:
                        f.data_store = bucket_name
                        f.data_store_type = "s3"
                        f.provider = "aws"
                    profile.findings.extend(findings)
                except Exception:
                    continue
        except Exception as e:
            logger.warning(f"Failed to sample {bucket_name}: {e}")

        # Compute highest sensitivity
        if profile.findings:
            severities = [f.sensitivity for f in profile.findings]
            profile.highest_sensitivity = min(severities, key=lambda s: list(Sensitivity).index(s))
            profile.categories = list({f.category for f in profile.findings})

        return profile
