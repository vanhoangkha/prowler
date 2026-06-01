"""Agentless workload scanner - scans VMs/containers without installing agents.

Workflow: Snapshot disk -> Mount/read -> Scan for vulns/secrets/malware -> Report findings
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


class ScanType(Enum):
    VULNERABILITY = "vulnerability"
    SECRET = "secret"
    MALWARE = "malware"
    SBOM = "sbom"


@dataclass
class ScanTarget:
    provider: str
    resource_id: str
    resource_type: str  # ec2, azure_vm, gce
    region: str
    account_id: str
    metadata: dict = field(default_factory=dict)


@dataclass
class ScanFinding:
    finding_type: ScanType
    severity: str  # critical, high, medium, low
    title: str
    description: str
    resource_id: str
    package_name: str | None = None
    package_version: str | None = None
    cve_id: str | None = None
    fix_version: str | None = None
    file_path: str | None = None


@dataclass
class ScanResult:
    target: ScanTarget
    findings: list[ScanFinding] = field(default_factory=list)
    sbom_packages: list[dict] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    error: str | None = None


class AgentlessScanner(ABC):
    """Base class for agentless workload scanners."""

    @abstractmethod
    def create_snapshot(self, target: ScanTarget) -> str:
        """Create a disk snapshot. Returns snapshot ID."""

    @abstractmethod
    def scan_snapshot(self, snapshot_id: str, scan_types: list[ScanType]) -> ScanResult:
        """Scan the snapshot for vulnerabilities, secrets, malware."""

    @abstractmethod
    def cleanup_snapshot(self, snapshot_id: str) -> None:
        """Delete the snapshot after scanning."""

    def run(self, target: ScanTarget, scan_types: list[ScanType] | None = None) -> ScanResult:
        """Execute full scan workflow: snapshot -> scan -> cleanup."""
        if scan_types is None:
            scan_types = [ScanType.VULNERABILITY, ScanType.SECRET]

        logger.info(f"Starting agentless scan for {target.resource_id}")
        snapshot_id = None
        try:
            snapshot_id = self.create_snapshot(target)
            logger.info(f"Created snapshot {snapshot_id} for {target.resource_id}")
            result = self.scan_snapshot(snapshot_id, scan_types)
            logger.info(f"Scan complete: {len(result.findings)} findings for {target.resource_id}")
            return result
        except Exception as e:
            logger.error(f"Scan failed for {target.resource_id}: {e}")
            return ScanResult(target=target, error=str(e))
        finally:
            if snapshot_id:
                try:
                    self.cleanup_snapshot(snapshot_id)
                except Exception as e:
                    logger.warning(f"Cleanup failed for snapshot {snapshot_id}: {e}")
