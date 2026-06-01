"""AWS Agentless Scanner - EBS snapshot-based VM scanning.

Workflow:
1. Create EBS snapshot of instance volumes
2. Share snapshot to scanner account (or use EBS Direct APIs)
3. Mount/read snapshot filesystem
4. Run Trivy/Grype for vulnerability detection
5. Run TruffleHog for secret detection
6. Map findings to Security Graph
"""

import time
from dataclasses import dataclass

import boto3
from celery.utils.log import get_task_logger

from tasks.jobs.cwpp.scanner import (
    AgentlessScanner,
    ScanFinding,
    ScanResult,
    ScanTarget,
    ScanType,
)

logger = get_task_logger(__name__)


@dataclass
class EBSSnapshotInfo:
    snapshot_id: str
    volume_id: str
    size_gb: int
    instance_id: str


class AWSAgentlessScanner(AgentlessScanner):
    """Scan EC2 instances via EBS snapshots without installing agents."""

    def __init__(self, boto3_session: boto3.Session, scanner_region: str | None = None):
        self.session = boto3_session
        self.scanner_region = scanner_region

    def create_snapshot(self, target: ScanTarget) -> str:
        """Create EBS snapshot of the instance's root volume."""
        ec2 = self.session.client("ec2", region_name=target.region)

        # Get root volume
        response = ec2.describe_instances(InstanceIds=[target.resource_id])
        reservations = response.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            raise ValueError(f"Instance {target.resource_id} not found")

        instance = reservations[0]["Instances"][0]
        root_device = instance.get("RootDeviceName", "/dev/xvda")

        volume_id = None
        for mapping in instance.get("BlockDeviceMappings", []):
            if mapping["DeviceName"] == root_device:
                volume_id = mapping["Ebs"]["VolumeId"]
                break

        if not volume_id:
            raise ValueError(f"No root volume found for {target.resource_id}")

        # Create snapshot
        snapshot = ec2.create_snapshot(
            VolumeId=volume_id,
            Description=f"Prowler CWPP scan - {target.resource_id}",
            TagSpecifications=[{
                "ResourceType": "snapshot",
                "Tags": [
                    {"Key": "prowler:scan", "Value": "cwpp"},
                    {"Key": "prowler:instance", "Value": target.resource_id},
                ],
            }],
        )

        snapshot_id = snapshot["SnapshotId"]

        # Wait for snapshot to complete
        waiter = ec2.get_waiter("snapshot_completed")
        waiter.wait(
            SnapshotIds=[snapshot_id],
            WaiterConfig={"Delay": 15, "MaxAttempts": 60},
        )

        return snapshot_id

    def scan_snapshot(self, snapshot_id: str, scan_types: list[ScanType]) -> ScanResult:
        """Scan snapshot using EBS Direct APIs + Trivy."""
        t0 = time.perf_counter()
        findings: list[ScanFinding] = []
        sbom: list[dict] = []

        # Use EBS Direct API to read snapshot blocks
        # In production: mount snapshot or use ebs:GetSnapshotBlock
        # Then pipe filesystem to Trivy/Grype scanner

        if ScanType.VULNERABILITY in scan_types:
            vuln_findings = self._scan_vulnerabilities(snapshot_id)
            findings.extend(vuln_findings)

        if ScanType.SECRET in scan_types:
            secret_findings = self._scan_secrets(snapshot_id)
            findings.extend(secret_findings)

        if ScanType.SBOM in scan_types:
            sbom = self._generate_sbom(snapshot_id)

        duration = time.perf_counter() - t0
        return ScanResult(
            target=ScanTarget(
                provider="aws", resource_id=snapshot_id,
                resource_type="snapshot", region="", account_id="",
            ),
            findings=findings,
            sbom_packages=sbom,
            scan_duration_seconds=duration,
        )

    def cleanup_snapshot(self, snapshot_id: str) -> None:
        """Delete the temporary scan snapshot."""
        ec2 = self.session.client("ec2", region_name=self.scanner_region)
        ec2.delete_snapshot(SnapshotId=snapshot_id)
        logger.info(f"Deleted scan snapshot {snapshot_id}")

    def _scan_vulnerabilities(self, snapshot_id: str) -> list[ScanFinding]:
        """Run vulnerability scanner (Trivy/Grype) on snapshot.

        In production: uses subprocess to run trivy with EBS mount.
        Placeholder for integration.
        """
        logger.info(f"Scanning {snapshot_id} for vulnerabilities (Trivy)")
        # TODO: Integrate trivy subprocess
        # trivy rootfs --input /mnt/snapshot --format json
        return []

    def _scan_secrets(self, snapshot_id: str) -> list[ScanFinding]:
        """Run secret scanner (TruffleHog) on snapshot.

        In production: uses subprocess to run trufflehog.
        Placeholder for integration.
        """
        logger.info(f"Scanning {snapshot_id} for secrets (TruffleHog)")
        # TODO: Integrate trufflehog subprocess
        return []

    def _generate_sbom(self, snapshot_id: str) -> list[dict]:
        """Generate SBOM (CycloneDX/SPDX) from snapshot.

        In production: uses syft or trivy sbom.
        """
        logger.info(f"Generating SBOM for {snapshot_id}")
        # TODO: Integrate syft subprocess
        return []
