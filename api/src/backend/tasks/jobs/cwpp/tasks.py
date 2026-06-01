"""Celery tasks for CWPP agentless scanning."""

from celery.utils.log import get_task_logger

from api.models import Provider as ProwlerAPIProvider
from tasks.jobs.cwpp.aws_scanner import AWSAgentlessScanner
from tasks.jobs.cwpp.container_scanner import ContainerImageScanner, ContainerImage
from tasks.jobs.cwpp.scanner import ScanResult, ScanTarget, ScanType

logger = get_task_logger(__name__)


def run_vm_scan(
    provider: ProwlerAPIProvider,
    instance_ids: list[str] | None = None,
    scan_types: list[str] | None = None,
) -> list[ScanResult]:
    """Run agentless VM scan for a provider.

    Args:
        provider: The Prowler API provider instance
        instance_ids: Specific instances to scan (None = all)
        scan_types: Types of scans to run (vulnerability, secret, malware, sbom)
    """
    results = []
    types = [ScanType(t) for t in (scan_types or ["vulnerability", "secret"])]

    if provider.provider_type == "aws":
        results = _scan_aws_instances(provider, instance_ids, types)
    elif provider.provider_type == "azure":
        logger.info("Azure VM scanning not yet implemented")
    elif provider.provider_type == "gcp":
        logger.info("GCP VM scanning not yet implemented")

    return results


def run_container_scan(
    provider: ProwlerAPIProvider,
    repositories: list[str] | None = None,
) -> list[ScanResult]:
    """Run container image scan for a provider's registries."""
    scanner = ContainerImageScanner()
    results = []

    if provider.provider_type == "aws":
        # TODO: get boto3 session from provider
        logger.info(f"Container scan for AWS provider {provider.uid}")
    elif provider.provider_type == "azure":
        logger.info("Azure ACR scanning not yet implemented")
    elif provider.provider_type == "gcp":
        logger.info("GCP GCR/AR scanning not yet implemented")

    return results


def _scan_aws_instances(
    provider: ProwlerAPIProvider,
    instance_ids: list[str] | None,
    scan_types: list[ScanType],
) -> list[ScanResult]:
    """Scan AWS EC2 instances via EBS snapshots."""
    import boto3

    # TODO: Get session from provider's SDK credentials
    session = boto3.Session()
    scanner = AWSAgentlessScanner(session)
    results = []

    if not instance_ids:
        # Discover instances from provider
        logger.info(f"Discovering EC2 instances for {provider.uid}")
        # TODO: List instances from provider
        return results

    for instance_id in instance_ids:
        target = ScanTarget(
            provider="aws",
            resource_id=instance_id,
            resource_type="ec2",
            region="",  # TODO: resolve from instance
            account_id=provider.uid,
        )
        result = scanner.run(target, scan_types)
        results.append(result)

    return results
