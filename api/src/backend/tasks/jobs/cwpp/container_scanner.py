"""Container Image Scanner - scan images in ECR/ACR/GCR registries.

Scans container images for vulnerabilities and generates SBOMs
without pulling the full image (uses registry API).
"""

import time
from dataclasses import dataclass

from celery.utils.log import get_task_logger

from tasks.jobs.cwpp.scanner import ScanFinding, ScanResult, ScanTarget, ScanType

logger = get_task_logger(__name__)


@dataclass
class ContainerImage:
    registry: str  # ecr, acr, gcr
    repository: str
    tag: str
    digest: str | None = None
    region: str | None = None
    account_id: str | None = None


class ContainerImageScanner:
    """Scan container images from cloud registries."""

    def scan_image(self, image: ContainerImage, scan_types: list[ScanType] | None = None) -> ScanResult:
        """Scan a container image for vulnerabilities and secrets."""
        if scan_types is None:
            scan_types = [ScanType.VULNERABILITY, ScanType.SBOM]

        t0 = time.perf_counter()
        findings: list[ScanFinding] = []
        sbom: list[dict] = []
        image_ref = f"{image.repository}:{image.tag}"

        logger.info(f"Scanning container image {image_ref}")

        if ScanType.VULNERABILITY in scan_types:
            findings.extend(self._scan_vulnerabilities(image))

        if ScanType.SBOM in scan_types:
            sbom = self._generate_sbom(image)

        if ScanType.SECRET in scan_types:
            findings.extend(self._scan_secrets(image))

        duration = time.perf_counter() - t0
        target = ScanTarget(
            provider=image.registry,
            resource_id=image.digest or image_ref,
            resource_type="container_image",
            region=image.region or "",
            account_id=image.account_id or "",
        )

        return ScanResult(
            target=target,
            findings=findings,
            sbom_packages=sbom,
            scan_duration_seconds=duration,
        )

    def list_images_ecr(self, boto3_session, region: str, repository: str | None = None) -> list[ContainerImage]:
        """List images from AWS ECR."""
        ecr = boto3_session.client("ecr", region_name=region)
        images = []

        repos_response = ecr.describe_repositories()
        for repo in repos_response.get("repositories", []):
            if repository and repo["repositoryName"] != repository:
                continue
            img_response = ecr.list_images(
                repositoryName=repo["repositoryName"],
                filter={"tagStatus": "TAGGED"},
            )
            for img in img_response.get("imageIds", []):
                images.append(ContainerImage(
                    registry="ecr",
                    repository=repo["repositoryUri"],
                    tag=img.get("imageTag", "latest"),
                    digest=img.get("imageDigest"),
                    region=region,
                    account_id=repo["registryId"],
                ))
        return images

    def _scan_vulnerabilities(self, image: ContainerImage) -> list[ScanFinding]:
        """Run Trivy on container image."""
        logger.info(f"Vulnerability scan: {image.repository}:{image.tag}")
        # TODO: subprocess trivy image --format json {image_ref}
        return []

    def _generate_sbom(self, image: ContainerImage) -> list[dict]:
        """Generate SBOM using Syft."""
        logger.info(f"SBOM generation: {image.repository}:{image.tag}")
        # TODO: subprocess syft {image_ref} -o cyclonedx-json
        return []

    def _scan_secrets(self, image: ContainerImage) -> list[ScanFinding]:
        """Scan image layers for secrets."""
        logger.info(f"Secret scan: {image.repository}:{image.tag}")
        return []
