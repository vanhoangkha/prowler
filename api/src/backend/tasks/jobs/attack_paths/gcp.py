import time

import neo4j

from cartography.config import Config as CartographyConfig
from cartography.intel import gcp as cartography_gcp
from celery.utils.log import get_task_logger

from api.models import (
    AttackPathsScan as ProwlerAPIAttackPathsScan,
    Provider as ProwlerAPIProvider,
)
from prowler.providers.common.provider import Provider as ProwlerSDKProvider
from tasks.jobs.attack_paths import db_utils, utils

logger = get_task_logger(__name__)


def start_gcp_ingestion(
    neo4j_session: neo4j.Session,
    cartography_config: CartographyConfig,
    prowler_api_provider: ProwlerAPIProvider,
    prowler_sdk_provider: ProwlerSDKProvider,
    attack_paths_scan: ProwlerAPIAttackPathsScan,
) -> dict[str, dict[str, str]]:
    """Ingest GCP resources into Neo4j via Cartography."""
    common_job_parameters = {
        "UPDATE_TAG": cartography_config.update_tag,
    }

    credentials = prowler_sdk_provider.session.current_session
    project_id = prowler_api_provider.uid
    projects = _resolve_projects(prowler_sdk_provider)

    db_utils.update_attack_paths_scan_progress(attack_paths_scan, 3)

    failed_syncs = _sync_gcp_resources(
        neo4j_session,
        credentials,
        project_id,
        projects,
        common_job_parameters,
        cartography_config,
        prowler_api_provider,
        attack_paths_scan,
    )

    logger.info(f"Syncing metadata for GCP project {project_id}")
    t0 = time.perf_counter()
    cartography_gcp.merge_module_sync_metadata(
        neo4j_session,
        group_type="GCPProject",
        group_id=project_id,
        synced_type="GCPProject",
        update_tag=cartography_config.update_tag,
        stat_handler=cartography_gcp.stat_handler,
    )
    logger.info(
        f"Synced metadata for GCP project {project_id} in {time.perf_counter() - t0:.3f}s"
    )
    db_utils.update_attack_paths_scan_progress(attack_paths_scan, 93)

    return failed_syncs


def _resolve_projects(prowler_sdk_provider: ProwlerSDKProvider) -> list[str]:
    """Resolve GCP project IDs to scan."""
    identity = prowler_sdk_provider.identity
    if hasattr(identity, "project_ids") and identity.project_ids:
        return list(identity.project_ids)
    if hasattr(identity, "projects") and identity.projects:
        return list(identity.projects)
    return []


def _sync_gcp_resources(
    neo4j_session: neo4j.Session,
    credentials,
    project_id: str,
    projects: list[str],
    common_job_parameters: dict,
    cartography_config: CartographyConfig,
    prowler_api_provider: ProwlerAPIProvider,
    attack_paths_scan: ProwlerAPIAttackPathsScan,
) -> dict[str, str]:
    """Sync GCP resources using Cartography's GCP intel module."""
    failed_syncs = {}
    requested_syncs = list(cartography_gcp.RESOURCE_FUNCTIONS.keys())

    current_progress = 3
    max_progress = 92
    n_steps = len(requested_syncs) or 1
    progress_step = (max_progress - current_progress) / n_steps

    for func_name in requested_syncs:
        if func_name not in cartography_gcp.RESOURCE_FUNCTIONS:
            continue

        logger.info(
            f"Syncing function {func_name} for GCP project {project_id}"
        )
        current_progress += progress_step
        db_utils.update_attack_paths_scan_progress(
            attack_paths_scan, int(current_progress)
        )

        try:
            t0 = time.perf_counter()
            cartography_gcp.RESOURCE_FUNCTIONS[func_name](
                neo4j_session=neo4j_session,
                credentials=credentials,
                project_id=project_id,
                projects=projects,
                update_tag=cartography_config.update_tag,
                common_job_parameters=common_job_parameters,
            )
            logger.info(
                f"Synced function {func_name} for GCP project {project_id} "
                f"in {time.perf_counter() - t0:.3f}s"
            )
        except Exception as e:
            exception_message = utils.stringify_exception(
                e, f"Exception for GCP sync function: {func_name}"
            )
            failed_syncs[func_name] = exception_message
            logger.warning(
                f"Caught exception syncing function {func_name} from GCP "
                f"project {project_id}: {e}. Continuing.",
                exc_info=True,
            )

    return failed_syncs


def extract_short_uid(uid: str) -> str:
    """Return the short identifier from a GCP resource ID.

    GCP resource IDs use '/' as separator. The last segment is typically
    the resource name.
    """
    return uid.rsplit("/", 1)[-1]
