import time

import neo4j

from cartography.config import Config as CartographyConfig
from cartography.intel import azure as cartography_azure
from celery.utils.log import get_task_logger

from api.models import (
    AttackPathsScan as ProwlerAPIAttackPathsScan,
    Provider as ProwlerAPIProvider,
)
from prowler.providers.common.provider import Provider as ProwlerSDKProvider
from tasks.jobs.attack_paths import db_utils, utils

logger = get_task_logger(__name__)


def start_azure_ingestion(
    neo4j_session: neo4j.Session,
    cartography_config: CartographyConfig,
    prowler_api_provider: ProwlerAPIProvider,
    prowler_sdk_provider: ProwlerSDKProvider,
    attack_paths_scan: ProwlerAPIAttackPathsScan,
) -> dict[str, dict[str, str]]:
    """Ingest Azure resources into Neo4j via Cartography.

    Mirrors the AWS ingestion pattern. Progress range: caller sets 2 at start,
    this function advances to 93 before returning.
    """
    common_job_parameters = {
        "UPDATE_TAG": cartography_config.update_tag,
    }

    credentials = _get_azure_credentials(prowler_api_provider, prowler_sdk_provider)
    tenant_id = prowler_api_provider.uid
    subscriptions = _resolve_subscriptions(prowler_sdk_provider)

    db_utils.update_attack_paths_scan_progress(attack_paths_scan, 3)

    failed_syncs = _sync_azure_resources(
        neo4j_session,
        credentials,
        tenant_id,
        subscriptions,
        common_job_parameters,
        cartography_config,
        prowler_api_provider,
        attack_paths_scan,
    )

    logger.info(f"Syncing metadata for Azure tenant {tenant_id}")
    t0 = time.perf_counter()
    cartography_azure.merge_module_sync_metadata(
        neo4j_session,
        group_type="AzureTenant",
        group_id=tenant_id,
        synced_type="AzureTenant",
        update_tag=cartography_config.update_tag,
        stat_handler=cartography_azure.stat_handler,
    )
    logger.info(
        f"Synced metadata for Azure tenant {tenant_id} in {time.perf_counter() - t0:.3f}s"
    )
    db_utils.update_attack_paths_scan_progress(attack_paths_scan, 93)

    return failed_syncs


def _get_azure_credentials(
    prowler_api_provider: ProwlerAPIProvider,
    prowler_sdk_provider: ProwlerSDKProvider,
):
    """Extract Azure credentials from the Prowler SDK provider session."""
    return prowler_sdk_provider.session.current_session


def _resolve_subscriptions(prowler_sdk_provider: ProwlerSDKProvider) -> list[str]:
    """Resolve Azure subscription IDs to scan."""
    identity = prowler_sdk_provider.identity
    if hasattr(identity, "subscriptions") and identity.subscriptions:
        return list(identity.subscriptions)
    if hasattr(identity, "subscription_ids") and identity.subscription_ids:
        return list(identity.subscription_ids)
    return []


def _sync_azure_resources(
    neo4j_session: neo4j.Session,
    credentials,
    tenant_id: str,
    subscriptions: list[str],
    common_job_parameters: dict,
    cartography_config: CartographyConfig,
    prowler_api_provider: ProwlerAPIProvider,
    attack_paths_scan: ProwlerAPIAttackPathsScan,
) -> dict[str, str]:
    """Sync Azure resources using Cartography's Azure intel module."""
    failed_syncs = {}
    requested_syncs = list(cartography_azure.RESOURCE_FUNCTIONS.keys())

    current_progress = 3
    max_progress = 92
    n_steps = len(requested_syncs) or 1
    progress_step = (max_progress - current_progress) / n_steps

    for func_name in requested_syncs:
        if func_name not in cartography_azure.RESOURCE_FUNCTIONS:
            continue

        logger.info(
            f"Syncing function {func_name} for Azure tenant {tenant_id}"
        )
        current_progress += progress_step
        db_utils.update_attack_paths_scan_progress(
            attack_paths_scan, int(current_progress)
        )

        try:
            t0 = time.perf_counter()
            cartography_azure.RESOURCE_FUNCTIONS[func_name](
                neo4j_session=neo4j_session,
                credentials=credentials,
                tenant_id=tenant_id,
                subscription_ids=subscriptions,
                update_tag=cartography_config.update_tag,
                common_job_parameters=common_job_parameters,
            )
            logger.info(
                f"Synced function {func_name} for Azure tenant {tenant_id} "
                f"in {time.perf_counter() - t0:.3f}s"
            )
        except Exception as e:
            exception_message = utils.stringify_exception(
                e, f"Exception for Azure sync function: {func_name}"
            )
            failed_syncs[func_name] = exception_message
            logger.warning(
                f"Caught exception syncing function {func_name} from Azure "
                f"tenant {tenant_id}: {e}. Continuing.",
                exc_info=True,
            )

    return failed_syncs


def extract_short_uid(uid: str) -> str:
    """Return the short identifier from an Azure resource ID.

    Azure resource IDs use '/' as separator. The last segment is typically
    the resource name (e.g., /subscriptions/.../resourceGroups/.../providers/.../vmName).
    """
    return uid.rsplit("/", 1)[-1]
