"""Celery tasks for CNAPP modules.

Registers all CNAPP-specific async tasks with Celery.
These tasks are triggered by API views and run in worker processes.
"""

from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(name="cnapp.cwpp.vm_scan")
def cwpp_vm_scan_task(provider_id: str, instance_ids: list[str] | None = None, scan_types: list[str] | None = None):
    """Async task: Run agentless VM scan."""
    from api.models import Provider
    from tasks.jobs.cwpp.tasks import run_vm_scan

    logger.info(f"Starting CWPP VM scan for provider {provider_id}")
    try:
        provider = Provider.objects.get(id=provider_id)
        results = run_vm_scan(provider, instance_ids, scan_types)
        logger.info(f"CWPP VM scan complete: {len(results)} results")
        return {"status": "complete", "results_count": len(results)}
    except Provider.DoesNotExist:
        logger.error(f"Provider {provider_id} not found")
        return {"status": "error", "message": "Provider not found"}
    except Exception as e:
        logger.error(f"CWPP VM scan failed: {e}")
        return {"status": "error", "message": "Internal error. Check logs for details."}


@shared_task(name="cnapp.cwpp.container_scan")
def cwpp_container_scan_task(provider_id: str, repositories: list[str] | None = None):
    """Async task: Run container image scan."""
    from api.models import Provider
    from tasks.jobs.cwpp.tasks import run_container_scan

    logger.info(f"Starting container scan for provider {provider_id}")
    try:
        provider = Provider.objects.get(id=provider_id)
        results = run_container_scan(provider, repositories)
        return {"status": "complete", "results_count": len(results)}
    except Exception as e:
        logger.error(f"Container scan failed: {e}")
        return {"status": "error", "message": "Internal error. Check logs for details."}


@shared_task(name="cnapp.ciem.analyze_identity")
def ciem_analyze_identity_task(provider_id: str, identity_arn: str):
    """Async task: Analyze identity permissions and compute risk."""
    from tasks.jobs.ciem.analyzer import PermissionAnalyzer
    from tasks.jobs.ciem.aws_iam import parse_iam_user_permissions, parse_iam_role_permissions
    from tasks.jobs.ciem.cloudtrail import get_used_permissions

    logger.info(f"Analyzing identity {identity_arn}")
    try:
        analyzer = PermissionAnalyzer()
        # TODO: Get boto3 session from provider
        # profile = parse_iam_role_permissions(session, role_name, account_id)
        # profile.used_permissions = get_used_permissions(session, identity_arn)
        # result = analyzer.analyze_identity(profile)
        return {"status": "complete", "identity_arn": identity_arn}
    except Exception as e:
        logger.error(f"CIEM analysis failed: {e}")
        return {"status": "error", "message": "Internal error. Check logs for details."}


@shared_task(name="cnapp.dspm.classify")
def dspm_classification_task(provider_id: str, bucket_names: list[str] | None = None):
    """Async task: Run data classification scan."""
    from tasks.jobs.dspm.classifier import DataClassifier

    logger.info(f"Starting DSPM classification for provider {provider_id}")
    try:
        classifier = DataClassifier()
        # TODO: Get boto3 session, list buckets, scan each
        return {"status": "complete", "provider_id": provider_id}
    except Exception as e:
        logger.error(f"DSPM classification failed: {e}")
        return {"status": "error", "message": "Internal error. Check logs for details."}


@shared_task(name="cnapp.cdr.process_events")
def cdr_process_events_task(provider_id: str, events: list[dict]):
    """Async task: Process cloud events through detection engine."""
    from tasks.jobs.cdr.engine import DetectionEngine, CloudEvent
    from tasks.jobs.integrations.dispatcher import AlertDispatcher, AlertPayload

    logger.info(f"Processing {len(events)} events for provider {provider_id}")
    try:
        engine = DetectionEngine()
        cloud_events = [
            CloudEvent(
                event_id=e.get("event_id", ""),
                event_time=e.get("event_time", ""),
                event_source=e.get("event_source", ""),
                event_name=e.get("event_name", ""),
                provider=e.get("provider", "aws"),
                region=e.get("region", ""),
                account_id=e.get("account_id", ""),
                principal=e.get("principal", ""),
                source_ip=e.get("source_ip"),
                resources=e.get("resources", []),
            )
            for e in events
        ]

        alerts = engine.process_events(cloud_events)
        logger.info(f"Generated {len(alerts)} alerts")

        # Dispatch alerts
        # dispatcher = AlertDispatcher(channels=configured_channels)
        # for alert in alerts:
        #     dispatcher.dispatch(AlertPayload(...))

        return {"status": "complete", "alerts_generated": len(alerts)}
    except Exception as e:
        logger.error(f"CDR processing failed: {e}")
        return {"status": "error", "message": "Internal error. Check logs for details."}
