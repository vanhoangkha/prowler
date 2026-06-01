"""Cloud event ingestion - pulls events from SQS/EventHub/PubSub.

Runs as a Celery beat task to continuously ingest cloud events
and feed them to the CDR detection engine.
"""

import json
from celery.utils.log import get_task_logger

import boto3

from tasks.jobs.cdr.engine import CloudEvent, DetectionEngine

logger = get_task_logger(__name__)


def ingest_aws_cloudtrail_sqs(
    boto3_session: boto3.Session,
    queue_url: str,
    max_messages: int = 10,
) -> list[CloudEvent]:
    """Pull CloudTrail events from SQS queue."""
    sqs = boto3_session.client("sqs")
    events = []

    response = sqs.receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=max_messages,
        WaitTimeSeconds=5,
    )

    for message in response.get("Messages", []):
        try:
            body = json.loads(message["Body"])
            # Handle SNS-wrapped messages
            if "Message" in body:
                body = json.loads(body["Message"])

            # Parse CloudTrail records
            records = body.get("Records", [body])
            for record in records:
                event = CloudEvent(
                    event_id=record.get("eventID", message["MessageId"]),
                    event_time=record.get("eventTime", ""),
                    event_source=record.get("eventSource", ""),
                    event_name=record.get("eventName", ""),
                    provider="aws",
                    region=record.get("awsRegion", ""),
                    account_id=record.get("recipientAccountId", ""),
                    principal=record.get("userIdentity", {}).get("arn", ""),
                    source_ip=record.get("sourceIPAddress"),
                    user_agent=record.get("userAgent"),
                    resources=[r.get("ARN", "") for r in record.get("resources", [])],
                    raw=record,
                )
                events.append(event)

            # Delete processed message
            sqs.delete_message(
                QueueUrl=queue_url,
                ReceiptHandle=message["ReceiptHandle"],
            )
        except Exception as e:
            logger.warning(f"Failed to parse SQS message: {e}")

    return events


def process_and_alert(events: list[CloudEvent]) -> int:
    """Process events through detection engine and dispatch alerts."""
    engine = DetectionEngine()
    alerts = engine.process_events(events)

    if alerts:
        logger.info(f"Generated {len(alerts)} alerts from {len(events)} events")
        # TODO: Persist alerts to CDRAlert model
        # TODO: Dispatch via AlertDispatcher

    return len(alerts)
