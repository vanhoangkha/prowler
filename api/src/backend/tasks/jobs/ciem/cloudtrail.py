"""CloudTrail analyzer - determines which permissions are actually used.

Ingests CloudTrail events to compare granted vs used permissions,
enabling least-privilege recommendations.
"""

from collections import Counter
from datetime import datetime, timedelta, timezone

import boto3
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


def get_used_permissions(
    boto3_session: boto3.Session,
    identity_arn: str,
    days: int = 90,
    region: str = "us-east-1",
) -> list[str]:
    """Get list of API actions actually used by an identity from CloudTrail."""
    client = boto3_session.client("cloudtrail", region_name=region)
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)

    used_actions: set[str] = set()
    paginator = client.get_paginator("lookup_events")

    # Extract username/role from ARN for lookup
    lookup_value = identity_arn.split("/")[-1] if "/" in identity_arn else identity_arn

    try:
        pages = paginator.paginate(
            LookupAttributes=[{
                "AttributeKey": "Username",
                "AttributeValue": lookup_value,
            }],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=1000,
        )

        for page in pages:
            for event in page.get("Events", []):
                event_source = event.get("EventSource", "")
                event_name = event.get("EventName", "")
                # Convert to IAM action format: service:Action
                service = event_source.replace(".amazonaws.com", "")
                action = f"{service}:{event_name}"
                used_actions.add(action)

    except Exception as e:
        logger.warning(f"CloudTrail lookup failed for {identity_arn}: {e}")

    return sorted(used_actions)


def get_unused_credentials(
    boto3_session: boto3.Session,
    days_threshold: int = 90,
) -> list[dict]:
    """Find IAM credentials not used within threshold days."""
    iam = boto3_session.client("iam")
    unused = []
    threshold = datetime.now(timezone.utc) - timedelta(days=days_threshold)

    # Check users
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            password_last_used = user.get("PasswordLastUsed")
            if password_last_used and password_last_used < threshold:
                unused.append({
                    "type": "password",
                    "identity": user["UserName"],
                    "arn": user["Arn"],
                    "last_used": str(password_last_used),
                    "days_unused": (datetime.now(timezone.utc) - password_last_used).days,
                })

            # Check access keys
            keys = iam.list_access_keys(UserName=user["UserName"])
            for key in keys.get("AccessKeyMetadata", []):
                if key["Status"] != "Active":
                    continue
                last_used_resp = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                last_used = last_used_resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                if last_used and last_used < threshold:
                    unused.append({
                        "type": "access_key",
                        "identity": user["UserName"],
                        "arn": user["Arn"],
                        "key_id": key["AccessKeyId"],
                        "last_used": str(last_used),
                        "days_unused": (datetime.now(timezone.utc) - last_used).days,
                    })

    return unused
