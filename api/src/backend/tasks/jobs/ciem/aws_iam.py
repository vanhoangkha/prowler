"""AWS IAM Policy Parser - evaluates effective permissions.

Parses IAM policies (identity + resource + SCPs + permission boundaries)
to compute what an identity can actually do.
"""

import json
from celery.utils.log import get_task_logger

from tasks.jobs.ciem.analyzer import IdentityProfile, Permission

logger = get_task_logger(__name__)


def parse_iam_user_permissions(
    boto3_session,
    user_name: str,
    account_id: str,
) -> IdentityProfile:
    """Parse all effective permissions for an IAM user."""
    iam = boto3_session.client("iam")
    permissions: list[Permission] = []

    # 1. Inline policies
    inline_policies = iam.list_user_policies(UserName=user_name)
    for policy_name in inline_policies.get("PolicyNames", []):
        doc = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
        perms = _parse_policy_document(doc["PolicyDocument"], source=f"inline:{policy_name}")
        permissions.extend(perms)

    # 2. Attached managed policies
    attached = iam.list_attached_user_policies(UserName=user_name)
    for policy in attached.get("AttachedPolicies", []):
        doc = _get_policy_document(iam, policy["PolicyArn"])
        if doc:
            perms = _parse_policy_document(doc, source=policy["PolicyArn"])
            permissions.extend(perms)

    # 3. Group policies
    groups = iam.list_groups_for_user(UserName=user_name)
    for group in groups.get("Groups", []):
        group_perms = _get_group_permissions(iam, group["GroupName"])
        permissions.extend(group_perms)

    # Get last activity
    last_used = None
    try:
        access_keys = iam.list_access_keys(UserName=user_name)
        for key in access_keys.get("AccessKeyMetadata", []):
            key_last = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
            used = key_last.get("AccessKeyLastUsed", {}).get("LastUsedDate")
            if used:
                last_used = str(used)
    except Exception:
        pass

    return IdentityProfile(
        identity_id=f"arn:aws:iam::{account_id}:user/{user_name}",
        identity_type="user",
        provider="aws",
        name=user_name,
        granted_permissions=permissions,
        last_activity=last_used,
    )


def parse_iam_role_permissions(
    boto3_session,
    role_name: str,
    account_id: str,
) -> IdentityProfile:
    """Parse all effective permissions for an IAM role."""
    iam = boto3_session.client("iam")
    permissions: list[Permission] = []

    # Inline policies
    inline = iam.list_role_policies(RoleName=role_name)
    for policy_name in inline.get("PolicyNames", []):
        doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        perms = _parse_policy_document(doc["PolicyDocument"], source=f"inline:{policy_name}")
        permissions.extend(perms)

    # Attached managed policies
    attached = iam.list_attached_role_policies(RoleName=role_name)
    for policy in attached.get("AttachedPolicies", []):
        doc = _get_policy_document(iam, policy["PolicyArn"])
        if doc:
            perms = _parse_policy_document(doc, source=policy["PolicyArn"])
            permissions.extend(perms)

    # Get role last used
    last_used = None
    try:
        role_info = iam.get_role(RoleName=role_name)
        last = role_info["Role"].get("RoleLastUsed", {}).get("LastUsedDate")
        if last:
            last_used = str(last)
    except Exception:
        pass

    return IdentityProfile(
        identity_id=f"arn:aws:iam::{account_id}:role/{role_name}",
        identity_type="role",
        provider="aws",
        name=role_name,
        granted_permissions=permissions,
        last_activity=last_used,
    )


def _get_policy_document(iam_client, policy_arn: str) -> dict | None:
    """Get the default version document of a managed policy."""
    try:
        policy = iam_client.get_policy(PolicyArn=policy_arn)
        version_id = policy["Policy"]["DefaultVersionId"]
        version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        return version["PolicyVersion"]["Document"]
    except Exception as e:
        logger.warning(f"Failed to get policy {policy_arn}: {e}")
        return None


def _get_group_permissions(iam_client, group_name: str) -> list[Permission]:
    """Get all permissions from a group's policies."""
    permissions = []

    # Inline
    inline = iam_client.list_group_policies(GroupName=group_name)
    for name in inline.get("PolicyNames", []):
        doc = iam_client.get_group_policy(GroupName=group_name, PolicyName=name)
        permissions.extend(_parse_policy_document(doc["PolicyDocument"], source=f"group:{group_name}:{name}"))

    # Attached
    attached = iam_client.list_attached_group_policies(GroupName=group_name)
    for policy in attached.get("AttachedPolicies", []):
        doc = _get_policy_document(iam_client, policy["PolicyArn"])
        if doc:
            permissions.extend(_parse_policy_document(doc, source=policy["PolicyArn"]))

    return permissions


def _parse_policy_document(document: dict | str, source: str = "") -> list[Permission]:
    """Parse an IAM policy document into Permission objects."""
    if isinstance(document, str):
        document = json.loads(document)

    permissions = []
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        effect = stmt.get("Effect", "Deny")
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", ["*"])
        condition = stmt.get("Condition")

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        for action in actions:
            for resource in resources:
                permissions.append(Permission(
                    action=action,
                    resource=resource,
                    effect=effect,
                    condition=condition,
                    source=source,
                ))

    return permissions
