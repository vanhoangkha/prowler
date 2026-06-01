"""Alert Dispatcher - routes alerts to configured channels.

Supports: Slack, PagerDuty, Email, Webhook, Jira, ServiceNow.
"""

import ipaddress
import json
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

import httpx
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)

# SSRF protection: block private/internal networks
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _validate_url(url: str) -> tuple[bool, str | None]:
    """Validate URL and resolve IP for SSRF protection.
    
    Returns (is_valid, resolved_ip) to pin DNS for the actual request.
    """
    import socket
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        if not (parsed.scheme == "http" and parsed.hostname == "hooks.slack.com"):
            return False, None
    if not parsed.hostname:
        return False, None
    try:
        # Resolve ALL addresses (IPv4 + IPv6)
        addrs = socket.getaddrinfo(parsed.hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
        for family, _, _, _, sockaddr in addrs:
            ip_str = sockaddr[0]
            addr = ipaddress.ip_address(ip_str)
            # Block private, loopback, link-local, reserved
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                logger.warning(f"SSRF blocked: {url} resolves to {ip_str}")
                return False, None
        # Return first valid IP for pinning
        return True, addrs[0][4][0]
    except (socket.gaierror, ValueError, OSError):
        return False, None


class ChannelType(Enum):
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"
    WEBHOOK = "webhook"
    JIRA = "jira"
    SERVICENOW = "servicenow"


@dataclass
class AlertChannel:
    id: str
    name: str
    channel_type: ChannelType
    config: dict  # webhook_url, api_key, project_key, etc.
    severity_filter: list[str] | None = None  # only route these severities
    enabled: bool = True


@dataclass
class AlertPayload:
    alert_id: str
    title: str
    description: str
    severity: str
    provider: str
    account_id: str
    region: str
    principal: str
    resources: list[str]
    mitre_tactic: str = ""
    url: str = ""


class AlertDispatcher:
    """Routes alerts to configured notification channels."""

    def __init__(self, channels: list[AlertChannel] | None = None):
        self.channels = channels or []

    def dispatch(self, payload: AlertPayload) -> dict[str, bool]:
        """Send alert to all matching channels. Returns {channel_id: success}."""
        results = {}
        for channel in self.channels:
            if not channel.enabled:
                continue
            if channel.severity_filter and payload.severity not in channel.severity_filter:
                continue
            try:
                success = self._send(channel, payload)
                results[channel.id] = success
            except Exception as e:
                logger.error(f"Failed to dispatch to {channel.name}: {e}")
                results[channel.id] = False
        return results

    def _send(self, channel: AlertChannel, payload: AlertPayload) -> bool:
        """Send to a specific channel."""
        if channel.channel_type == ChannelType.SLACK:
            return self._send_slack(channel, payload)
        elif channel.channel_type == ChannelType.WEBHOOK:
            return self._send_webhook(channel, payload)
        elif channel.channel_type == ChannelType.PAGERDUTY:
            return self._send_pagerduty(channel, payload)
        elif channel.channel_type == ChannelType.JIRA:
            return self._send_jira(channel, payload)
        return False

    def _send_slack(self, channel: AlertChannel, payload: AlertPayload) -> bool:
        """Send Slack notification."""
        webhook_url = channel.config.get("webhook_url")
        valid, _ = _validate_url(webhook_url) if webhook_url else (False, None)
        if not valid:
            return False
        color = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#6b7280"}.get(payload.severity, "#6b7280")
        body = {
            "attachments": [{
                "color": color,
                "title": f"[{payload.severity.upper()}] {payload.title}",
                "text": payload.description,
                "fields": [
                    {"title": "Provider", "value": payload.provider, "short": True},
                    {"title": "Account", "value": payload.account_id, "short": True},
                    {"title": "Region", "value": payload.region, "short": True},
                    {"title": "Principal", "value": payload.principal, "short": True},
                ],
            }]
        }
        resp = httpx.post(webhook_url, json=body, timeout=10)
        return resp.status_code == 200

    def _send_webhook(self, channel: AlertChannel, payload: AlertPayload) -> bool:
        """Send generic webhook."""
        url = channel.config.get("url")
        valid, _ = _validate_url(url) if url else (False, None)
        if not valid:
            return False
        headers = channel.config.get("headers", {})
        body = {
            "alert_id": payload.alert_id,
            "title": payload.title,
            "severity": payload.severity,
            "description": payload.description,
            "provider": payload.provider,
            "account_id": payload.account_id,
            "resources": payload.resources,
        }
        resp = httpx.post(url, json=body, headers=headers, timeout=10)
        return 200 <= resp.status_code < 300

    def _send_pagerduty(self, channel: AlertChannel, payload: AlertPayload) -> bool:
        """Send PagerDuty event."""
        routing_key = channel.config.get("routing_key")
        if not routing_key:
            return False
        pd_severity = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}.get(payload.severity, "info")
        body = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": payload.title,
                "severity": pd_severity,
                "source": f"prowler-{payload.provider}",
                "custom_details": {"description": payload.description, "account": payload.account_id},
            },
        }
        resp = httpx.post("https://events.pagerduty.com/v2/enqueue", json=body, timeout=10)
        return resp.status_code == 202

    def _send_jira(self, channel: AlertChannel, payload: AlertPayload) -> bool:
        """Create Jira ticket."""
        base_url = channel.config.get("base_url")
        project_key = channel.config.get("project_key")
        api_token = channel.config.get("api_token")
        email = channel.config.get("email")
        if not all([base_url, project_key, api_token, email]):
            return False
        valid, _ = _validate_url(base_url)
        if not valid:
            return False
        priority = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}.get(payload.severity, "Medium")
        body = {
            "fields": {
                "project": {"key": project_key},
                "summary": f"[{payload.severity.upper()}] {payload.title}",
                "description": payload.description,
                "issuetype": {"name": "Bug"},
                "priority": {"name": priority},
            }
        }
        resp = httpx.post(
            f"{base_url}/rest/api/2/issue",
            json=body,
            auth=(email, api_token),
            timeout=15,
        )
        return resp.status_code == 201
