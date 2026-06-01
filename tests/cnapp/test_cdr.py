"""Tests for CDR detection engine."""

import sys
sys.path.insert(0, "api/src/backend")

from tasks.jobs.cdr.engine import DetectionEngine, CloudEvent, AlertSeverity


def _make_event(event_name: str, principal: str = "arn:aws:iam::123:user/test") -> CloudEvent:
    return CloudEvent(
        event_id="evt-1",
        event_time="2026-06-01T12:00:00Z",
        event_source="iam.amazonaws.com",
        event_name=event_name,
        provider="aws",
        region="us-east-1",
        account_id="123456789012",
        principal=principal,
    )


def test_detect_root_login():
    engine = DetectionEngine()
    event = _make_event("ConsoleLogin", principal="arn:aws:iam::123:root")
    alerts = engine.process_event(event)
    assert len(alerts) >= 1
    assert any(a.severity == AlertSeverity.CRITICAL for a in alerts)


def test_detect_cloudtrail_stopped():
    engine = DetectionEngine()
    event = _make_event("StopLogging")
    alerts = engine.process_event(event)
    assert len(alerts) >= 1
    assert alerts[0].rule_id == "cdr-aws-cloudtrail-stopped"


def test_detect_iam_user_created():
    engine = DetectionEngine()
    event = _make_event("CreateUser")
    alerts = engine.process_event(event)
    assert len(alerts) >= 1
    assert alerts[0].mitre_tactic == "Persistence"


def test_no_alert_normal_event():
    engine = DetectionEngine()
    event = _make_event("DescribeInstances")
    alerts = engine.process_event(event)
    assert len(alerts) == 0


def test_batch_processing():
    engine = DetectionEngine()
    events = [
        _make_event("ConsoleLogin", "arn:aws:iam::123:root"),
        _make_event("DescribeInstances"),
        _make_event("StopLogging"),
    ]
    alerts = engine.process_events(events)
    assert len(alerts) >= 2


def test_alert_has_mitre_mapping():
    engine = DetectionEngine()
    event = _make_event("ScheduleKeyDeletion")
    alerts = engine.process_event(event)
    assert len(alerts) >= 1
    assert alerts[0].mitre_technique == "T1485"
