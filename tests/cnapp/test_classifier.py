"""Tests for the DSPM data classifier."""

import sys
sys.path.insert(0, "api/src/backend")

from tasks.jobs.dspm.classifier import DataClassifier, DataCategory, Sensitivity


def test_detect_ssn():
    classifier = DataClassifier()
    findings = classifier.classify_text("SSN: 123-45-6789")
    assert len(findings) >= 1
    assert any(f.category == DataCategory.PII and f.rule_name == "SSN" for f in findings)


def test_detect_credit_card():
    classifier = DataClassifier()
    findings = classifier.classify_text("Card: 4111111111111111")
    assert any(f.category == DataCategory.PCI for f in findings)


def test_detect_email():
    classifier = DataClassifier()
    findings = classifier.classify_text("Contact: user@example.com")
    assert any(f.rule_name == "Email" for f in findings)


def test_detect_aws_key():
    classifier = DataClassifier()
    findings = classifier.classify_text("key=AKIAIOSFODNN7EXAMPLE")
    assert any(f.category == DataCategory.CREDENTIALS for f in findings)


def test_detect_private_key():
    classifier = DataClassifier()
    findings = classifier.classify_text("-----BEGIN RSA PRIVATE KEY-----")
    assert any(f.rule_name == "Private Key" for f in findings)


def test_no_findings_clean_text():
    classifier = DataClassifier()
    findings = classifier.classify_text("This is a normal document with no sensitive data.")
    assert len(findings) == 0


def test_multiple_findings():
    classifier = DataClassifier()
    text = "SSN: 123-45-6789, Email: test@test.com, Card: 5500000000000004"
    findings = classifier.classify_text(text)
    categories = {f.category for f in findings}
    assert DataCategory.PII in categories
    assert DataCategory.PCI in categories


def test_sensitivity_levels():
    classifier = DataClassifier()
    findings = classifier.classify_text("AKIAIOSFODNN7EXAMPLE")
    assert all(f.sensitivity == Sensitivity.CRITICAL for f in findings if f.rule_name == "AWS Key")
