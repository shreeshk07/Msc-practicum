"""Tests for phishtriage.parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from phishtriage.parser import parse_eml, parse_bytes


FIXTURES = Path(__file__).parent / "fixtures"


# Benign fixture

def test_parse_benign_extracts_from_fields():
    parsed = parse_eml(FIXTURES / "sample_benign.eml")
    assert parsed.from_address == "newsletter@notifications.example.com"
    assert parsed.from_domain == "notifications.example.com"
    assert parsed.display_name == "Example Newsletter"
    assert parsed.return_path == "newsletter@notifications.example.com"
    assert parsed.reply_to == ""


def test_parse_benign_extracts_subject_and_message_id():
    parsed = parse_eml(FIXTURES / "sample_benign.eml")
    assert parsed.subject == "Weekly digest from Example Inc."
    assert parsed.message_id.endswith("@notifications.example.com>")


def test_parse_benign_normalises_date_to_iso():
    parsed = parse_eml(FIXTURES / "sample_benign.eml")
    assert parsed.date_iso.startswith("2026-04-29T14:22:25")


def test_parse_benign_extracts_authentication_results():
    parsed = parse_eml(FIXTURES / "sample_benign.eml")
    ar = parsed.authentication_results.lower()
    assert "spf=pass" in ar
    assert "dkim=pass" in ar
    assert "dmarc=pass" in ar


def test_parse_benign_finds_text_and_html_bodies():
    parsed = parse_eml(FIXTURES / "sample_benign.eml")
    assert "Weekly product digest" in parsed.body_text or \
           "weekly product digest" in parsed.body_text
    assert "<a href=" in parsed.body_html


def test_parse_benign_extracts_three_urls():
    parsed = parse_eml(FIXTURES / "sample_benign.eml")
    # Three href URLs in the HTML; same three appear in plain text so
    # de-duplication should leave exactly three.
    assert len(parsed.urls) == 3
    assert any("blog/2026-04-29-roundup" in u for u in parsed.urls)


def test_parse_benign_received_chain_oldest_first():
    parsed = parse_eml(FIXTURES / "sample_benign.eml")
    assert isinstance(parsed.received_chain, list)
    assert len(parsed.received_chain) >= 1
    # First element should be the earliest hop (closest to sender)
    assert "mta-out-1.example.com" in parsed.received_chain[0]


def test_parse_benign_no_warnings():
    parsed = parse_eml(FIXTURES / "sample_benign.eml")
    assert parsed.warnings == []


# Phishing fixture

def test_parse_phishing_detects_mismatched_return_path():
    parsed = parse_eml(FIXTURES / "sample_phishing.eml")
    assert parsed.from_domain == "paypa1.com"
    assert parsed.return_path.endswith("@bulksender.tld")
    assert parsed.reply_to.endswith("@unrelated-mail.tld")


def test_parse_phishing_xmailer_absent():
    parsed = parse_eml(FIXTURES / "sample_phishing.eml")
    assert parsed.mailer == ""


def test_parse_phishing_extracts_ip_url():
    parsed = parse_eml(FIXTURES / "sample_phishing.eml")
    assert any("192.0.2.99" in u for u in parsed.urls)


# Robustness on malformed input

def test_parse_empty_bytes_does_not_raise():
    parsed = parse_bytes(b"")
    # Empty input still produces an object; downstream stages must
    # tolerate this case rather than the parser raising.
    assert parsed.from_address == ""
    assert parsed.urls == []


def test_parse_malformed_headers_does_not_raise():
    raw = b"This is not a valid email.\r\nIt has no headers.\r\n\r\nJust a body."
    parsed = parse_bytes(raw)
    # Should produce an object even when header parsing fails.
    assert isinstance(parsed.urls, list)
    assert isinstance(parsed.warnings, list)


def test_parse_html_only_message_derives_text():
    raw = (
        b"From: a@b.com\r\n"
        b"Subject: html-only\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b"<html><body><p>Hello <b>world</b>.</p>"
        b"<a href='https://example.org/x'>x</a></body></html>"
    )
    parsed = parse_bytes(raw)
    assert "Hello" in parsed.body_text
    assert "https://example.org/x" in parsed.urls
