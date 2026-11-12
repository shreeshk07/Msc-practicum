"""Tests for phishtriage.auth."""

from __future__ import annotations

from phishtriage.auth import check_auth


# Common header shapes

PASS_HEADER = (
    "mx.recipient.com; "
    "spf=pass smtp.mailfrom=example.com; "
    "dkim=pass header.d=example.com; "
    "dmarc=pass action=none header.from=example.com"
)

FAIL_HEADER = (
    "mx.recipient.com; "
    "spf=fail smtp.mailfrom=bulksender.tld; "
    "dkim=none; "
    "dmarc=fail action=quarantine header.from=paypa1.com"
)

PARTIAL_HEADER = (
    "mx.recipient.com; "
    "spf=softfail smtp.mailfrom=marketing.example.com; "
    "dkim=pass header.d=example.com"
)

# Some MTAs emit a single-token "spf=neutral" or "dmarc=temperror".
EDGE_HEADER = (
    "mx.recipient.com; "
    "spf=neutral; "
    "dkim=fail; "
    "dmarc=temperror"
)


# Happy path

def test_all_pass_header():
    r = check_auth(PASS_HEADER, from_domain="example.com")
    assert r.spf == "pass"
    assert r.dkim == "pass"
    assert r.dmarc == "pass"
    assert r.aligned is True
    assert r.ar_present is True


def test_all_fail_header():
    r = check_auth(FAIL_HEADER, from_domain="paypa1.com")
    assert r.spf == "fail"
    assert r.dkim == "none"
    assert r.dmarc == "fail"
    assert r.aligned is False


# Edge cases

def test_partial_header_softfail_and_dkim_only():
    r = check_auth(PARTIAL_HEADER, from_domain="example.com")
    assert r.spf == "softfail"
    assert r.dkim == "pass"
    # No DMARC token at all, should remain unknown
    assert r.dmarc == "unknown"
    # Aligned requires DMARC pass, so this must be False.
    assert r.aligned is False


def test_edge_keywords_are_preserved():
    r = check_auth(EDGE_HEADER, from_domain="example.com")
    assert r.spf == "neutral"
    assert r.dkim == "fail"
    assert r.dmarc == "temperror"


def test_absent_header_returns_unknowns():
    r = check_auth("", from_domain="example.com")
    assert r.spf == "unknown"
    assert r.dkim == "unknown"
    assert r.dmarc == "unknown"
    assert r.ar_present is False
    assert r.aligned is False


def test_no_from_domain_does_not_align_even_on_pass():
    r = check_auth(PASS_HEADER, from_domain="")
    # No From-domain means alignment cannot be evaluated.
    assert r.aligned is False


def test_unrelated_from_domain_does_not_align():
    # All three pass but the From-domain belongs to a different
    # organisation, so alignment must be False.
    r = check_auth(PASS_HEADER, from_domain="totally-different.tld")
    assert r.spf == "pass"
    assert r.dmarc == "pass"
    assert r.aligned is False


def test_subdomain_alignment_is_relaxed():
    header = (
        "mx; spf=pass smtp.mailfrom=mail.example.com; "
        "dkim=pass header.d=example.com; "
        "dmarc=pass header.from=example.com"
    )
    r = check_auth(header, from_domain="example.com")
    # mail.example.com is a subdomain of example.com, so relaxed alignment is OK.
    assert r.aligned is True
