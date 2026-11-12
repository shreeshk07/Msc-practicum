"""Tests for phishtriage.indicators."""

from __future__ import annotations

import base64
from pathlib import Path

from phishtriage.indicators import (
    extract_indicators,
    _analyse_url,
    _analyse_headers,
    _analyse_content,
)
from phishtriage.parser import ParsedEmail, parse_eml
from phishtriage.utils import load_settings


FIXTURES = Path(__file__).parent / "fixtures"
SETTINGS = load_settings()
BRANDS = {b.lower() for b in SETTINGS.get("known_brand_keywords", [])}
SUBJECT_BRANDS = {b.lower() for b in SETTINGS.get("subject_brand_keywords", [])} or BRANDS
SHORTENERS = {s.lower() for s in SETTINGS.get("url_shorteners", [])}
LONG = int(SETTINGS.get("url_length_threshold", 150))
# URL-008 redirector-unwrapping configuration, loaded the same way the
# pipeline loads it in extract_indicators.
REDIRECTOR_HOSTS = {h.lower() for h in SETTINGS.get("url_redirector_hosts", [])}
REDIRECT_PARAMS = {p.lower() for p in SETTINGS.get("redirect_param_names", [])}
SUSPICIOUS_TLDS = {t.lower().lstrip(".") for t in SETTINGS.get("suspicious_tlds", [])}


# URL analysis: unit tests

def test_url_with_ip_host_flagged_as_ip():
    f = _analyse_url("http://192.0.2.99/login.php?session=abc",
                     BRANDS, SHORTENERS, {}, LONG)
    assert f.is_ip is True
    assert f.is_subdomain_brand_spoof is False  # IP URLs never trip URL-005


def test_url_with_punycode_label_flagged():
    f = _analyse_url("https://xn--paypa1-9zd.example.tld/",
                     BRANDS, SHORTENERS, {}, LONG)
    assert f.is_punycode is True


def test_url_with_known_shortener_flagged():
    f = _analyse_url("https://bit.ly/abc123", BRANDS, SHORTENERS, {}, LONG)
    assert f.is_shortener is True


def test_url_with_subdomain_brand_spoof():
    f = _analyse_url("https://paypal.attacker.tld/secure",
                     BRANDS, SHORTENERS, {}, LONG)
    assert f.is_subdomain_brand_spoof is True
    assert f.spoofed_brand == "paypal"


def test_genuine_brand_not_flagged_as_spoof():
    # On the real paypal.com domain, paypal-as-subdomain shouldn't trip
    # the spoof detector.
    f = _analyse_url("https://www.paypal.com/login",
                     BRANDS, SHORTENERS, {}, LONG)
    assert f.is_subdomain_brand_spoof is False


def test_long_url_flagged():
    long_url = "https://example.com/" + "a" * 200
    f = _analyse_url(long_url, BRANDS, SHORTENERS, {}, LONG)
    assert f.is_long is True
    assert f.length == len(long_url)


def test_short_url_not_flagged_as_long():
    f = _analyse_url("https://example.com/x", BRANDS, SHORTENERS, {}, LONG)
    assert f.is_long is False


def test_ioc_match_url_grained():
    iocs = {"https://bad.tld/login": "urlhaus_recent.txt"}
    f = _analyse_url("https://bad.tld/login", BRANDS, SHORTENERS, iocs, LONG)
    assert f.is_in_ioc_list is True
    assert f.matching_ioc_source == "urlhaus_recent.txt"


def test_ioc_match_domain_grained():
    iocs = {"bad.tld": "phishtank_recent.txt"}
    f = _analyse_url("https://bad.tld/somepath", BRANDS, SHORTENERS, iocs, LONG)
    assert f.is_in_ioc_list is True


# Header analysis

def test_header_from_vs_return_path_mismatch():
    pe = ParsedEmail(from_address="a@example.com",
                     return_path="bounce@other.tld")
    h = _analyse_headers(pe, BRANDS)
    assert h.from_vs_return_path_mismatch is True


def test_header_no_mismatch_on_aligned_subdomain():
    pe = ParsedEmail(from_address="news@news.example.com",
                     return_path="bounce@example.com")
    h = _analyse_headers(pe, BRANDS)
    # Both registered domains are example.com, so it should NOT mismatch.
    assert h.from_vs_return_path_mismatch is False


def test_header_brand_spoof_in_display_name():
    pe = ParsedEmail(from_address="x@paypa1.com",
                     display_name="PayPal Security Team")
    h = _analyse_headers(pe, BRANDS)
    assert h.display_name_brand_spoof is True
    assert h.display_name_brand == "paypal"


def test_header_brand_in_display_name_on_genuine_domain_not_spoof():
    pe = ParsedEmail(from_address="x@paypal.com",
                     display_name="PayPal Security Team")
    h = _analyse_headers(pe, BRANDS)
    assert h.display_name_brand == "paypal"
    assert h.display_name_brand_spoof is False


def test_header_x_mailer_present_flag():
    pe = ParsedEmail(from_address="x@a.tld", mailer="My MUA 1.0")
    assert _analyse_headers(pe, BRANDS).mailer_present is True

    pe2 = ParsedEmail(from_address="x@a.tld", mailer="")
    assert _analyse_headers(pe2, BRANDS).mailer_present is False


# Content analysis

def test_content_urgency_phrase_detected():
    pe = ParsedEmail(body_text="Your account will be suspended within 24 hours. ACT NOW.")
    c = _analyse_content(pe, SETTINGS)
    assert "within 24 hours" in c.urgency_hits
    assert "act now" in c.urgency_hits


def test_content_credential_phrase_detected():
    pe = ParsedEmail(body_text="Please verify your identity and update your payment.")
    c = _analyse_content(pe, SETTINGS)
    assert any("verify your identity" in p for p in c.credential_hits)


def test_content_no_phrases_in_clean_text():
    pe = ParsedEmail(body_text="Here's the weekly digest. Three new articles.")
    c = _analyse_content(pe, SETTINGS)
    assert c.urgency_hits == []
    assert c.credential_hits == []


def test_content_hidden_text_in_html():
    pe = ParsedEmail(body_html='<p style="display:none">hidden marketing text</p><p>Visible body.</p>')
    c = _analyse_content(pe, SETTINGS)
    assert c.has_hidden_text is True


def test_content_zero_width_chars_detected():
    # Zero-width space embedded in HTML
    pe = ParsedEmail(body_html="<p>p\u200ba\u200by\u200bp\u200ba\u200bl</p>")
    c = _analyse_content(pe, SETTINGS)
    assert c.has_hidden_text is True


def test_content_visible_vs_href_mismatch_detected():
    html = '<a href="http://attacker.tld/x">https://www.paypal.com/login</a>'
    pe = ParsedEmail(body_html=html)
    c = _analyse_content(pe, SETTINGS)
    assert c.visible_vs_href_mismatch is True


def test_content_visible_vs_href_no_mismatch_on_text_label():
    # Visible text is just "click here", not a URL, so no false positive.
    html = '<a href="http://attacker.tld/x">click here</a>'
    pe = ParsedEmail(body_html=html)
    c = _analyse_content(pe, SETTINGS)
    assert c.visible_vs_href_mismatch is False


# Integration on the real fixtures

def test_phishing_fixture_has_expected_indicators():
    parsed = parse_eml(FIXTURES / "sample_phishing.eml")
    ind = extract_indicators(parsed, SETTINGS)
    assert ind.header.from_vs_return_path_mismatch is True
    assert ind.header.from_vs_reply_to_mismatch is True
    assert ind.header.display_name_brand_spoof is True
    assert ind.header.mailer_present is False
    assert any(u.is_ip for u in ind.urls)
    assert ind.content.urgency_hits  # non-empty
    assert ind.content.credential_hits
    assert ind.content.visible_vs_href_mismatch is True


def test_benign_fixture_has_no_red_flags():
    parsed = parse_eml(FIXTURES / "sample_benign.eml")
    ind = extract_indicators(parsed, SETTINGS)
    assert ind.header.from_vs_return_path_mismatch is False
    assert ind.header.from_vs_reply_to_mismatch is False
    assert ind.header.display_name_brand_spoof is False
    assert ind.header.mailer_present is True
    assert all(not u.is_ip for u in ind.urls)
    assert ind.content.urgency_hits == []
    assert ind.content.credential_hits == []
    assert ind.content.visible_vs_href_mismatch is False
    # New rules shouldn't trip on the benign fixture either.
    assert ind.header.subject_brand_from_mismatch is False
    assert ind.content.subject_pretext_hits == []


# Subject pretext and subject-vs-from brand checks (CNT-006 / HDR-006)

def test_subject_pretext_phrase_detected():
    pe = ParsedEmail(subject="Your mailbox is full, please verify",
                     body_text="hello")
    c = _analyse_content(pe, SETTINGS)
    assert "mailbox is full" in c.subject_pretext_hits


def test_subject_pretext_not_detected_on_clean_subject():
    pe = ParsedEmail(subject="Weekly product digest from the team",
                     body_text="hello")
    c = _analyse_content(pe, SETTINGS)
    assert c.subject_pretext_hits == []


def test_subject_brand_mismatch_detected_when_from_unrelated():
    pe = ParsedEmail(subject="Fifth Third Bank Account Alerts",
                     from_address="x@creditloiuse.com")
    h = _analyse_headers(pe, BRANDS, SUBJECT_BRANDS)
    assert h.subject_brand_from_mismatch is True
    assert h.subject_brand == "fifth third bank"


def test_subject_brand_no_mismatch_when_brand_in_from_domain():
    pe = ParsedEmail(subject="PayPal account update notification",
                     from_address="x@mail.paypal.com")
    h = _analyse_headers(pe, BRANDS, SUBJECT_BRANDS)
    # "paypal" is in the subject AND in the from-domain
    # "mail.paypal.com", so HDR-006 should not fire.
    assert h.subject_brand_from_mismatch is False


def test_subject_brand_no_mismatch_when_subject_clean():
    pe = ParsedEmail(subject="Weekly newsletter, three new articles",
                     from_address="x@some-newsletter.com")
    h = _analyse_headers(pe, BRANDS, SUBJECT_BRANDS)
    assert h.subject_brand_from_mismatch is False
    assert h.subject_brand == ""


# CNT-007 subject lure regex patterns (v1.3)

def test_cnt_007_fires_on_system_alert_subject():
    # FN case 1 from v1.2 pilot.
    pe = ParsedEmail(subject="Mailbox Bandwith Storage Server is full")
    c = _analyse_content(pe, SETTINGS)
    assert c.subject_lure_matches, \
        f"expected a lure match, got {c.subject_lure_matches!r}"


def test_cnt_007_fires_on_financial_lure_subject():
    # FN cases 7 and 8 from v1.2 pilot.
    pe = ParsedEmail(subject="Purchase-Order/SOA/Invoice/Payment")
    c = _analyse_content(pe, SETTINGS)
    assert c.subject_lure_matches


def test_cnt_007_fires_on_file_sharing_impersonation():
    # FN case 3 from v1.2 pilot.
    pe = ParsedEmail(subject="George Lancaster shared an Onshape folder with you")
    c = _analyse_content(pe, SETTINGS)
    assert c.subject_lure_matches


def test_cnt_007_fires_on_hr_pretext_subject():
    # FN case 6 from v1.2 pilot.
    pe = ParsedEmail(subject="2024 Annual Leave Compliance Report")
    c = _analyse_content(pe, SETTINGS)
    assert c.subject_lure_matches


def test_cnt_007_fires_on_credential_keyword_subject():
    # FN case 2 from v1.2 pilot.
    pe = ParsedEmail(subject="IMPORTANT: Keep Same Credential For Monkey Email")
    c = _analyse_content(pe, SETTINGS)
    assert c.subject_lure_matches


def test_cnt_007_does_not_fire_on_clean_subject():
    pe = ParsedEmail(subject="Weekly product digest from the team")
    c = _analyse_content(pe, SETTINGS)
    assert c.subject_lure_matches == []


def test_cnt_007_fires_on_email_service_alert():
    # v3b regression. The system-alert noun group used to be '\bmail\b',
    # which cannot match inside "Email" (no word boundary before the 'm'),
    # so this subject silently failed to fire CNT-007. The fix uses
    # 'e?mails?' so "Email" / "email" / "emails" all match.
    pe = ParsedEmail(subject="Important: Email Service Alert")
    c = _analyse_content(pe, SETTINGS)
    assert c.subject_lure_matches, \
        f"expected a lure match, got {c.subject_lure_matches!r}"


# HDR-006 substring regression: "chase" must not match inside "purchase"

def test_hdr_006_substring_bug_chase_not_in_purchase():
    # v1.2 fired HDR-006 here because "chase" appeared as a literal
    # substring of "purchase". v1.3 uses word-boundary regex matching,
    # so the rule must NOT trip on this subject.
    pe = ParsedEmail(subject="Purchase-Order/SOA/Invoice/Payment",
                     from_address="x@veenra.com")
    h = _analyse_headers(pe, BRANDS, SUBJECT_BRANDS)
    assert h.subject_brand != "chase"
    assert h.subject_brand_from_mismatch is False


# URL-008 first-hop redirector unwrapping (v3b)

def test_url_008_unwraps_redirecturl_param():
    # A named redirect parameter (redirectUrl=) carrying a percent-encoded
    # destination whose host is an IP literal. The wrapper host itself is
    # an ordinary .com, so only the unwrapped destination is risky.
    wrapped = ("https://t.example-tracker.com/clk?"
               "redirectUrl=http%3A%2F%2F192.0.2.77%2Flogin&sig=abc")
    f = _analyse_url(wrapped, BRANDS, SHORTENERS, {}, LONG,
                     redirector_hosts=REDIRECTOR_HOSTS,
                     redirect_params=REDIRECT_PARAMS,
                     suspicious_tlds=SUSPICIOUS_TLDS)
    assert f.is_wrapped_redirect is True
    assert f.unwrapped_host == "192.0.2.77"
    assert f.unwrapped_destination_risky is True
    assert f.unwrapped_risk_reason == "ip_host"


def test_url_008_unwraps_base64_target():
    # A 'target=' parameter holding a base64 blob that decodes to a URL
    # with an IP-literal host. Exercises the base64 destination path.
    blob = base64.urlsafe_b64encode(b"https://192.0.2.88/verify").decode().rstrip("=")
    wrapped = f"https://go.example-redir.com/r?target={blob}"
    f = _analyse_url(wrapped, BRANDS, SHORTENERS, {}, LONG,
                     redirector_hosts=REDIRECTOR_HOSTS,
                     redirect_params=REDIRECT_PARAMS,
                     suspicious_tlds=SUSPICIOUS_TLDS)
    assert f.is_wrapped_redirect is True
    assert f.unwrapped_host == "192.0.2.88"
    assert f.unwrapped_destination_risky is True


def test_url_008_does_not_fire_on_clean_redirect():
    # A genuine Microsoft Safe Links wrapper pointing at microsoft.com.
    # The host is recognised as a redirector (so is_wrapped_redirect is
    # True) and the destination is extracted, but microsoft.com trips no
    # URL risk signal, so URL-008 must NOT fire.
    wrapped = ("https://na01.safelinks.protection.outlook.com/?"
               "url=https%3A%2F%2Fwww.microsoft.com%2Fen-us%2Fsecurity&data=x")
    f = _analyse_url(wrapped, BRANDS, SHORTENERS, {}, LONG,
                     redirector_hosts=REDIRECTOR_HOSTS,
                     redirect_params=REDIRECT_PARAMS,
                     suspicious_tlds=SUSPICIOUS_TLDS)
    assert f.is_wrapped_redirect is True
    assert f.unwrapped_host == "www.microsoft.com"
    assert f.unwrapped_destination_risky is False
    assert f.unwrapped_risk_reason == ""
