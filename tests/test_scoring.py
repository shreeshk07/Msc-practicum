"""Tests for phishtriage.scoring."""

from __future__ import annotations

from pathlib import Path

from phishtriage.auth import AuthResult, check_auth
from phishtriage.indicators import (
    ContentFindings,
    HeaderFindings,
    Indicators,
    extract_indicators,
)
from phishtriage.parser import ParsedEmail, parse_eml
from phishtriage.scoring import score, _assign_band
from phishtriage.utils import load_settings, load_rules


FIXTURES = Path(__file__).parent / "fixtures"
SETTINGS = load_settings()
RULES = load_rules()


# Band assignment unit tests

def test_band_assignment_low():
    bands = SETTINGS["risk_bands"]
    assert _assign_band(0, bands) == "LOW"
    assert _assign_band(20, bands) == "LOW"


def test_band_assignment_medium():
    bands = SETTINGS["risk_bands"]
    assert _assign_band(21, bands) == "MEDIUM"
    assert _assign_band(50, bands) == "MEDIUM"


def test_band_assignment_high():
    bands = SETTINGS["risk_bands"]
    assert _assign_band(51, bands) == "HIGH"
    assert _assign_band(80, bands) == "HIGH"


def test_band_assignment_critical():
    bands = SETTINGS["risk_bands"]
    assert _assign_band(81, bands) == "CRITICAL"
    assert _assign_band(500, bands) == "CRITICAL"


def test_band_assignment_negative_clamps_to_low():
    bands = SETTINGS["risk_bands"]
    assert _assign_band(-50, bands) == "LOW"


# End-to-end on fixtures

def _pipeline(path: Path):
    parsed = parse_eml(path)
    auth = check_auth(parsed.authentication_results, parsed.from_domain)
    ind = extract_indicators(parsed, SETTINGS)
    return parsed, auth, ind


def test_phishing_fixture_lands_in_critical():
    parsed, auth, ind = _pipeline(FIXTURES / "sample_phishing.eml")
    s = score(parsed, auth, ind, rules=RULES, settings=SETTINGS)
    assert s.band == "CRITICAL"
    assert s.score >= 81
    # We expect the strong-evidence rules to fire
    fired = {h.rule_id for h in s.hits}
    assert "AUTH-001" in fired      # SPF fail
    assert "AUTH-003" in fired      # DMARC fail
    assert "HDR-001" in fired       # From vs Return-Path
    assert "URL-001" in fired       # IP in URL
    assert "CNT-001" in fired       # urgency
    assert "CNT-002" in fired       # credentials


def test_benign_fixture_lands_in_low():
    parsed, auth, ind = _pipeline(FIXTURES / "sample_benign.eml")
    s = score(parsed, auth, ind, rules=RULES, settings=SETTINGS)
    assert s.band == "LOW"
    assert s.score == 0  # AUTH-004 fires negative, clamped


def test_score_never_negative():
    parsed, auth, ind = _pipeline(FIXTURES / "sample_benign.eml")
    s = score(parsed, auth, ind, rules=RULES, settings=SETTINGS)
    assert s.score >= 0


def test_audit_trail_contains_evidence_for_each_hit():
    parsed, auth, ind = _pipeline(FIXTURES / "sample_phishing.eml")
    s = score(parsed, auth, ind, rules=RULES, settings=SETTINGS)
    for hit in s.hits:
        assert hit.rule_id
        assert hit.description
        # Negative-weight rules can fire with no body evidence, so the
        # only requirement is a present, non-empty evidence list.
        assert isinstance(hit.evidence, list)
        assert len(hit.evidence) >= 1


def test_category_breakdown_sums_to_total():
    parsed, auth, ind = _pipeline(FIXTURES / "sample_phishing.eml")
    s = score(parsed, auth, ind, rules=RULES, settings=SETTINGS)
    cat_total = sum(s.by_category.values())
    # Total before clamping equals the category sum; after clamping
    # they may diverge only if the running total went negative (which
    # is not the case for the phishing fixture).
    assert cat_total == s.score


def test_evaluated_rules_matches_rulebook_size():
    parsed, auth, ind = _pipeline(FIXTURES / "sample_benign.eml")
    s = score(parsed, auth, ind, rules=RULES, settings=SETTINGS)
    assert s.evaluated_rules == len(RULES)


# Injection: a custom minimal rulebook

def test_injected_rulebook_runs_subset_only():
    # Only AUTH-001. Checks that the engine ignores rule IDs missing
    # from the rulebook and that injection works (used for ablation
    # experiments).
    custom = [r for r in RULES if r["id"] == "AUTH-001"]
    parsed, auth, ind = _pipeline(FIXTURES / "sample_phishing.eml")
    s = score(parsed, auth, ind, rules=custom, settings=SETTINGS)
    assert s.evaluated_rules == 1
    assert s.fired_rules == 1
    assert s.score == 25
    assert s.band == "MEDIUM"


# AUTH-006 / HDR-006 / CNT-006 (v1.2 compromised-sender rules)

def test_cnt_006_fires_on_pretext_subject():
    parsed = ParsedEmail(subject="Your mailbox is full",
                         from_address="user@some.tld",
                         from_domain="some.tld")
    auth = AuthResult()
    ind = Indicators(content=ContentFindings(
        subject_pretext_hits=["mailbox is full"]
    ))
    s = score(parsed, auth, ind, rules=RULES, settings=SETTINGS)
    fired = {h.rule_id for h in s.hits}
    assert "CNT-006" in fired


def test_hdr_006_fires_on_brand_mismatch_subject():
    parsed = ParsedEmail(subject="Fifth Third Bank Account Alerts",
                         from_address="x@creditloiuse.com",
                         from_domain="creditloiuse.com")
    auth = AuthResult()
    ind = Indicators(header=HeaderFindings(
        subject_brand="fifth third bank",
        subject_brand_from_mismatch=True,
    ))
    s = score(parsed, auth, ind, rules=RULES, settings=SETTINGS)
    fired = {h.rule_id for h in s.hits}
    assert "HDR-006" in fired


def test_auth_006_suppresses_auth_004_bonus_on_pretext():
    # The compromised-sender case: SPF/DKIM/DMARC all pass and align
    # (so AUTH-004 fires for -10) AND the subject is a credential
    # pretext (so AUTH-006 fires for +10). Net auth contribution from
    # these two rules: 0.
    parsed = ParsedEmail(subject="Mailbox quota notification",
                         from_address="user@example.com",
                         from_domain="example.com")
    auth = AuthResult(spf="pass", dkim="pass", dmarc="pass", aligned=True)
    ind = Indicators(content=ContentFindings(
        subject_pretext_hits=["mailbox quota"]
    ))
    s = score(parsed, auth, ind, rules=RULES, settings=SETTINGS)
    fired = {h.rule_id: h.weight for h in s.hits}
    assert "AUTH-004" in fired
    assert "AUTH-006" in fired
    assert fired["AUTH-004"] + fired["AUTH-006"] == 0
