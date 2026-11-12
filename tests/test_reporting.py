"""Tests for phishtriage.reporting."""

from __future__ import annotations

import json
from pathlib import Path

from phishtriage.auth import check_auth
from phishtriage.indicators import extract_indicators
from phishtriage.parser import parse_eml
from phishtriage.reporting import render_markdown, render_thehive_case
from phishtriage.scoring import score
from phishtriage.utils import load_settings, load_rules


FIXTURES = Path(__file__).parent / "fixtures"
SETTINGS = load_settings()
RULES = load_rules()


def _full(path: Path):
    parsed = parse_eml(path)
    auth = check_auth(parsed.authentication_results, parsed.from_domain)
    ind = extract_indicators(parsed, SETTINGS)
    s = score(parsed, auth, ind, rules=RULES, settings=SETTINGS)
    return parsed, auth, ind, s


# Markdown

def test_markdown_includes_verdict_and_score():
    parsed, auth, ind, s = _full(FIXTURES / "sample_phishing.eml")
    md = render_markdown(parsed, auth, ind, s)
    assert "CRITICAL" in md
    assert f"score {s.score}" in md
    # Auth table present
    assert "| SPF" in md
    assert "| DKIM" in md
    assert "| DMARC" in md


def test_markdown_lists_every_fired_rule():
    parsed, auth, ind, s = _full(FIXTURES / "sample_phishing.eml")
    md = render_markdown(parsed, auth, ind, s)
    for hit in s.hits:
        assert hit.rule_id in md, f"Rule {hit.rule_id} missing from report"


def test_markdown_includes_url_section_when_urls_present():
    parsed, auth, ind, s = _full(FIXTURES / "sample_phishing.eml")
    md = render_markdown(parsed, auth, ind, s)
    assert "URLs extracted" in md
    for url in parsed.urls:
        assert url in md


def test_markdown_for_benign_fixture():
    parsed, auth, ind, s = _full(FIXTURES / "sample_benign.eml")
    md = render_markdown(parsed, auth, ind, s)
    assert "LOW" in md
    assert "Authentication" in md


# TheHive case JSON

def test_thehive_case_required_top_level_fields():
    parsed, auth, ind, s = _full(FIXTURES / "sample_phishing.eml")
    case = render_thehive_case(parsed, auth, ind, s)
    for key in ("title", "description", "severity", "tlp", "tags",
                "status", "startDate", "metrics", "observables", "audit"):
        assert key in case


def test_thehive_severity_mapping():
    parsed, auth, ind, s = _full(FIXTURES / "sample_phishing.eml")
    case = render_thehive_case(parsed, auth, ind, s)
    assert case["severity"] == 4               # CRITICAL -> 4
    assert case["flag"] is True                # high/critical flagged

    parsed2, auth2, ind2, s2 = _full(FIXTURES / "sample_benign.eml")
    case2 = render_thehive_case(parsed2, auth2, ind2, s2)
    assert case2["severity"] == 1              # LOW -> 1
    assert case2["flag"] is False


def test_thehive_observables_have_required_shape():
    parsed, auth, ind, s = _full(FIXTURES / "sample_phishing.eml")
    case = render_thehive_case(parsed, auth, ind, s)
    assert isinstance(case["observables"], list)
    assert case["observables"], "Should have at least one observable"
    for obs in case["observables"]:
        assert "dataType" in obs
        assert "data" in obs
        assert obs["dataType"] in {
            "mail", "mail-subject", "domain", "url", "ip", "hash", "filename"
        }


def test_thehive_case_serialises_to_json():
    parsed, auth, ind, s = _full(FIXTURES / "sample_phishing.eml")
    case = render_thehive_case(parsed, auth, ind, s)
    # Should round-trip cleanly through JSON
    text = json.dumps(case, default=str)
    reloaded = json.loads(text)
    assert reloaded["severity"] == case["severity"]
    assert len(reloaded["observables"]) == len(case["observables"])


def test_thehive_audit_matches_scoring_hits():
    parsed, auth, ind, s = _full(FIXTURES / "sample_phishing.eml")
    case = render_thehive_case(parsed, auth, ind, s)
    audit = case["audit"]
    assert len(audit) == len(s.hits)
    audit_ids = [a["rule_id"] for a in audit]
    hit_ids = [h.rule_id for h in s.hits]
    assert audit_ids == hit_ids


def test_thehive_tags_include_band():
    parsed, auth, ind, s = _full(FIXTURES / "sample_phishing.eml")
    case = render_thehive_case(parsed, auth, ind, s)
    assert "phishing" in case["tags"]
    assert "band:critical" in case["tags"]
    assert "spf-fail" in case["tags"]
    assert "dmarc-fail" in case["tags"]
