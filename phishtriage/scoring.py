"""Stage 4: scoring engine.

Runs every rule in config/rules.yaml against the parsed email and adds
up the weights of the ones that fire. Each hit keeps its evidence so
the report can show why an email got the score it did.

Weights and descriptions live in the YAML. The test that decides
whether a rule fires lives here in Python. They are linked by rule id,
so a new rule is one YAML block plus one evaluator registered in
_EVALUATORS at the bottom.

The total is clamped at zero and then mapped to a band (LOW, MEDIUM,
HIGH, CRITICAL) from the lower bounds in settings.risk_bands.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Callable

from phishtriage.auth import AuthResult
from phishtriage.indicators import Indicators
from phishtriage.parser import ParsedEmail
from phishtriage.utils import Evidence, RuleHit, load_rules, load_settings


@dataclass
class ScoringResult:
    """Scoring outcome for one email."""
    score: int = 0
    band: str = "LOW"
    hits: list[RuleHit] = field(default_factory=list)
    evaluated_rules: int = 0          # rules in the rulebook
    fired_rules: int = 0              # rules that actually fired
    by_category: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "band": self.band,
            "evaluated_rules": self.evaluated_rules,
            "fired_rules": self.fired_rules,
            "by_category": self.by_category,
            "hits": [h.to_dict() for h in self.hits],
        }


def score(parsed: ParsedEmail,
          auth: AuthResult,
          indicators: Indicators,
          rules: list[dict] | None = None,
          settings: dict | None = None) -> ScoringResult:
    """Evaluate every rule and return the aggregate result.

    rules and settings default to the files on disk. Tests and the
    ablation runs pass a cut-down rulebook instead.
    """
    if rules is None:
        rules = load_rules()
    if settings is None:
        settings = load_settings()

    out = ScoringResult(evaluated_rules=len(rules))

    for rule in rules:
        rid = rule.get("id", "")
        evaluator = _EVALUATORS.get(rid)
        if evaluator is None:
            # rule defined in YAML but no evaluator yet; skip it
            continue
        evidence = evaluator(parsed, auth, indicators, settings)
        if not evidence:
            continue
        hit = RuleHit(
            rule_id=rid,
            category=rule.get("category", ""),
            weight=int(rule.get("weight", 0)),
            description=rule.get("description", ""),
            evidence=evidence if isinstance(evidence, list) else [evidence],
        )
        out.hits.append(hit)
        out.score += hit.weight
        out.fired_rules += 1
        out.by_category[hit.category] = out.by_category.get(hit.category, 0) + hit.weight

    # AUTH-004 is negative, so a clean authenticated email can go below
    # zero. A negative risk score reads as broken, so clamp to 0.
    if out.score < 0:
        out.score = 0

    out.band = _assign_band(out.score, settings.get("risk_bands", {}))
    return out


def _assign_band(total: int, bands: dict[str, int]) -> str:
    """Highest band whose lower bound the score meets. Bounds are
    inclusive, so a score of 21 is already MEDIUM."""
    if not bands:
        return "LOW"
    ordered = sorted(bands.items(), key=lambda kv: kv[1])
    chosen = ordered[0][0]
    for name, threshold in ordered:
        if total >= int(threshold):
            chosen = name
    return chosen


# Every evaluator takes (parsed, auth, indicators, settings). Return
# None to stay quiet, or Evidence (or a list of it) to fire. Whatever
# an evaluator returns goes into the report's audit trail, so the
# detail strings are written to be read by an analyst.

EvaluatorFn = Callable[
    [ParsedEmail, AuthResult, Indicators, dict],
    "list[Evidence] | Evidence | None",
]


def _eval_auth_001(p, a, i, s):
    if a.spf in {"fail", "softfail"}:
        return Evidence(source="auth", key="spf_result", value=a.spf,
                        detail=f"SPF check returned {a.spf!r} for domain {a.spf_domain or '?'}")
    return None


def _eval_auth_002(p, a, i, s):
    if a.dkim in {"fail", "none", "permerror"}:
        return Evidence(source="auth", key="dkim_result", value=a.dkim,
                        detail=f"DKIM result is {a.dkim!r}")
    return None


def _eval_auth_003(p, a, i, s):
    if a.dmarc == "fail":
        return Evidence(source="auth", key="dmarc_result", value=a.dmarc,
                        detail=f"DMARC failed for {a.dmarc_domain or p.from_domain or '?'}")
    return None


def _eval_auth_004(p, a, i, s):
    # The only negative rule. Full pass plus alignment subtracts 10.
    # Kept small so it cannot cancel out a genuine signal.
    if a.spf == "pass" and a.dkim == "pass" and a.dmarc == "pass" and a.aligned:
        return Evidence(source="auth", key="all_pass_aligned", value=True,
                        detail="All authentication methods pass and align with From")
    return None


def _eval_auth_005(p, a, i, s):
    # Authentication-Results is RFC 7601 (2015). Older mail predates the
    # header, so its absence there means nothing. Only fire on mail from
    # 2015 on, or when the Date is missing (often stripped to evade).
    if a.ar_present:
        return None
    if p.date_iso:
        try:
            year = int(p.date_iso[:4])
            if year < 2015:
                return None
        except ValueError:
            pass
    return Evidence(source="auth", key="ar_present", value=False,
                    detail="Authentication-Results header is absent")


def _eval_hdr_001(p, a, i, s):
    if i.header.from_vs_return_path_mismatch:
        return Evidence(source="header", key="from_vs_return_path", value=True,
                        detail=f"From={p.from_address!r} but Return-Path={p.return_path!r}")
    return None


def _eval_hdr_002(p, a, i, s):
    if i.header.from_vs_reply_to_mismatch:
        return Evidence(source="header", key="from_vs_reply_to", value=True,
                        detail=f"From={p.from_address!r} but Reply-To={p.reply_to!r}")
    return None


def _eval_hdr_003(p, a, i, s):
    if i.header.display_name_brand_spoof:
        return Evidence(source="header", key="display_name_brand_spoof",
                        value=i.header.display_name_brand,
                        detail=f"Display name claims brand {i.header.display_name_brand!r} "
                               f"but From-domain is {p.from_domain!r}")
    return None


def _eval_hdr_004(p, a, i, s):
    if not i.header.mailer_present:
        return Evidence(source="header", key="x_mailer", value="absent",
                        detail="X-Mailer header is absent or empty")
    return None


def _eval_hdr_005(p, a, i, s):
    # Placeholder, never fires. Routing geography needs a GeoIP database
    # and the pipeline is offline by design. Left registered so the
    # rulebook count reflects what exists.
    return None


def _eval_url_001(p, a, i, s):
    hits = [u for u in i.urls if u.is_ip]
    if hits:
        return [Evidence(source="url", key="ip_in_url", value=u.url,
                         detail=f"URL uses literal IP host {u.hostname}")
                for u in hits]
    return None


def _eval_url_002(p, a, i, s):
    # Placeholder. Domain age needs WHOIS, and network calls would make
    # the timing measurements non-deterministic. If a WHOIS adapter is
    # ever added this reads u.domain_age_days.
    return None


def _eval_url_003(p, a, i, s):
    hits = [u for u in i.urls if u.is_shortener]
    if hits:
        return [Evidence(source="url", key="shortener", value=u.url,
                         detail=f"URL uses shortener domain {u.registered_domain or u.hostname}")
                for u in hits]
    return None


def _eval_url_004(p, a, i, s):
    hits = [u for u in i.urls if u.is_punycode]
    if hits:
        return [Evidence(source="url", key="punycode", value=u.url,
                         detail=f"URL contains punycode label in {u.hostname}")
                for u in hits]
    return None


def _eval_url_005(p, a, i, s):
    hits = [u for u in i.urls if u.is_subdomain_brand_spoof]
    if hits:
        return [Evidence(source="url", key="subdomain_spoof", value=u.url,
                         detail=f"Brand {u.spoofed_brand!r} appears in {u.hostname} "
                                f"but registered domain is {u.registered_domain!r}")
                for u in hits]
    return None


def _eval_url_006(p, a, i, s):
    hits = [u for u in i.urls if u.is_long]
    if hits:
        return [Evidence(source="url", key="long_url", value=u.url,
                         detail=f"URL is {u.length} characters long")
                for u in hits]
    return None


def _eval_url_007(p, a, i, s):
    hits = [u for u in i.urls if u.is_in_ioc_list]
    if hits:
        return [Evidence(source="url", key="ioc_match", value=u.url,
                         detail=f"URL matches local IOC list ({u.matching_ioc_source})")
                for u in hits]
    return None


def _eval_url_008(p, a, i, s):
    # Catches redirectors: a clean-looking first hop (link tracker,
    # ad-click, Safe Links) wrapping a hidden destination. The unwrap
    # happens in indicators._unwrap_redirector. Fires only when the
    # destination differs from the wrapper host and trips a risk signal
    # on its own, so a wrapper around a clean target stays quiet.
    hits = [u for u in i.urls if u.unwrapped_destination_risky]
    if hits:
        return [Evidence(source="url", key="redirector_unwrap", value=u.url,
                         detail=f"First hop {u.hostname} unwraps to {u.unwrapped_host} "
                                f"which trips {u.unwrapped_risk_reason}")
                for u in hits]
    return None


def _eval_cnt_001(p, a, i, s):
    if i.content.urgency_hits:
        return Evidence(source="content", key="urgency_phrases",
                        value=i.content.urgency_hits,
                        detail=f"Body contains urgency phrases: {', '.join(i.content.urgency_hits[:5])}")
    return None


def _eval_cnt_002(p, a, i, s):
    if i.content.credential_hits:
        return Evidence(source="content", key="credential_phrases",
                        value=i.content.credential_hits,
                        detail=f"Body asks for credentials/payment: {', '.join(i.content.credential_hits[:5])}")
    return None


def _eval_cnt_003(p, a, i, s):
    if i.content.executable_attachments:
        return Evidence(source="content", key="executable_attachments",
                        value=i.content.executable_attachments,
                        detail=f"Executable / macro attachment(s): {', '.join(i.content.executable_attachments)}")
    return None


def _eval_cnt_004(p, a, i, s):
    if i.content.has_hidden_text:
        return Evidence(source="content", key="hidden_text", value=True,
                        detail="HTML body uses CSS to hide content (display:none, visibility:hidden, font-size:0, or zero-width chars)")
    return None


def _eval_cnt_005(p, a, i, s):
    if i.content.visible_vs_href_mismatch:
        return Evidence(source="content", key="visible_vs_href_mismatch", value=True,
                        detail="At least one anchor's visible URL text differs from its href")
    return None


def _eval_cnt_006(p, a, i, s):
    if i.content.subject_pretext_hits:
        return Evidence(source="content", key="subject_pretext_phrases",
                        value=i.content.subject_pretext_hits,
                        detail=f"Subject contains credential-pretext phrases: "
                               f"{', '.join(i.content.subject_pretext_hits[:5])}")
    return None


def _eval_cnt_007(p, a, i, s):
    if i.content.subject_lure_matches:
        return Evidence(source="content", key="subject_lure_match",
                        value=i.content.subject_lure_matches,
                        detail=f"Subject matches phishing-lure pattern: "
                               f"{', '.join(repr(m) for m in i.content.subject_lure_matches[:3])}")
    return None


def _eval_hdr_006(p, a, i, s):
    if i.header.subject_brand_from_mismatch:
        return Evidence(source="header", key="subject_brand_from_mismatch",
                        value=i.header.subject_brand,
                        detail=f"Subject names brand {i.header.subject_brand!r} "
                               f"but From-domain is {p.from_domain or '?'!r}")
    return None


def _eval_auth_006(p, a, i, s):
    # Compromised accounts still authenticate, so AUTH-004 was handing
    # its -10 to phishing sent through hijacked tenants. This adds 10
    # back when the mail is DMARC-aligned but the subject is a
    # credential pretext, cancelling the bonus.
    if i.content.subject_pretext_hits and a.aligned:
        return Evidence(source="auth", key="aligned_with_pretext_subject",
                        value=True,
                        detail="Authenticated mail (DMARC-aligned) with credential-pretext subject; "
                               "neutralises AUTH-004 bonus")
    return None


_EVALUATORS: dict[str, EvaluatorFn] = {
    "AUTH-001": _eval_auth_001,
    "AUTH-002": _eval_auth_002,
    "AUTH-003": _eval_auth_003,
    "AUTH-004": _eval_auth_004,
    "AUTH-005": _eval_auth_005,
    "AUTH-006": _eval_auth_006,
    "HDR-001":  _eval_hdr_001,
    "HDR-002":  _eval_hdr_002,
    "HDR-003":  _eval_hdr_003,
    "HDR-004":  _eval_hdr_004,
    "HDR-005":  _eval_hdr_005,
    "HDR-006":  _eval_hdr_006,
    "URL-001":  _eval_url_001,
    "URL-002":  _eval_url_002,
    "URL-003":  _eval_url_003,
    "URL-004":  _eval_url_004,
    "URL-005":  _eval_url_005,
    "URL-006":  _eval_url_006,
    "URL-007":  _eval_url_007,
    "URL-008":  _eval_url_008,
    "CNT-001":  _eval_cnt_001,
    "CNT-002":  _eval_cnt_002,
    "CNT-003":  _eval_cnt_003,
    "CNT-004":  _eval_cnt_004,
    "CNT-005":  _eval_cnt_005,
    "CNT-006":  _eval_cnt_006,
    "CNT-007":  _eval_cnt_007,
}
