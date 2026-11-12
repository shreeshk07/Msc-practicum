"""Stage 5: reporting.

Each triaged email produces two outputs: a Markdown report for an
analyst to read (verdict, banded score, evidence grouped by category,
URL list, timing), and a TheHive/Cortex case JSON shaped like
TheHive's case schema so a SOC platform can ingest it directly.

Bands map to TheHive's 1-4 severity scale: LOW 1, MEDIUM 2, HIGH 3,
CRITICAL 4. TLP defaults to AMBER, since phishing samples carry
attacker indicators that should not be shared openly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from phishtriage.auth import AuthResult
from phishtriage.indicators import Indicators
from phishtriage.parser import ParsedEmail
from phishtriage.scoring import ScoringResult


_BAND_TO_SEVERITY = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# one-line analyst recommendation per band
_BAND_TO_ACTION = {
    "LOW":      "Likely benign. No action needed, retain evidence per policy.",
    "MEDIUM":   "Suspicious. Escalate to a tier-2 analyst for confirmation.",
    "HIGH":     "Likely phishing. Block sender, hunt for similar mail, notify recipient.",
    "CRITICAL": "Confirmed phishing class. Contain immediately, block IOCs, broadcast to detections team.",
}


def render_markdown(parsed: ParsedEmail,
                    auth: AuthResult,
                    indicators: Indicators,
                    scoring: ScoringResult,
                    timings: dict[str, float] | None = None) -> str:
    """Return a Markdown report for a single triaged email."""
    timings = timings or {}
    severity = _BAND_TO_SEVERITY.get(scoring.band, 1)
    action = _BAND_TO_ACTION.get(scoring.band, "")

    lines: list[str] = []
    lines.append(f"# PhishTriage Report: {scoring.band} (score {scoring.score})")
    lines.append("")
    lines.append(f"**Verdict band:** {scoring.band}  ")
    lines.append(f"**Numeric score:** {scoring.score}  ")
    lines.append(f"**TheHive severity:** {severity}/4  ")
    lines.append(f"**Recommended action:** {action}")
    lines.append("")
    lines.append(f"_Generated at {datetime.now(timezone.utc).isoformat(timespec='seconds')}_")
    lines.append("")

    lines.append("## Message")
    lines.append("")
    lines.append(f"- **Source file**: `{parsed.source_path or '(in-memory)'}`")
    lines.append(f"- **Message-ID**: `{parsed.message_id or '(absent)'}`")
    lines.append(f"- **Date**: {parsed.date_iso or parsed.date_raw or '(absent)'}")
    lines.append(f"- **Subject**: {parsed.subject!r}")
    lines.append(f"- **From**: {parsed.display_name!r} <{parsed.from_address}> "
                 f"(domain: `{parsed.from_domain or '?'}`)")
    lines.append(f"- **Return-Path**: `{parsed.return_path or '(absent)'}`")
    lines.append(f"- **Reply-To**: `{parsed.reply_to or '(absent)'}`")
    lines.append(f"- **X-Mailer**: `{parsed.mailer or '(absent)'}`")
    lines.append("")

    lines.append("## Authentication")
    lines.append("")
    lines.append("| Method | Result | Domain |")
    lines.append("|--------|--------|--------|")
    lines.append(f"| SPF    | {auth.spf} | {auth.spf_domain or '-'} |")
    lines.append(f"| DKIM   | {auth.dkim} | {auth.dkim_domain or '-'} |")
    lines.append(f"| DMARC  | {auth.dmarc} | {auth.dmarc_domain or '-'} |")
    lines.append("")
    lines.append(f"DMARC alignment: **{auth.aligned}**.  "
                 f"Authentication-Results header present: **{auth.ar_present}**.")
    lines.append("")

    lines.append("## Score breakdown")
    lines.append("")
    if scoring.by_category:
        lines.append("| Category | Contribution |")
        lines.append("|----------|-------------:|")
        for cat in ("auth", "header", "url", "content"):
            v = scoring.by_category.get(cat, 0)
            lines.append(f"| {cat:8s} | {v:+d} |")
        lines.append(f"| **TOTAL**| **{scoring.score:+d}** |")
        lines.append("")
    lines.append(f"{scoring.fired_rules} of {scoring.evaluated_rules} rules "
                 f"in the rulebook fired against this message.")
    lines.append("")

    lines.append("## Evidence trail")
    lines.append("")
    if not scoring.hits:
        lines.append("_No rules fired._")
    for hit in scoring.hits:
        sign = "+" if hit.weight >= 0 else ""
        lines.append(f"### {hit.rule_id}  ({sign}{hit.weight} pts, {hit.category})")
        lines.append(f"_{hit.description}_")
        lines.append("")
        for ev in hit.evidence:
            detail = ev.detail or f"{ev.key}={ev.value}"
            lines.append(f"- {detail}")
        lines.append("")

    if parsed.urls:
        lines.append("## URLs extracted")
        lines.append("")
        for u in parsed.urls:
            lines.append(f"- `{u}`")
        lines.append("")

    if timings:
        lines.append("## Timing (seconds)")
        lines.append("")
        for key, value in timings.items():
            lines.append(f"- {key}: {value:.6f}")
        lines.append("")

    if parsed.warnings:
        lines.append("## Parser warnings")
        lines.append("")
        for w in parsed.warnings:
            lines.append(f"- ⚠ {w}")
        lines.append("")

    return "\n".join(lines)


def render_thehive_case(parsed: ParsedEmail,
                        auth: AuthResult,
                        indicators: Indicators,
                        scoring: ScoringResult,
                        timings: dict[str, float] | None = None) -> dict:
    """Return a dict shaped for TheHive's POST /api/case body.

    Fills in the fields that map cleanly from a triage report, so the
    dict can be posted to TheHive (or a SIEM that ingests its cases)
    as-is.
    """
    timings = timings or {}
    severity = _BAND_TO_SEVERITY.get(scoring.band, 1)

    case: dict[str, Any] = {
        "title": _case_title(parsed, scoring),
        "description": _case_description(parsed, auth, scoring),
        "severity": severity,
        "tlp": 2,                       # AMBER
        "pap": 2,                       # AMBER
        "tags": _case_tags(parsed, auth, scoring),
        "status": "Open",
        "flag": scoring.band in {"HIGH", "CRITICAL"},
        "startDate": int(datetime.now(timezone.utc).timestamp() * 1000),
        "metrics": {
            "phishtriage_score": scoring.score,
            "phishtriage_band": scoring.band,
            "fired_rules": scoring.fired_rules,
            "evaluated_rules": scoring.evaluated_rules,
            **{f"timing.{k}": v for k, v in timings.items()},
        },
        "customFields": {
            "phishtriage_message_id": {"string": parsed.message_id or ""},
            "phishtriage_from_domain": {"string": parsed.from_domain or ""},
            "phishtriage_subject": {"string": parsed.subject or ""},
        },
        "observables": _case_observables(parsed, indicators),
        "audit": [hit.to_dict() for hit in scoring.hits],
    }
    return case


def _case_title(parsed: ParsedEmail, scoring: ScoringResult) -> str:
    subject = parsed.subject or "(no subject)"
    truncated = subject if len(subject) <= 80 else subject[:77] + "..."
    return f"[{scoring.band}] Phishing triage: {truncated}"


def _case_description(parsed: ParsedEmail,
                      auth: AuthResult,
                      scoring: ScoringResult) -> str:
    return (
        f"Automated phishing triage by PhishTriage rule engine.\n\n"
        f"Verdict band: **{scoring.band}** (score {scoring.score}).\n"
        f"From: {parsed.from_address!r} ({parsed.from_domain}).\n"
        f"Auth: SPF={auth.spf}, DKIM={auth.dkim}, DMARC={auth.dmarc}, "
        f"aligned={auth.aligned}.\n"
        f"{scoring.fired_rules} of {scoring.evaluated_rules} rules fired."
    )


def _case_tags(parsed: ParsedEmail,
               auth: AuthResult,
               scoring: ScoringResult) -> list[str]:
    tags = [
        "phishing",
        "phishtriage",
        f"band:{scoring.band.lower()}",
    ]
    if parsed.from_domain:
        tags.append(f"from-domain:{parsed.from_domain}")
    if auth.spf == "fail":
        tags.append("spf-fail")
    if auth.dkim in {"fail", "none"}:
        tags.append(f"dkim-{auth.dkim}")
    if auth.dmarc == "fail":
        tags.append("dmarc-fail")
    return tags


def _case_observables(parsed: ParsedEmail, indicators: Indicators) -> list[dict]:
    """TheHive-shaped observables from the parsed mail. Types follow
    TheHive convention: mail, mail-subject, domain, url, ip, hash,
    filename."""
    out: list[dict] = []

    if parsed.from_address:
        out.append({"dataType": "mail", "data": parsed.from_address,
                    "message": "Envelope From address", "ioc": False, "tags": ["sender"]})
    if parsed.return_path:
        out.append({"dataType": "mail", "data": parsed.return_path,
                    "message": "Return-Path", "ioc": False, "tags": ["return-path"]})
    if parsed.reply_to:
        out.append({"dataType": "mail", "data": parsed.reply_to,
                    "message": "Reply-To", "ioc": False, "tags": ["reply-to"]})
    if parsed.subject:
        out.append({"dataType": "mail-subject", "data": parsed.subject,
                    "message": "Subject", "ioc": False})
    if parsed.from_domain:
        out.append({"dataType": "domain", "data": parsed.from_domain,
                    "message": "From-domain", "ioc": False})

    seen_hosts: set[str] = set()
    for u in indicators.urls:
        if u.url:
            out.append({
                "dataType": "url", "data": u.url,
                "message": "URL extracted from body",
                "ioc": u.is_in_ioc_list or u.is_subdomain_brand_spoof or u.is_punycode,
                "tags": _url_tags(u),
            })
        if u.is_ip and u.hostname and u.hostname not in seen_hosts:
            out.append({"dataType": "ip", "data": u.hostname,
                        "message": "IP literal in URL host", "ioc": True})
            seen_hosts.add(u.hostname)
        elif u.registered_domain and u.registered_domain not in seen_hosts:
            out.append({"dataType": "domain", "data": u.registered_domain,
                        "message": "Domain extracted from URL",
                        "ioc": u.is_in_ioc_list or u.is_subdomain_brand_spoof})
            seen_hosts.add(u.registered_domain)

    for att in parsed.attachments:
        if att.filename:
            out.append({"dataType": "filename", "data": att.filename,
                        "message": f"Attachment ({att.mime_type})", "ioc": False})
        if att.sha256:
            out.append({"dataType": "hash", "data": att.sha256,
                        "message": "SHA-256 of attachment payload", "ioc": False})

    return out


def _url_tags(u) -> list[str]:
    tags = []
    if u.is_ip:
        tags.append("ip-host")
    if u.is_punycode:
        tags.append("punycode")
    if u.is_shortener:
        tags.append("shortener")
    if u.is_subdomain_brand_spoof:
        tags.append(f"brand-spoof:{u.spoofed_brand}")
    if u.is_in_ioc_list:
        tags.append("ioc-match")
    if u.is_long:
        tags.append("long-url")
    return tags
