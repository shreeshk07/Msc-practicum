"""Stage 3: indicator extraction.

Reads a ParsedEmail and derives the structured facts the scoring
engine needs for the URL, domain, header, and content rules. This
stage does no scoring itself, only fact-gathering. Keeping the two
apart is what makes a verdict auditable: the indicator output and
rules.yaml line up, so the reasoning behind a verdict can be
reconstructed from them.

Every check is a pure function over the parsed message and the
settings, with no network calls. The IOC lookup reads local text files
under data/iocs/. Staying offline keeps the auto-triage timing free of
the network latency that would otherwise vary between runs.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote, urlparse

import tldextract
from bs4 import BeautifulSoup

from phishtriage.parser import ParsedEmail
from phishtriage.utils import PROJECT_ROOT, load_settings, log


@dataclass
class UrlFinding:
    """Per-URL facts, one per URL in the body."""
    url: str
    scheme: str = ""
    hostname: str = ""
    registered_domain: str = ""        # e.g. "example.com" via tldextract
    suffix: str = ""                   # e.g. "co.uk"
    is_ip: bool = False
    is_punycode: bool = False
    is_shortener: bool = False
    is_subdomain_brand_spoof: bool = False
    spoofed_brand: str = ""            # which brand the URL pretends to be
    is_in_ioc_list: bool = False
    matching_ioc_source: str = ""
    is_long: bool = False
    length: int = 0
    # URL-008 first-hop redirector unwrapping. is_wrapped_redirect is
    # True when the URL is recognised as a redirector/wrapper (known
    # host, redirect param, or base64 destination). unwrapped_* describe
    # the extracted destination. unwrapped_destination_risky is the gate
    # for URL-008: the destination host differs from the first hop AND
    # independently trips a URL risk signal (IOC / IP / punycode /
    # suspicious-TLD); unwrapped_risk_reason names which one.
    is_wrapped_redirect: bool = False
    unwrapped_url: str = ""
    unwrapped_host: str = ""
    unwrapped_destination_risky: bool = False
    unwrapped_risk_reason: str = ""


@dataclass
class HeaderFindings:
    """Header-level mismatches and anomalies."""
    from_vs_return_path_mismatch: bool = False
    from_vs_reply_to_mismatch: bool = False
    display_name_brand: str = ""       # which brand the display name claims
    display_name_brand_spoof: bool = False
    mailer_present: bool = False
    # Subject-vs-from brand check (HDR-006). subject_brand is set
    # whenever a brand keyword from settings.subject_brand_keywords
    # is found in the Subject; subject_brand_from_mismatch is True
    # only when that brand is NOT a substring of the From-domain.
    subject_brand: str = ""
    subject_brand_from_mismatch: bool = False


@dataclass
class ContentFindings:
    """Body-text and body-HTML signals."""
    urgency_hits: list[str] = field(default_factory=list)
    credential_hits: list[str] = field(default_factory=list)
    executable_attachments: list[str] = field(default_factory=list)
    has_hidden_text: bool = False
    visible_vs_href_mismatch: bool = False
    # Subject-only credential-pretext phrases (CNT-006).
    subject_pretext_hits: list[str] = field(default_factory=list)
    # Subject regex lure matches (CNT-007). Stores the matched
    # substrings so the audit trail explains why the rule fired.
    subject_lure_matches: list[str] = field(default_factory=list)


@dataclass
class Indicators:
    """Aggregate output of stage 3."""
    urls: list[UrlFinding] = field(default_factory=list)
    header: HeaderFindings = field(default_factory=HeaderFindings)
    content: ContentFindings = field(default_factory=ContentFindings)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# suffix_list_urls=() keeps tldextract from fetching the Public Suffix
# List over the network; it uses its embedded copy, which stays
# deterministic and offline for fair timing.
_TLDX = tldextract.TLDExtract(suffix_list_urls=())


def _registered_of_extract(ex) -> str:
    """Registered domain (eTLD+1) from a tldextract result.

    Newer tldextract exposes top_domain_under_public_suffix; older
    versions only registered_domain. The new name is tried first to
    avoid a DeprecationWarning on every call.
    """
    val = getattr(ex, "top_domain_under_public_suffix", None)
    if val is None:
        val = getattr(ex, "registered_domain", "") or ""
    return (val or "").lower()


def extract_indicators(parsed: ParsedEmail, settings: dict | None = None) -> Indicators:
    """Run stage 3 on a parsed email and return derived facts."""
    if settings is None:
        settings = load_settings()

    out = Indicators()

    # URL facts
    iocs = _load_iocs(settings.get("ioc_lists", []))
    shorteners = {s.lower() for s in settings.get("url_shorteners", [])}
    brand_keywords = {b.lower() for b in settings.get("known_brand_keywords", [])}
    long_threshold = int(settings.get("url_length_threshold", 150))

    # URL-008 redirector unwrapping config
    redirector_hosts = {h.lower() for h in settings.get("url_redirector_hosts", [])}
    redirect_params = {p.lower() for p in settings.get("redirect_param_names", [])}
    suspicious_tlds = {t.lower().lstrip(".") for t in settings.get("suspicious_tlds", [])}

    max_urls = int(settings.get("runtime", {}).get("max_urls_per_email", 100))
    for url in parsed.urls[:max_urls]:
        out.urls.append(_analyse_url(
            url, brand_keywords, shorteners, iocs, long_threshold,
            redirector_hosts=redirector_hosts,
            redirect_params=redirect_params,
            suspicious_tlds=suspicious_tlds,
        ))

    # Header facts. HDR-006 uses its own subject-side brand list, and
    # falls back to the display-name list when subject_brand_keywords is
    # absent from settings.
    subject_brands_raw = settings.get("subject_brand_keywords") or []
    subject_brand_keywords = {b.lower() for b in subject_brands_raw} or brand_keywords
    out.header = _analyse_headers(parsed, brand_keywords, subject_brand_keywords)

    out.content = _analyse_content(parsed, settings)

    return out


def _analyse_url(url: str,
                 brand_keywords: set[str],
                 shorteners: set[str],
                 iocs: dict[str, str],
                 long_threshold: int,
                 redirector_hosts: set[str] | None = None,
                 redirect_params: set[str] | None = None,
                 suspicious_tlds: set[str] | None = None) -> UrlFinding:
    """Examine one URL and return a UrlFinding.

    redirector_hosts, redirect_params, and suspicious_tlds drive
    URL-008. They are optional so callers that only need the per-URL
    signals, including the tests, can leave them out.
    """
    f = UrlFinding(url=url, length=len(url))

    try:
        p = urlparse(url)
    except Exception as exc:                         # noqa: BLE001
        log.debug("urlparse failed for %r: %s", url, exc)
        return f

    f.scheme = (p.scheme or "").lower()
    f.hostname = (p.hostname or "").lower()

    if not f.hostname:
        return f

    # IP-address hostname (URL-001)
    f.is_ip = _is_ip(f.hostname)

    # Punycode marker on any label (URL-004)
    f.is_punycode = "xn--" in f.hostname

    # tldextract: split host into subdomain, domain, suffix
    ex = _TLDX(f.hostname)
    f.suffix = ex.suffix
    f.registered_domain = _registered_of_extract(ex)

    # Known shortener (URL-003)
    f.is_shortener = f.registered_domain in shorteners or f.hostname in shorteners

    # Sub-domain brand spoof (URL-005): a brand keyword appears as a
    # sub-domain label of a registered domain that is NOT the brand itself.
    # e.g. paypal.attacker.tld -> registered_domain "attacker.tld",
    # subdomain "paypal" -> spoof.
    #
    # Skip this check entirely when the host is an IP literal. URL-001
    # already covers IP-host URLs, and double-counting just produces
    # confusing evidence text.
    spoofed = ""
    if not f.is_ip and ex.subdomain:
        # Split sub-domain into individual labels so partial matches
        # ("ipaypalsupport") cannot trip the rule.
        sub_labels = {label.lower() for label in ex.subdomain.split(".") if label}
        for brand in brand_keywords:
            if not brand:
                continue
            # If the registered domain *is* the brand (or a subdomain of
            # the brand), it is the genuine site, not a spoof.
            if f.registered_domain == brand or f.registered_domain.endswith("." + brand):
                continue
            if brand in sub_labels:
                spoofed = brand
                break
    f.spoofed_brand = spoofed
    f.is_subdomain_brand_spoof = bool(spoofed)

    # Long URL (URL-006)
    f.is_long = f.length > long_threshold

    # IOC list match (URL-007). Full URL first, then registered domain,
    # then hostname, so both URL- and domain-grained feeds match.
    if iocs:
        for needle in (url, f.hostname, f.registered_domain):
            if needle and needle in iocs:
                f.is_in_ioc_list = True
                f.matching_ioc_source = iocs[needle]
                break

    # First-hop redirector unwrapping (URL-008).
    _unwrap_redirector(f, p, iocs,
                       redirector_hosts or set(),
                       redirect_params or set(),
                       suspicious_tlds or set())

    return f


def _unwrap_redirector(f: UrlFinding,
                       p,
                       iocs: dict[str, str],
                       redirector_hosts: set[str],
                       redirect_params: set[str],
                       suspicious_tlds: set[str]) -> None:
    """Populate the URL-008 fields on ``f`` in place.

    A URL is treated as a wrapper when its host is a known redirector,
    when it carries a redirect parameter, or when a parameter value is a
    base64 blob that decodes to a URL. The embedded destination is
    extracted and its host re-checked for an IOC / IP / punycode /
    suspicious-TLD signal. URL-008 only fires when the destination
    differs from the first hop AND independently trips one of those.
    """
    host = f.hostname
    is_redirector_host = _host_suffix_match(host, redirector_hosts)
    params = list(_iter_query_params(p.query or ""))
    has_redirect_param = any(k.lower() in redirect_params for k, _ in params)

    if not (is_redirector_host or has_redirect_param):
        return

    # Build candidate values: named redirect params first (most
    # reliable), then every other param value when the host itself is a
    # known redirector (covers non-standard names such as 'adurl').
    candidates: list[str] = [v for k, v in params if k.lower() in redirect_params]
    if is_redirector_host:
        candidates += [v for k, v in params if k.lower() not in redirect_params]

    dest = ""
    for raw in candidates:
        dest = _coerce_to_url(raw)
        if dest:
            break

    f.is_wrapped_redirect = True
    if not dest:
        return

    dest_host = _host(dest)
    if not dest_host or dest_host == host:
        # Self-referential or unparseable destination: nothing new to see.
        f.unwrapped_url = dest
        f.unwrapped_host = dest_host
        return

    f.unwrapped_url = dest
    f.unwrapped_host = dest_host

    reason = ""
    dest_registered = _registered(dest_host)
    if iocs and any(n and n in iocs for n in (dest, dest_host, dest_registered)):
        reason = "ioc"
    elif _is_ip(dest_host):
        reason = "ip_host"
    elif "xn--" in dest_host:
        reason = "punycode"
    elif suspicious_tlds and _TLDX(dest_host).suffix.lower() in suspicious_tlds:
        reason = "suspicious_tld"

    if reason:
        f.unwrapped_destination_risky = True
        f.unwrapped_risk_reason = reason


def _iter_query_params(query: str):
    """Yield (key, raw_value) pairs from a query string.

    Unlike ``urllib.parse.parse_qsl`` this does NOT plus-decode, so a
    '+' inside a base64 destination survives. Values stay percent-encoded
    and are decoded later by ``_coerce_to_url``.
    """
    for pair in query.split("&"):
        if not pair:
            continue
        k, _, v = pair.partition("=")
        yield k, v


def _coerce_to_url(raw: str) -> str:
    """Turn a redirect parameter value into an http(s) URL, or ''.

    Handles three encodings seen in the wild: a percent-encoded URL, a
    plain URL, and a base64 blob that decodes to a (possibly
    percent-encoded) URL.
    """
    if not raw:
        return ""
    decoded = unquote(raw)
    if decoded.lower().startswith(("http://", "https://")):
        return decoded
    b64 = _maybe_base64_text(raw.strip())
    if b64:
        cand = b64 if b64.lower().startswith(("http://", "https://")) else unquote(b64)
        if cand.lower().startswith(("http://", "https://")):
            return cand
    return ""


def _maybe_base64_text(s: str) -> str:
    """Decode ``s`` if it is a plausible base64 blob, else return ''."""
    if len(s) < 8 or not re.fullmatch(r"[A-Za-z0-9_\-+/=]+", s):
        return ""
    padded = s + "=" * (-len(s) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(padded).decode("utf-8", "strict")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
    return ""


def _host_suffix_match(host: str, suffixes: set[str]) -> bool:
    """True if host equals or is a sub-domain of any configured suffix.

    Suffix match (not registered-domain match) so a full wrapper host
    like 'safelinks.protection.outlook.com' can be listed without also
    matching legitimate 'outlook.com' mail.
    """
    if not host:
        return False
    for suf in suffixes:
        if host == suf or host.endswith("." + suf):
            return True
    return False


def _is_ip(host: str) -> bool:
    """Return True if the hostname is a literal IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _load_iocs(paths: Iterable[str]) -> dict[str, str]:
    """Load IOC files into a {indicator: source_filename} dict.

    The result is cached at module level, keyed on the sorted list of
    paths, so a 78k-line URLhaus list is read from disk once per
    process rather than once per email. That matters for the
    experiment runner, where the read cost would otherwise dominate
    the per-email triage time.
    """
    key = tuple(sorted(paths))
    if key in _IOC_CACHE:
        return _IOC_CACHE[key]
    out: dict[str, str] = {}
    for raw_path in paths:
        p = Path(raw_path)
        if not p.is_absolute():
            p = PROJECT_ROOT / p
        if not p.exists():
            continue
        try:
            with p.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    out[line.lower()] = p.name
        except Exception as exc:                     # noqa: BLE001
            log.warning("Failed to read IOC file %s: %s", p, exc)
    _IOC_CACHE[key] = out
    return out


# Module-level cache for the IOC list. Keyed on the tuple of paths
# passed to ``_load_iocs`` so multiple rule-set configurations can
# coexist (e.g. ablation runs with IOCs disabled).
_IOC_CACHE: dict[tuple, dict[str, str]] = {}


def _analyse_headers(parsed: ParsedEmail,
                     brand_keywords: set[str],
                     subject_brand_keywords: set[str] | None = None) -> HeaderFindings:
    """Compute the header-level findings used by HDR-001..006.

    ``subject_brand_keywords`` is optional. If not passed, the same list
    used for the display-name check is reused for the subject check.
    """
    h = HeaderFindings()

    from_dom = _domain_of(parsed.from_address)
    rp_dom = _domain_of(parsed.return_path)
    reply_dom = _domain_of(parsed.reply_to)

    # Mailing-list listservers legitimately rewrite Return-Path and
    # Reply-To. Suppressing HDR-001/HDR-002 for these messages avoids
    # false positives on legitimate list traffic. Rationale is in
    # docs/calibration_notes.md (pilot finding #2).
    if not parsed.is_mailing_list:
        # HDR-001: From vs Return-Path mismatch.
        # Only fires when both are present and disagree on the registered
        # domain (relaxed comparison so newsletter.example.com vs
        # bounce.example.com does not falsely trip).
        if from_dom and rp_dom and _registered(from_dom) != _registered(rp_dom):
            h.from_vs_return_path_mismatch = True

        # HDR-002: From vs Reply-To mismatch (same rule, different headers).
        if from_dom and reply_dom and _registered(from_dom) != _registered(reply_dom):
            h.from_vs_reply_to_mismatch = True

    # HDR-003: display name claims a brand whose domain isn't the From-domain.
    # Compare the brand keyword to the second-level-domain label only, so
    # that a display name 'PayPal Support' on a from-domain of 'paypal.com'
    # is correctly classified as legitimate (sld == 'paypal') but the
    # same display name on 'paypa1.com' is classified as spoof
    # (sld == 'paypa1').
    name = (parsed.display_name or "").lower()
    from_sld = _sld(from_dom)
    for brand in brand_keywords:
        if brand and brand in name:
            h.display_name_brand = brand
            if from_sld != brand:
                h.display_name_brand_spoof = True
            break

    # HDR-004: X-Mailer presence flag (the rule fires when absent).
    h.mailer_present = bool(parsed.mailer)

    # HDR-006: Subject mentions a brand whose name doesn't appear in
    # the From-domain. Catches compromised-sender phishing where the
    # subject impersonates a brand the actual sender has nothing to do
    # with. v1.3: uses regex \b word-boundary matching so 'chase' no
    # longer matches inside 'purchase' and 'ups' no longer matches
    # inside 'support'. Both subject AND from-domain sides use the
    # same word-boundary check.
    subj = (parsed.subject or "").lower()
    subj_brands = subject_brand_keywords if subject_brand_keywords is not None else brand_keywords
    if subj and subj_brands:
        for brand in sorted(subj_brands):
            if not brand:
                continue
            b = brand.lower()
            brand_re = re.compile(r"\b" + re.escape(b) + r"\b", re.IGNORECASE)
            if brand_re.search(subj):
                # Subject names this brand as a whole word. Is the
                # brand also a whole word in the From-domain? If yes,
                # the sender is plausibly legitimate for that brand;
                # don't flag.
                if not brand_re.search(from_dom or ""):
                    h.subject_brand = brand
                    h.subject_brand_from_mismatch = True
                    break

    return h


def _sld(host: str) -> str:
    """Return the second-level-domain label of a host, lowercased.

    For 'mail.paypal.com' returns 'paypal'; for 'co.uk' returns ''.
    """
    if not host:
        return ""
    ex = _TLDX(host)
    return (ex.domain or "").lower()


def _domain_of(addr: str) -> str:
    """Lowercase domain part of an email address, or ''."""
    if not addr or "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].strip().lower()


def _registered(host: str) -> str:
    """Registered-domain (eTLD+1) of a host, lowercased; '' on failure."""
    if not host:
        return ""
    ex = _TLDX(host)
    return _registered_of_extract(ex) or host.lower()


# hidden-text CSS patterns for CNT-004
_HIDDEN_CSS_RE = re.compile(
    r"""(?xi)
    (?:
        display\s*:\s*none      |
        visibility\s*:\s*hidden |
        font-size\s*:\s*0       |
        color\s*:\s*\#?fff      # white text, common with implicit white bg
    )
    """,
)


def _analyse_content(parsed: ParsedEmail, settings: dict) -> ContentFindings:
    """Compute the content-level findings used by CNT-001..005."""
    c = ContentFindings()

    # Search subject + body together. Phishing subjects often carry the
    # strongest urgency language ('[FINAL Notice]', 'Account verification')
    # and the v0 calibration missed these by searching body-only.
    search_text = ((parsed.subject or "") + "\n" + (parsed.body_text or "")).lower()
    html_lower = (parsed.body_html or "").lower()

    # CNT-001 urgency phrases
    for phrase in settings.get("urgency_phrases", []):
        p = phrase.lower()
        if p and p in search_text:
            c.urgency_hits.append(phrase)

    # CNT-002 credential / payment phrases
    for phrase in settings.get("credential_phrases", []):
        p = phrase.lower()
        if p and p in search_text:
            c.credential_hits.append(phrase)

    # CNT-003 executable / macro attachments
    exe_mimes = {m.lower() for m in settings.get("executable_mime_types", [])}
    exe_exts = {e.lower() for e in settings.get("executable_extensions", [])}
    for att in parsed.attachments:
        mime = (att.mime_type or "").lower()
        fname = (att.filename or "").lower()
        suffix = "." + fname.rsplit(".", 1)[1] if "." in fname else ""
        if mime in exe_mimes or suffix in exe_exts:
            c.executable_attachments.append(att.filename or "(unnamed)")

    # CNT-004 hidden text in HTML
    if parsed.body_html:
        if _HIDDEN_CSS_RE.search(parsed.body_html) or _has_zero_width(parsed.body_html):
            c.has_hidden_text = True

    # CNT-005 visible link text vs href domain mismatch
    c.visible_vs_href_mismatch = _href_visible_mismatch(parsed.body_html)

    # CNT-006 subject-only credential-pretext phrases. Scanned against
    # the Subject alone (not the body) so this is a strictly stronger
    # signal than CNT-001/CNT-002, which already cover body matches.
    subj = (parsed.subject or "").lower()
    if subj:
        for phrase in settings.get("subject_pretext_phrases", []):
            p = phrase.lower()
            if p and p in subj:
                c.subject_pretext_hits.append(phrase)

    # CNT-007 subject regex lure patterns. Generalises past CNT-006's
    # literal-substring list by matching against token-order- and
    # separator-tolerant patterns.
    if subj:
        for compiled in _compile_lure_patterns(
                tuple(settings.get("subject_lure_patterns", []))):
            m = compiled.search(subj)
            if m:
                c.subject_lure_matches.append(m.group(0))

    return c


# Compiled regex cache for CNT-007 lure patterns. Keyed on the tuple of
# raw pattern strings so swapping the rule-set between runs (e.g. for
# ablation experiments) doesn't keep stale compiled patterns around.
_LURE_RE_CACHE: dict[tuple, list] = {}


def _compile_lure_patterns(patterns: tuple) -> list:
    """Return a list of compiled lure patterns, cached on the input tuple."""
    if patterns in _LURE_RE_CACHE:
        return _LURE_RE_CACHE[patterns]
    compiled: list = []
    for raw in patterns:
        if not raw:
            continue
        try:
            compiled.append(re.compile(raw, re.IGNORECASE))
        except re.error as exc:
            log.warning("Invalid subject_lure_patterns entry skipped: %r (%s)",
                        raw, exc)
    _LURE_RE_CACHE[patterns] = compiled
    return compiled


def _has_zero_width(text: str) -> bool:
    """Detect zero-width space and joiner characters used to evade keyword filters."""
    return any(ch in text for ch in ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"))


def _href_visible_mismatch(html: str) -> bool:
    """True if an <a> tag's visible text is itself a URL that points to
    a different registered domain than its href. Only that case is
    flagged, so a plain <a href="...">click here</a> does not trip it.
    """
    if not html:
        return False
    try:
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return False

    url_in_text = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
    for a in soup.find_all("a"):
        href = (a.get("href") or "").strip()
        text = (a.get_text() or "").strip()
        if not href.lower().startswith(("http://", "https://")):
            continue
        m = url_in_text.search(text)
        if not m:
            continue
        visible_url = m.group(0).rstrip(".,);:'\"")
        visible_host = _host(visible_url)
        href_host = _host(href)
        if not visible_host or not href_host:
            continue
        visible_reg = _registered(visible_host)
        href_reg = _registered(href_host)
        if visible_reg and href_reg:
            if visible_reg != href_reg:
                return True
        elif _is_ip(visible_host) != _is_ip(href_host):
            return True
        elif visible_host != href_host:
            return True
    return False


def _host(url: str) -> str:
    """Lowercase hostname of a URL, or '' on failure."""
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""
