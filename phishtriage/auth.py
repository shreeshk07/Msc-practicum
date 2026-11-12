"""Stage 2: email authentication checker.

Reads the Authentication-Results header (RFC 7601) and exposes the SPF,
DKIM, and DMARC outcomes as a structured object for the scoring engine.
The signal here is the receiving MTA's own verification, recorded in
that header.

The AR grammar is awkward, so the parser prefers the authheaders
package when it imports. When it does not, a regex parser handles the
common shapes from the SpamAssassin and Nazario corpora.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict

try:
    from authheaders import parse_authentication_results  # type: ignore
    _HAVE_AUTHHEADERS = True
except Exception:                                   # noqa: BLE001
    _HAVE_AUTHHEADERS = False

from phishtriage.utils import log


# Result keywords the scoring engine understands. Anything else becomes
# "unknown".
_VALID = {"pass", "fail", "softfail", "neutral", "none", "policy",
          "permerror", "temperror"}


@dataclass
class AuthResult:
    """Parsed outcome of email authentication checks for one message."""
    spf: str = "unknown"             # one of _VALID or "unknown"
    spf_domain: str = ""             # domain SPF was evaluated against
    dkim: str = "unknown"
    dkim_domain: str = ""
    dmarc: str = "unknown"
    dmarc_domain: str = ""
    aligned: bool = False            # SPF or DKIM aligns with From per DMARC
    raw_header: str = ""             # original header text for the report
    ar_present: bool = False         # was Authentication-Results found at all?
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def check_auth(authentication_results: str, from_domain: str = "") -> AuthResult:
    """Parse an Authentication-Results header value.

    from_domain drives the aligned flag. Always returns a populated
    object and never raises; an empty header gives "unknown" results
    and ar_present=False.
    """
    out = AuthResult(raw_header=authentication_results or "")

    if not authentication_results:
        return out

    out.ar_present = True

    if _HAVE_AUTHHEADERS:
        out = _parse_with_authheaders(authentication_results, out)
    else:
        out = _parse_with_regex(authentication_results, out)

    # DMARC aligned only when SPF or DKIM passed and its domain lines up
    # with the From-domain. Alignment is relaxed: a sub-domain match
    # either way counts.
    fd = (from_domain or "").lower().lstrip("@")
    spf_ok = out.spf == "pass" and _aligns(out.spf_domain, fd)
    dkim_ok = out.dkim == "pass" and _aligns(out.dkim_domain, fd)
    out.aligned = bool(fd) and (spf_ok or dkim_ok) and out.dmarc == "pass"

    return out


def _parse_with_authheaders(header: str, out: AuthResult) -> AuthResult:
    """Parse the AR header with the authheaders package."""
    try:
        # Return shape varies across authheaders versions, so values
        # are pulled out defensively below.
        parsed = parse_authentication_results(header)
    except Exception as exc:                        # noqa: BLE001
        out.notes.append(f"authheaders parse failed: {exc}; using regex fallback")
        log.debug("authheaders failed, fallback to regex: %s", exc)
        return _parse_with_regex(header, out)

    # Newer versions yield method objects with .method/.result/
    # .properties; older ones yield dicts.
    try:
        for entry in parsed:
            method = _get_attr(entry, "method", "").lower()
            result = _normalise(_get_attr(entry, "result", ""))
            props = _get_attr(entry, "properties", {}) or {}
            domain = _props_domain(props)

            if method == "spf":
                out.spf, out.spf_domain = result, domain or out.spf_domain
            elif method == "dkim":
                out.dkim, out.dkim_domain = result, domain or out.dkim_domain
            elif method == "dmarc":
                out.dmarc, out.dmarc_domain = result, domain or out.dmarc_domain
    except Exception as exc:                        # noqa: BLE001
        out.notes.append(f"authheaders shape unexpected: {exc}; regex fallback")
        return _parse_with_regex(header, out)

    return out


def _get_attr(obj, name, default=None):
    """Return an attribute or dict key from obj, with a default."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _props_domain(props) -> str:
    """Pull a domain out of authheaders' properties structure."""
    if not props:
        return ""
    if isinstance(props, dict):
        for k in ("smtp.mailfrom", "header.from", "header.d", "header.i"):
            if k in props and props[k]:
                return str(props[k]).strip().lstrip("@").lower()
        # some versions nest, e.g. {"smtp": {"mailfrom": "..."}}
        for v in props.values():
            if isinstance(v, dict):
                for inner in v.values():
                    if inner:
                        return str(inner).strip().lstrip("@").lower()
    return ""


# spf=pass / dkim=fail / dmarc=none tokens
_TOKEN_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*([A-Za-z]+)",
    re.IGNORECASE,
)

# the domain token that follows a method, e.g. spf=pass
# smtp.mailfrom=example.com, or dkim=pass header.d=example.com
_DOMAIN_RE = re.compile(
    r"(?:smtp\.mailfrom|header\.d|header\.i|header\.from)\s*=\s*([^\s;]+)",
    re.IGNORECASE,
)


def _parse_with_regex(header: str, out: AuthResult) -> AuthResult:
    """Regex parser for when authheaders is unavailable. Covers the
    common Microsoft/Google/standard-MTA shapes, not the full RFC 7601.
    """
    # Semicolons separate the methods. Each block holds at most one
    # method token plus its property tokens.
    for block in re.split(r";", header):
        m = _TOKEN_RE.search(block)
        if not m:
            continue
        method = m.group(1).lower()
        result = _normalise(m.group(2))

        d_match = _DOMAIN_RE.search(block)
        domain = d_match.group(1).strip().lstrip("@").lower() if d_match else ""

        if method == "spf":
            out.spf, out.spf_domain = result, domain or out.spf_domain
        elif method == "dkim":
            out.dkim, out.dkim_domain = result, domain or out.dkim_domain
        elif method == "dmarc":
            out.dmarc, out.dmarc_domain = result, domain or out.dmarc_domain

    return out


def _normalise(token: str) -> str:
    """One of the _VALID keywords, or 'unknown'."""
    t = (token or "").strip().lower()
    return t if t in _VALID else "unknown"


def _aligns(auth_domain: str, from_domain: str) -> bool:
    """Relaxed DMARC alignment: the auth domain equals the From domain
    or is a sub-domain of it, either direction."""
    if not auth_domain or not from_domain:
        return False
    a, f = auth_domain.lower().lstrip("@"), from_domain.lower().lstrip("@")
    return a == f or a.endswith("." + f) or f.endswith("." + a)
