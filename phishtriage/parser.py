"""Stage 1: email ingestion and parsing.

Turns raw RFC-5322 bytes into the ParsedEmail object the rest of the
pipeline reads. The public corpora contain plenty of broken messages,
and one crash would abort a whole experiment run, so anything the
stdlib email module cannot parse becomes a warning and the field is
left empty. A half-parsed email still gets a verdict.

Built on the stdlib email module with policy.default. This stage
normalises the sender fields, the headers the rules care about, both
body forms, the extracted URLs, and attachment hashes.
"""

from __future__ import annotations

import email
import hashlib
import re
from dataclasses import dataclass, field, asdict
from email import policy
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup

from phishtriage.utils import log


@dataclass
class Attachment:
    filename: str
    mime_type: str
    size_bytes: int
    sha256: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ParsedEmail:
    """Structured form of a single email."""
    message_id: str = ""
    source_path: str = ""

    from_address: str = ""
    from_domain: str = ""
    display_name: str = ""
    return_path: str = ""
    reply_to: str = ""

    to_addresses: list[str] = field(default_factory=list)
    cc_addresses: list[str] = field(default_factory=list)

    subject: str = ""
    date_raw: str = ""
    date_iso: str = ""
    mailer: str = ""

    # Set when any List-Id / List-Unsubscribe / Mailing-List / List-Post
    # header is present. Used to suppress HDR-001/HDR-002, which fire on
    # the header rewriting that listservers do as normal behaviour.
    is_mailing_list: bool = False
    list_id: str = ""

    authentication_results: str = ""
    received_chain: list[str] = field(default_factory=list)

    body_text: str = ""
    body_html: str = ""

    urls: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)

    # Shown in the report, never raised.
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["attachments"] = [a.to_dict() for a in self.attachments]
        return d


# Loose http(s) URL matcher for plain text. It over-matches on purpose;
# tldextract drops the junk downstream, and missing a real link costs
# more than a false one here.
_URL_RE = re.compile(
    r"""(?xi)
    \b
    (?:https?://)
    [^\s<>"']+
    """,
    re.IGNORECASE,
)


def parse_eml(path: str | Path) -> ParsedEmail:
    """Parse an .eml file from disk. Malformed content lands in
    ParsedEmail.warnings rather than raising; a missing file still raises.
    """
    p = Path(path)
    raw_bytes = p.read_bytes()
    parsed = parse_bytes(raw_bytes)
    parsed.source_path = str(p)
    return parsed


def parse_bytes(raw: bytes) -> ParsedEmail:
    """Parse raw RFC-5322 bytes. Tests use this directly since building
    bytes in memory is easier than writing a temp file."""
    out = ParsedEmail()
    try:
        msg: EmailMessage = email.message_from_bytes(
            raw, policy=policy.default
        )
    except Exception as exc:                       # noqa: BLE001  keep going
        out.warnings.append(f"top-level parse failed: {exc}")
        log.warning("Top-level parse failed: %s", exc)
        return out

    out.message_id = _strip(msg.get("Message-ID", ""))
    out.subject = _strip(msg.get("Subject", ""))
    out.mailer = _strip(msg.get("X-Mailer", ""))
    out.date_raw = _strip(msg.get("Date", ""))
    out.date_iso = _to_iso(out.date_raw, out)

    raw_from = _strip(msg.get("From", ""))
    display_name, addr = parseaddr(raw_from)
    out.display_name = display_name
    out.from_address = addr
    out.from_domain = _domain_of(addr)

    rp = _strip(msg.get("Return-Path", ""))
    out.return_path = parseaddr(rp)[1] if rp else ""
    reply = _strip(msg.get("Reply-To", ""))
    out.reply_to = parseaddr(reply)[1] if reply else ""

    out.to_addresses = [a for _, a in getaddresses(msg.get_all("To", []))]
    out.cc_addresses = [a for _, a in getaddresses(msg.get_all("Cc", []))]

    # raw header; stage 2 parses it
    out.authentication_results = _strip(msg.get("Authentication-Results", ""))

    # Any of these headers means list traffic. Listservers rewrite
    # Return-Path and Reply-To routinely, which used to trip HDR-001 and
    # HDR-002 on legitimate list mail. List-Id is kept so the report can
    # say why those rules were held back.
    out.list_id = _strip(msg.get("List-Id", "") or msg.get("List-ID", ""))
    out.is_mailing_list = bool(
        out.list_id
        or msg.get("List-Unsubscribe")
        or msg.get("List-Post")
        or msg.get("Mailing-List")
    )

    # Received headers are newest-first in the message; reverse so
    # stage 3 reads the routing forwards in time.
    out.received_chain = list(reversed(msg.get_all("Received", []) or []))

    _walk_parts(msg, out)

    out.urls = _extract_urls(out.body_text, out.body_html)

    return out


def _strip(value: Any) -> str:
    """Strip surrounding whitespace, or return '' for None."""
    if value is None:
        return ""
    return str(value).strip()


def _domain_of(address: str) -> str:
    """Lowercase domain part of an email address, or ''."""
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().lower()


def _to_iso(raw_date: str, out: ParsedEmail) -> str:
    """RFC-2822 Date header to ISO-8601, best effort."""
    if not raw_date:
        return ""
    try:
        return parsedate_to_datetime(raw_date).isoformat()
    except Exception as exc:                       # noqa: BLE001
        out.warnings.append(f"date parse failed: {exc}")
        return ""


def _walk_parts(msg: EmailMessage, out: ParsedEmail) -> None:
    """Walk the MIME tree, filling in body text, HTML, and attachments."""
    text_parts: list[str] = []
    html_parts: list[str] = []

    for part in msg.walk():
        if part.is_multipart():
            continue

        ctype = (part.get_content_type() or "").lower()
        disp = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()

        if disp == "attachment" or filename:
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception as exc:                # noqa: BLE001
                out.warnings.append(f"attachment decode failed: {exc}")
                payload = b""
            out.attachments.append(
                Attachment(
                    filename=filename or "",
                    mime_type=ctype,
                    size_bytes=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest() if payload else "",
                )
            )
            continue

        if ctype == "text/plain":
            text_parts.append(_decode_text(part, out))
        elif ctype == "text/html":
            html_parts.append(_decode_text(part, out))

    out.body_text = "\n".join(text_parts).strip()
    out.body_html = "\n".join(html_parts).strip()

    # HTML-only mail is common in the phishing corpora, and the language
    # rules (CNT-001/002) only read body_text, so derive a text snapshot
    # from the HTML. lxml if it is installed, the stdlib parser if not,
    # and a warning if both fail.
    if not out.body_text and out.body_html:
        try:
            try:
                soup = BeautifulSoup(out.body_html, "lxml")
            except Exception:
                soup = BeautifulSoup(out.body_html, "html.parser")
            out.body_text = soup.get_text(separator=" ", strip=True)
        except Exception as exc:                    # noqa: BLE001
            out.warnings.append(f"html-to-text fallback failed: {exc}")


def _decode_text(part: EmailMessage, out: ParsedEmail) -> str:
    """Decode a text/* part to str, tolerating bad encodings."""
    try:
        return part.get_content()
    except Exception:
        try:
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
        except Exception as exc:                    # noqa: BLE001
            out.warnings.append(f"text part decode failed: {exc}")
            return ""


def _extract_urls(text: str, html: str) -> list[str]:
    """De-duplicated URLs from the body.

    HTML href attributes come first so the CNT-005 visible-text vs
    target check can compare the two, then plain-text URLs.
    """
    urls: list[str] = []
    seen: set[str] = set()

    if html:
        try:
            soup = BeautifulSoup(html, "lxml")
            for tag in soup.find_all(["a", "area", "form"]):
                href = tag.get("href") or tag.get("action") or ""
                if href.lower().startswith(("http://", "https://")):
                    if href not in seen:
                        seen.add(href)
                        urls.append(href)
        except Exception:
            pass  # fall through to regex

    for source in (text or "", html or ""):
        for match in _URL_RE.findall(source):
            cleaned = match.rstrip(".,);:'\"")
            if cleaned not in seen:
                seen.add(cleaned)
                urls.append(cleaned)

    return urls
