"""Per-FN readout for a corpus run CSV.

Reads a run CSV, finds false negatives (actual phishing scored in the
LOW band, i.e. predicted benign), re-loads the raw email by sha256 from
the Nazario mboxes and phishing_pot tree, re-runs the pipeline, and
prints subject / from-domain / fired rules / auth / URLs / attachments
for each miss. Pattern-analysis aid only; changes nothing.

Usage:
    python tools/fn_readout.py results/operational_v3_modern.csv
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

from phishtriage.auth import check_auth
from phishtriage.experiment import (
    iter_nazario,
    iter_phishing_pot,
    iter_spamassassin,
)
from phishtriage.indicators import extract_indicators
from phishtriage.parser import parse_bytes
from phishtriage.scoring import score
from phishtriage.utils import load_settings

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "raw"
LOW = "LOW"


def asc(s: str) -> str:
    """ASCII-safe rendering so cp1252 consoles don't blow up."""
    return (s or "").encode("ascii", "replace").decode("ascii")


def main(csv_path: str) -> None:
    with open(csv_path, encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    fns = [r for r in rows
           if r["label"] == "phishing" and r["predicted_band"] == LOW]
    # FP = benign that landed in a phishing-positive band (not LOW).
    fps = [r for r in rows
           if r["label"] == "benign" and r["predicted_band"] != LOW]
    misses = fns + fps
    miss_sha = {r["sha256"]: r for r in misses}
    print(f"Run: {csv_path}")
    print(f"Total rows: {len(rows)}   FN (phishing->LOW): {len(fns)}   "
          f"FP (benign->MEDIUM+): {len(fps)}")
    by_corpus: dict[str, int] = {}
    for r in fns:
        by_corpus[r["corpus"]] = by_corpus.get(r["corpus"], 0) + 1
    print(f"FN by corpus: {by_corpus}\n")

    # Re-load raw bytes for the miss shas from the live corpora.
    raw_by_sha: dict[str, bytes] = {}
    sources = [iter_phishing_pot(DATA / "phishing_pot"),
               iter_spamassassin(DATA / "spamassassin")]
    for mbox in sorted((DATA / "nazario").glob("*.mbox")):
        sources.append(iter_nazario(mbox))
    for src in sources:
        for item in src:
            if item.sha256 in miss_sha and item.sha256 not in raw_by_sha:
                raw_by_sha[item.sha256] = item.raw_bytes

    settings = load_settings()

    # Print FNs first (phishing_pot fresh misses ahead of nazario), then FPs.
    order = sorted(misses, key=lambda r: (
        r["label"] != "phishing",            # FNs before FPs
        r["corpus"] != "phishing_pot",       # fresh phishing_pot first
        r["corpus"], r["source_id"]))
    for i, r in enumerate(order, 1):
        sha = r["sha256"]
        kind = "FN" if r["label"] == "phishing" else "FP"
        print("=" * 72)
        print(f"[{i}/{len(order)}] {kind}  {r['corpus']}  {asc(r['source_id'])}")
        print(f"  CSV: band={r['predicted_band']} score={r['predicted_score']} "
              f"fired={r['fired_rules']}")
        raw = raw_by_sha.get(sha)
        if raw is None:
            print("  (raw bytes not found in live corpora, skipped)")
            continue
        parsed = parse_bytes(raw)
        auth = check_auth(parsed.authentication_results, parsed.from_domain)
        ind = extract_indicators(parsed, settings)
        sc = score(parsed, auth, ind, settings=settings)
        fired = ",".join(h.rule_id for h in sc.hits) or "(none)"
        print(f"  subject : {asc(parsed.subject)!r}")
        print(f"  from_dom: {asc(parsed.from_domain)!r}")
        print(f"  score   : {sc.score}  band={sc.band}  fired=[{fired}]")
        print(f"  auth    : spf={auth.spf} dkim={auth.dkim} dmarc={auth.dmarc} "
              f"aligned={auth.aligned} ar_present={auth.ar_present}")
        urls = parsed.urls or []
        print(f"  urls    : {len(urls)}")
        for u in urls[:6]:
            print(f"            {asc(u)}")
        atts = parsed.attachments or []
        print(f"  attach  : {len(atts)}")
        for a in atts:
            print(f"            {asc(a.filename)}  {a.mime_type}  {a.size_bytes}B")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "results/operational_v3_modern.csv")
