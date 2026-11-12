"""Convert participant session JSON exports into the manual baseline
CSVs that run_experiment.py analyse --manual expects.

Reads every triage_P*.json in --json-dir, the JSON the web form
produces (participant block, timestamp, ESS answers, and an emails
list of email_id/verdict/confidence/time_ms records). Each email_id is
joined to its SHA-256 through the session manifest. The column names
and order match convert_form_to_manual.py (sha256, manual_verdict,
manual_seconds, pseudonym, email_id), with manual_confidence appended
as a trailing column the analyser ignores.

Writes one {pseudonym}_manual.csv per participant and a combined
all_manual.csv to --out-dir. Nothing is written if any file fails
validation: wrong email count, an email_id missing from the manifest,
a verdict that is not phishing or benign, or a repeated email.

    python tools/convert_json_to_manual.py \
        --json-dir results/raw_sessions \
        --manifest tools/manual_triage_form/session_emails/manifest.json \
        --out-dir results/manual
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

EXPECTED_EMAILS = 20
VALID_VERDICTS = {"phishing", "benign"}
OUTPUT_COLUMNS = ["sha256", "manual_verdict", "manual_seconds",
                  "pseudonym", "email_id", "manual_confidence"]


def load_manifest_hashes(manifest_path: Path) -> dict[str, str]:
    """Map every manifest email_id to its SHA-256."""
    entries = json.loads(manifest_path.read_text(encoding="utf-8"))
    return {str(e["email_id"]): str(e["sha256"]) for e in entries}


def convert_one(json_path: Path, hashes: dict[str, str]) -> tuple[str, list[list[str]]]:
    """Convert one participant export. Returns (pseudonym, rows)."""
    data = json.loads(json_path.read_text(encoding="utf-8"))
    pseudonym = str(data["participant"]["pseudonym"]).strip()
    emails = data.get("emails", [])
    if len(emails) != EXPECTED_EMAILS:
        raise ValueError(
            f"{json_path.name}: participant {pseudonym} has "
            f"{len(emails)} emails, expected {EXPECTED_EMAILS}"
        )
    rows: list[list[str]] = []
    seen: set[str] = set()
    for rec in emails:
        email_id = str(rec["email_id"]).strip()
        if email_id in seen:
            raise ValueError(
                f"{json_path.name}: duplicate email_id {email_id!r} "
                f"for participant {pseudonym}"
            )
        seen.add(email_id)
        if email_id not in hashes:
            raise ValueError(
                f"{json_path.name}: email_id {email_id!r} is not in "
                "the manifest"
            )
        verdict = str(rec["verdict"]).strip().lower()
        if verdict not in VALID_VERDICTS:
            raise ValueError(
                f"{json_path.name}: verdict {verdict!r} for {email_id} "
                "is neither phishing nor benign"
            )
        seconds = float(rec["time_ms"]) / 1000.0
        rows.append([
            hashes[email_id],
            verdict,
            f"{seconds:.3f}",
            pseudonym,
            email_id,
            str(rec.get("confidence", "")).strip().lower(),
        ])
    return pseudonym, rows


def convert_all(json_dir: Path, manifest: Path, out_dir: Path) -> None:
    hashes = load_manifest_hashes(manifest)
    files = sorted(
        json_dir.glob("triage_P*.json"),
        key=lambda p: int(re.search(r"_P(\d+)_", p.name).group(1)),
    )
    if not files:
        raise ValueError(f"no triage_P*.json files found in {json_dir}")

    # Convert everything first so a validation failure on any file
    # means nothing at all is written.
    converted: list[tuple[str, list[list[str]]]] = []
    pseudonyms: set[str] = set()
    for f in files:
        pseudonym, rows = convert_one(f, hashes)
        if pseudonym in pseudonyms:
            raise ValueError(f"duplicate pseudonym {pseudonym!r} across files")
        pseudonyms.add(pseudonym)
        converted.append((pseudonym, rows))

    out_dir.mkdir(parents=True, exist_ok=True)
    all_rows: list[list[str]] = []
    for pseudonym, rows in converted:
        per = out_dir / f"{pseudonym}_manual.csv"
        with open(per, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(OUTPUT_COLUMNS)
            w.writerows(rows)
        print(f"wrote {per} ({len(rows)} rows)")
        all_rows.extend(rows)
    combined = out_dir / "all_manual.csv"
    with open(combined, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(OUTPUT_COLUMNS)
        w.writerows(all_rows)
    print(f"wrote {combined} ({len(all_rows)} rows, "
          f"{len(converted)} participants)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Convert participant session JSON exports into "
                    "manual baseline CSVs for analyse --manual."
    )
    ap.add_argument("--json-dir", required=True, type=Path,
                    help="Directory holding the triage_P*.json exports.")
    ap.add_argument("--manifest", required=True, type=Path,
                    help="Path to the session manifest.json.")
    ap.add_argument("--out-dir", required=True, type=Path,
                    help="Directory for the converted manual CSVs.")
    args = ap.parse_args(argv)
    try:
        convert_all(args.json_dir, args.manifest, args.out_dir)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
