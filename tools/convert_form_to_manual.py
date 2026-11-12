"""Convert a participant web form CSV export into the manual baseline
CSV that ``run_experiment.py analyse --manual`` expects.

The web form (tools/manual_triage_form) exports one CSV per
participant whose columns include pseudonym, email_id, verdict, and
time_ms. The analyser joins manual rows to automated rows on the
email's SHA-256 and reads manual_verdict and manual_seconds. This
script bridges the two formats:

* Each email_id is looked up in the session manifest. The SHA-256
  comes from an explicit ``sha256`` field on the manifest entry when
  one is present; otherwise it is computed from the raw bytes of the
  .eml file the entry points to, which is the same hash the pipeline
  uses for its own rows.
* time_ms is converted to seconds (divided by 1000).
* The verdict passes through as phishing or benign.

Usage:

    python tools/convert_form_to_manual.py \
        --form-csv results/manual/P1.csv \
        --manifest tools/manual_triage_form/manifest.json \
        --output results/manual/P1_manual.csv

The output columns are sha256, manual_verdict, manual_seconds,
pseudonym, email_id. Run it once per participant. The analyser
accepts manual CSVs holding several participants, so per-participant
outputs can be concatenated afterwards (keep a single header line).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path

VALID_VERDICTS = {"phishing", "benign"}
OUTPUT_COLUMNS = ["sha256", "manual_verdict", "manual_seconds",
                  "pseudonym", "email_id"]


def load_manifest_hashes(manifest_path: Path) -> dict[str, str]:
    """Map every manifest email_id to its SHA-256."""
    entries = json.loads(manifest_path.read_text(encoding="utf-8"))
    hashes: dict[str, str] = {}
    for entry in entries:
        email_id = str(entry["email_id"])
        sha = entry.get("sha256")
        if not sha:
            eml = (manifest_path.parent / str(entry["filename"])).resolve()
            if not eml.is_file():
                raise ValueError(
                    f"manifest entry {email_id!r} has no sha256 field and "
                    f"its file does not exist: {eml}"
                )
            sha = hashlib.sha256(eml.read_bytes()).hexdigest()
        hashes[email_id] = str(sha)
    return hashes


def convert(form_csv: Path, manifest: Path, output: Path) -> int:
    """Convert one participant's form export. Returns the row count."""
    hashes = load_manifest_hashes(manifest)
    rows_out: list[list[str]] = []
    with open(form_csv, encoding="utf-8", newline="") as fh:
        for lineno, row in enumerate(csv.DictReader(fh), start=2):
            email_id = (row.get("email_id") or "").strip()
            if email_id not in hashes:
                raise ValueError(
                    f"{form_csv}, line {lineno}: email_id {email_id!r} "
                    f"was not found in the manifest {manifest}"
                )
            verdict = (row.get("verdict") or "").strip().lower()
            if verdict not in VALID_VERDICTS:
                raise ValueError(
                    f"{form_csv}, line {lineno}: verdict {verdict!r} is "
                    "neither phishing nor benign"
                )
            try:
                seconds = float(row["time_ms"]) / 1000.0
            except (KeyError, ValueError) as exc:
                raise ValueError(
                    f"{form_csv}, line {lineno}: time_ms is missing or "
                    f"not a number ({exc})"
                ) from exc
            rows_out.append([
                hashes[email_id],
                verdict,
                f"{seconds:.3f}",
                (row.get("pseudonym") or "").strip(),
                email_id,
            ])
    with open(output, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(OUTPUT_COLUMNS)
        writer.writerows(rows_out)
    return len(rows_out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert a web form participant CSV into the "
                    "manual baseline CSV used by analyse --manual."
    )
    parser.add_argument("--form-csv", required=True, type=Path,
                        help="Path to one participant's form CSV export.")
    parser.add_argument("--manifest", required=True, type=Path,
                        help="Path to the session manifest.json.")
    parser.add_argument("--output", required=True, type=Path,
                        help="Path for the converted manual CSV.")
    args = parser.parse_args(argv)
    try:
        n = convert(args.form_csv, args.manifest, args.output)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {n} rows to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
