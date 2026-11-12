"""triage.py: command-line entrypoint for PhishTriage.

Runs the five stages over one email.

    # Markdown report to stdout
    python triage.py --input tests/fixtures/sample_phishing.eml

    # also write Markdown and TheHive JSON to disk
    python triage.py -i tests/fixtures/sample_phishing.eml --write

    # JSON only, for piping into jq
    python triage.py -i tests/fixtures/sample_phishing.eml --json

    # one-line summary, for batch logs
    python triage.py -i tests/fixtures/sample_phishing.eml --quiet
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from phishtriage.auth import check_auth
from phishtriage.indicators import extract_indicators
from phishtriage.parser import parse_eml
from phishtriage.reporting import render_markdown, render_thehive_case
from phishtriage.scoring import score
from phishtriage.utils import PROJECT_ROOT, load_settings, log, timed


def run_pipeline(eml_path: Path) -> dict:
    """Run the five stages on one email.

    Returns the parsed objects, scoring result, both reports, and
    per-stage timings. total_elapsed_seconds is the MTT figure the
    experiment uses.
    """
    settings = load_settings()

    timings: dict[str, float] = {}

    with timed("stage1_parser") as t:
        parsed = parse_eml(eml_path)
    timings["stage1_parser"] = t["elapsed_seconds"]

    with timed("stage2_auth") as t:
        auth = check_auth(parsed.authentication_results, parsed.from_domain)
    timings["stage2_auth"] = t["elapsed_seconds"]

    with timed("stage3_indicators") as t:
        indicators = extract_indicators(parsed, settings)
    timings["stage3_indicators"] = t["elapsed_seconds"]

    with timed("stage4_scoring") as t:
        scoring = score(parsed, auth, indicators, settings=settings)
    timings["stage4_scoring"] = t["elapsed_seconds"]

    with timed("stage5_reporting") as t:
        md = render_markdown(parsed, auth, indicators, scoring, timings)
        case = render_thehive_case(parsed, auth, indicators, scoring, timings)
    timings["stage5_reporting"] = t["elapsed_seconds"]

    timings["total_elapsed_seconds"] = round(sum(timings.values()), 6)

    return {
        "parsed": parsed,
        "auth": auth,
        "indicators": indicators,
        "scoring": scoring,
        "markdown": md,
        "thehive_case": case,
        "timings": timings,
    }


def _safe_filename(text: str) -> str:
    """Filesystem-safe slug from a Message-ID-like string."""
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", text or "")
    return s.strip("_") or "no-message-id"


def _quiet_line(result: dict) -> str:
    p = result["parsed"]
    s = result["scoring"]
    t = result["timings"]["total_elapsed_seconds"]
    return (f"{s.band:8s} score={s.score:>4d}  "
            f"fired={s.fired_rules}/{s.evaluated_rules}  "
            f"t={t:.4f}s  "
            f"from={p.from_address}  "
            f"subject={p.subject!r}")


def write_outputs(result: dict, out_dir: Path) -> tuple[Path, Path]:
    """Write Markdown and JSON reports for one email; return the paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    p = result["parsed"]
    name = _safe_filename(p.message_id or Path(p.source_path).stem)

    md_path = out_dir / f"{name}.md"
    json_path = out_dir / f"{name}.json"

    md_path.write_text(result["markdown"], encoding="utf-8")
    json_path.write_text(
        json.dumps(result["thehive_case"], indent=2, default=str),
        encoding="utf-8",
    )
    return md_path, json_path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="triage",
        description="Rule-based phishing email triage (PhishTriage).",
    )
    ap.add_argument("--input", "-i", required=True,
                    help="Path to a single .eml file.")
    ap.add_argument("--json", action="store_true",
                    help="Emit the TheHive case JSON to stdout instead of Markdown.")
    ap.add_argument("--quiet", action="store_true",
                    help="Print a single line per email; suppresses report body.")
    ap.add_argument("--write", action="store_true",
                    help="Write Markdown + JSON reports under results/per_email/.")
    args = ap.parse_args(argv)

    path = Path(args.input)
    if not path.exists():
        log.error("Input file not found: %s", path)
        return 2

    result = run_pipeline(path)

    if args.write:
        out_dir = PROJECT_ROOT / "results" / "per_email"
        md_path, json_path = write_outputs(result, out_dir)
        log.info("Markdown report: %s", md_path)
        log.info("TheHive JSON   : %s", json_path)

    if args.quiet:
        print(_quiet_line(result))
    elif args.json:
        print(json.dumps(result["thehive_case"], indent=2, default=str))
    else:
        print(result["markdown"])

    return 0


if __name__ == "__main__":
    sys.exit(main())
