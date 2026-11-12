"""run_experiment.py: corpus experiment CLI for PhishTriage.

    # 20-email balanced pilot across SpamAssassin subsets
    python run_experiment.py pilot

    # 100-email run per the CA2 protocol
    python run_experiment.py full

    # custom run with explicit per-bucket sizes
    python run_experiment.py custom \
        --sa data/raw/spamassassin \
        --nazario data/raw/nazario/phishing-2024.mbox \
        --sample spamassassin:easy_ham=10 \
        --sample spamassassin:spam_2=10 \
        --sample nazario:phishing-2024=10 \
        --output results/run1.csv

    # analyse a written CSV, optionally against a manual baseline
    python run_experiment.py analyse --csv results/pilot.csv
    python run_experiment.py analyse --csv results/pilot.csv --manual results/manual.csv
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from phishtriage.experiment import (
    analyse_results,
    collect_corpus,
    deterministic_sample,
    run_corpus,
)
from phishtriage.utils import PROJECT_ROOT, log


# 20-email pilot, a quick end-to-end check of the runner.
PILOT_SAMPLE = {
    "spamassassin:easy_ham":  5,
    "spamassassin:hard_ham":  5,
    "spamassassin:spam":      5,
    "spamassassin:spam_2":    5,
}

# 100-email full run per experiment_protocol.md. Change the nazario
# subset name to whichever year is downloaded.
FULL_SAMPLE = {
    "spamassassin:easy_ham":      30,
    "spamassassin:hard_ham":      20,
    "spamassassin:spam_2":        20,
    "nazario:phishing-2024":      30,
}


def _parse_sample_arg(args: list[str]) -> dict[str, int]:
    """Parse --sample bucket=N pairs into a dict."""
    out: dict[str, int] = {}
    for a in args or []:
        if "=" not in a:
            raise SystemExit(f"--sample expects bucket=N, got {a!r}")
        k, v = a.split("=", 1)
        try:
            out[k.strip()] = int(v)
        except ValueError as exc:
            raise SystemExit(f"--sample value not an integer: {a!r}") from exc
    return out


def _gather(sa_root: Path | None,
            nazario_paths: list[Path],
            phishing_pot: Path | None = None,
            champa_csv: Path | None = None) -> list:
    sa = sa_root if sa_root and sa_root.exists() else None
    if not sa:
        log.warning("SpamAssassin root %s not found, skipping that corpus", sa_root)
    return collect_corpus(sa, nazario_paths, phishing_pot, champa_csv)


def _print_summary(summary, csv_path: Path) -> None:
    print("-" * 50)
    print(f"  Processed   : {summary.n_processed}")
    print(f"  Skipped     : {summary.n_skipped}")
    print(f"  Wall-clock  : {summary.elapsed_total:.3f} s")
    print(f"  CSV         : {csv_path}")
    if summary.counts_by_band:
        print("  By band     :", dict(summary.counts_by_band))
    if summary.counts_by_label:
        print("  By label    :", dict(summary.counts_by_label))
    print("-" * 50)


def _print_analysis(result) -> None:
    d = result.to_dict()
    print(json.dumps(d, indent=2))


def _opt_path(value):
    return Path(value) if value else None


def cmd_pilot(args) -> int:
    sa = Path(args.sa) if args.sa else PROJECT_ROOT / "data/raw/spamassassin"
    nazario = [Path(p) for p in (args.nazario or [])]
    items = _gather(sa, nazario, _opt_path(args.phishing_pot), _opt_path(args.champa))
    if not items:
        log.error("No corpus items found.")
        return 2
    sample = deterministic_sample(items, PILOT_SAMPLE)
    log.info("Pilot sample: %d items", len(sample))
    output_csv = Path(args.output) if args.output else PROJECT_ROOT / "results/pilot.csv"
    json_dir = PROJECT_ROOT / "results/per_email"
    summary = run_corpus(sample, output_csv, json_dir)
    _print_summary(summary, output_csv)
    return 0


def cmd_full(args) -> int:
    sa = Path(args.sa) if args.sa else PROJECT_ROOT / "data/raw/spamassassin"
    nazario = [Path(p) for p in (args.nazario or [])]
    if not nazario:
        # fall back to phishing-2024 if present
        candidate = PROJECT_ROOT / "data/raw/nazario/phishing-2024.mbox"
        if candidate.exists():
            nazario = [candidate]
    items = _gather(sa, nazario, _opt_path(args.phishing_pot), _opt_path(args.champa))
    if not items:
        log.error("No corpus items found.")
        return 2
    sample = deterministic_sample(items, FULL_SAMPLE)
    log.info("Full sample: %d items", len(sample))
    output_csv = Path(args.output) if args.output else PROJECT_ROOT / "results/full.csv"
    json_dir = PROJECT_ROOT / "results/per_email"
    summary = run_corpus(sample, output_csv, json_dir)
    _print_summary(summary, output_csv)
    return 0


def cmd_custom(args) -> int:
    sa = Path(args.sa) if args.sa else None
    nazario = [Path(p) for p in (args.nazario or [])]
    sample_spec = _parse_sample_arg(args.sample)
    items = _gather(sa, nazario, _opt_path(args.phishing_pot), _opt_path(args.champa))
    if not items:
        log.error("No corpus items found.")
        return 2
    sample = deterministic_sample(items, sample_spec)
    log.info("Custom sample: %d items", len(sample))
    output_csv = Path(args.output) if args.output else PROJECT_ROOT / "results/custom.csv"
    json_dir = PROJECT_ROOT / "results/per_email"
    summary = run_corpus(sample, output_csv, json_dir)
    _print_summary(summary, output_csv)
    return 0


def cmd_analyse(args) -> int:
    csv_path = Path(args.csv)
    manual = Path(args.manual) if args.manual else None
    if not csv_path.exists():
        log.error("CSV not found: %s", csv_path)
        return 2
    result = analyse_results(csv_path, manual)
    _print_analysis(result)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="PhishTriage corpus experiment runner")
    sub = ap.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--sa", help="Path to extracted SpamAssassin root.")
    common.add_argument("--nazario", action="append",
                        help="Path to a Nazario mbox (repeatable).")
    common.add_argument("--phishing-pot", dest="phishing_pot",
                        help="Path to a phishing_pot directory tree of .eml files.")
    common.add_argument("--champa",
                        help="Path to the Champa et al. 2024 curated CSV.")
    common.add_argument("--output", "-o", help="Output CSV path.")

    sp = sub.add_parser("pilot", parents=[common],
                        help="20-email balanced pilot run.")
    sp.set_defaults(func=cmd_pilot)

    sf = sub.add_parser("full", parents=[common],
                        help="100-email full run per CA2 protocol.")
    sf.set_defaults(func=cmd_full)

    sc = sub.add_parser("custom", parents=[common],
                        help="Custom sample with explicit --sample bucket=N pairs.")
    sc.add_argument("--sample", action="append", metavar="bucket=N",
                    help="Per-bucket sample size; repeatable.")
    sc.set_defaults(func=cmd_custom)

    sa = sub.add_parser("analyse",
                        help="Analyse an existing CSV; optionally join a manual CSV.")
    sa.add_argument("--csv", required=True, help="Auto-run CSV produced by run_corpus.")
    sa.add_argument("--manual", help="Manual baseline CSV "
                                     "(columns: sha256, manual_verdict, manual_seconds).")
    sa.set_defaults(func=cmd_analyse)

    args = ap.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
