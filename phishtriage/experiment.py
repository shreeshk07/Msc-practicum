"""Stage 6: experiment runner.

Turns the per-email pipeline into a controlled experiment over
labelled corpora. Three parts:

- Corpus loaders (iter_spamassassin, iter_nazario, and the modern-
  corpus loaders) yield CorpusItem records. Items sort by SHA-256 of
  their bytes, so a re-run draws the same deterministic subset.
- run_corpus drives the pipeline over a sample and writes one CSV row
  per email, plus optional per-email JSON.
- analyse_results reads that CSV, joins it to ground-truth labels, and
  computes precision/recall/F1, the confusion matrix, and timing. Given
  a manual-baseline CSV it adds the paired t-test (or Wilcoxon when the
  delta is not normal) and McNemar's test.

No network calls happen during measurement, so the auto-MTT figures do
not pick up network latency that would vary between runs.
"""

from __future__ import annotations

import csv
import hashlib
import json
import mailbox
import random
import re
import statistics
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from pathlib import Path
from typing import Iterator

from phishtriage.auth import check_auth
from phishtriage.indicators import extract_indicators
from phishtriage.parser import parse_bytes
from phishtriage.reporting import render_thehive_case
from phishtriage.scoring import score
from phishtriage.utils import PROJECT_ROOT, load_settings, log, timed


# The pipeline uses two class labels throughout: phishing (positive)
# and benign (negative). This normalises SpamAssassin's 'spam'
# vocabulary and Nazario's 'phishing' vocabulary onto one pair.
LABEL_PHISHING = "phishing"
LABEL_BENIGN = "benign"


@dataclass
class CorpusItem:
    """One labelled email drawn from a corpus."""
    corpus: str           # 'spamassassin' or 'nazario'
    subset: str           # 'easy_ham' / 'spam_2' / 'phishing-2025' / ...
    label: str            # LABEL_PHISHING or LABEL_BENIGN
    raw_bytes: bytes      # the full message bytes
    source_id: str        # corpus-specific stable id
    sha256: str           # of raw_bytes, used for sampling and joins


# Mapping from SpamAssassin subset directory name to the binary label.
_SA_LABELS = {
    "easy_ham":   LABEL_BENIGN,
    "easy_ham_2": LABEL_BENIGN,
    "hard_ham":   LABEL_BENIGN,
    "spam":       LABEL_PHISHING,    # SA's 'spam' is treated as positive
    "spam_2":     LABEL_PHISHING,    # since it includes phishing samples
}


def iter_spamassassin(root: Path) -> Iterator[CorpusItem]:
    """Yield CorpusItems from an extracted SpamAssassin corpus.

    Expects a directory layout where ``<root>/<subset>/`` contains one
    file per email. Subset names not in ``_SA_LABELS`` are skipped with
    a warning so unexpected directories don't silently mislabel data.
    """
    for subset_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        subset = subset_dir.name
        label = _SA_LABELS.get(subset)
        if label is None:
            log.warning("SpamAssassin: skipping unknown subset %r", subset)
            continue
        for email_path in sorted(subset_dir.iterdir()):
            if not email_path.is_file():
                continue
            try:
                raw = email_path.read_bytes()
            except OSError as exc:
                log.warning("Failed to read %s: %s", email_path, exc)
                continue
            yield CorpusItem(
                corpus="spamassassin",
                subset=subset,
                label=label,
                raw_bytes=raw,
                source_id=f"spamassassin/{subset}/{email_path.name}",
                sha256=hashlib.sha256(raw).hexdigest(),
            )


def iter_nazario(mbox_path: Path) -> Iterator[CorpusItem]:
    """Yield CorpusItems from a Nazario-style mbox of phishing emails.

    All Nazario messages are labelled ``phishing``. The subset name
    comes from the mbox filename so that mixing several years in the
    same experiment keeps subsets distinguishable in the analysis CSV.
    """
    if not mbox_path.exists():
        return
    subset = mbox_path.stem
    try:
        box = mailbox.mbox(str(mbox_path))
    except Exception as exc:                            # noqa: BLE001
        log.warning("Failed to open mbox %s: %s", mbox_path, exc)
        return
    try:
        for idx, msg in enumerate(box):
            try:
                raw = bytes(msg)
            except Exception as exc:                    # noqa: BLE001
                log.debug("Skipping malformed Nazario message #%d: %s", idx, exc)
                continue
            sha = hashlib.sha256(raw).hexdigest()
            yield CorpusItem(
                corpus="nazario",
                subset=subset,
                label=LABEL_PHISHING,
                raw_bytes=raw,
                source_id=f"nazario/{subset}/{idx:05d}",
                sha256=sha,
            )
    finally:
        # Releases the mbox file lock the mailbox module takes.
        try:
            box.close()
        except Exception:
            pass


def iter_phishing_pot(root: Path) -> Iterator[CorpusItem]:
    """Yield CorpusItems from a phishing_pot directory tree of .eml files.

    The rf-peixoto/phishing_pot repo is a tree of curated phishing
    .eml files (CC BY-NC 4.0). Every file in the tree is labelled
    ``phishing`` and the sub-folder structure does not represent
    distinct classes (unlike SpamAssassin's easy_ham/spam_2 split),
    so every item is tagged with subset ``"all"``. CLI sample specs
    therefore use ``--sample phishing_pot:all=N``.
    """
    if not root.exists() or not root.is_dir():
        return
    for eml in sorted(root.rglob("*.eml")):
        try:
            raw = eml.read_bytes()
        except OSError as exc:
            log.warning("Failed to read %s: %s", eml, exc)
            continue
        try:
            relative = eml.relative_to(root)
        except ValueError:
            relative = Path(eml.name)
        yield CorpusItem(
            corpus="phishing_pot",
            subset="all",
            label=LABEL_PHISHING,
            raw_bytes=raw,
            source_id=f"phishing_pot/{relative.as_posix()}",
            sha256=hashlib.sha256(raw).hexdigest(),
        )


def iter_champa(csv_path: Path) -> Iterator[CorpusItem]:
    """Yield CorpusItems from the Champa et al. 2024 curated CSV.

    Column lookup is case-insensitive. Recognised columns:
        sender, receiver, date, subject, body, urls, label
    Any of these may be absent (e.g. the Ling.csv inside the Figshare
    article only carries subject/body/label). Whatever is present is
    used to reconstruct a minimal RFC-5322 message in memory so the
    rest of the pipeline (parser, auth, indicators) can consume
    Champa rows the same way it consumes real .eml files.

    The label column is mapped:
        phishing / phish / spam / 1   -> phishing
        legitimate / ham / 0          -> benign
    Rows with any other label are skipped.
    """
    if not csv_path.exists() or not csv_path.is_file():
        return
    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        for idx, row in enumerate(reader):
            # Case-insensitive column lookup. The Champa article ships
            # several CSVs and they don't all use the same casing.
            lc = {(k or "").lower(): v for k, v in row.items()}
            sender = (lc.get("sender") or "").strip()
            recipient = (lc.get("receiver") or "").strip()
            date = (lc.get("date") or "").strip()
            subject = (lc.get("subject") or "").strip()
            body = lc.get("body") or ""
            label_raw = (lc.get("label") or "").strip().lower()

            if label_raw in {"phishing", "phish", "spam", "1"}:
                label = LABEL_PHISHING
                subset = "phishing"
            elif label_raw in {"legitimate", "legit", "ham", "benign", "0"}:
                label = LABEL_BENIGN
                subset = "legitimate"
            else:
                continue

            # Build a small RFC-5322 message. CRLF line endings keep
            # the email stdlib happy on both Windows and Linux.
            header_lines = []
            if sender:
                header_lines.append(f"From: {sender}")
            if recipient:
                header_lines.append(f"To: {recipient}")
            if date:
                header_lines.append(f"Date: {date}")
            if subject:
                header_lines.append(f"Subject: {subject}")
            header_lines.append("MIME-Version: 1.0")
            header_lines.append('Content-Type: text/plain; charset="utf-8"')
            raw_text = "\r\n".join(header_lines) + "\r\n\r\n" + body
            raw = raw_text.encode("utf-8", errors="replace")

            yield CorpusItem(
                corpus="champa",
                subset=subset,
                label=label,
                raw_bytes=raw,
                source_id=f"champa/{subset}/{idx:06d}",
                sha256=hashlib.sha256(raw).hexdigest(),
            )


def collect_corpus(spam_assassin_root: Path | None = None,
                   nazario_mboxes: list[Path] | None = None,
                   phishing_pot_root: Path | None = None,
                   champa_csv: Path | None = None) -> list[CorpusItem]:
    """Load every available CorpusItem into a list.

    Sampling needs all items in hand before it can draw the
    deterministic subset. The combined corpora still fit in memory, so
    there is no streaming sampler.
    """
    items: list[CorpusItem] = []
    if spam_assassin_root and spam_assassin_root.exists():
        items.extend(iter_spamassassin(spam_assassin_root))
    for mbox in (nazario_mboxes or []):
        items.extend(iter_nazario(Path(mbox)))
    if phishing_pot_root and Path(phishing_pot_root).exists():
        items.extend(iter_phishing_pot(Path(phishing_pot_root)))
    if champa_csv and Path(champa_csv).exists():
        items.extend(iter_champa(Path(champa_csv)))
    return items


def deterministic_sample(items: list[CorpusItem],
                         per_subset: dict[str, int]) -> list[CorpusItem]:
    """Take a deterministic subset of items, n per (corpus, subset).

    Items are sorted by SHA-256 of their raw bytes and the first n of
    each (corpus, subset) bucket are taken. This is reproducible across
    re-downloads and does not require persisting a random seed.
    """
    by_bucket: dict[tuple[str, str], list[CorpusItem]] = {}
    for item in items:
        by_bucket.setdefault((item.corpus, item.subset), []).append(item)

    out: list[CorpusItem] = []
    for (corpus, subset), bucket in by_bucket.items():
        n = per_subset.get(f"{corpus}:{subset}", 0)
        if n <= 0:
            continue
        bucket.sort(key=lambda ci: ci.sha256)
        out.extend(bucket[:n])
    return out


@dataclass
class RunSummary:
    """High-level summary of a corpus run."""
    n_processed: int = 0
    n_skipped: int = 0
    counts_by_band: dict[str, int] = field(default_factory=dict)
    counts_by_label: dict[str, int] = field(default_factory=dict)
    elapsed_total: float = 0.0


CSV_COLUMNS = [
    "source_id", "corpus", "subset", "label", "sha256",
    "message_id", "from_domain", "subject",
    "predicted_band", "predicted_score", "fired_rules", "evaluated_rules",
    "t_total", "t_parser", "t_auth", "t_indicators", "t_scoring", "t_reporting",
]


def run_corpus(items: list[CorpusItem],
               output_csv: Path,
               json_dir: Path | None = None,
               settings: dict | None = None) -> RunSummary:
    """Run the pipeline on every item, write per-email CSV rows.

    Parameters
    ----------
    items
        Sample produced by :func:`deterministic_sample` (or any list of
        CorpusItem).
    output_csv
        Destination for the experiment CSV. The directory is created
        if it does not exist. Existing files are overwritten.
    json_dir
        Optional. If supplied, every email's TheHive case JSON is
        written to that directory under its sha256-prefixed filename.
        Useful for spot-checking individual verdicts without reading
        the corpus archives again.
    settings
        Optional pre-loaded settings dict. Loaded from disk if absent.

    Returns
    -------
    RunSummary
        Aggregate counts and total wall-clock elapsed time.
    """
    settings = settings or load_settings()
    summary = RunSummary()

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    if json_dir:
        json_dir.mkdir(parents=True, exist_ok=True)

    with output_csv.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()

        with timed("run_corpus") as t_run:
            for item in items:
                row = _process_one(item, json_dir, settings)
                if row is None:
                    summary.n_skipped += 1
                    continue
                writer.writerow(row)
                summary.n_processed += 1
                summary.counts_by_band[row["predicted_band"]] = (
                    summary.counts_by_band.get(row["predicted_band"], 0) + 1
                )
                summary.counts_by_label[row["label"]] = (
                    summary.counts_by_label.get(row["label"], 0) + 1
                )
        summary.elapsed_total = round(t_run["elapsed_seconds"], 6)

    return summary


def _process_one(item: CorpusItem,
                 json_dir: Path | None,
                 settings: dict) -> dict | None:
    """Run the full pipeline on one CorpusItem and return a CSV row dict.

    Returns ``None`` if processing fails fatally so the caller can
    record a skip. Stage failures are logged but never raised. The
    goal is that one bad email never aborts a 100-email experiment
    run.
    """
    try:
        timings: dict[str, float] = {}

        with timed("p") as t:
            parsed = parse_bytes(item.raw_bytes)
        timings["t_parser"] = t["elapsed_seconds"]

        with timed("a") as t:
            auth = check_auth(parsed.authentication_results, parsed.from_domain)
        timings["t_auth"] = t["elapsed_seconds"]

        with timed("i") as t:
            indicators = extract_indicators(parsed, settings)
        timings["t_indicators"] = t["elapsed_seconds"]

        with timed("s") as t:
            sc = score(parsed, auth, indicators, settings=settings)
        timings["t_scoring"] = t["elapsed_seconds"]

        with timed("r") as t:
            case = render_thehive_case(parsed, auth, indicators, sc, timings)
        timings["t_reporting"] = t["elapsed_seconds"]

        timings["t_total"] = round(sum(timings.values()), 6)

        # Optional per-email JSON dump. Filename uses sha256 prefix for
        # filesystem-safety, then the cleaned message-id for readability.
        if json_dir:
            mid = re.sub(r"[^A-Za-z0-9._-]+", "_", parsed.message_id or "")[:80]
            stem = f"{item.sha256[:12]}_{mid or 'no-mid'}"
            (json_dir / f"{stem}.json").write_text(
                json.dumps(case, indent=2, default=str), encoding="utf-8"
            )

        return {
            "source_id": item.source_id,
            "corpus": item.corpus,
            "subset": item.subset,
            "label": item.label,
            "sha256": item.sha256,
            "message_id": parsed.message_id,
            "from_domain": parsed.from_domain,
            "subject": (parsed.subject or "")[:120],
            "predicted_band": sc.band,
            "predicted_score": sc.score,
            "fired_rules": sc.fired_rules,
            "evaluated_rules": sc.evaluated_rules,
            **{k: f"{v:.6f}" for k, v in timings.items()},
        }
    except Exception as exc:                            # noqa: BLE001
        log.warning("Pipeline failed on %s: %s", item.source_id, exc)
        return None


@dataclass
class AnalysisResult:
    """Aggregate metrics for one experiment run."""
    n: int = 0
    confusion: dict[str, int] = field(default_factory=dict)
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    accuracy: float = 0.0
    timing_seconds: dict[str, float] = field(default_factory=dict)
    by_band: dict[str, dict[str, int]] = field(default_factory=dict)
    paired_test: dict | None = None      # populated when manual CSV given

    def to_dict(self) -> dict:
        return {
            "n": self.n,
            "confusion": self.confusion,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "timing_seconds": {k: round(v, 6) for k, v in self.timing_seconds.items()},
            "by_band": self.by_band,
            "paired_test": self.paired_test,
        }


# Bands considered "phishing predictions" for the binary classification
# metric. MEDIUM is included by default because in a SOC operational
# sense an analyst would still escalate it; sensitivity analysis with
# different thresholds is one of the planned ablations.
DEFAULT_PHISHING_BANDS = {"MEDIUM", "HIGH", "CRITICAL"}


def analyse_results(csv_path: Path,
                    manual_csv: Path | None = None,
                    phishing_bands: set[str] | None = None) -> AnalysisResult:
    """Read an experiment CSV and compute classification + timing metrics.

    Parameters
    ----------
    csv_path
        The CSV produced by :func:`run_corpus`.
    manual_csv
        Optional path to a manual-baseline CSV. Expected columns:
        ``sha256, manual_verdict, manual_seconds`` where
        ``manual_verdict`` is one of {phishing, benign}. When supplied,
        a paired comparison of timing is added to the result.
    phishing_bands
        Override the set of bands counted as positive predictions.
        Defaults to {MEDIUM, HIGH, CRITICAL}.
    """
    bands = set(phishing_bands or DEFAULT_PHISHING_BANDS)
    rows = list(_read_csv(csv_path))
    if not rows:
        return AnalysisResult()

    out = AnalysisResult(n=len(rows))
    confusion = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}

    for r in rows:
        actual_phish = r["label"] == LABEL_PHISHING
        pred_phish = r["predicted_band"] in bands
        if pred_phish and actual_phish:
            confusion["tp"] += 1
        elif pred_phish and not actual_phish:
            confusion["fp"] += 1
        elif not pred_phish and actual_phish:
            confusion["fn"] += 1
        else:
            confusion["tn"] += 1

    out.confusion = confusion
    tp, tn, fp, fn = (confusion[k] for k in ("tp", "tn", "fp", "fn"))
    out.precision = tp / (tp + fp) if (tp + fp) else 0.0
    out.recall    = tp / (tp + fn) if (tp + fn) else 0.0
    out.f1 = (2 * out.precision * out.recall /
              (out.precision + out.recall)) if (out.precision + out.recall) else 0.0
    out.accuracy = (tp + tn) / len(rows) if rows else 0.0

    # Timing summary
    totals = [_f(r.get("t_total")) for r in rows]
    if totals:
        out.timing_seconds = {
            "min":    min(totals),
            "max":    max(totals),
            "mean":   statistics.fmean(totals),
            "median": statistics.median(totals),
            "stdev":  statistics.pstdev(totals),
        }

    # Per-band breakdown by ground-truth label
    by_band: dict[str, dict[str, int]] = {}
    for r in rows:
        b = r["predicted_band"]
        by_band.setdefault(b, {}).setdefault(r["label"], 0)
        by_band[b][r["label"]] += 1
    out.by_band = by_band

    # Paired comparison with manual baseline.
    if manual_csv and Path(manual_csv).exists():
        out.paired_test = _paired_with_manual(rows, Path(manual_csv))

    return out


def _read_csv(path: Path) -> Iterator[dict]:
    with Path(path).open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            yield row


def _f(v) -> float:
    """Forgiving float-coerce; returns 0.0 on any failure."""
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


# Bootstrap settings for the time-reduction confidence interval. Fixed
# so the reported interval is reproducible.
_BOOTSTRAP_RESAMPLES = 5000
_BOOTSTRAP_SEED = 42


def _percentile(sorted_values: list[float], pct: float) -> float:
    """Linear-interpolation percentile of an already-sorted list.

    pct is given on a 0 to 100 scale. Matches the common
    ``numpy.percentile`` linear method so the interval is standard.
    """
    if not sorted_values:
        raise ValueError("percentile of empty sequence")
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    low = int(rank)
    high = min(low + 1, len(sorted_values) - 1)
    frac = rank - low
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * frac


def _cohen_kappa(rater_a: list[bool], rater_b: list[bool]) -> float | None:
    """Cohen's kappa for two binary raters over the same items.

    Computed directly from the 2x2 agreement counts:
    kappa = (po - pe) / (1 - pe). Returns None when there are no items
    or when expected agreement pe equals 1 (one rater is constant in a
    way that makes kappa undefined).
    """
    n = len(rater_a)
    if n == 0 or n != len(rater_b):
        return None
    po = sum(1 for a, b in zip(rater_a, rater_b) if a == b) / n
    a_pos = sum(1 for a in rater_a if a) / n
    b_pos = sum(1 for b in rater_b if b) / n
    pe = a_pos * b_pos + (1 - a_pos) * (1 - b_pos)
    if pe >= 1.0:
        return None
    return (po - pe) / (1 - pe)


def _paired_with_manual(auto_rows: list[dict], manual_csv: Path) -> dict:
    """Run the paired-timing comparison on the joined rows.

    Each manual row is joined to its automated row on ``sha256``, so a
    manual CSV holding several participants (multiple rows per email)
    contributes every row to the pairing; nothing is overwritten or
    dropped. Falls back to a simple summary when SciPy is not
    available so the runner remains usable in a minimal environment.
    """
    auto_by_sha = {r["sha256"]: r for r in auto_rows}
    # Each pair is (auto_seconds, manual_seconds, auto_phish, manual_phish,
    # truth_phish, pseudonym). The pseudonym carries the participant
    # identity through for the per-participant kappa and means; it
    # defaults to ALL when the manual CSV has no pseudonym column.
    pairs: list[tuple[float, float, bool, bool, bool, str]] = []
    for m in _read_csv(manual_csv):
        r = auto_by_sha.get(m.get("sha256", ""))
        if r is None:
            continue
        try:
            t_auto = float(r["t_total"])
            t_man = float(m["manual_seconds"])
        except (KeyError, ValueError):
            continue
        pred_phish_auto = r["predicted_band"] in DEFAULT_PHISHING_BANDS
        pred_phish_man = (m.get("manual_verdict", "").lower() == LABEL_PHISHING)
        truth_phish = (r.get("label", "").lower() == LABEL_PHISHING)
        pseudonym = (m.get("pseudonym", "") or "ALL").strip() or "ALL"
        pairs.append((t_auto, t_man, pred_phish_auto, pred_phish_man,
                      truth_phish, pseudonym))

    if not pairs:
        log.warning(
            "No manual rows joined to any automated row on sha256. "
            "Check the manual CSV format (expected columns: sha256, "
            "manual_verdict, manual_seconds)."
        )
        return {"note": "no joinable rows between auto and manual CSVs"}

    auto_times = [p[0] for p in pairs]
    man_times = [p[1] for p in pairs]
    deltas = [m - a for a, m, _, _, _, _ in pairs]
    auto_mean = statistics.fmean(auto_times)
    man_mean = statistics.fmean(man_times)

    summary: dict = {
        "n_pairs": len(pairs),
        "auto_mean_seconds":   round(auto_mean, 6),
        "auto_median_seconds": round(statistics.median(auto_times), 6),
        "manual_mean_seconds":   round(man_mean, 6),
        "manual_median_seconds": round(statistics.median(man_times), 6),
        "mean_reduction_pct": round(
            100.0 * (man_mean - auto_mean) / man_mean, 2
        ) if man_mean > 0 else 0.0,
        "cohen_d": None,
        "mcnemar_b": 0,
        "mcnemar_c": 0,
        "mcnemar_p": 1.0,
    }

    # Bootstrap 95% confidence interval on the time reduction percentage.
    # Percentile bootstrap over the paired (auto, manual) seconds, with a
    # fixed seed so the interval is reproducible across runs.
    if len(pairs) >= 2:
        rng = random.Random(_BOOTSTRAP_SEED)
        n = len(pairs)
        reductions: list[float] = []
        for _ in range(_BOOTSTRAP_RESAMPLES):
            sample = [pairs[rng.randrange(n)] for _ in range(n)]
            a_mean = statistics.fmean([s[0] for s in sample])
            m_mean = statistics.fmean([s[1] for s in sample])
            if m_mean > 0:
                reductions.append(100.0 * (m_mean - a_mean) / m_mean)
        if reductions:
            reductions.sort()
            lo = _percentile(reductions, 2.5)
            hi = _percentile(reductions, 97.5)
            summary["bootstrap_ci_low"] = round(lo, 4)
            summary["bootstrap_ci_high"] = round(hi, 4)
        else:
            summary["bootstrap_ci_low"] = None
            summary["bootstrap_ci_high"] = None
    else:
        summary["bootstrap_ci_low"] = None
        summary["bootstrap_ci_high"] = None
    summary["bootstrap_resamples"] = _BOOTSTRAP_RESAMPLES
    summary["bootstrap_seed"] = _BOOTSTRAP_SEED

    # Manual-condition precision, recall and F1, pooled across all
    # participants. Manual verdict versus the ground-truth label.
    m_tp = sum(1 for _, _, _, pm, truth, _ in pairs if pm and truth)
    m_fp = sum(1 for _, _, _, pm, truth, _ in pairs if pm and not truth)
    m_fn = sum(1 for _, _, _, pm, truth, _ in pairs if not pm and truth)
    summary["manual_precision"] = (
        round(m_tp / (m_tp + m_fp), 6) if (m_tp + m_fp) else None
    )
    summary["manual_recall"] = (
        round(m_tp / (m_tp + m_fn), 6) if (m_tp + m_fn) else None
    )
    if summary["manual_precision"] and summary["manual_recall"]:
        mp, mr = summary["manual_precision"], summary["manual_recall"]
        summary["manual_f1"] = round(2 * mp * mr / (mp + mr), 6)
    else:
        summary["manual_f1"] = None

    # Per-participant kappa and per-participant means. Group the pairs by
    # pseudonym; kappa compares each participant's verdicts against the
    # automated band decision over the emails they triaged.
    by_pseudonym: dict[str, list[tuple]] = {}
    for pair in pairs:
        by_pseudonym.setdefault(pair[5], []).append(pair)

    kappa_per_participant: dict[str, float | None] = {}
    kappa_gt_per_participant: dict[str, float | None] = {}
    per_participant: dict[str, dict] = {}
    for name, group in by_pseudonym.items():
        kappa_per_participant[name] = _cohen_kappa(
            [g[3] for g in group],   # manual phishing decision
            [g[2] for g in group],   # automated phishing decision
        )
        kappa_gt_per_participant[name] = _cohen_kappa(
            [g[3] for g in group],   # manual phishing decision
            [g[4] for g in group],   # ground-truth phishing label
        )
        g_man = [g[1] for g in group]
        g_man_mean = statistics.fmean(g_man)
        per_participant[name] = {
            "n_pairs": len(group),
            "manual_mean_seconds": round(g_man_mean, 6),
            "reduction_pct": round(
                100.0 * (g_man_mean - auto_mean) / g_man_mean, 2
            ) if g_man_mean > 0 else 0.0,
        }
    summary["kappa_per_participant"] = kappa_per_participant
    kappa_vals = [k for k in kappa_per_participant.values() if k is not None]
    if kappa_vals:
        summary["kappa_mean"] = round(statistics.fmean(kappa_vals), 6)
        summary["kappa_min"] = round(min(kappa_vals), 6)
        summary["kappa_max"] = round(max(kappa_vals), 6)
    else:
        summary["kappa_mean"] = None
        summary["kappa_min"] = None
        summary["kappa_max"] = None

    # Same per-participant kappa, but against the ground-truth label
    # instead of the engine's verdict. Kept under separate kappa_gt_*
    # keys so it is never confused with the engine-agreement figures
    # above.
    summary["kappa_gt_per_participant"] = kappa_gt_per_participant
    kappa_gt_vals = [k for k in kappa_gt_per_participant.values() if k is not None]
    if kappa_gt_vals:
        summary["kappa_gt_mean"] = round(statistics.fmean(kappa_gt_vals), 6)
        summary["kappa_gt_min"] = round(min(kappa_gt_vals), 6)
        summary["kappa_gt_max"] = round(max(kappa_gt_vals), 6)
    else:
        summary["kappa_gt_mean"] = None
        summary["kappa_gt_min"] = None
        summary["kappa_gt_max"] = None

    summary["per_participant"] = per_participant

    # Statistical tests (paired t-test, McNemar's). Best-effort.
    try:
        from scipy import stats as _stats
        # Shapiro-Wilk on the deltas to choose between t-test and Wilcoxon
        if len(deltas) >= 8:
            _, p_shapiro = _stats.shapiro(deltas)
            summary["shapiro_p"] = round(float(p_shapiro), 6)
            if p_shapiro >= 0.05:
                t_stat, p_val = _stats.ttest_rel(auto_times, man_times)
                summary["test"] = "paired_t"
            else:
                t_stat, p_val = _stats.wilcoxon(auto_times, man_times)
                summary["test"] = "wilcoxon"
            summary["statistic"] = round(float(t_stat), 6)
            summary["p_value"]   = round(float(p_val), 6)
    except ImportError:
        summary["note"] = "scipy not installed; install for paired tests"

    # Cohen's d for paired samples: the mean of the per-email
    # differences (manual minus automated) over the standard
    # deviation of those differences.
    if len(deltas) >= 2:
        sd = statistics.stdev(deltas)
        summary["cohen_d"] = (
            round(statistics.fmean(deltas) / sd, 6) if sd > 0 else None
        )

    # McNemar's exact test on decision correctness. A decision is
    # correct when the phishing-or-not call matches the ground-truth
    # label carried on the auto row. Only the discordant pairs feed
    # the test: b = auto correct and manual wrong, c = auto wrong
    # and manual correct.
    b = c = 0
    for _, _, pa, pm, truth, _ in pairs:
        auto_ok = (pa == truth)
        man_ok = (pm == truth)
        if auto_ok and not man_ok:
            b += 1
        elif man_ok and not auto_ok:
            c += 1
    summary["mcnemar_b"] = b
    summary["mcnemar_c"] = c
    if b + c > 0:
        try:
            from scipy import stats as _stats
            res = _stats.binomtest(min(b, c), b + c, 0.5,
                                   alternative="two-sided")
            summary["mcnemar_p"] = round(float(res.pvalue), 6)
        except ImportError:
            from math import comb

            n = b + c
            k = min(b, c)
            tail = sum(comb(n, i) for i in range(0, k + 1)) / (2 ** n)
            p_val = min(1.0, 2.0 * tail)
            summary["mcnemar_p"] = round(float(p_val), 6)

    return summary
