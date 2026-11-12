"""Tests for phishtriage.experiment."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from phishtriage.experiment import (
    LABEL_BENIGN,
    LABEL_PHISHING,
    AnalysisResult,
    CorpusItem,
    analyse_results,
    deterministic_sample,
    iter_champa,
    iter_phishing_pot,
    iter_spamassassin,
    run_corpus,
)


FIXTURES = Path(__file__).parent / "fixtures"


# CorpusItem and sampling

def _items_with_subset(subset: str, label: str, count: int) -> list[CorpusItem]:
    """Build N stub CorpusItems with deterministic SHA-256 ordering."""
    out = []
    for i in range(count):
        # Vary the bytes so SHA differs deterministically
        raw = f"sha-bucket-{i:04d}".encode()
        sha = __import__("hashlib").sha256(raw).hexdigest()
        out.append(CorpusItem(
            corpus="spamassassin", subset=subset, label=label,
            raw_bytes=raw, source_id=f"{subset}/{i}", sha256=sha,
        ))
    return out


def test_deterministic_sample_takes_first_n_per_bucket():
    items = (_items_with_subset("easy_ham", LABEL_BENIGN, 10) +
             _items_with_subset("spam_2", LABEL_PHISHING, 10))
    sample = deterministic_sample(items, {
        "spamassassin:easy_ham": 3,
        "spamassassin:spam_2": 5,
    })
    assert len(sample) == 8
    by_subset = {}
    for s in sample:
        by_subset.setdefault(s.subset, 0)
        by_subset[s.subset] += 1
    assert by_subset == {"easy_ham": 3, "spam_2": 5}


def test_deterministic_sample_repeatable():
    items = _items_with_subset("easy_ham", LABEL_BENIGN, 50)
    spec = {"spamassassin:easy_ham": 5}
    s1 = deterministic_sample(items, spec)
    s2 = deterministic_sample(items, spec)
    assert [x.sha256 for x in s1] == [x.sha256 for x in s2]


def test_deterministic_sample_zero_n_drops_bucket():
    items = _items_with_subset("easy_ham", LABEL_BENIGN, 3)
    sample = deterministic_sample(items, {"spamassassin:easy_ham": 0})
    assert sample == []


def test_deterministic_sample_unknown_bucket_ignored():
    items = _items_with_subset("easy_ham", LABEL_BENIGN, 3)
    sample = deterministic_sample(items, {"spamassassin:does_not_exist": 5})
    assert sample == []


# SpamAssassin loader

def test_iter_spamassassin_skips_unknown_subset(tmp_path):
    # Build a tiny synthetic corpus: known subset + unknown subset.
    (tmp_path / "easy_ham").mkdir()
    (tmp_path / "easy_ham" / "0001").write_bytes(b"From: a@example.com\n\nbody1")
    (tmp_path / "weird_thing").mkdir()
    (tmp_path / "weird_thing" / "0001").write_bytes(b"From: b@example.com\n\nbody2")

    items = list(iter_spamassassin(tmp_path))
    # Only the known subset should be loaded.
    assert len(items) == 1
    assert items[0].subset == "easy_ham"
    assert items[0].label == LABEL_BENIGN


def test_iter_spamassassin_assigns_labels_correctly(tmp_path):
    for sub in ("easy_ham", "hard_ham", "spam", "spam_2"):
        (tmp_path / sub).mkdir()
        (tmp_path / sub / "msg").write_bytes(b"From: x@y\n\nx")
    items = sorted(iter_spamassassin(tmp_path), key=lambda i: i.subset)
    by_subset = {i.subset: i.label for i in items}
    assert by_subset == {
        "easy_ham": LABEL_BENIGN,
        "hard_ham": LABEL_BENIGN,
        "spam":     LABEL_PHISHING,
        "spam_2":   LABEL_PHISHING,
    }


# Batch runner

def _two_items_from_fixtures() -> list[CorpusItem]:
    """Build a 2-item corpus from the existing test fixtures."""
    import hashlib
    benign = (FIXTURES / "sample_benign.eml").read_bytes()
    phish = (FIXTURES / "sample_phishing.eml").read_bytes()
    return [
        CorpusItem(corpus="test", subset="benign", label=LABEL_BENIGN,
                   raw_bytes=benign, source_id="test/benign",
                   sha256=hashlib.sha256(benign).hexdigest()),
        CorpusItem(corpus="test", subset="phishing", label=LABEL_PHISHING,
                   raw_bytes=phish, source_id="test/phishing",
                   sha256=hashlib.sha256(phish).hexdigest()),
    ]


def test_run_corpus_writes_csv_with_expected_columns(tmp_path):
    items = _two_items_from_fixtures()
    csv_path = tmp_path / "out.csv"
    summary = run_corpus(items, csv_path)
    assert summary.n_processed == 2
    assert summary.n_skipped == 0
    rows = list(csv.DictReader(csv_path.open()))
    assert len(rows) == 2
    expected = {"source_id", "corpus", "subset", "label", "sha256",
                "predicted_band", "predicted_score", "fired_rules",
                "t_total", "t_parser", "t_auth", "t_indicators",
                "t_scoring", "t_reporting"}
    assert expected.issubset(rows[0].keys())


def test_run_corpus_assigns_correct_bands_to_fixtures(tmp_path):
    items = _two_items_from_fixtures()
    csv_path = tmp_path / "out.csv"
    run_corpus(items, csv_path)
    rows = {r["label"]: r for r in csv.DictReader(csv_path.open())}
    assert rows[LABEL_BENIGN]["predicted_band"] == "LOW"
    assert rows[LABEL_PHISHING]["predicted_band"] in {"HIGH", "CRITICAL"}


def test_run_corpus_with_json_dir_writes_per_email_files(tmp_path):
    items = _two_items_from_fixtures()
    csv_path = tmp_path / "out.csv"
    json_dir = tmp_path / "per_email"
    run_corpus(items, csv_path, json_dir=json_dir)
    json_files = list(json_dir.glob("*.json"))
    assert len(json_files) == 2


# Analysis

def test_analyse_results_basic_metrics(tmp_path):
    items = _two_items_from_fixtures()
    csv_path = tmp_path / "out.csv"
    run_corpus(items, csv_path)

    res = analyse_results(csv_path)
    assert res.n == 2
    # A 2-email perfect run gives 1 TP, 1 TN, 0 FP, 0 FN.
    assert res.confusion["tp"] == 1
    assert res.confusion["tn"] == 1
    assert res.confusion["fp"] == 0
    assert res.confusion["fn"] == 0
    assert res.precision == 1.0
    assert res.recall == 1.0
    assert res.f1 == 1.0
    assert "mean" in res.timing_seconds


def test_analyse_results_handles_empty_csv(tmp_path):
    csv_path = tmp_path / "empty.csv"
    csv_path.write_text("source_id,label,predicted_band,t_total\n")
    res = analyse_results(csv_path)
    assert isinstance(res, AnalysisResult)
    assert res.n == 0


def test_analyse_results_to_dict_serialisable(tmp_path):
    items = _two_items_from_fixtures()
    csv_path = tmp_path / "out.csv"
    run_corpus(items, csv_path)
    res = analyse_results(csv_path)
    import json
    blob = json.dumps(res.to_dict())
    assert "precision" in blob


# Modern-corpora loaders: phishing_pot and Champa et al.

def test_iter_phishing_pot_yields_labelled_phishing(tmp_path):
    # Build a tiny synthetic phishing_pot tree with two sub-folders.
    sample_2024 = tmp_path / "sample-2024"
    sample_2024.mkdir()
    (sample_2024 / "0001.eml").write_bytes(
        b"From: attacker@bad.tld\r\nSubject: Verify your mailbox\r\n\r\nbody1"
    )
    (sample_2024 / "0002.eml").write_bytes(
        b"From: x@y.tld\r\nSubject: Account requires update\r\n\r\nbody2"
    )
    sample_2025 = tmp_path / "sample-2025"
    sample_2025.mkdir()
    (sample_2025 / "0003.eml").write_bytes(
        b"From: a@b.tld\r\nSubject: Mailbox full\r\n\r\nbody3"
    )

    items = list(iter_phishing_pot(tmp_path))
    assert len(items) == 3
    # Every item is phishing.
    assert {i.label for i in items} == {LABEL_PHISHING}
    # All items use the single subset "all" so CLI sample specs can
    # use --sample phishing_pot:all=N rather than per-subfolder keys.
    assert {i.subset for i in items} == {"all"}
    # Source ids are deterministic and contain the relative path
    # (the sub-folder structure is still visible there for traceability).
    assert all(i.source_id.startswith("phishing_pot/") for i in items)
    assert any("sample-2024" in i.source_id for i in items)
    assert any("sample-2025" in i.source_id for i in items)


def test_iter_champa_reconstructs_minimal_eml(tmp_path):
    csv_path = tmp_path / "champa.csv"
    csv_path.write_text(
        "Sender,Receiver,Date,Subject,Body,URLs,Label\n"
        '"attacker@bad.tld","victim@example.com","Mon, 12 Feb 2024 09:00:00 +0000",'
        '"Mailbox is full","Please verify your mailbox now.",'
        '"https://bad.tld/verify","phishing"\n',
        encoding="utf-8",
    )
    items = list(iter_champa(csv_path))
    assert len(items) == 1
    raw = items[0].raw_bytes.decode("utf-8", errors="replace")
    # The reconstructed message has the standard RFC-5322 headers.
    assert "From: attacker@bad.tld" in raw
    assert "To: victim@example.com" in raw
    assert "Subject: Mailbox is full" in raw
    assert "Date: Mon, 12 Feb 2024 09:00:00 +0000" in raw
    # And the body lives below the header/body separator.
    assert "Please verify your mailbox now." in raw
    # Label maps to LABEL_PHISHING with subset "phishing".
    assert items[0].label == LABEL_PHISHING
    assert items[0].subset == "phishing"


def test_iter_champa_uses_label_column(tmp_path):
    csv_path = tmp_path / "champa.csv"
    csv_path.write_text(
        "Sender,Receiver,Date,Subject,Body,URLs,Label\n"
        '"a@x.tld","b@y.tld","","Phish 1","body","","phishing"\n'
        '"c@x.tld","d@y.tld","","Phish 2","body","","spam"\n'
        '"e@x.tld","f@y.tld","","Ham 1","body","","legitimate"\n'
        '"g@x.tld","h@y.tld","","Ham 2","body","","ham"\n'
        '"i@x.tld","j@y.tld","","Numeric phish","body","","1"\n'
        '"k@x.tld","l@y.tld","","Numeric ham","body","","0"\n'
        '"m@x.tld","n@y.tld","","Unknown","body","","weird-label"\n',
        encoding="utf-8",
    )
    items = list(iter_champa(csv_path))
    labels = [i.label for i in items]
    # Unknown labels are dropped, everything else is mapped to one of
    # the two canonical labels.
    assert labels.count(LABEL_PHISHING) == 3   # "phishing", "spam", "1"
    assert labels.count(LABEL_BENIGN) == 3     # "legitimate", "ham", "0"
    assert len(items) == 6
    # Subsets match the binary label so CLI sample specs can target
    # them: --sample champa:phishing=N, --sample champa:legitimate=N.
    assert {i.subset for i in items} == {"phishing", "legitimate"}


# Paired manual analysis: McNemar's exact test

def test_paired_manual_mcnemar_exact(tmp_path):
    """McNemar's exact test on a synthetic b=2, c=8 discordant split.

    Ten emails, all phishing by ground truth. In two of them the
    automated band is positive (HIGH) while the manual verdict is
    wrong (benign): b = 2. In the other eight the automated band is
    LOW (wrong) while the manual verdict is phishing (correct):
    c = 8. The exact binomial p for min(2, 8) successes in 10 trials
    at 0.5 is 112/1024 = 0.109375.
    """
    from phishtriage.experiment import _paired_with_manual

    man_secs = [30.5, 41.2, 28.9, 55.0, 33.3, 47.1, 38.8, 29.4, 50.6, 36.7]
    auto_secs = [0.031, 0.042, 0.027, 0.055, 0.033, 0.047, 0.038, 0.029, 0.051, 0.036]

    auto_rows = []
    manual_lines = ["sha256,manual_seconds,manual_verdict"]
    for i in range(10):
        sha = f"{i:064x}"
        if i < 2:
            band, verdict = "HIGH", "benign"      # auto correct, manual wrong
        else:
            band, verdict = "LOW", "phishing"     # auto wrong, manual correct
        auto_rows.append({
            "sha256": sha,
            "t_total": str(auto_secs[i]),
            "predicted_band": band,
            "label": "phishing",
        })
        manual_lines.append(f"{sha},{man_secs[i]},{verdict}")

    manual_csv = tmp_path / "manual.csv"
    manual_csv.write_text("\n".join(manual_lines) + "\n", encoding="utf-8")

    summary = _paired_with_manual(auto_rows, manual_csv)

    assert summary["n_pairs"] == 10
    assert summary["mcnemar_b"] == 2
    assert summary["mcnemar_c"] == 8
    assert summary["mcnemar_p"] == pytest.approx(0.109375, abs=1e-6)


def test_paired_manual_two_participants(tmp_path):
    """A manual CSV holding two participants keeps every row.

    Three emails, all phishing by ground truth, with automated bands
    LOW, LOW, HIGH. Participant A answers phishing on all three and
    participant B answers benign on all three, so the six manual rows
    give c = 2 from A (auto wrong, manual correct on the LOW emails)
    and b = 1 from B (auto correct, manual wrong on the HIGH email).
    A join that kept one row per email would lose a participant and
    report three pairs.
    """
    from phishtriage.experiment import _paired_with_manual

    bands = ["LOW", "LOW", "HIGH"]
    autos = [0.1, 0.2, 0.3]
    auto_rows = []
    for i in range(3):
        auto_rows.append({
            "sha256": f"{i:064x}",
            "t_total": str(autos[i]),
            "predicted_band": bands[i],
            "label": "phishing",
        })

    lines = ["sha256,manual_seconds,manual_verdict"]
    for i, t in enumerate([10.0, 20.0, 30.0]):       # participant A
        lines.append(f"{i:064x},{t},phishing")
    for i, t in enumerate([40.0, 50.0, 60.0]):       # participant B
        lines.append(f"{i:064x},{t},benign")
    manual_csv = tmp_path / "manual.csv"
    manual_csv.write_text("\n".join(lines) + "\n", encoding="utf-8")

    summary = _paired_with_manual(auto_rows, manual_csv)

    assert summary["n_pairs"] == 6
    assert summary["manual_mean_seconds"] == pytest.approx(35.0)
    assert summary["auto_mean_seconds"] == pytest.approx(0.2)
    assert summary["mcnemar_b"] == 1
    assert summary["mcnemar_c"] == 2


def test_paired_manual_cohens_d(tmp_path):
    """Cohen's d on known per-email differences.

    Manual minus automated deltas are 1, 2, 3, 4 seconds: mean 2.5,
    sample standard deviation sqrt(5/3), so d = 2.5 / 1.290994 =
    1.936 to three decimal places.
    """
    from phishtriage.experiment import _paired_with_manual

    man_secs = [2.0, 3.0, 4.0, 5.0]
    auto_rows = []
    lines = ["sha256,manual_seconds,manual_verdict"]
    for i, t in enumerate(man_secs):
        sha = f"{i + 100:064x}"
        auto_rows.append({
            "sha256": sha,
            "t_total": "1.0",
            "predicted_band": "LOW",
            "label": "phishing",
        })
        lines.append(f"{sha},{t},phishing")
    manual_csv = tmp_path / "manual.csv"
    manual_csv.write_text("\n".join(lines) + "\n", encoding="utf-8")

    summary = _paired_with_manual(auto_rows, manual_csv)

    assert summary["cohen_d"] == pytest.approx(1.936, abs=1e-3)


def _write_manual(tmp_path, rows, name="manual.csv", with_pseudonym=True):
    """Helper: write a manual CSV and return matching auto rows.

    rows is a list of (sha, manual_seconds, manual_verdict, label,
    predicted_band, pseudonym). The auto side carries t_total 1.0.
    """
    header = "sha256,manual_seconds,manual_verdict"
    if with_pseudonym:
        header += ",pseudonym"
    lines = [header]
    auto_by_sha = {}
    for sha, t_man, verdict, label, band, pseudo in rows:
        auto_by_sha[sha] = {
            "sha256": sha, "t_total": "1.0",
            "predicted_band": band, "label": label,
        }
        line = f"{sha},{t_man},{verdict}"
        if with_pseudonym:
            line += f",{pseudo}"
        lines.append(line)
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return list(auto_by_sha.values()), path


def test_paired_manual_bootstrap_ci(tmp_path):
    """Bootstrap CI brackets the point estimate and is seed-stable.

    Four pairs with manual times far above automated times, so the
    reduction percentage is high and positive. The 95 percent interval
    must contain the point estimate, and two runs must be identical
    because the resampling seed is fixed.
    """
    from phishtriage.experiment import _paired_with_manual

    rows = [
        (f"{i:064x}", t, "phishing", "phishing", "LOW", "P1")
        for i, t in enumerate([40.0, 55.0, 48.0, 60.0])
    ]
    auto_rows, manual_csv = _write_manual(tmp_path, rows)

    s1 = _paired_with_manual(auto_rows, manual_csv)
    s2 = _paired_with_manual(auto_rows, manual_csv)

    assert s1["bootstrap_resamples"] == 5000
    assert s1["bootstrap_seed"] == 42
    assert s1["bootstrap_ci_low"] <= s1["mean_reduction_pct"] <= s1["bootstrap_ci_high"]
    # Seed determinism: identical interval across two runs.
    assert s1["bootstrap_ci_low"] == s2["bootstrap_ci_low"]
    assert s1["bootstrap_ci_high"] == s2["bootstrap_ci_high"]


def test_paired_manual_kappa_per_participant(tmp_path):
    """Per-participant Cohen's kappa against the automated band.

    Four emails, ground-truth and automated bands fixed so the
    automated phishing decision is [True, True, False, False].
    Participant A verdicts are [phishing, phishing, benign, benign]
    which agrees perfectly: kappa = 1.0. Participant B verdicts are
    [phishing, benign, phishing, benign]: agree on 2 of 4 (po = 0.5),
    each rater is positive on 2 of 4 so pe = 0.5, giving kappa = 0.0.
    """
    from phishtriage.experiment import _paired_with_manual

    bands = ["CRITICAL", "CRITICAL", "LOW", "LOW"]   # auto phish T,T,F,F
    a_verd = ["phishing", "phishing", "benign", "benign"]
    b_verd = ["phishing", "benign", "phishing", "benign"]
    rows = []
    for i in range(4):
        sha = f"{i:064x}"
        rows.append((sha, 10.0 + i, a_verd[i], "phishing", bands[i], "A"))
    for i in range(4):
        sha = f"{i:064x}"
        rows.append((sha, 20.0 + i, b_verd[i], "phishing", bands[i], "B"))
    auto_rows, manual_csv = _write_manual(tmp_path, rows)

    summary = _paired_with_manual(auto_rows, manual_csv)

    assert summary["kappa_per_participant"]["A"] == pytest.approx(1.0, abs=1e-4)
    assert summary["kappa_per_participant"]["B"] == pytest.approx(0.0, abs=1e-4)
    assert summary["kappa_mean"] == pytest.approx(0.5, abs=1e-4)
    assert summary["kappa_min"] == pytest.approx(0.0, abs=1e-4)
    assert summary["kappa_max"] == pytest.approx(1.0, abs=1e-4)


def test_paired_manual_kappa_gt_perfect_agreement(tmp_path):
    """Per-participant kappa against ground truth, not the engine band.

    Two participants, four emails each, every manual verdict matches
    the ground-truth label exactly, so kappa_gt is 1.0 for both and
    for the mean/min/max. The automated band is set to disagree with
    both the manual verdict and the truth on every row, so a passing
    result here proves kappa_gt is computed against truth and not
    against the engine's band (which is what kappa_per_participant
    already covers).
    """
    from phishtriage.experiment import _paired_with_manual

    truth = ["phishing", "phishing", "benign", "benign"]
    # Band disagrees with truth on every row (LOW for phishing rows,
    # CRITICAL for benign rows), so an implementation that accidentally
    # reused the engine comparison would not score 1.0 here.
    bands = ["LOW", "LOW", "CRITICAL", "CRITICAL"]
    rows = []
    for pseudo in ("A", "B"):
        for i in range(4):
            sha = f"{pseudo}{i:063x}"
            rows.append((sha, 10.0 + i, truth[i], truth[i], bands[i], pseudo))
    auto_rows, manual_csv = _write_manual(tmp_path, rows)

    summary = _paired_with_manual(auto_rows, manual_csv)

    assert summary["kappa_gt_per_participant"]["A"] == pytest.approx(1.0, abs=1e-4)
    assert summary["kappa_gt_per_participant"]["B"] == pytest.approx(1.0, abs=1e-4)
    assert summary["kappa_gt_mean"] == pytest.approx(1.0, abs=1e-4)
    assert summary["kappa_gt_min"] == pytest.approx(1.0, abs=1e-4)
    assert summary["kappa_gt_max"] == pytest.approx(1.0, abs=1e-4)
    # The existing engine-kappa keys are untouched by this change: the
    # band disagrees with the manual verdict on every row, so kappa
    # against the engine is 0.0, not 1.0.
    assert summary["kappa_per_participant"]["A"] == pytest.approx(-1.0, abs=1e-4)


def test_cohen_kappa_pooled_ground_truth_known_case():
    """_cohen_kappa on a known pooled confusion matrix.

    TP 97, FP 10, FN 3, TN 90 (n=200) is the reported pooled kappa
    between participant verdicts and ground truth across the full
    10-participant study. po = 187/200 = 0.935, manual positive rate
    0.535, truth positive rate 0.5, pe = 0.5, giving
    kappa = (0.935 - 0.5) / (1 - 0.5) = 0.870 exactly. This is the
    same helper _paired_with_manual calls for kappa_gt, exercised
    directly against a hand-checked figure instead of a synthetic CSV.
    """
    from phishtriage.experiment import _cohen_kappa

    manual = (
        [True] * 97    # TP: manual phishing, truth phishing
        + [True] * 10  # FP: manual phishing, truth benign
        + [False] * 3  # FN: manual benign, truth phishing
        + [False] * 90 # TN: manual benign, truth benign
    )
    truth = (
        [True] * 97
        + [False] * 10
        + [True] * 3
        + [False] * 90
    )

    kappa = _cohen_kappa(manual, truth)

    assert kappa == pytest.approx(0.870, abs=1e-3)


def test_paired_manual_per_participant_means(tmp_path):
    """Per-participant block reports each participant's mean and count.

    Participant A times average 15.0, participant B times average 25.0,
    over two emails each. Reduction is against the pooled automated
    mean of 1.0 second.
    """
    from phishtriage.experiment import _paired_with_manual

    rows = [
        ("0" * 63 + "0", 10.0, "phishing", "phishing", "LOW", "A"),
        ("0" * 63 + "1", 20.0, "phishing", "phishing", "LOW", "A"),
        ("0" * 63 + "2", 20.0, "benign", "benign", "LOW", "B"),
        ("0" * 63 + "3", 30.0, "benign", "benign", "LOW", "B"),
    ]
    auto_rows, manual_csv = _write_manual(tmp_path, rows)

    summary = _paired_with_manual(auto_rows, manual_csv)
    pp = summary["per_participant"]

    assert pp["A"]["n_pairs"] == 2
    assert pp["A"]["manual_mean_seconds"] == pytest.approx(15.0)
    assert pp["B"]["n_pairs"] == 2
    assert pp["B"]["manual_mean_seconds"] == pytest.approx(25.0)
    # Reduction against pooled auto mean 1.0: (15 - 1) / 15 * 100 = 93.33.
    assert pp["A"]["reduction_pct"] == pytest.approx(93.33, abs=1e-2)


def test_paired_manual_condition_prf(tmp_path):
    """Manual-condition precision, recall and F1 from known counts.

    Five phishing and five benign emails. The manual verdicts give
    tp = 4, fp = 1, fn = 1: precision 0.8, recall 0.8, F1 0.8.

    The manual times vary per row. Only the verdict and label decide
    the three figures asserted below, but an identical time on every
    row would make the paired differences constant, and Shapiro-Wilk
    cannot work on a zero-variance sample. Real sessions never produce
    identical times, so varied values keep the fixture representative.
    """
    from phishtriage.experiment import _paired_with_manual

    # Times differ per row; the auto side is fixed at 1.0 second.
    secs = [10.0, 12.5, 11.0, 13.5, 9.5, 14.0, 10.5, 12.0, 11.5, 13.0]
    rows = []
    # 4 true positives: phishing labelled phishing.
    for i in range(4):
        rows.append((f"{i:064x}", secs[i], "phishing", "phishing", "LOW", "P1"))
    # 1 false negative: phishing called benign.
    rows.append((f"{4:064x}", secs[4], "benign", "phishing", "LOW", "P1"))
    # 1 false positive: benign called phishing.
    rows.append((f"{5:064x}", secs[5], "phishing", "benign", "LOW", "P1"))
    # 4 true negatives: benign called benign.
    for i in range(6, 10):
        rows.append((f"{i:064x}", secs[i], "benign", "benign", "LOW", "P1"))
    auto_rows, manual_csv = _write_manual(tmp_path, rows)

    summary = _paired_with_manual(auto_rows, manual_csv)

    assert summary["manual_precision"] == pytest.approx(0.8, abs=1e-6)
    assert summary["manual_recall"] == pytest.approx(0.8, abs=1e-6)
    assert summary["manual_f1"] == pytest.approx(0.8, abs=1e-6)
