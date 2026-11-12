"""Tests for tools/convert_form_to_manual.py."""

from __future__ import annotations

import csv
import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).parent.parent / "tools" / "convert_form_to_manual.py"
_spec = importlib.util.spec_from_file_location("convert_form_to_manual", _SCRIPT)
convert_form_to_manual = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(convert_form_to_manual)


def test_convert_synthetic_form_csv(tmp_path):
    """A two-row form export converts to the analyser's manual format.

    The sha256 comes from the manifest, time_ms becomes seconds, and
    the verdict, pseudonym, and email_id pass through. An email_id
    that is not in the manifest raises a clear error.
    """
    sha1, sha2 = "a" * 64, "b" * 64
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps([
        {"email_id": "s-01", "filename": "x1.eml",
         "ground_truth": "phishing", "sha256": sha1},
        {"email_id": "s-02", "filename": "x2.eml",
         "ground_truth": "benign", "sha256": sha2},
    ]), encoding="utf-8")

    form_csv = tmp_path / "P1.csv"
    form_csv.write_text(
        "pseudonym,stratum,email_id,verdict,confidence,time_ms,"
        "checklist_items_ticked,reason\n"
        "P1,SOC,s-01,phishing,high,65432,5,bad links\n"
        "P1,SOC,s-02,benign,medium,1200,3,looks fine\n",
        encoding="utf-8",
    )

    output = tmp_path / "manual.csv"
    n = convert_form_to_manual.convert(form_csv, manifest, output)
    assert n == 2

    with open(output, encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert [r["sha256"] for r in rows] == [sha1, sha2]
    assert [r["manual_verdict"] for r in rows] == ["phishing", "benign"]
    assert [r["manual_seconds"] for r in rows] == ["65.432", "1.200"]
    assert [r["pseudonym"] for r in rows] == ["P1", "P1"]
    assert [r["email_id"] for r in rows] == ["s-01", "s-02"]

    # An email_id missing from the manifest is a clear error, not a
    # silently dropped row.
    bad_csv = tmp_path / "P2.csv"
    bad_csv.write_text(
        "pseudonym,stratum,email_id,verdict,confidence,time_ms,"
        "checklist_items_ticked,reason\n"
        "P2,student,s-99,phishing,low,5000,1,\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="s-99"):
        convert_form_to_manual.convert(bad_csv, manifest,
                                       tmp_path / "out2.csv")
