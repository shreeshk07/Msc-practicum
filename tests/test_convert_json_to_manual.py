"""Tests for tools/convert_json_to_manual.py."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).parent.parent / "tools" / "convert_json_to_manual.py"
_spec = importlib.util.spec_from_file_location("convert_json_to_manual", _SCRIPT)
convert_json_to_manual = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(convert_json_to_manual)


def _manifest_hashes(n=20):
    return {f"email_{i:02d}": f"{i:064x}" for i in range(1, n + 1)}


def test_convert_one_raises_on_short_participant(tmp_path):
    """A participant with fewer than 20 emails is rejected loudly.

    kappa_gt is only trustworthy when every participant's manual CSV
    holds a full 20-email session, since a short session skews that
    participant's kappa relative to the other nine. convert_one is the
    stage that guarantees the CSV feeding analyse --manual always has
    exactly 20 rows per participant, so this checks that guarantee is
    still in place rather than re-implementing it in the analyser.
    """
    hashes = _manifest_hashes()
    session = tmp_path / "triage_P3_2026.json"
    session.write_text(json.dumps({
        "participant": {"pseudonym": "P3"},
        "emails": [
            {"email_id": f"email_{i:02d}", "verdict": "phishing",
             "time_ms": 30000, "confidence": "high"}
            for i in range(1, 19)   # 18 emails, not 20
        ],
    }), encoding="utf-8")

    with pytest.raises(ValueError, match=r"P3.*18 emails, expected 20"):
        convert_json_to_manual.convert_one(session, hashes)
