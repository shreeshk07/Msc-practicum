"""Shared helpers for the pipeline.

Config loading, the Evidence and RuleHit records the scoring engine
builds, the logger, and the timer the experiment runner uses. These
live together so the stage modules do not have to import each other.
"""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterator

import yaml


def setup_logger(name: str = "phishtriage", level: int = logging.INFO) -> logging.Logger:
    """Return a logger that prints ISO-8601 timestamp, level, module, message."""
    logger = logging.getLogger(name)
    if logger.handlers:
        # tests re-import this module, so don't add a second handler
        return logger
    logger.setLevel(level)
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-7s %(name)s.%(module)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    logger.addHandler(handler)
    return logger


log = setup_logger()


# two levels up from phishtriage/utils.py
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"


def load_yaml(path: Path | str) -> dict:
    """Load a YAML file into a dict. Relative paths resolve under the project root."""
    p = Path(path)
    if not p.is_absolute():
        p = PROJECT_ROOT / p
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {p}")
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data


def load_rules() -> list[dict]:
    return load_yaml(CONFIG_DIR / "rules.yaml").get("rules", [])


def load_settings() -> dict:
    return load_yaml(CONFIG_DIR / "settings.yaml")


@dataclass
class Evidence:
    """One piece of evidence behind a rule firing.

    The report shows these verbatim, which is what lets an analyst see
    why a rule fired rather than just that it did.
    """
    source: str               # auth / header / url / content
    key: str                  # e.g. spf_result, from_domain, url
    value: Any
    detail: str = ""          # readable context for the report

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RuleHit:
    """A rule that fired, with the evidence that tripped it. This is the
    audit trail an analyst uses to defend or hand over a verdict."""
    rule_id: str
    category: str
    weight: int
    description: str
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "weight": self.weight,
            "description": self.description,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@contextmanager
def timed(label: str = "block") -> Iterator[dict]:
    """Time a block of code.

        with timed("auth_stage") as t:
            run_auth_checks(...)
        print(t["elapsed_seconds"])

    The dict fills in on exit, so it is readable both inside the block
    and after it.
    """
    captured: dict = {"label": label, "elapsed_seconds": None}
    start = time.perf_counter()
    try:
        yield captured
    finally:
        captured["elapsed_seconds"] = round(time.perf_counter() - start, 6)
