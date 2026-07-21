"""Anchor guard: every claims-audit quote must still exist in editorial.js.

The claims suites pair a verbatim editorial quote with a data assertion.
The data half runs nightly, but until now nothing checked that the QUOTE
still exists — copy edits could orphan a check silently (a ghost test
anchored to deleted copy was found guarding nothing on 2026-07-21).

This test normalizes editorial.js (string literals unwrapped, whitespace
collapsed) and requires every claim quote's literal chunks (template
{placeholders} act as wildcards) to appear in it. When it fails, either
the copy changed (re-anchor the quote and re-verify the assertion still
matches the new wording) or the claim was removed (delete its check).
"""
from __future__ import annotations

import importlib
import pkgutil
import re
from pathlib import Path

import pytest

EDITORIAL = (Path(__file__).resolve().parents[2]
             / "site" / "js" / "editorial.js")

# Quotes that summarize a data relationship rather than quoting copy
# verbatim. Keep this list SHORT and deliberate — every entry here is a
# claim the anchor guard cannot protect.
PARAPHRASE_EXEMPT = {
    "{pct} of actively exploited vulnerabilities are rated below High",
}


def _normalized_editorial() -> str:
    src = EDITORIAL.read_text(encoding="utf-8")
    # Unwrap JS string concatenation: drop quotes, plus-joins and comments,
    # then collapse whitespace so quotes match across wrapped lines.
    src = re.sub(r"//[^\n]*", " ", src)
    src = src.replace('" +', " ").replace('"', " ").replace("' +", " ")
    return re.sub(r"\s+", " ", src).lower()


def _claims_modules():
    tests_pkg = Path(__file__).parent
    for info in pkgutil.iter_modules([str(tests_pkg)]):
        if info.name.startswith("test_claims_") and \
                info.name != "test_claims_anchors":
            yield importlib.import_module(f"pipeline.tests.{info.name}")


def _chunks(quote: str) -> list[str]:
    """Literal fragments of the quote, with {placeholders} as split points;
    only fragments long enough to be meaningful anchors count."""
    parts = re.split(r"\{\w+\}", quote)
    return [re.sub(r"\s+", " ", p).strip().lower() for p in parts
            if len(p.strip()) >= 12]


def _all_claims():
    for mod in _claims_modules():
        for entry in getattr(mod, "CLAIMS", []):
            quote = entry[0]
            yield pytest.param(mod.__name__, quote,
                               id=f"{mod.__name__.split('.')[-1]}:"
                                  f"{quote[:40]}")


@pytest.mark.parametrize("module_name,quote", _all_claims())
def test_claim_quote_still_anchored(module_name: str, quote: str) -> None:
    if quote in PARAPHRASE_EXEMPT:
        pytest.skip("deliberately paraphrased claim (see PARAPHRASE_EXEMPT)")
    text = _normalized_editorial()
    missing = [c for c in _chunks(quote) if c not in text]
    assert not missing, (
        f"{module_name}: claim quote no longer matches editorial.js — "
        f"missing fragment(s): {missing!r}. Re-anchor the quote (and "
        f"re-verify its assertion) or remove the orphaned check."
    )
