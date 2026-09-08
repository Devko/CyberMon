"""Claims-gate integrity: "audited" must never be mistaken for "skipped".

Every claims module skips when its data file is missing, and two skip when
a history-backed record is thin. Those skips exist so a fixture run or a
launch night is not judged against copy written for a mature record — but
they also mean a stage that silently drops its output, a history file that
gets lost, or a module carried forward for months all read as green.

This module closes that gap using meta.json as the signal of what the run
actually did:

* every module output that the pipeline emits must be present in
  site/data — always for the corpus-pass files, and whenever meta.sources
  carries that module's block for the single-upstream ones (a block is
  written only when the stage ran or was deliberately carried forward);
* a ``stale`` marker, wherever it appears, must be the boolean True and
  its source's ``fetched_at`` must be recent — a module may degrade for a
  night, not for a season;
* the history-backed records the copy relies on must still have their
  substance, so the "wait for the backfill" skips in the changelog and
  EPSS-report audits cannot hide a lost file.

Skips itself only under the same conditions as every other claims module:
sample data or no committed edition at all.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

DATA_DIR = Path(__file__).resolve().parents[2] / "site" / "data"

_meta_path = DATA_DIR / "meta.json"
if not _meta_path.exists():
    pytest.skip("site/data/meta.json missing — no committed data to audit",
                allow_module_level=True)
_META = json.loads(_meta_path.read_text("utf-8"))
if _META.get("sample") is True:
    pytest.skip("site/data holds sample data — claims audit only judges "
                "real data", allow_module_level=True)

# Outputs built from the shared corpus pass plus the three core feeds
# (cvelist, EPSS, KEV): a run cannot succeed without them.
ALWAYS = [
    "severity_inflation.json", "nine_eight_flood.json",
    "score_vs_reality.json", "cna_leaderboard.json", "volume_curve.json",
    "kev_latency.json", "cna_concentration.json", "advisory_quality.json",
    "cwe_distribution.json", "kev_ransomware.json", "kev_guards.json",
    "cve_calendar.json", "time_to_poc.json", "ai_alibi.json",
]

# Single-upstream / stateful outputs: present exactly when their
# meta.sources block is (the pipeline writes both, or neither).
BY_SOURCE = {
    "breach_ledger.json": "hibp",
    "extortion_ledger.json": "ransomwhere",
    "dnssec_adoption.json": "apnic",
    "nvd_decay.json": "nvd",
    "nvd_throughput.json": "nvd",
    "market_hype.json": "market",
    "attack_churn.json": "attack",
    "naming.json": "naming",
    "epss_report.json": "epss_history",
    "rescore_log.json": "rescores",
    "kev_changelog.json": "kev_changelog",
    "cwe_top25.json": "top25",
    "adp_coverage.json": "adp",
    "epss_volatility.json": "epssvol",
    "cna_roster.json": "roster",
    "botnet_weather.json": "feodo",
}

# A degraded module may be carried forward for a few nights while an
# upstream recovers; beyond this the site is quietly serving old numbers
# under tonight's edition stamp and somebody has to look.
MAX_STALE_DAYS = 14

# History-backed records the copy relies on. Below these floors the module
# audits skip ("waiting for the backfill") — which must only ever happen on
# a launch night, never because the committed history was lost.
HISTORY_FLOORS = {
    ("kev_changelog", "events_total"): 500,
    ("epss_history", "graded"): 200,
    ("rescores", "events_total"): 100,
}


def _iso(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc)


@pytest.mark.parametrize("name", ALWAYS)
def test_corpus_pass_output_is_present(name: str) -> None:
    assert (DATA_DIR / name).exists(), (
        f"{name} is missing from site/data although the run succeeded — "
        f"its claims audit would have skipped silently"
    )


@pytest.mark.parametrize("name,source", sorted(BY_SOURCE.items()))
def test_source_backed_output_is_present(name: str, source: str) -> None:
    sources = _META["sources"]
    present = (DATA_DIR / name).exists()
    if source in sources:
        assert present, (
            f"meta.sources.{source} says the stage ran (or was carried "
            f"forward) but {name} is missing — its claims audit skipped "
            f"instead of judging"
        )
    else:
        assert not present, (
            f"{name} exists but meta.sources has no {source!r} block — the "
            f"file is an orphan from an earlier run and its numbers are "
            f"of unknown age"
        )


def test_stale_markers_are_boolean_and_recent() -> None:
    generated = _iso(_META["generated_at"])
    stale_sources = {k: v for k, v in _META["sources"].items()
                     if isinstance(v, dict) and "stale" in v}
    for key, block in stale_sources.items():
        assert block["stale"] is True, (
            f"meta.sources.{key}.stale must be the boolean true when "
            f"present, not {block['stale']!r}"
        )
        fetched = block.get("fetched_at")
        assert isinstance(fetched, str), (
            f"meta.sources.{key} is stale but carries no fetched_at to "
            f"date it by"
        )
        age = (generated - _iso(fetched)).days
        assert age <= MAX_STALE_DAYS, (
            f"meta.sources.{key} has been carried forward for {age} days "
            f"(fetched {fetched}, edition {_META['generated_at']}) — a "
            f"degraded upstream is a one-night allowance, not a season"
        )
    # The files themselves: a stale file must have a stale source, and a
    # stale source must have a stale file, or the footer's "(carried
    # forward)" and the section's numbers disagree about what is fresh.
    for name, source in BY_SOURCE.items():
        path = DATA_DIR / name
        if not path.exists():
            continue
        obj = json.loads(path.read_text("utf-8"))
        if "stale" in obj:
            assert obj["stale"] is True, f"{name}.stale must be true, not {obj['stale']!r}"
            assert source in stale_sources, (
                f"{name} is marked stale but meta.sources.{source} is not"
            )


@pytest.mark.parametrize("key,field,floor", [
    (k, f, v) for (k, f), v in HISTORY_FLOORS.items()
])
def test_history_backed_records_keep_their_substance(key: str, field: str,
                                                     floor: int) -> None:
    block = _META["sources"].get(key)
    if block is None:
        pytest.skip(f"meta.sources.{key} absent — stage did not run")
    value = block.get(field)
    assert isinstance(value, int) and value >= floor, (
        f"meta.sources.{key}.{field} = {value!r}, below the {floor} floor "
        f"the copy needs — the committed history behind this module has "
        f"shrunk (lost file? state reset?), and the module's claims audit "
        f"is skipping rather than judging"
    )
