"""Claims audit for the Botnet Weather module (pattern:
test_claims_roster.py).

The c2.html copy (site/js/editorial.js) makes verbal claims about
site/data/botnet_weather.json. The hero series is launch-thin by design and
its copy makes no history-based numeric claim; the claims audited here are
structural (the aggregates-only red line) or snapshot-based (tonight's
blocklist size), so they hold from day one. Each CLAIMS entry quotes the
copy verbatim (grep for it in editorial.js) and asserts the underlying data
still sits where the sentence stays true. Ranges are tolerant — normal
night-to-night drift must not trip them; only a claim becoming untrue
should.

When a test here fails: either the world changed (fix the copy in
site/js/editorial.js AND this test's quoted claim + range, in the same
commit) or the pipeline broke (fix the pipeline). NEVER silence a failing
claim check without doing one of the two.

Skips itself when site/data/ holds sample data or the files are missing —
this audit only ever judges the committed real data.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from . import claims_support

DATA_DIR = claims_support.DATA_DIR

_meta_path = DATA_DIR / "meta.json"
if not _meta_path.exists():
    pytest.skip(
        "site/data/meta.json missing — no committed data to audit",
        allow_module_level=True,
    )
if json.loads(_meta_path.read_text("utf-8")).get("sample") is True:
    pytest.skip(
        "site/data holds sample data — claims audit only judges real data",
        allow_module_level=True,
    )


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return claims_support.read_json(path)


_IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def check_weather_not_blocklist(d: dict) -> None:
    # editorial.js (c2.html composition caption): "the module is the weather,
    # not the blocklist" — structural red line: the emitted file must hold
    # aggregates only. No per-server key, no IP-shaped string, anywhere.
    def walk(node, path="botnet_weather"):
        if isinstance(node, dict):
            for k, v in node.items():
                assert k not in ("ip_address", "hostname", "ip", "port"), (
                    f"{path}.{k}: per-server field in the emitted file — "
                    f"'the weather, not the blocklist' is no longer true"
                )
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str):
            assert not _IPV4_RE.search(node), (
                f"{path}: {node!r} looks like an IP address in the emitted "
                f"file — 'the weather, not the blocklist' is no longer true"
            )

    walk(d)


def check_a_handful_listed(d: dict) -> None:
    # editorial.js (c2.html composition headline): "Tonight's blocklist
    # holds a handful of C2 servers." (2026-10-03: 5, unchanged since the
    # record began on 2026-07-21.) More than ten is not a handful.
    size = d["catalog"]["snapshot_size"]
    assert size <= 10, (
        f"'a handful of C2 servers' needs ten or fewer; tonight's blocklist "
        f"holds {size}"
    )


def check_age_buckets_span(d: dict) -> None:
    # editorial.js (c2.html age caption): "The buckets run from under 30
    # days to over two years; a bucket is empty when no listed server was
    # first seen in that range." — every bucket is published, empty ones
    # at zero. (2026-10-03: the two youngest are empty.)
    buckets = d["c2_age"]["buckets"]
    if not d["c2_age"]["n"]:
        return  # an empty blocklist renders the no-data card instead
    labels = [b["label"] for b in buckets]
    assert labels[0] == "under 30 days" and labels[-1] == "over 2 years", (
        labels)
    assert sum(b["n"] for b in buckets) == d["c2_age"]["n"], buckets


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "The module publishes counts only, never the blocklist itself",
        "botnet_weather.json",
        check_weather_not_blocklist,
    ),
    (
        "Tonight's blocklist holds a handful of C2 servers.",
        "botnet_weather.json",
        check_a_handful_listed,
    ),
    (
        "The buckets run from under 30 days to over two years; a bucket is "
        "empty when no listed server was first seen in that range.",
        "botnet_weather.json",
        check_age_buckets_span,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
