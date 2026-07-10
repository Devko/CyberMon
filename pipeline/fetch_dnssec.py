"""APNIC Labs measured DNSSEC validation rates (stats.labs.apnic.net).

Two upstream shapes, both live-verified 2026-07-10:

* **Per-code time series (JSON)** —
  ``https://stats.labs.apnic.net/cgi-bin/json-table.pl?x=<CODE>`` where
  ``<CODE>`` is an ISO-3166 economy code or one of APNIC's private
  region codes (``XA`` = world). Returns the FULL daily history
  (2013-10-07 onward, ~4,650 rows, ~3.9 MB) as
  ``{"copyright", "description", "docs", "data": [row, ...]}`` with each
  row carrying ``date``, ``cc`` and five smoothing windows (``1_day``,
  ``10_day``, ``30_day``, ``60_day``, ``90_day``), each window an object
  ``{seen, validating, validating_pc, partial_validating,
  partial_validating_pc}``. Because upstream history is complete, the
  pipeline fetches it statelessly every night — no committed history
  file is needed for this module.

* **All-economies snapshot (HTML)** —
  ``https://stats.labs.apnic.net/dnssec`` embeds its world-map table as
  inline Google-Charts JS rows (there is no JSON equivalent; fetching
  ~240 per-economy series nightly instead would be abusive). Each row is
  machine-generated and strictly regular; :func:`parse_index` extracts
  it with an anchored regex and FAILS LOUDLY (``ValueError``) when fewer
  than ``min_rows`` economies parse, so silent shape drift can never
  publish an empty distribution.

Terms: every JSON response states "(c) APNIC Pty/Ltd. re-use with
attribution permitted"; the bulk-data docs add that the data is provided
on a 'hold harmless' basis with attribution. CyberMon credits APNIC Labs
in the site footer and README.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

SERIES_URL = "https://stats.labs.apnic.net/cgi-bin/json-table.pl"
INDEX_URL = "https://stats.labs.apnic.net/dnssec"

USER_AGENT = "CyberMon/1.0 (+https://github.com/Devko/CyberMon)"
_HEADERS = {"User-Agent": USER_AGENT}

# APNIC's world aggregate pseudo-code.
WORLD_CC = "XA"

# The smoothing window this module reads everywhere. 30 days matches the
# headline number APNIC itself shows on the world-map table.
WINDOW_KEY = "30_day"

# The fixed economy set for the "economies compared" chart: the ten
# largest economies by APNIC's own weighted 30-day sample count (its
# estimate of the economy's internet-user population) as measured at
# module creation, 2026-07-10. FROZEN on purpose: re-picking members
# nightly would let membership churn masquerade as adoption change.
ECONOMIES: tuple[tuple[str, str], ...] = (
    ("CN", "China"),
    ("IN", "India"),
    ("US", "United States"),
    ("BR", "Brazil"),
    ("ID", "Indonesia"),
    ("JP", "Japan"),
    ("MX", "Mexico"),
    ("RU", "Russia"),
    ("PH", "Philippines"),
    ("NG", "Nigeria"),
)

# APNIC augments ISO-3166 with private codes for aggregates: XA..XW for
# world/continents/sub-regions and QM..QS for UN sub-regions (per
# https://data1.labs.apnic.net/ipv6-data-format.html). Only these are
# excluded from the per-economy snapshot — QA (Qatar) etc. are real
# economies and must be kept.
_REGION_CODE = re.compile(r"^(X[A-Z]|Q[M-Z])$")

# One inline world-map table row, e.g.:
#   ["<a href=\"/dnssec/DE\">DE</a>","<a ...>Germany</a>, <a ...>...",
#    {v: 80.96, f:'80.96%'}, {v: 3.18, f: '3.18%'}, {v: 84.15, f: '84.15%'},
#    5788219,1.41,8147757],
# Columns: code, name/region links, validating %, partially validating %,
# combined %, samples seen (30-day), weight, weighted samples.
_INDEX_ROW = re.compile(
    r'\["<a href=\\"/dnssec/(?P<cc>[A-Z]{2})\\">(?P=cc)</a>",'
    r'".*?",'  # name/region links; ends at the first ",{v: (never inside)
    r"\{v: (?P<validating>[\d.]+), f:\s*'[\d.]+%'\},\s*"
    r"\{v: (?P<partial>[\d.]+), f:\s*'[\d.]+%'\},\s*"
    r"\{v: [\d.]+, f:\s*'[\d.]+%'\},"
    r"(?P<seen>\d+),(?P<weight>[\d.]+),(?P<weighted>\d+)\]")


@dataclass
class DnssecPoint:
    """One day of one series, restricted to the 30-day window."""

    date: str  # YYYY-MM-DD
    seen: int
    validating_pc: float
    partial_pc: float


@dataclass
class DnssecSeries:
    """Daily validation series for one code (economy or aggregate)."""

    cc: str
    points: list[DnssecPoint] = field(default_factory=list, repr=False)


@dataclass
class EconomySnapshot:
    """One economy row of the world-map table (current 30-day values)."""

    cc: str
    validating_pc: float
    partial_pc: float
    seen: int
    weighted: int


@dataclass
class DnssecData:
    """Everything the hygiene metrics need for one nightly build."""

    world: DnssecSeries
    economies: dict[str, DnssecSeries] = field(default_factory=dict)
    snapshot: list[EconomySnapshot] = field(default_factory=list)


def parse_series(obj: dict, cc: str) -> DnssecSeries:
    """Extract the 30-day window series from a json-table.pl document.

    Malformed rows are skipped (fetch_kev's lenient-row philosophy), but
    an EMPTY result fails loudly: if no row parses, the shape drifted
    and publishing nothing must break the run, not the charts.
    """
    rows = obj.get("data")
    if not isinstance(rows, list):
        raise ValueError(f"APNIC series {cc}: no 'data' array in response")
    points: list[DnssecPoint] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        date = row.get("date")
        window = row.get(WINDOW_KEY)
        if (not isinstance(date, str) or len(date) != 10
                or not isinstance(window, dict)):
            continue
        seen = window.get("seen")
        validating_pc = window.get("validating_pc")
        partial_pc = window.get("partial_validating_pc")
        if (isinstance(seen, bool) or not isinstance(seen, int)
                or not isinstance(validating_pc, (int, float))
                or not isinstance(partial_pc, (int, float))):
            continue
        # A row for a different code means the endpoint's semantics
        # drifted (x=<code> no longer selects what we asked for).
        if row.get("cc") != cc:
            raise ValueError(f"APNIC series {cc}: row carries cc="
                             f"{row.get('cc')!r} — endpoint drift")
        points.append(DnssecPoint(date=date, seen=seen,
                                  validating_pc=float(validating_pc),
                                  partial_pc=float(partial_pc)))
    if not points:
        raise ValueError(f"APNIC series {cc}: zero parseable rows "
                         f"(upstream shape drift?)")
    points.sort(key=lambda p: p.date)
    return DnssecSeries(cc=cc, points=points)


def parse_index(html: str, *, min_rows: int = 100) -> list[EconomySnapshot]:
    """Extract per-economy current rates from the world-map page.

    Region pseudo-codes (XA..XW, QM..QS) are excluded — this snapshot is
    the one-economy-one-row distribution. Fails loudly when fewer than
    ``min_rows`` economies parse: the inline table is the one upstream
    shape here that is NOT a stable JSON contract, so drift must break
    the run instead of quietly shrinking the spread chart.
    """
    seen_ccs: set[str] = set()
    rows: list[EconomySnapshot] = []
    for m in _INDEX_ROW.finditer(html):
        cc = m["cc"]
        if _REGION_CODE.match(cc) or cc in seen_ccs:
            continue
        seen_ccs.add(cc)
        rows.append(EconomySnapshot(cc=cc,
                                    validating_pc=float(m["validating"]),
                                    partial_pc=float(m["partial"]),
                                    seen=int(m["seen"]),
                                    weighted=int(m["weighted"])))
    if len(rows) < min_rows:
        raise ValueError(
            f"APNIC world-map table: only {len(rows)} economy rows parsed "
            f"(expected >= {min_rows}) — upstream page shape drift?")
    return rows


def load_series_file(path: Path, cc: str) -> DnssecSeries:
    """Load one series from a local JSON file (fixtures)."""
    return parse_series(json.loads(path.read_text(encoding="utf-8")), cc)


def load_index_file(path: Path, *, min_rows: int = 100) -> list[EconomySnapshot]:
    """Load the world-map snapshot from a local HTML file (fixtures)."""
    return parse_index(path.read_text(encoding="utf-8"), min_rows=min_rows)


def fetch_series(cc: str, session, timeout: float = 120.0) -> DnssecSeries:
    """Download and parse one code's full daily series (~3.9 MB)."""
    resp = session.get(SERIES_URL, params={"x": cc}, headers=_HEADERS,
                       timeout=timeout)
    resp.raise_for_status()
    return parse_series(resp.json(), cc)


def fetch_index(session, timeout: float = 60.0,
                *, min_rows: int = 100) -> list[EconomySnapshot]:
    """Download and parse the all-economies world-map snapshot."""
    resp = session.get(INDEX_URL, headers=_HEADERS, timeout=timeout)
    resp.raise_for_status()
    return parse_index(resp.text, min_rows=min_rows)


def fetch_dnssec(session=None, sleep=time.sleep, log=print) -> DnssecData:
    """Fetch world series, the fixed economy set, and the snapshot.

    Twelve requests, ~42 MB, once a night, spaced by a polite pause —
    the whole-history fetch is what keeps the module stateless.
    """
    import requests

    session = session or requests.Session()
    log(f"  APNIC world series ({WORLD_CC}) ...")
    world = fetch_series(WORLD_CC, session)
    economies: dict[str, DnssecSeries] = {}
    for cc, _label in ECONOMIES:
        sleep(0.5)
        economies[cc] = fetch_series(cc, session)
    log(f"  APNIC economy series: {', '.join(economies)}")
    sleep(0.5)
    snapshot = fetch_index(session)
    log(f"  APNIC world-map snapshot: {len(snapshot)} economies")
    return DnssecData(world=world, economies=economies, snapshot=snapshot)
