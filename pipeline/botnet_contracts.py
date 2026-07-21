"""Contract for the Botnet Weather output (botnet_weather.json).

Same philosophy as pipeline/contracts.py — a hand-rolled stdlib validator
that fails loudly — kept in its own module so this stage lands without
touching the core contracts file (mirrors roster_contracts and friends).
The coordinator merges :data:`VALIDATORS` into the pipeline's dispatch;
failures raise the same :class:`pipeline.contracts.ContractViolation`.

The internal-consistency checks are deliberately strong: the weather
series derives from the committed CSV and the today/age sections from the
same snapshot, so their totals MUST agree — a mismatch means the builder
(or the record) broke. Zero is everywhere a legal reading: the tracker's
documented empty state is data, not damage.

One red-line check lives here too: the emitted object must contain **no
per-server records** — families, countries and networks are the only
labels allowed out (the module is the weather, not the blocklist).
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .botnet_metrics import AGE_BUCKET_LABELS, TOTAL_KEY
from .contracts import (DATE_RE, _check_generated_at, _check_int,
                        _check_list, _check_sorted, _check_str, _fail, _get)

_IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def _check_breakdown(obj: Any, path: str, *, total: int) -> None:
    """A ``[{label, n}]`` breakdown: non-empty unique labels, counts >= 1,
    sorted by count descending (ties label ascending), summing to
    ``total`` (every breakdown here is a clean partition of the listed
    set). Empty exactly when ``total`` is zero."""
    entries = _check_list(obj, path)
    if bool(entries) != (total > 0):
        _fail(path, f"breakdown must be empty exactly when the snapshot "
                    f"is empty (total {total}, {len(entries)} buckets)")
    labels: set[str] = set()
    keys: list[tuple] = []
    running = 0
    for i, e in enumerate(entries):
        p = f"{path}[{i}]"
        label = _get(e, "label", p)
        _check_str(label, f"{p}.label")
        if label in labels:
            _fail(f"{p}.label", f"duplicate label {label!r}")
        labels.add(label)
        n = _get(e, "n", p)
        _check_int(n, f"{p}.n", minimum=1)
        keys.append((-n, label))
        running += n
    _check_sorted(keys, f"{path} (by n desc, label asc)")
    if running != total:
        _fail(path, f"partition sums to {running}, snapshot total is {total}")


def _check_count_map(obj: Any, path: str, families: list[str]) -> int:
    """A ``{family: count}`` map: known families only, counts >= 0.
    Returns the sum."""
    if not isinstance(obj, dict):
        _fail(path, f"expected object, got {type(obj).__name__}")
    total = 0
    for fam, n in obj.items():
        if fam not in families:
            _fail(f"{path}.{fam}", "family missing from c2_weather.families")
        _check_int(n, f"{path}.{fam}")
        total += n
    return total


def _validate_botnet_weather(obj: Any) -> None:
    _check_generated_at(obj, "botnet_weather")

    # ---- c2_weather (the committed series — launch-thin, never faked) -------
    weather = _get(obj, "c2_weather", "botnet_weather")
    families = _check_list(_get(weather, "families", "botnet_weather.c2_weather"),
                           "botnet_weather.c2_weather.families")
    for i, fam in enumerate(families):
        _check_str(fam, f"botnet_weather.c2_weather.families[{i}]")
        if fam == TOTAL_KEY:
            _fail(f"botnet_weather.c2_weather.families[{i}]",
                  f"the {TOTAL_KEY!r} sentinel is not a family")
    _check_sorted(families, "botnet_weather.c2_weather.families")
    if len(set(families)) != len(families):
        _fail("botnet_weather.c2_weather.families", "duplicate families")

    series = _check_list(_get(weather, "series", "botnet_weather.c2_weather"),
                         "botnet_weather.c2_weather.series")
    if not series:
        # run_stage always merges tonight's row before building.
        _fail("botnet_weather.c2_weather.series",
              "must hold at least tonight's observation")
    dates: list[str] = []
    for i, pt in enumerate(series):
        p = f"botnet_weather.c2_weather.series[{i}]"
        day = _get(pt, "date", p)
        _check_str(day, f"{p}.date", DATE_RE)
        dates.append(day)
        online_sum = _check_count_map(_get(pt, "online", p), f"{p}.online",
                                      families)
        listed_sum = _check_count_map(_get(pt, "listed", p), f"{p}.listed",
                                      families)
        if set(pt["online"]) != set(pt["listed"]):
            _fail(p, "online and listed maps must cover the same families")
        for fam in pt["listed"]:
            if pt["listed"][fam] < 1:
                _fail(f"{p}.listed.{fam}",
                      "a family present on a day must have listed >= 1")
            if pt["online"][fam] > pt["listed"][fam]:
                _fail(f"{p}.online.{fam}", "online exceeds listed")
        online_total = _get(pt, "online_total", p)
        listed_total = _get(pt, "listed_total", p)
        _check_int(online_total, f"{p}.online_total")
        _check_int(listed_total, f"{p}.listed_total")
        if online_total != online_sum:
            _fail(f"{p}.online_total",
                  f"family online counts sum to {online_sum}")
        if listed_total != listed_sum:
            _fail(f"{p}.listed_total",
                  f"family listed counts sum to {listed_sum}")
    _check_sorted(dates, "botnet_weather.c2_weather.series (by date)")
    if len(set(dates)) != len(dates):
        _fail("botnet_weather.c2_weather.series", "duplicate observation dates")
    first_obs = _get(weather, "first_observed", "botnet_weather.c2_weather")
    if first_obs != dates[0]:
        _fail("botnet_weather.c2_weather.first_observed",
              "must equal the first series date")
    for key, idx in (("current_online", "online_total"),
                     ("current_listed", "listed_total")):
        v = _get(weather, key, "botnet_weather.c2_weather")
        _check_int(v, f"botnet_weather.c2_weather.{key}")
        if v != series[-1][idx]:
            _fail(f"botnet_weather.c2_weather.{key}",
                  f"must equal the last series {idx}")

    # ---- c2_today (tonight's composition — real from day one) ---------------
    today = _get(obj, "c2_today", "botnet_weather")
    snap_date = _get(today, "snapshot_date", "botnet_weather.c2_today")
    _check_str(snap_date, "botnet_weather.c2_today.snapshot_date", DATE_RE)
    if snap_date != dates[-1]:
        _fail("botnet_weather.c2_today.snapshot_date",
              "must equal the last series date")
    listed_total = _get(today, "listed_total", "botnet_weather.c2_today")
    online_total = _get(today, "online_total", "botnet_weather.c2_today")
    _check_int(listed_total, "botnet_weather.c2_today.listed_total")
    _check_int(online_total, "botnet_weather.c2_today.online_total")
    if online_total > listed_total:
        _fail("botnet_weather.c2_today.online_total", "exceeds listed_total")
    if listed_total != series[-1]["listed_total"] or \
            online_total != series[-1]["online_total"]:
        _fail("botnet_weather.c2_today",
              "snapshot totals must match the last series point")

    fam_entries = _check_list(_get(today, "families",
                                   "botnet_weather.c2_today"),
                              "botnet_weather.c2_today.families")
    if bool(fam_entries) != (listed_total > 0):
        _fail("botnet_weather.c2_today.families",
              "must be empty exactly when the snapshot is empty")
    keys: list[tuple] = []
    fam_labels: set[str] = set()
    listed_sum = online_sum = 0
    for i, e in enumerate(fam_entries):
        p = f"botnet_weather.c2_today.families[{i}]"
        label = _get(e, "label", p)
        _check_str(label, f"{p}.label")
        if label in fam_labels:
            _fail(f"{p}.label", f"duplicate label {label!r}")
        fam_labels.add(label)
        listed = _get(e, "listed", p)
        online = _get(e, "online", p)
        _check_int(listed, f"{p}.listed", minimum=1)
        _check_int(online, f"{p}.online")
        if online > listed:
            _fail(f"{p}.online", "online exceeds listed")
        keys.append((-listed, label))
        listed_sum += listed
        online_sum += online
    _check_sorted(keys, "botnet_weather.c2_today.families "
                        "(by listed desc, label asc)")
    if listed_sum != listed_total or online_sum != online_total:
        _fail("botnet_weather.c2_today.families",
              f"family counts sum to {listed_sum}/{online_sum}, snapshot "
              f"totals are {listed_total}/{online_total}")
    _check_breakdown(_get(today, "countries", "botnet_weather.c2_today"),
                     "botnet_weather.c2_today.countries", total=listed_total)
    _check_breakdown(_get(today, "asns", "botnet_weather.c2_today"),
                     "botnet_weather.c2_today.asns", total=listed_total)

    # ---- c2_age (infrastructure age — real from day one) --------------------
    age = _get(obj, "c2_age", "botnet_weather")
    if _get(age, "snapshot_date", "botnet_weather.c2_age") != snap_date:
        _fail("botnet_weather.c2_age.snapshot_date",
              "must equal c2_today.snapshot_date")
    n = _get(age, "n", "botnet_weather.c2_age")
    _check_int(n, "botnet_weather.c2_age.n")
    if n != listed_total:
        _fail("botnet_weather.c2_age.n",
              "every listed C2 has a first_seen — n must equal listed_total")
    med = _get(age, "median_age_days", "botnet_weather.c2_age")
    oldest = _get(age, "oldest_age_days", "botnet_weather.c2_age")
    if (med is None) != (n == 0) or (oldest is None) != (n == 0):
        _fail("botnet_weather.c2_age",
              "median/oldest must be null exactly when the snapshot is empty")
    if n > 0:
        _check_int(med, "botnet_weather.c2_age.median_age_days")
        _check_int(oldest, "botnet_weather.c2_age.oldest_age_days")
        if med > oldest:
            _fail("botnet_weather.c2_age.median_age_days",
                  "median cannot exceed the oldest age")
    buckets = _check_list(_get(age, "buckets", "botnet_weather.c2_age"),
                          "botnet_weather.c2_age.buckets")
    if [_get(b, "label", f"botnet_weather.c2_age.buckets[{i}]")
            for i, b in enumerate(buckets)] != list(AGE_BUCKET_LABELS):
        _fail("botnet_weather.c2_age.buckets",
              f"must carry exactly the fixed labels {list(AGE_BUCKET_LABELS)}")
    bucket_sum = 0
    for i, b in enumerate(buckets):
        v = _get(b, "n", f"botnet_weather.c2_age.buckets[{i}]")
        _check_int(v, f"botnet_weather.c2_age.buckets[{i}].n")
        bucket_sum += v
    if bucket_sum != n:
        _fail("botnet_weather.c2_age.buckets", f"bucket counts sum to "
                                               f"{bucket_sum}, n is {n}")

    # ---- catalog -------------------------------------------------------------
    catalog = _get(obj, "catalog", "botnet_weather")
    if _get(catalog, "snapshot_size", "botnet_weather.catalog") != listed_total:
        _fail("botnet_weather.catalog.snapshot_size",
              "must equal c2_today.listed_total")
    if _get(catalog, "online_now", "botnet_weather.catalog") != online_total:
        _fail("botnet_weather.catalog.online_now",
              "must equal c2_today.online_total")
    cat_fams = _check_list(_get(catalog, "families", "botnet_weather.catalog"),
                           "botnet_weather.catalog.families")
    _check_sorted(cat_fams, "botnet_weather.catalog.families")
    if set(cat_fams) != fam_labels:
        _fail("botnet_weather.catalog.families",
              "must name exactly tonight's c2_today families")
    if _get(catalog, "family_count", "botnet_weather.catalog") != len(cat_fams):
        _fail("botnet_weather.catalog.family_count",
              "must equal len(families)")
    if _get(catalog, "first_date", "botnet_weather.catalog") != dates[0]:
        _fail("botnet_weather.catalog.first_date",
              "must equal the first series date")
    if _get(catalog, "last_date", "botnet_weather.catalog") != dates[-1]:
        _fail("botnet_weather.catalog.last_date",
              "must equal the last series date")
    if _get(catalog, "days_observed", "botnet_weather.catalog") != len(series):
        _fail("botnet_weather.catalog.days_observed",
              "must equal the series length")

    # ---- red line: aggregates only, never the blocklist ----------------------
    # No key anywhere may be named like a per-server field, and no string
    # value may look like an IPv4 address (family/country/AS labels are the
    # only labels allowed out).
    def _scan(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("ip_address", "hostname", "ip", "port"):
                    _fail(f"{path}.{k}", "per-server fields must never be "
                                         "emitted (aggregates only)")
                _scan(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                _scan(v, f"{path}[{i}]")
        elif isinstance(node, str) and _IPV4_RE.search(node):
            _fail(path, f"string {node!r} looks like an IP address — "
                        f"the module is the weather, not the blocklist")

    _scan(obj, "botnet_weather")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "botnet_weather.json": _validate_botnet_weather,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the botnet-weather contract for
    ``filename``. Raises :class:`pipeline.contracts.ContractViolation` on
    any mismatch, ``KeyError`` if the filename has no contract here."""
    VALIDATORS[filename](obj)
