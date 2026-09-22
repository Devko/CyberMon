"""Contract for the Mutation Observatory output (observatory.json).

Same philosophy as pipeline/contracts.py — a hand-rolled stdlib validator
that fails loudly — kept in its own module (the botnet_contracts pattern)
and merged into the pipeline's dispatch at the bottom of contracts.py.

What it holds the file to:

* the vocabularies are the builder's own (``kinds``, ``kind_source``,
  ``granularities``) — the page indexes into them;
* every encoded event decodes: five ``|``-separated fields, a day offset
  >= 0, a CVE id, a known kind and granularity; events are sorted by day;
* nothing is dated before its history began: an event's date is on or
  after its source's ``first_observed``, and ``capture`` granularity
  appears only on KEV events on or before ``sources.kev.capture_until``;
* ``counts`` per kind and ``sources.*.events`` reconcile with the events
  actually shipped; ``last_observed`` is the newest event's date.
"""
from __future__ import annotations

import re
from datetime import date
from typing import Any, Callable

from .contracts import (DATE_RE, _check_generated_at, _check_int,
                        _check_list, _fail, _get, _check_str)
from .observatory import GRANULARITIES, KINDS, SEP, SOURCE_OF, SOURCES

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _opt_date(v: Any, path: str) -> None:
    if v is not None:
        _check_str(v, path, DATE_RE)


def _validate_observatory(obj: Any) -> None:
    root = "observatory"
    _check_generated_at(obj, root)
    if _get(obj, "kinds", root) != list(KINDS):
        _fail(f"{root}.kinds", "must equal the builder's KINDS, in order")
    if _get(obj, "kind_source", root) != [SOURCE_OF[k] for k in KINDS]:
        _fail(f"{root}.kind_source", "must map each kind to its source")
    if _get(obj, "granularities", root) != list(GRANULARITIES):
        _fail(f"{root}.granularities", "must equal the builder's list")

    sources = _get(obj, "sources", root)
    for name in SOURCES:
        src = _get(sources, name, f"{root}.sources")
        _opt_date(_get(src, "first_observed", f"{root}.sources.{name}"),
                  f"{root}.sources.{name}.first_observed")
        _check_int(_get(src, "events", f"{root}.sources.{name}"),
                   f"{root}.sources.{name}.events")
    kev = sources["kev"]
    for key in ("capture_until", "nightly_from"):
        _opt_date(_get(kev, key, f"{root}.sources.kev"),
                  f"{root}.sources.kev.{key}")
    for key in ("nights", "excluded_reset", "excluded_anomaly"):
        _check_int(_get(sources["epss"], key, f"{root}.sources.epss"),
                   f"{root}.sources.epss.{key}")

    base = _get(obj, "base_date", root)
    last = _get(obj, "last_observed", root)
    events = _check_list(_get(obj, "events", root), f"{root}.events")
    _check_int(_get(obj, "cves", root), f"{root}.cves")
    if not events:
        if last is not None:
            _fail(f"{root}.last_observed", "must be null with no events")
        _opt_date(base, f"{root}.base_date")
    else:
        _check_str(base, f"{root}.base_date", DATE_RE)
        _check_str(last, f"{root}.last_observed", DATE_RE)
    base_ord = date.fromisoformat(base).toordinal() if base else 0
    starts = {n: sources[n]["first_observed"] for n in SOURCES}
    if base is not None and any(s is not None and s < base
                                for s in starts.values()):
        _fail(f"{root}.base_date", "a history begins before base_date")

    counts = [0] * len(KINDS)
    per_source = dict.fromkeys(SOURCES, 0)
    cves: set[str] = set()
    prev_day = 0
    capture_until = kev["capture_until"]
    for i, s in enumerate(events):
        p = f"{root}.events[{i}]"
        if not isinstance(s, str):
            _fail(p, "expected an encoded string")
        parts = s.split(SEP)
        if len(parts) != 5:
            _fail(p, f"expected 5 {SEP!r}-separated fields, got {s!r}")
        day, cve, kind, _detail, grain = parts
        if not day.isdigit() or not kind.isdigit() or not grain.isdigit():
            _fail(p, f"non-numeric day/kind/granularity in {s!r}")
        day_n, kind_n, grain_n = int(day), int(kind), int(grain)
        if day_n < prev_day:
            _fail(p, "events must be sorted by day")
        prev_day = day_n
        if not CVE_RE.match(cve):
            _fail(p, f"bad CVE id {cve!r}")
        if kind_n >= len(KINDS) or grain_n >= len(GRANULARITIES):
            _fail(p, f"kind/granularity index out of range in {s!r}")
        source = SOURCE_OF[KINDS[kind_n]]
        iso = date.fromordinal(base_ord + day_n).isoformat()
        start = starts[source]
        if start is None or iso < start:
            _fail(p, f"{source} event dated {iso}, before its history "
                     f"began ({start})")
        if GRANULARITIES[grain_n] == "capture" and (
                source != "kev" or capture_until is None
                or iso > capture_until):
            _fail(p, f"capture granularity on a {source} event dated {iso}")
        counts[kind_n] += 1
        per_source[source] += 1
        cves.add(cve)
    if events and date.fromordinal(base_ord + prev_day).isoformat() != last:
        _fail(f"{root}.last_observed", "must be the newest event's date")

    shipped = _get(obj, "counts", root)
    for k, n in zip(KINDS, counts):
        if _get(shipped, k, f"{root}.counts") != n:
            _fail(f"{root}.counts.{k}", f"{shipped[k]} != {n} events shipped")
    for name in SOURCES:
        if sources[name]["events"] != per_source[name]:
            _fail(f"{root}.sources.{name}.events",
                  f"{sources[name]['events']} != {per_source[name]} shipped")
    if obj["cves"] != len(cves):
        _fail(f"{root}.cves", f"{obj['cves']} != {len(cves)} distinct ids")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "observatory.json": _validate_observatory,
}
