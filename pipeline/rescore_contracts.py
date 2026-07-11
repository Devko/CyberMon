"""Contract for the Silent Rescores output (rescore_log.json).

Same philosophy as pipeline/contracts.py — a hand-rolled stdlib validator
that fails loudly — kept in its own module so this stage lands without
touching the core contracts file (mirrors calendar_contracts and friends).
The coordinator merges :data:`VALIDATORS` into the pipeline's dispatch;
failures raise the same :class:`pipeline.contracts.ContractViolation`.

The internal-consistency checks here are deliberately strong: weeks,
magnitude, and catalog all derive from the same committed event log, so
their totals MUST agree — a mismatch means the builder (or the log) broke.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .contracts import (DATE_RE, _check_generated_at, _check_int,
                        _check_list, _check_num, _check_sorted, _check_str,
                        _fail, _get)

# Must match rescore_tracker.CHANGE_TYPES / DELTA_BUCKETS. Hardcoded here
# on purpose (calendar_contracts precedent): the contract states what the
# site may rely on, independently of the builder.
CHANGE_TYPES = ("rescore", "version_shift", "first_score", "score_removed")
DELTA_BUCKETS = ["<=-4.0", "-3.9..-2.0", "-1.9..-0.1",
                 "+0.1..+1.9", "+2.0..+3.9", ">=+4.0"]
WEEK_RE = re.compile(r"^\d{4}-W\d{2}$")

_WEEK_COUNT_KEYS = ("rescore_up", "rescore_down", "first_score",
                    "version_shift", "score_removed")


def _validate_rescore_log(obj: Any) -> None:
    _check_generated_at(obj, "rescore_log")

    # ---- weeks -------------------------------------------------------------
    entries = _check_list(_get(obj, "weeks", "rescore_log"),
                          "rescore_log.weeks")
    labels: list[str] = []
    week_sums = dict.fromkeys(_WEEK_COUNT_KEYS, 0)
    for i, e in enumerate(entries):
        path = f"rescore_log.weeks[{i}]"
        label = _get(e, "week", path)
        _check_str(label, f"{path}.week", WEEK_RE)
        labels.append(label)
        for key in _WEEK_COUNT_KEYS:
            v = _get(e, key, path)
            _check_int(v, f"{path}.{key}")
            week_sums[key] += v
    _check_sorted(labels, "rescore_log.weeks")
    if len(set(labels)) != len(labels):
        _fail("rescore_log.weeks", "duplicate week labels")

    # ---- magnitude ---------------------------------------------------------
    mag = _get(obj, "magnitude", "rescore_log")
    _check_int(_get(mag, "min_n", "rescore_log.magnitude"),
               "rescore_log.magnitude.min_n", minimum=1)
    n = _get(mag, "n", "rescore_log.magnitude")
    _check_int(n, "rescore_log.magnitude.n")
    up = _get(mag, "up", "rescore_log.magnitude")
    down = _get(mag, "down", "rescore_log.magnitude")
    _check_int(up, "rescore_log.magnitude.up")
    _check_int(down, "rescore_log.magnitude.down")
    if up + down != n:
        _fail("rescore_log.magnitude", f"up ({up}) + down ({down}) "
                                       f"must equal n ({n})")
    buckets = _get(mag, "buckets", "rescore_log.magnitude")
    median = _get(mag, "median_delta", "rescore_log.magnitude")
    gated = n < mag["min_n"]
    if (buckets is None) != gated:
        _fail("rescore_log.magnitude.buckets",
              "must be null exactly when n is below min_n")
    if (median is None) != gated:
        _fail("rescore_log.magnitude.median_delta",
              "must be null exactly when buckets are")
    if buckets is not None:
        _check_list(buckets, "rescore_log.magnitude.buckets")
        if [b.get("bucket") for b in buckets] != DELTA_BUCKETS:
            _fail("rescore_log.magnitude.buckets",
                  f"bucket labels must equal {DELTA_BUCKETS} in order")
        total = 0
        for i, b in enumerate(buckets):
            path = f"rescore_log.magnitude.buckets[{i}]"
            _check_int(_get(b, "n", path), f"{path}.n")
            total += b["n"]
        if total != n:
            _fail("rescore_log.magnitude.buckets",
                  f"bucket counts sum to {total}, n is {n}")
        _check_num(median, "rescore_log.magnitude.median_delta",
                   -10.0, 10.0)

    # ---- cna_board ---------------------------------------------------------
    board = _get(obj, "cna_board", "rescore_log")
    min_events = _get(board, "min_events", "rescore_log.cna_board")
    _check_int(min_events, "rescore_log.cna_board.min_events", minimum=1)
    cnas = _check_list(_get(board, "cnas", "rescore_log.cna_board"),
                       "rescore_log.cna_board.cnas")
    counts = []
    names = set()
    board_total = 0
    for i, c in enumerate(cnas):
        path = f"rescore_log.cna_board.cnas[{i}]"
        name = _get(c, "cna", path)
        _check_str(name, f"{path}.cna")
        if name in names:
            _fail(f"{path}.cna", f"duplicate CNA {name!r}")
        names.add(name)
        rescores = _get(c, "rescores", path)
        _check_int(rescores, f"{path}.rescores", minimum=min_events)
        c_up = _get(c, "up", path)
        c_down = _get(c, "down", path)
        _check_int(c_up, f"{path}.up")
        _check_int(c_down, f"{path}.down")
        if c_up + c_down != rescores:
            _fail(path, f"up ({c_up}) + down ({c_down}) must equal "
                        f"rescores ({rescores})")
        counts.append(rescores)
        board_total += rescores
    _check_sorted(counts, "rescore_log.cna_board.cnas (by rescores)",
                  descending=True)

    # ---- catalog (audit block) ----------------------------------------------
    catalog = _get(obj, "catalog", "rescore_log")
    _check_int(_get(catalog, "state_size", "rescore_log.catalog"),
               "rescore_log.catalog.state_size")
    _check_str(_get(catalog, "corpus_release", "rescore_log.catalog"),
               "rescore_log.catalog.corpus_release")
    totals = _get(catalog, "totals", "rescore_log.catalog")
    if set(totals) != set(CHANGE_TYPES):
        _fail("rescore_log.catalog.totals",
              f"must carry exactly the keys {sorted(CHANGE_TYPES)}")
    for key in CHANGE_TYPES:
        _check_int(totals[key], f"rescore_log.catalog.totals.{key}")
    events_total = _get(catalog, "events_total", "rescore_log.catalog")
    _check_int(events_total, "rescore_log.catalog.events_total")
    if sum(totals.values()) != events_total:
        _fail("rescore_log.catalog.events_total",
              f"totals sum to {sum(totals.values())}, "
              f"events_total is {events_total}")
    first = _get(catalog, "first_observed", "rescore_log.catalog")
    if (first is None) != (events_total == 0):
        _fail("rescore_log.catalog.first_observed",
              "must be null exactly when the log is empty")
    if first is not None:
        _check_str(first, "rescore_log.catalog.first_observed", DATE_RE)

    # ---- cross-section consistency (one log, one arithmetic) ----------------
    if week_sums["rescore_up"] + week_sums["rescore_down"] != \
            totals["rescore"]:
        _fail("rescore_log.weeks", "weekly rescore up+down must sum to "
                                   "catalog.totals.rescore")
    for key in ("first_score", "version_shift", "score_removed"):
        if week_sums[key] != totals[key]:
            _fail("rescore_log.weeks", f"weekly {key} counts must sum to "
                                       f"catalog.totals.{key}")
    if mag["n"] != totals["rescore"]:
        _fail("rescore_log.magnitude.n",
              "must equal catalog.totals.rescore (same population)")
    if board_total > totals["rescore"]:
        _fail("rescore_log.cna_board",
              "board rescores exceed catalog.totals.rescore")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "rescore_log.json": _validate_rescore_log,
}
