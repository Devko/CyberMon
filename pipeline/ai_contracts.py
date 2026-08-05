"""Contract for the AI Alibi output (ai_alibi.json).

Hand-rolled stdlib validator, own module (the poc_contracts /
roster_contracts precedent), merged into pipeline/contracts.py's dispatch.

Module-specific rules beyond the shared helpers:

* **the timeline is checked against its own vocabulary** — every
  milestone ``kind`` must be one the module knows how to render and
  every row must carry a source URL, so an un-cited or un-renderable
  entry fails the build instead of shipping as a bare marker;
* **month-precision rows must plot mid-month** — the derived
  ``plot_date`` is re-derived here and compared, so a hand-edit to
  ai_timeline_data.py can never silently move a marker;
* **era cutoffs may not straddle** — ``cut_year`` must be exactly the
  year before the era date, the rule that keeps the pre/post split
  honest, and eras must be chronological with exactly one default;
* **levels may legitimately be NEGATIVE and shares may exceed 100** —
  the gap metric measures exploit code that predates the CVE record, and
  ``pct_banked`` above 100 means the pre-era level had already travelled
  further than the era ever did. Both are range-checked as plain bounded
  numbers rather than through the share helpers;
* **verdict arithmetic is enforced** — ``insufficient`` is the ONLY
  verdict allowed to carry a missing level or a post-window shorter than
  the module's minimum, and a judged cell must have ``era_shift`` equal
  to ``post - pre``. A violation means the builder's guards broke, and
  publishing it would print a verdict nothing backs.
"""
from __future__ import annotations

from typing import Any, Callable

from .ai_metrics import MIN_POST_YEARS, cut_year_for
from .ai_timeline_data import ERAS, VALID_KINDS
from .contracts import (_check_generated_at, _check_int, _check_list,
                        _check_num, _check_sorted, _check_str, _fail, _get)

# Widest plausible level for a days-unit metric (the corpus spans ~40
# years); percent-unit levels are bounded 0-100 by their own nature.
_DAYS_LIMIT = 20000.0
# pct_banked is a ratio of travelled distances: over 100 is meaningful,
# far outside this band means the denominator was noise after all.
_BANKED_LIMIT = 1000.0

_VERDICTS = frozenset(
    {"accelerated", "decelerated", "no_inflection", "insufficient"})
_UNITS = frozenset({"days", "percent"})
_PRECISION = frozenset({"day", "month"})
_FASTER = frozenset({"up", "down"})


def _check_level(obj: Any, path: str, unit: str) -> float | None:
    """One era level: a value (or None when withheld) plus its audit
    trail of contributing years and matched CVEs."""
    value = _get(obj, "value", path)
    years = _get(obj, "years", path)
    n = _get(obj, "n", path)
    _check_int(years, f"{path}.years", minimum=0)
    _check_int(n, f"{path}.n", minimum=0)
    if value is None:
        if years:
            _fail(f"{path}.value",
                  f"withheld level must have no contributing years, got "
                  f"{years}")
        return None
    if not years:
        _fail(f"{path}.years", "a level with a value needs >= 1 year")
    if unit == "days":
        _check_num(value, f"{path}.value", -_DAYS_LIMIT, _DAYS_LIMIT)
    else:
        _check_num(value, f"{path}.value", 0.0, 100.0)
    return float(value)


def _validate_ai_alibi(obj: Any) -> None:
    _check_generated_at(obj, "ai_alibi")

    # ---- eras -------------------------------------------------------------
    eras = _check_list(_get(obj, "eras", "ai_alibi"), "ai_alibi.eras")
    if len(eras) != len(ERAS):
        _fail("ai_alibi.eras",
              f"expected {len(ERAS)} eras (ai_timeline_data.ERAS), "
              f"got {len(eras)}")
    known = {e.id: e for e in ERAS}
    era_ids, cut_years, defaults = [], [], 0
    for i, row in enumerate(eras):
        path = f"ai_alibi.eras[{i}]"
        era_id = _get(row, "id", path)
        _check_str(era_id, f"{path}.id")
        if era_id not in known:
            _fail(f"{path}.id", f"unknown era {era_id!r}")
        era_ids.append(era_id)
        for key in ("label", "date", "caption"):
            _check_str(_get(row, key, path), f"{path}.{key}")
        cut = _get(row, "cut_year", path)
        _check_int(cut, f"{path}.cut_year", minimum=1988)
        # The no-straddle rule, re-derived rather than trusted.
        expected = cut_year_for(known[era_id])
        if cut != expected:
            _fail(f"{path}.cut_year",
                  f"era {era_id!r} dated {row['date']} must cut at "
                  f"{expected} (the last year ending before it), got {cut}")
        cut_years.append(cut)
        if not isinstance(_get(row, "default", path), bool):
            _fail(f"{path}.default", "must be a bool")
        defaults += bool(row["default"])
    if defaults != 1:
        _fail("ai_alibi.eras",
              f"exactly one era must be the default, found {defaults}")
    _check_sorted(cut_years, "ai_alibi.eras")

    # ---- milestones -------------------------------------------------------
    ms = _check_list(_get(obj, "milestones", "ai_alibi"), "ai_alibi.milestones")
    if not ms:
        _fail("ai_alibi.milestones", "the timeline overlay may not be empty")
    plot_dates = []
    for i, row in enumerate(ms):
        path = f"ai_alibi.milestones[{i}]"
        for key in ("date", "plot_date", "precision", "kind", "label", "note",
                    "source"):
            _check_str(_get(row, key, path), f"{path}.{key}")
        if row["precision"] not in _PRECISION:
            _fail(f"{path}.precision", f"unknown precision "
                                       f"{row['precision']!r}")
        if row["kind"] not in VALID_KINDS:
            _fail(f"{path}.kind", f"unknown kind {row['kind']!r}")
        # Every row is a citation or it is not a row.
        if not row["source"].startswith("https://"):
            _fail(f"{path}.source",
                  f"every milestone needs an https source URL, got "
                  f"{row['source']!r}")
        # plot_date is DERIVED — re-derive it so a hand-edit to the
        # committed table can never silently move a marker.
        expected = row["date"] if row["precision"] == "day" \
            else f"{row['date']}-15"
        if row["plot_date"] != expected:
            _fail(f"{path}.plot_date",
                  f"{row['precision']}-precision {row['date']!r} must plot "
                  f"at {expected!r}, got {row['plot_date']!r}")
        if len(row["plot_date"]) != 10:
            _fail(f"{path}.plot_date", "must be a YYYY-MM-DD date")
        plot_dates.append(row["plot_date"])
    _check_sorted(plot_dates, "ai_alibi.milestones")

    # ---- clock ------------------------------------------------------------
    clock = _get(obj, "clock", "ai_alibi")
    _check_str(_get(clock, "source_file", "ai_alibi.clock"),
               "ai_alibi.clock.source_file")
    first_year = _get(clock, "first_year", "ai_alibi.clock")
    last_year = _get(clock, "last_year", "ai_alibi.clock")
    _check_int(first_year, "ai_alibi.clock.first_year", minimum=0)
    _check_int(last_year, "ai_alibi.clock.last_year", minimum=0)
    if last_year < first_year:
        _fail("ai_alibi.clock.last_year",
              f"last_year ({last_year}) precedes first_year ({first_year})")

    metrics = _check_list(_get(clock, "metrics", "ai_alibi.clock"),
                          "ai_alibi.clock.metrics")
    if not metrics:
        _fail("ai_alibi.clock.metrics", "no clock metric survived")
    units: dict[str, str] = {}
    by_metric: dict[str, dict[int, float]] = {}
    for i, m in enumerate(metrics):
        path = f"ai_alibi.clock.metrics[{i}]"
        mid = _get(m, "id", path)
        _check_str(mid, f"{path}.id")
        _check_str(_get(m, "label", path), f"{path}.label")
        unit = _get(m, "unit", path)
        if unit not in _UNITS:
            _fail(f"{path}.unit", f"unknown unit {unit!r}")
        if _get(m, "faster", path) not in _FASTER:
            _fail(f"{path}.faster", f"unknown direction {m['faster']!r}")
        units[mid] = unit
        rows = _check_list(_get(m, "years", path), f"{path}.years")
        seen = []
        for j, r in enumerate(rows):
            rpath = f"{path}.years[{j}]"
            year = _get(r, "year", rpath)
            _check_int(year, f"{rpath}.year", minimum=1988)
            seen.append(year)
            _check_int(_get(r, "n", rpath), f"{rpath}.n", minimum=1)
            value = _get(r, "value", rpath)
            if unit == "days":
                _check_num(value, f"{rpath}.value", -_DAYS_LIMIT, _DAYS_LIMIT)
            else:
                _check_num(value, f"{rpath}.value", 0.0, 100.0)
        _check_sorted(seen, f"{path}.years")
        if len(set(seen)) != len(seen):
            _fail(f"{path}.years", "duplicate years")
        if seen and (seen[0] != first_year or seen[-1] != last_year):
            _fail(f"{path}.years",
                  f"metric {mid!r} spans {seen[0]}-{seen[-1]}, but the clock "
                  f"declares {first_year}-{last_year} — every metric shares "
                  f"one cohort and must share one span")
        by_metric[mid] = {r["year"]: r["value"] for r in rows}

    # poc_negative (gap < 0) is a strict SUBSET of poc_week (gap <= 7), so
    # its share can never exceed poc_week's in any year. The page leans on
    # that nesting when it tells readers these are not independent tests;
    # a violation means the upstream fields drifted apart and the claim
    # would silently become false.
    neg, week = by_metric.get("poc_negative"), by_metric.get("poc_week")
    if neg and week:
        for year in sorted(set(neg) & set(week)):
            if neg[year] > week[year] + 0.05:
                _fail("ai_alibi.clock.metrics",
                      f"{year}: poc_negative ({neg[year]}%) exceeds poc_week "
                      f"({week[year]}%), but every negative gap is also "
                      f"<= 7 days — the two fields have drifted apart")

    # ---- banked -----------------------------------------------------------
    banked = _get(obj, "banked", "ai_alibi")
    _check_int(_get(banked, "window_years", "ai_alibi.banked"),
               "ai_alibi.banked.window_years", minimum=1)
    _check_num(_get(banked, "inflection_threshold_pct", "ai_alibi.banked"),
               "ai_alibi.banked.inflection_threshold_pct", 0.0, 100.0)
    bmetrics = _check_list(_get(banked, "metrics", "ai_alibi.banked"),
                           "ai_alibi.banked.metrics")
    for i, m in enumerate(bmetrics):
        path = f"ai_alibi.banked.metrics[{i}]"
        mid = _get(m, "id", path)
        _check_str(mid, f"{path}.id")
        if mid not in units:
            _fail(f"{path}.id",
                  f"banked metric {mid!r} has no clock series to rest on")
        unit = _get(m, "unit", path)
        if unit != units[mid]:
            _fail(f"{path}.unit",
                  f"unit {unit!r} disagrees with the clock's "
                  f"{units[mid]!r} for {mid!r}")
        _check_str(_get(m, "label", path), f"{path}.label")
        if _get(m, "faster", path) not in _FASTER:
            _fail(f"{path}.faster", f"unknown direction {m['faster']!r}")

        blocks = _check_list(_get(m, "eras", path), f"{path}.eras")
        if [b.get("era") for b in blocks] != era_ids:
            _fail(f"{path}.eras",
                  f"every metric must be judged against all eras in order "
                  f"{era_ids}, got {[b.get('era') for b in blocks]}")
        for j, b in enumerate(blocks):
            bpath = f"{path}.eras[{j}]"
            _check_int(_get(b, "cut_year", bpath), f"{bpath}.cut_year",
                       minimum=1988)
            if b["cut_year"] != cut_years[j]:
                _fail(f"{bpath}.cut_year",
                      f"must equal the era's own cut_year ({cut_years[j]})")
            early = _check_level(_get(b, "early", bpath), f"{bpath}.early",
                                 unit)
            pre = _check_level(_get(b, "pre", bpath), f"{bpath}.pre", unit)
            post_obj = _get(b, "post", bpath)
            post = _check_level(post_obj, f"{bpath}.post", unit)

            verdict = _get(b, "verdict", bpath)
            _check_str(verdict, f"{bpath}.verdict")
            if verdict not in _VERDICTS:
                _fail(f"{bpath}.verdict", f"unknown verdict {verdict!r}")

            shift = _get(b, "era_shift", bpath)
            pct = _get(b, "pct_banked", bpath)
            share = _get(b, "shift_share_pct", bpath)
            missing = early is None or pre is None or post is None
            thin = int(post_obj["years"]) < MIN_POST_YEARS

            if verdict == "insufficient":
                if not (missing or thin):
                    _fail(f"{bpath}.verdict",
                          f"'insufficient' needs a missing level or a "
                          f"post window under {MIN_POST_YEARS} years; this "
                          f"cell has neither")
                if pct is not None or share is not None:
                    _fail(f"{bpath}.pct_banked",
                          "an unjudged cell may not carry a banked share")
            else:
                if missing:
                    _fail(f"{bpath}.verdict",
                          f"verdict {verdict!r} rests on a missing level")
                if thin:
                    _fail(f"{bpath}.verdict",
                          f"verdict {verdict!r} rests on "
                          f"{post_obj['years']} post-cutoff year(s), under "
                          f"the {MIN_POST_YEARS}-year minimum")
                _check_num(shift, f"{bpath}.era_shift",
                           -_DAYS_LIMIT, _DAYS_LIMIT)
                if abs(float(shift) - (post - pre)) > 0.15:
                    _fail(f"{bpath}.era_shift",
                          f"era_shift ({shift}) must equal post - pre "
                          f"({post} - {pre})")
                if pct is not None:
                    _check_num(pct, f"{bpath}.pct_banked",
                               -_BANKED_LIMIT, _BANKED_LIMIT)
                if share is not None:
                    _check_num(share, f"{bpath}.shift_share_pct",
                               -_BANKED_LIMIT, _BANKED_LIMIT)
                    # The sign IS the finding — a chart reads it without
                    # knowing which direction is bad for which metric, so
                    # it may never disagree with the verdict that names
                    # that direction in words.
                    if verdict == "accelerated" and share <= 0:
                        _fail(f"{bpath}.shift_share_pct",
                              f"'accelerated' needs a positive (toward "
                              f"faster) share, got {share}")
                    if verdict == "decelerated" and share >= 0:
                        _fail(f"{bpath}.shift_share_pct",
                              f"'decelerated' needs a negative (toward "
                              f"slower) share, got {share}")

    # ---- attention --------------------------------------------------------
    att = _get(obj, "attention", "ai_alibi")
    available = _get(att, "available", "ai_alibi.attention")
    if not isinstance(available, bool):
        _fail("ai_alibi.attention.available", "must be a bool")
    _check_int(_get(att, "window_months", "ai_alibi.attention"),
               "ai_alibi.attention.window_months", minimum=0)
    terms = _check_list(_get(att, "terms", "ai_alibi.attention"),
                        "ai_alibi.attention.terms")
    if not available and terms:
        _fail("ai_alibi.attention.terms",
              "an unavailable attention section may not carry terms")
    for i, t in enumerate(terms):
        path = f"ai_alibi.attention.terms[{i}]"
        _check_str(_get(t, "id", path), f"{path}.id")
        _check_str(_get(t, "label", path), f"{path}.label")
        months = _check_list(_get(t, "months", path), f"{path}.months")
        if not months:
            _fail(f"{path}.months", "a charted term needs at least one month")
        seen_m = []
        for j, p in enumerate(months):
            ppath = f"{path}.months[{j}]"
            month = _get(p, "month", ppath)
            _check_str(month, f"{ppath}.month")
            if len(month) != 7 or month[4] != "-":
                _fail(f"{ppath}.month", f"must be YYYY-MM, got {month!r}")
            seen_m.append(month)
            _check_num(_get(p, "index", ppath), f"{ppath}.index", 0.0, 100.0)
            _check_int(_get(p, "sources", ppath), f"{ppath}.sources",
                       minimum=1)
        _check_sorted(seen_m, f"{path}.months")
        if len(set(seen_m)) != len(seen_m):
            _fail(f"{path}.months", "duplicate months")

    crows = _check_list(_get(att, "clock", "ai_alibi.attention"),
                        "ai_alibi.attention.clock")
    cyears = []
    for i, r in enumerate(crows):
        path = f"ai_alibi.attention.clock[{i}]"
        year = _get(r, "year", path)
        _check_int(year, f"{path}.year", minimum=1988)
        cyears.append(year)
        _check_num(_get(r, "value", path), f"{path}.value",
                   -_DAYS_LIMIT, _DAYS_LIMIT)
    _check_sorted(cyears, "ai_alibi.attention.clock")

    head_att = att.get("headline")
    if head_att is not None:
        path = "ai_alibi.attention.headline"
        _check_str(_get(head_att, "term_id", path), f"{path}.term_id")
        _check_str(_get(head_att, "label", path), f"{path}.label")
        for key in ("index_first", "index_last"):
            _check_num(_get(head_att, key, path), f"{path}.{key}", 0.0, 100.0)
        for key in ("clock_min", "clock_max", "clock_mean"):
            _check_num(_get(head_att, key, path), f"{path}.{key}",
                       -_DAYS_LIMIT, _DAYS_LIMIT)
        if head_att["clock_min"] > head_att["clock_max"]:
            _fail(f"{path}.clock_min", "clock_min exceeds clock_max")

    # ---- headline ---------------------------------------------------------
    head = _get(obj, "headline", "ai_alibi")
    path = "ai_alibi.headline"
    era_id = _get(head, "era", path)
    if era_id not in era_ids:
        _fail(f"{path}.era", f"unknown era {era_id!r}")
    _check_str(_get(head, "era_label", path), f"{path}.era_label")
    _check_int(_get(head, "cut_year", path), f"{path}.cut_year", minimum=1988)
    if _get(head, "verdict", path) not in _VERDICTS:
        _fail(f"{path}.verdict", f"unknown verdict {head['verdict']!r}")
    for key in ("milestones", "no_uplift_reports", "cells", "judged",
                "accelerated", "decelerated", "no_inflection"):
        _check_int(_get(head, key, path), f"{path}.{key}", minimum=0)
    if head["milestones"] != len(ms):
        _fail(f"{path}.milestones",
              f"must equal the timeline length ({len(ms)})")
    if head["judged"] > head["cells"]:
        _fail(f"{path}.judged", "judged cells cannot exceed total cells")
    tally = head["accelerated"] + head["decelerated"] + head["no_inflection"]
    if tally != head["judged"]:
        _fail(f"{path}.judged",
              f"accelerated + decelerated + no_inflection ({tally}) must "
              f"equal judged ({head['judged']})")
    _check_num(_get(head, "pct_accelerated", path), f"{path}.pct_accelerated",
               0.0, 100.0)
    if head.get("pct_banked") is not None:
        _check_num(head["pct_banked"], f"{path}.pct_banked",
                   -_BANKED_LIMIT, _BANKED_LIMIT)


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "ai_alibi.json": _validate_ai_alibi,
}
