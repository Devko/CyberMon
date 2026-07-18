"""Contract for the CNA Roster History output (cna_roster.json).

Same philosophy as pipeline/contracts.py — a hand-rolled stdlib validator
that fails loudly — kept in its own module so this stage lands without
touching the core contracts file (mirrors rescore_contracts and friends).
The coordinator merges :data:`VALIDATORS` into the pipeline's dispatch;
failures raise the same :class:`pipeline.contracts.ContractViolation`.

The internal-consistency checks are deliberately strong: roster_size,
roster_flux and roster_mix each derive from the committed record, so their
totals MUST agree — a mismatch means the builder (or the record) broke.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .contracts import (DATE_RE, _check_generated_at, _check_int,
                        _check_list, _check_sorted, _check_str, _fail, _get)

# Must match cna_roster.CHANGE_TYPES. Hardcoded here on purpose (the
# calendar_contracts precedent): the contract states what the site may rely
# on, independently of the builder.
CHANGE_TYPES = ("onboarded", "departed", "scope_changed")
MONTH_RE = re.compile(r"^\d{4}-\d{2}$")


def _check_signed_int(v: Any, path: str) -> None:
    if isinstance(v, bool) or not isinstance(v, int):
        _fail(path, f"expected integer, got {v!r}")


def _check_breakdown(obj: Any, path: str, *, total: int,
                     partition: bool) -> None:
    """A ``[{label, n}]`` breakdown: non-empty labels, unique within the
    breakdown, counts >= 1, sorted by count descending. ``partition`` breakdowns
    (one bucket per org) must sum to ``total``; flattened ones (an org may fall
    in several buckets) only cap each bucket at ``total``."""
    entries = _check_list(obj, path)
    labels: set[str] = set()
    counts: list[int] = []
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
        if n > total:
            _fail(f"{p}.n", f"bucket count {n} exceeds roster total {total}")
        counts.append(n)
        running += n
    _check_sorted(counts, f"{path} (by n)", descending=True)
    if partition and running != total:
        _fail(path, f"partition sums to {running}, roster total is {total}")


def _validate_cna_roster(obj: Any) -> None:
    _check_generated_at(obj, "cna_roster")

    # ---- roster_mix (today's composition — real from day one) ----------------
    mix = _get(obj, "roster_mix", "cna_roster")
    total = _get(mix, "total", "cna_roster.roster_mix")
    _check_int(total, "cna_roster.roster_mix.total", minimum=1)
    _check_breakdown(_get(mix, "by_type", "cna_roster.roster_mix"),
                     "cna_roster.roster_mix.by_type", total=total,
                     partition=False)
    for key in ("by_tlr", "by_root", "by_country"):
        _check_breakdown(_get(mix, key, "cna_roster.roster_mix"),
                         f"cna_roster.roster_mix.{key}", total=total,
                         partition=True)

    # ---- roster_size (committed size history — thin at launch) ---------------
    size = _get(obj, "roster_size", "cna_roster")
    min_n = _get(size, "min_n", "cna_roster.roster_size")
    _check_int(min_n, "cna_roster.roster_size.min_n", minimum=1)
    series = _check_list(_get(size, "series", "cna_roster.roster_size"),
                         "cna_roster.roster_size.series")
    dates: list[str] = []
    sizes: list[int] = []
    for i, pt in enumerate(series):
        p = f"cna_roster.roster_size.series[{i}]"
        date = _get(pt, "date", p)
        _check_str(date, f"{p}.date", DATE_RE)
        _check_int(_get(pt, "size", p), f"{p}.size")
        dates.append(date)
        sizes.append(pt["size"])
    _check_sorted(dates, "cna_roster.roster_size.series (by date)")
    if len(set(dates)) != len(dates):
        _fail("cna_roster.roster_size.series", "duplicate observation dates")
    current = _get(size, "current", "cna_roster.roster_size")
    _check_int(current, "cna_roster.roster_size.current")
    first_obs = _get(size, "first_observed", "cna_roster.roster_size")
    net = _get(size, "net_change", "cna_roster.roster_size")
    if series:
        if current != sizes[-1]:
            _fail("cna_roster.roster_size.current",
                  "must equal the last series size")
        if first_obs != dates[0]:
            _fail("cna_roster.roster_size.first_observed",
                  "must equal the first series date")
        gated = len(series) < min_n
        if (net is None) != gated:
            _fail("cna_roster.roster_size.net_change",
                  "must be null exactly when the series is below min_n points")
        if net is not None:
            _check_signed_int(net, "cna_roster.roster_size.net_change")
            if net != sizes[-1] - sizes[0]:
                _fail("cna_roster.roster_size.net_change",
                      "must equal last size minus first size")
    else:
        if first_obs is not None:
            _fail("cna_roster.roster_size.first_observed",
                  "must be null when the series is empty")
        if net is not None:
            _fail("cna_roster.roster_size.net_change",
                  "must be null when the series is empty")

    # ---- roster_flux (the event log — empty at launch) -----------------------
    flux = _get(obj, "roster_flux", "cna_roster")
    totals = _get(flux, "totals", "cna_roster.roster_flux")
    if set(totals) != set(CHANGE_TYPES):
        _fail("cna_roster.roster_flux.totals",
              f"must carry exactly the keys {sorted(CHANGE_TYPES)}")
    for t in CHANGE_TYPES:
        _check_int(totals[t], f"cna_roster.roster_flux.totals.{t}")
    events_total = _get(flux, "events_total", "cna_roster.roster_flux")
    _check_int(events_total, "cna_roster.roster_flux.events_total")
    if sum(totals.values()) != events_total:
        _fail("cna_roster.roster_flux.events_total",
              f"totals sum to {sum(totals.values())}, "
              f"events_total is {events_total}")
    months = _check_list(_get(flux, "months", "cna_roster.roster_flux"),
                         "cna_roster.roster_flux.months")
    labels: list[str] = []
    month_sums = dict.fromkeys(CHANGE_TYPES, 0)
    for i, m in enumerate(months):
        p = f"cna_roster.roster_flux.months[{i}]"
        label = _get(m, "month", p)
        _check_str(label, f"{p}.month", MONTH_RE)
        labels.append(label)
        for t in CHANGE_TYPES:
            v = _get(m, t, p)
            _check_int(v, f"{p}.{t}")
            month_sums[t] += v
    _check_sorted(labels, "cna_roster.roster_flux.months")
    if len(set(labels)) != len(labels):
        _fail("cna_roster.roster_flux.months", "duplicate month labels")
    for t in CHANGE_TYPES:
        if month_sums[t] != totals[t]:
            _fail("cna_roster.roster_flux.months",
                  f"monthly {t} counts must sum to totals.{t}")
    first_flux = _get(flux, "first_observed", "cna_roster.roster_flux")
    if (first_flux is None) != (events_total == 0):
        _fail("cna_roster.roster_flux.first_observed",
              "must be null exactly when the log is empty")
    if first_flux is not None:
        _check_str(first_flux, "cna_roster.roster_flux.first_observed", DATE_RE)

    # ---- headline (summarizes the composition; always present) ---------------
    headline = _get(obj, "headline", "cna_roster")
    for k in ("roster_total", "top_type_n", "country_count", "root_count",
              "mitre_n", "cisa_n"):
        _check_int(_get(headline, k, "cna_roster.headline"),
                   f"cna_roster.headline.{k}")
    _check_str(_get(headline, "top_type", "cna_roster.headline"),
               "cna_roster.headline.top_type")
    if headline["roster_total"] != total:
        _fail("cna_roster.headline.roster_total",
              "must equal roster_mix.total")
    by_type = mix["by_type"]
    if headline["top_type"] != by_type[0]["label"]:
        _fail("cna_roster.headline.top_type", "must equal by_type[0].label")
    if headline["top_type_n"] != by_type[0]["n"]:
        _fail("cna_roster.headline.top_type_n", "must equal by_type[0].n")
    if headline["country_count"] != len(mix["by_country"]):
        _fail("cna_roster.headline.country_count",
              "must equal the number of country buckets")
    if headline["mitre_n"] + headline["cisa_n"] > total:
        _fail("cna_roster.headline",
              "mitre_n + cisa_n cannot exceed the roster total")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "cna_roster.json": _validate_cna_roster,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the roster contract for ``filename``.

    Raises :class:`pipeline.contracts.ContractViolation` on any mismatch,
    ``KeyError`` if the filename has no roster contract.
    """
    VALIDATORS[filename](obj)
