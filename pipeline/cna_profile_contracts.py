"""Contract for cna_profiles.json (CNA Concentration page, section 04,
CNA profile).

Same philosophy as pipeline/contracts.py — hand-rolled stdlib validators
that fail loudly; registered into the pipeline's dispatch at the bottom
of contracts.py. Beyond shapes it checks the promises the page makes in
its copy: every listed CNA meets the volume floor, ranks are the
competition ranks of the shipped values (1 = highest), the summary's
median is the median CNA of those values, and the window is the last
complete years before the edition.
"""
from __future__ import annotations

import statistics
from typing import Any, Callable

from .contracts import (DATE_RE, _check_generated_at, _check_int, _check_list,
                        _check_num, _check_sorted, _check_str, _fail, _get)

# Hardcoded on purpose: the contract states what the site may rely on,
# independently of the builder's constants.
METRICS = ["score_median", "cwe_pct", "scored_pct", "affected_pct",
           "rejected_pct", "rescores", "kev_pct", "exploit_pct"]
SCORE_BINS = ["0.0-0.9", "1.0-1.9", "2.0-2.9", "3.0-3.9", "4.0-4.9",
              "5.0-5.9", "6.0-6.9", "7.0-7.9", "8.0-8.9", "9.0-10.0"]
COUNT_KEYS = ["scored", "cwe", "affected", "kev", "exploit"]
PCT_FROM_COUNT = {"cwe_pct": "cwe", "scored_pct": "scored",
                  "affected_pct": "affected", "kev_pct": "kev",
                  "exploit_pct": "exploit"}


def _pct(num: int, den: int) -> float:
    return round(100.0 * num / den, 1) if den else 0.0


def _check_value(metric: str, v: Any, path: str) -> None:
    if metric == "rescores":
        _check_int(v, path)
    elif metric == "score_median":
        _check_num(v, path, 0.0, 10.0)
    else:
        _check_num(v, path, 0.0, 100.0)


def _check_bins(bins: Any, path: str) -> int:
    _check_list(bins, path)
    if len(bins) != len(SCORE_BINS):
        _fail(path, f"expected {len(SCORE_BINS)} bins, got {len(bins)}")
    for i, n in enumerate(bins):
        _check_int(n, f"{path}[{i}]")
    return sum(bins)


def _validate_cna_profiles(obj: Any) -> None:
    p = "cna_profiles"
    _check_generated_at(obj, p)
    edition_year = int(obj["generated_at"][:4])

    window = _get(obj, "window", p)
    for k in ("from", "to", "years"):
        _check_int(_get(window, k, f"{p}.window"), f"{p}.window.{k}",
                   minimum=1)
    if window["to"] != edition_year - 1:
        _fail(f"{p}.window.to", f"{window['to']} must be the last complete "
              f"year before the {edition_year} edition")
    if window["to"] - window["from"] + 1 != window["years"]:
        _fail(f"{p}.window", "from/to do not span `years` years")

    min_published = _get(obj, "min_published", p)
    _check_int(min_published, f"{p}.min_published", minimum=1)
    min_scored = _get(obj, "min_scored", p)
    _check_int(min_scored, f"{p}.min_scored", minimum=1)
    if _get(obj, "metrics", p) != METRICS:
        _fail(f"{p}.metrics", f"must be exactly {METRICS}")
    if _get(obj, "score_bins", p) != SCORE_BINS:
        _fail(f"{p}.score_bins", f"must be exactly {SCORE_BINS}")

    pooled = _get(obj, "all", p)
    for k in ("cna_count", "published", "scored"):
        _check_int(_get(pooled, k, f"{p}.all"), f"{p}.all.{k}")
    if pooled["scored"] > pooled["published"]:
        _fail(f"{p}.all.scored", "exceeds published")
    if _check_bins(_get(pooled, "score_bins", f"{p}.all"),
                   f"{p}.all.score_bins") != pooled["scored"]:
        _fail(f"{p}.all.score_bins", "bins do not sum to all.scored")
    median = _get(pooled, "score_median", f"{p}.all")
    if pooled["scored"] == 0:
        if median is not None:
            _fail(f"{p}.all.score_median", "must be null with no scores")
    else:
        _check_num(median, f"{p}.all.score_median", 0.0, 10.0)

    log = _get(obj, "rescore_log", p)
    first = _get(log, "first_observed", f"{p}.rescore_log")
    last = _get(log, "last_observed", f"{p}.rescore_log")
    _check_int(_get(log, "rescores", f"{p}.rescore_log"),
               f"{p}.rescore_log.rescores")
    if (first is None) != (last is None):
        _fail(f"{p}.rescore_log", "first/last_observed must both be set "
              "or both be null")
    if first is not None:
        _check_str(first, f"{p}.rescore_log.first_observed", DATE_RE)
        _check_str(last, f"{p}.rescore_log.last_observed", DATE_RE)
        if first > last:
            _fail(f"{p}.rescore_log", "first_observed after last_observed")

    rows = _check_list(_get(obj, "cnas", p), f"{p}.cnas")
    seen: set[str] = set()
    for i, row in enumerate(rows):
        path = f"{p}.cnas[{i}]"
        cna = _get(row, "cna", path)
        _check_str(cna, f"{path}.cna")
        if cna in seen:
            _fail(f"{path}.cna", f"duplicate CNA {cna!r}")
        seen.add(cna)
        n = _get(row, "published", path)
        # min_published is the promise the picker makes.
        _check_int(n, f"{path}.published", minimum=min_published)
        _check_int(_get(row, "rejected", path), f"{path}.rejected")
        counts = _get(row, "counts", path)
        for k in COUNT_KEYS:
            _check_int(_get(counts, k, f"{path}.counts"),
                       f"{path}.counts.{k}")
            if counts[k] > n:
                _fail(f"{path}.counts.{k}", f"{counts[k]} exceeds "
                      f"{n} published")
        if _check_bins(_get(row, "score_bins", path),
                       f"{path}.score_bins") != counts["scored"]:
            _fail(f"{path}.score_bins", "bins do not sum to counts.scored")
        values = _get(row, "values", path)
        ranks = _get(row, "ranks", path)
        for m in METRICS:
            v = _get(values, m, f"{path}.values")
            r = _get(ranks, m, f"{path}.ranks")
            if v is None:
                if m != "score_median" or counts["scored"] >= min_scored:
                    _fail(f"{path}.values.{m}", "unexpected null")
                if r is not None:
                    _fail(f"{path}.ranks.{m}", "an unranked value has a rank")
                continue
            if m == "score_median" and counts["scored"] < min_scored:
                _fail(f"{path}.values.{m}", f"set on fewer than "
                      f"{min_scored} scored records")
            _check_value(m, v, f"{path}.values.{m}")
            _check_int(r, f"{path}.ranks.{m}", minimum=1)
        for m, k in PCT_FROM_COUNT.items():
            if values[m] != _pct(counts[k], n):
                _fail(f"{path}.values.{m}", f"{values[m]} is not "
                      f"{counts[k]}/{n}")
        if values["rejected_pct"] != _pct(row["rejected"],
                                          n + row["rejected"]):
            _fail(f"{path}.values.rejected_pct",
                  "is not rejected / (published + rejected)")
    _check_sorted([r["published"] for r in rows], f"{p}.cnas (by published)",
                  descending=True)

    summary = _get(obj, "summary", p)
    for m in METRICS:
        path = f"{p}.summary.{m}"
        block = _get(summary, m, f"{p}.summary")
        vals = [r["values"][m] for r in rows if r["values"][m] is not None]
        _check_int(_get(block, "n", path), f"{path}.n")
        if block["n"] != len(vals):
            _fail(f"{path}.n", f"{block['n']} != {len(vals)} ranked CNAs")
        stats = [_get(block, k, path)
                 for k in ("min", "p25", "median", "p75", "max")]
        if not vals:
            if any(s is not None for s in stats):
                _fail(path, "must be null with no ranked CNAs")
            continue
        for k, s in zip(("min", "p25", "median", "p75", "max"), stats):
            _check_num(s, f"{path}.{k}", 0.0, float("inf"))
        _check_sorted(stats, f"{path} (min <= p25 <= median <= p75 <= max)")
        if round(float(statistics.median(vals)), 1) != block["median"]:
            _fail(f"{path}.median", "is not the median CNA's value")
        for row in rows:
            v, r = row["values"][m], row["ranks"][m]
            if v is not None and r != 1 + sum(1 for x in vals if x > v):
                _fail(f"{p}.cnas[{row['cna']}].ranks.{m}",
                      f"rank {r} is not the competition rank of {v}")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "cna_profiles.json": _validate_cna_profiles,
}
