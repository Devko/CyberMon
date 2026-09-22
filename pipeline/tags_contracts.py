"""Contracts for cve_tags.json (module 23, Record Tags) and cvss_v4.json
(module 01, CVSS 4.0 adoption section).

Same philosophy as pipeline/contracts.py — hand-rolled stdlib validators
that fail loudly — kept in their own module so the two corpus-pass outputs
land without growing the core contracts file. The coordinator merges
:data:`VALIDATORS` into the pipeline's dispatch; failures raise the same
:class:`pipeline.contracts.ContractViolation` type.

Both files may be EMPTY-shaped (no tagged years, no v4 months) on a corpus
that carries none — the site renders its "not enough data yet" card — but
every key is always present.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .contracts import (_check_generated_at, _check_int, _check_list,
                        _check_num, _check_sorted, _check_str, _fail, _get)

# Hardcoded on purpose (as market_contracts hardcodes SOURCES): the contract
# states what the site may rely on, independently of the builder constants.
SCHEMA_TAGS = ["unsupported-when-assigned", "disputed",
               "exclusively-hosted-service"]
BOARD_TAGS = ["unsupported-when-assigned", "disputed"]
SEVERITY_KEYS = ["critical", "high", "medium", "low", "unscored"]
V4_CLASSES = ["v4_only", "both", "v3_only", "neither"]
MONTH_RE = re.compile(r"^\d{4}-(?:0[1-9]|1[0-2])$")


def _check_severity_counts(obj: Any, path: str) -> int:
    for k in SEVERITY_KEYS:
        _check_int(_get(obj, k, path), f"{path}.{k}")
    return sum(obj[k] for k in SEVERITY_KEYS)


def _check_top_sorted(rows: list, key: str, path: str) -> None:
    _check_sorted([r[key] for r in rows], f"{path} (by {key})",
                  descending=True)


# ------------------------------------------------------------ cve_tags.json

def _validate_cve_tags(obj: Any) -> None:
    p = "cve_tags"
    _check_generated_at(obj, p)
    if _get(obj, "schema_tags", p) != SCHEMA_TAGS:
        _fail(f"{p}.schema_tags", f"must be exactly {SCHEMA_TAGS}")

    rows = _check_list(_get(obj, "years", p), f"{p}.years")
    years = []
    for i, row in enumerate(rows):
        path = f"{p}.years[{i}]"
        year = _get(row, "year", path)
        _check_int(year, f"{path}.year", minimum=1990)
        published = _get(row, "published", path)
        _check_int(published, f"{path}.published")
        counts = _get(row, "counts", path)
        for tag in SCHEMA_TAGS:
            n = _get(counts, tag, f"{path}.counts")
            _check_int(n, f"{path}.counts.{tag}")
            if n > published:
                _fail(f"{path}.counts.{tag}",
                      f"{n} tagged exceeds {published} published")
        years.append(year)
    _check_sorted(years, f"{p}.years")
    if years and years != list(range(years[0], years[-1] + 1)):
        _fail(f"{p}.years", "years must be contiguous (gap-filled)")

    window = _get(obj, "window", p)
    for k in ("from", "to", "years"):
        _check_int(_get(window, k, f"{p}.window"), f"{p}.window.{k}")

    boards = _get(obj, "boards", p)
    for tag in BOARD_TAGS:
        path = f"{p}.boards.{tag}"
        board = _get(boards, tag, f"{p}.boards")
        total = _get(board, "total", path)
        _check_int(total, f"{path}.total")
        for k in ("cna_count", "active_cnas"):
            _check_int(_get(board, k, path), f"{path}.{k}")
        _check_int(_get(board, "min_n", path), f"{path}.min_n", minimum=1)
        for k in ("top1_share_pct", "top3_share_pct"):
            _check_num(_get(board, k, path), f"{path}.{k}", 0.0, 100.0)
        cnas = _check_list(_get(board, "cnas", path), f"{path}.cnas")
        for j, r in enumerate(cnas):
            rp = f"{path}.cnas[{j}]"
            _check_str(_get(r, "cna", rp), f"{rp}.cna")
            _check_int(_get(r, "n", rp), f"{rp}.n", minimum=board["min_n"])
            _check_int(_get(r, "cna_published", rp), f"{rp}.cna_published")
            for k in ("share_pct", "rate_pct"):
                _check_num(_get(r, k, rp), f"{rp}.{k}", 0.0, 100.0)
            if r["n"] > r["cna_published"]:
                _fail(f"{rp}.n", "tagged records exceed the CNA's published")
        _check_top_sorted(cnas, "n", f"{path}.cnas")

    sev = _get(obj, "severity", p)
    _check_severity_counts(_get(sev, "all", f"{p}.severity"),
                           f"{p}.severity.all")
    for tag in BOARD_TAGS:
        block = _get(sev, tag, f"{p}.severity")
        tagged = _check_severity_counts(
            _get(block, "tagged", f"{p}.severity.{tag}"),
            f"{p}.severity.{tag}.tagged")
        _check_severity_counts(
            _get(block, "same_cnas_untagged", f"{p}.severity.{tag}"),
            f"{p}.severity.{tag}.same_cnas_untagged")
        if tagged != boards[tag]["total"]:
            _fail(f"{p}.severity.{tag}.tagged",
                  f"{tagged} tagged records vs board total "
                  f"{boards[tag]['total']} (same window, same records)")

    ctx = _get(obj, "context", p)
    for key in ("private_tags", "adp_tags"):
        items = _check_list(_get(ctx, key, f"{p}.context"),
                            f"{p}.context.{key}")
        for j, r in enumerate(items):
            _check_str(_get(r, "tag", f"{p}.context.{key}[{j}]"),
                       f"{p}.context.{key}[{j}].tag")
            _check_int(_get(r, "n", f"{p}.context.{key}[{j}]"),
                       f"{p}.context.{key}[{j}].n", minimum=1)
        _check_top_sorted(items, "n", f"{p}.context.{key}")
    _check_int(_get(ctx, "private_tag_count", f"{p}.context"),
               f"{p}.context.private_tag_count")
    totals = _get(ctx, "schema_totals", f"{p}.context")
    for tag in SCHEMA_TAGS:
        _check_int(_get(totals, tag, f"{p}.context.schema_totals"),
                   f"{p}.context.schema_totals.{tag}")

    head = _get(obj, "headline", p)
    for k in ("latest_year", "unsupported_first_year", "unsupported_first",
              "unsupported_latest", "current_year", "unsupported_current",
              "disputed_from", "disputed_to", "disputed_min", "disputed_max"):
        _check_int(_get(head, k, f"{p}.headline"), f"{p}.headline.{k}")
    for k in ("unsupported_latest_share_pct", "disputed_share_pct"):
        _check_num(_get(head, k, f"{p}.headline"), f"{p}.headline.{k}",
                   0.0, 100.0)
    if head["disputed_min"] > head["disputed_max"]:
        _fail(f"{p}.headline", "disputed_min exceeds disputed_max")


# ------------------------------------------------------------- cvss_v4.json

def _check_class_row(row: Any, path: str) -> None:
    published = _get(row, "published", path)
    _check_int(published, f"{path}.published")
    for k in V4_CLASSES:
        _check_int(_get(row, k, path), f"{path}.{k}")
    if sum(row[k] for k in V4_CLASSES) != published:
        _fail(path, "coverage classes must partition published")


def _validate_cvss_v4(obj: Any) -> None:
    p = "cvss_v4"
    _check_generated_at(obj, p)
    _check_str(_get(obj, "since_month", p), f"{p}.since_month", MONTH_RE)
    if _get(obj, "container", p) != "cna":
        _fail(f"{p}.container", "must be 'cna' (coverage is CNA-scored)")
    if _get(obj, "classes", p) != V4_CLASSES:
        _fail(f"{p}.classes", f"must be exactly {V4_CLASSES}")

    months = _check_list(_get(obj, "months", p), f"{p}.months")
    keys = []
    for i, row in enumerate(months):
        path = f"{p}.months[{i}]"
        _check_str(_get(row, "month", path), f"{path}.month", MONTH_RE)
        _check_class_row(row, path)
        keys.append(row["month"])
    _check_sorted(keys, f"{p}.months (by month)")
    if len(set(keys)) != len(keys):
        _fail(f"{p}.months", "duplicate month buckets")
    if keys and keys[0] != obj["since_month"]:
        _fail(f"{p}.months", "series must start at since_month")

    years = _check_list(_get(obj, "years", p), f"{p}.years")
    ys = []
    for i, row in enumerate(years):
        path = f"{p}.years[{i}]"
        _check_int(_get(row, "year", path), f"{path}.year", minimum=1990)
        _check_class_row(row, path)
        _check_int(_get(row, "neither_adp", path), f"{path}.neither_adp")
        if row["neither_adp"] > row["neither"]:
            _fail(f"{path}.neither_adp", "exceeds neither")
        _check_int(_get(row, "v4_cnas", path), f"{path}.v4_cnas")
        ys.append(row["year"])
    _check_sorted(ys, f"{p}.years")

    ad = _get(obj, "adopters", p)
    ap = f"{p}.adopters"
    _check_str(_get(ad, "window_from", ap), f"{ap}.window_from", MONTH_RE)
    _check_int(_get(ad, "min_v4", ap), f"{ap}.min_v4", minimum=1)
    for k in ("window_published", "window_v4", "adopter_count"):
        _check_int(_get(ad, k, ap), f"{ap}.{k}")
    _check_num(_get(ad, "top_share_pct", ap), f"{ap}.top_share_pct",
               0.0, 100.0)
    rows = _check_list(_get(ad, "cnas", ap), f"{ap}.cnas")
    for j, r in enumerate(rows):
        rp = f"{ap}.cnas[{j}]"
        _check_str(_get(r, "cna", rp), f"{rp}.cna")
        _check_int(_get(r, "published", rp), f"{rp}.published")
        _check_int(_get(r, "v4", rp), f"{rp}.v4", minimum=ad["min_v4"])
        _check_int(_get(r, "v4_only", rp), f"{rp}.v4_only")
        if not r["v4_only"] <= r["v4"] <= r["published"]:
            _fail(rp, "need v4_only <= v4 <= published")
        for k in ("v4_share_pct", "v4_only_share_pct"):
            _check_num(_get(r, k, rp), f"{rp}.{k}", 0.0, 100.0)
    _check_top_sorted(rows, "v4", f"{ap}.cnas")

    cmp_ = _get(obj, "compare", p)
    cp = f"{p}.compare"
    n = _get(cmp_, "n", cp)
    _check_int(n, f"{cp}.n")
    for k in ("same_band", "v4_higher", "v4_lower"):
        _check_int(_get(cmp_, k, cp), f"{cp}.{k}")
    if cmp_["same_band"] + cmp_["v4_higher"] + cmp_["v4_lower"] != n:
        _fail(cp, "band agreement counts must partition n")
    for k in ("same_band_pct", "v4_higher_pct", "v4_lower_pct"):
        _check_num(_get(cmp_, k, cp), f"{cp}.{k}", 0.0, 100.0)
    _check_num(_get(cmp_, "median_delta", cp), f"{cp}.median_delta",
               -10.0, 10.0)
    bins = _check_list(_get(cmp_, "bins", cp), f"{cp}.bins")
    for j, b in enumerate(bins):
        bp = f"{cp}.bins[{j}]"
        for k in ("center", "lo", "hi"):
            _check_num(_get(b, k, bp), f"{bp}.{k}", -10.0, 10.0)
        _check_int(_get(b, "n", bp), f"{bp}.n")
        if not b["lo"] <= b["center"] <= b["hi"]:
            _fail(bp, "need lo <= center <= hi")
    _check_sorted([b["center"] for b in bins], f"{cp}.bins (by center)")
    if bins and sum(b["n"] for b in bins) != n:
        _fail(f"{cp}.bins", "bin counts must sum to n")
    _check_int(_get(cmp_, "min_n", cp), f"{cp}.min_n", minimum=1)
    for j, r in enumerate(_check_list(_get(cmp_, "cnas", cp), f"{cp}.cnas")):
        rp = f"{cp}.cnas[{j}]"
        _check_str(_get(r, "cna", rp), f"{rp}.cna")
        _check_int(_get(r, "n", rp), f"{rp}.n", minimum=cmp_["min_n"])
        _check_num(_get(r, "median_delta", rp), f"{rp}.median_delta",
                   -10.0, 10.0)
        for k in ("same_band_pct", "v4_higher_pct", "v4_lower_pct"):
            _check_num(_get(r, k, rp), f"{rp}.{k}", 0.0, 100.0)

    head = _get(obj, "headline", p)
    hp = f"{p}.headline"
    for k in ("current_year", "v4_current", "published_current",
              "latest_year", "v4_cnas_current"):
        _check_int(_get(head, k, hp), f"{hp}.{k}")
    _check_str(_get(head, "current_month", hp), f"{hp}.current_month",
               MONTH_RE)
    for k in ("v4_share_current_pct", "v4_share_latest_pct"):
        _check_num(_get(head, k, hp), f"{hp}.{k}", 0.0, 100.0)


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "cve_tags.json": _validate_cve_tags,
    "cvss_v4.json": _validate_cvss_v4,
}
