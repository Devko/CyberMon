"""Contract for ai_products.json (module 27, AI Product CVEs).

Same philosophy as pipeline/contracts.py: hand-rolled stdlib validators
that fail loudly, kept in their own module and merged into the pipeline's
dispatch by the coordinator. The file may be EMPTY-shaped (no years, zero
window counts) on a corpus with no AI-product CVE; every key is present.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .contracts import (_check_generated_at, _check_int, _check_list,
                        _check_num, _check_sorted, _check_str, _fail, _get)

# Hardcoded on purpose: the contract states what the site may rely on,
# independently of the classifier module's constants.
CATEGORIES = ["frameworks", "serving", "platforms", "apps"]
RATES = ["kev", "poc", "nuclei"]
CWE_RE = re.compile(r"^CWE-\d+$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _pct(obj: Any, key: str, path: str) -> float:
    v = _get(obj, key, path)
    _check_num(v, f"{path}.{key}", 0.0, 100.0)
    return v


def _validate(obj: Any) -> None:
    p = "ai_products"
    _check_generated_at(obj, p)
    current_year = int(obj["generated_at"][:4])

    cl = _get(obj, "classifier", p)
    _check_int(_get(cl, "version", f"{p}.classifier"),
               f"{p}.classifier.version", minimum=1)
    _check_str(_get(cl, "reviewed", f"{p}.classifier"),
               f"{p}.classifier.reviewed", DATE_RE)
    for k in ("rules", "products"):
        _check_int(_get(cl, k, f"{p}.classifier"), f"{p}.classifier.{k}",
                   minimum=1)
    if _get(obj, "categories", p) != CATEGORIES:
        _fail(f"{p}.categories", f"must be exactly {CATEGORIES}")

    rows = _check_list(_get(obj, "years", p), f"{p}.years")
    years = []
    for i, row in enumerate(rows):
        path = f"{p}.years[{i}]"
        _check_int(_get(row, "year", path), f"{path}.year", minimum=1990)
        for k in ("published", "named", "ai"):
            _check_int(_get(row, k, path), f"{path}.{k}")
        if not row["ai"] <= row["named"] <= row["published"]:
            _fail(path, "need ai <= named <= published")
        cats = _get(row, "by_category", path)
        for c in CATEGORIES:
            _check_int(_get(cats, c, f"{path}.by_category"),
                       f"{path}.by_category.{c}")
        if sum(cats[c] for c in CATEGORIES) != row["ai"]:
            _fail(f"{path}.by_category", "categories must partition ai")
        top = _get(row, "top_product", path)
        if (top is None) != (row["ai"] == 0):
            _fail(f"{path}.top_product", "null exactly when ai is 0")
        if top is not None:
            _check_str(_get(top, "label", f"{path}.top_product"),
                       f"{path}.top_product.label")
            _check_int(_get(top, "n", f"{path}.top_product"),
                       f"{path}.top_product.n", minimum=1)
            if top["n"] > row["ai"]:
                _fail(f"{path}.top_product.n", "exceeds ai")
        years.append(row["year"])
    _check_sorted(years, f"{p}.years")
    if years and years != list(range(years[0], years[-1] + 1)):
        _fail(f"{p}.years", "years must be contiguous (gap-filled)")
    if years and years[-1] != current_year:
        _fail(f"{p}.years", "series must end at the edition's year")

    w = _get(obj, "window", p)
    wp = f"{p}.window"
    for k in ("from", "to", "years"):
        _check_int(_get(w, k, wp), f"{wp}.{k}", minimum=1)
    if w["to"] != current_year or w["to"] - w["from"] + 1 != w["years"]:
        _fail(wp, "window must end at the edition's year and span 'years'")
    weights = _check_list(_get(w, "weights", wp), f"{wp}.weights")
    for j, r in enumerate(weights):
        _check_int(_get(r, "year", f"{wp}.weights[{j}]"),
                   f"{wp}.weights[{j}].year", minimum=w["from"])
        _pct(r, "pct", f"{wp}.weights[{j}]")
    _check_sorted([r["year"] for r in weights], f"{wp}.weights")

    cwe = _get(obj, "cwe", p)
    cp = f"{p}.cwe"
    n = _get(cwe, "n", cp)
    _check_int(n, f"{cp}.n")
    window_ai = sum(r["ai"] for r in rows if w["from"] <= r["year"] <= w["to"])
    if n != window_ai:
        _fail(f"{cp}.n", f"{n} vs {window_ai} AI-product CVEs in the window")
    _check_int(_get(cwe, "no_cwe", cp), f"{cp}.no_cwe")
    for k in ("no_cwe_pct", "baseline_no_cwe_pct", "top_share_pct"):
        _pct(cwe, k, cp)
    top = _check_list(_get(cwe, "top", cp), f"{cp}.top")
    for j, t in enumerate(top):
        tp = f"{cp}.top[{j}]"
        _check_str(_get(t, "cwe", tp), f"{tp}.cwe", CWE_RE)
        _check_str(_get(t, "name", tp), f"{tp}.name")
        _check_int(_get(t, "n", tp), f"{tp}.n", minimum=1)
        _pct(t, "pct", tp)
        _pct(t, "baseline_pct", tp)
    _check_sorted([t["n"] for t in top], f"{cp}.top (by n)", descending=True)
    spec = _get(cwe, "ai_specific", cp)
    ids = _check_list(_get(spec, "ids", f"{cp}.ai_specific"),
                      f"{cp}.ai_specific.ids")
    for j, i in enumerate(ids):
        _check_str(i, f"{cp}.ai_specific.ids[{j}]", CWE_RE)
    _check_int(_get(spec, "n", f"{cp}.ai_specific"), f"{cp}.ai_specific.n")
    if spec["n"] > n:
        _fail(f"{cp}.ai_specific.n", "exceeds the window's AI-product CVEs")

    ex = _get(obj, "exploited", p)
    ep = f"{p}.exploited"
    if _get(ex, "n", ep) != n:
        _fail(f"{ep}.n", "must equal cwe.n (same window, same records)")
    _check_int(_get(ex, "baseline_n", ep), f"{ep}.baseline_n")
    for k in RATES:
        _check_int(_get(ex, k, ep), f"{ep}.{k}")
        if ex[k] > n:
            _fail(f"{ep}.{k}", "exceeds n")
        _pct(ex, f"{k}_pct", ep)
        _pct(ex, f"{k}_baseline_pct", ep)
        _check_num(_get(ex, f"{k}_expected", ep), f"{ep}.{k}_expected",
                   0.0, float(n))
    kev_cves = _check_list(_get(ex, "kev_cves", ep), f"{ep}.kev_cves")
    for j, r in enumerate(kev_cves):
        _check_str(_get(r, "cve", f"{ep}.kev_cves[{j}]"),
                   f"{ep}.kev_cves[{j}].cve", CVE_RE)
        _check_str(_get(r, "product", f"{ep}.kev_cves[{j}]"),
                   f"{ep}.kev_cves[{j}].product")
    if len(kev_cves) != ex["kev"]:
        _fail(f"{ep}.kev_cves", "must list every KEV-listed CVE counted")

    board = _check_list(_get(obj, "products", p), f"{p}.products")
    for j, b in enumerate(board):
        bp = f"{p}.products[{j}]"
        for k in ("key", "label", "top_cna"):
            _check_str(_get(b, k, bp), f"{bp}.{k}")
        if _get(b, "category", bp) not in CATEGORIES:
            _fail(f"{bp}.category", f"must be one of {CATEGORIES}")
        for k in ("n", "all_years", "first_year"):
            _check_int(_get(b, k, bp), f"{bp}.{k}", minimum=1)
        for k in ("kev", "poc"):
            _check_int(_get(b, k, bp), f"{bp}.{k}")
            if b[k] > b["n"]:
                _fail(f"{bp}.{k}", "exceeds n")
        if b["n"] > b["all_years"]:
            _fail(f"{bp}.n", "window count exceeds the all-years count")
        _pct(b, "top_cna_pct", bp)
    _check_sorted([b["n"] for b in board], f"{p}.products (by n)",
                  descending=True)
    _check_int(_get(obj, "product_count", p), f"{p}.product_count")
    if obj["product_count"] < len(board):
        _fail(f"{p}.product_count", "fewer than the listed products")

    cn = _get(obj, "cnas", p)
    np_ = f"{p}.cnas"
    if _get(cn, "n", np_) != n:
        _fail(f"{np_}.n", "must equal cwe.n")
    _check_int(_get(cn, "cna_count", np_), f"{np_}.cna_count")
    _pct(cn, "top3_pct", np_)
    for j, r in enumerate(_check_list(_get(cn, "top", np_), f"{np_}.top")):
        _check_str(_get(r, "cna", f"{np_}.top[{j}]"), f"{np_}.top[{j}].cna")
        _check_int(_get(r, "n", f"{np_}.top[{j}]"), f"{np_}.top[{j}].n",
                   minimum=1)
        _pct(r, "pct", f"{np_}.top[{j}]")

    h = _get(obj, "headline", p)
    hp = f"{p}.headline"
    for k in ("latest_year", "latest_ai", "current_year", "current_ai",
              "lead_n"):
        _check_int(_get(h, k, hp), f"{hp}.{k}")
    for k in ("latest_share_pct", "current_share_pct", "lead_pct"):
        _pct(h, k, hp)
    if not isinstance(_get(h, "lead_label", hp), str):
        _fail(f"{hp}.lead_label", "must be a string")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "ai_products.json": _validate,
}
