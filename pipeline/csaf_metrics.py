"""Machine-Readable Advisories (module 31): CSAF providers listed by the
BSI CSAF Lister, their documents per year, the share that are VEX
documents, and how complete a fixed sample of their documents is
(csaf_adoption.json).

The crawl (``fetch_csaf``) returns, per listed source, the document list
of each public distribution and the field summaries of the sampled
documents. This stage turns that into three sections:

* ``sources`` — one row per listed source: status, documents, documents
  per year of initial release, the estimated category mix (VEX / security
  advisory / other) and the sampled field completeness;
* ``years`` — documents per initial-release year over all measured
  sources, and how many sources have at least one document that year;
* ``totals`` — the headline numbers.

Estimation. Category mix and completeness come from the sample, one
stratum per distribution: a distribution with N documents whose sample of
n holds v VEX documents contributes N·v/n estimated VEX documents (largest
remainder rounding, so each distribution's estimates sum to N). A
provider's completeness share for a field is the document-weighted mean of
its distributions' sample shares. A distribution with N ≤ SAMPLE_K is
sampled whole, so its numbers are counts, not estimates.

Event time vs observation time: a document's year is the year of its
initial release (the CSAF year folder, or the ROLIE ``published`` date),
which for converted older advisories predates the CSAF file. Nothing here
is a history CyberMon recorded; the lister keeps none, so listing dates are
not shown.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Callable

from .fetch_csaf import (FIELDS, NEW_CAP, REFRESH_CAP, CsafCrawl,
                         FixtureSession, SourceResult, category_group, crawl)

FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures"

GROUPS = ("vex", "advisory", "other", "unsampled")
STATUSES = ("measured", "carried", "robots", "denied", "empty", "error")
NEARLY_ALL = 90.0


def _pct(n: float, d: float) -> float | None:
    return round(100.0 * n / d, 1) if d else None


def _largest_remainder(total: int, shares: dict[str, int], n: int
                       ) -> dict[str, int]:
    """Split ``total`` in proportion to sample counts ``shares`` (summing
    to ``n``) into integers that sum exactly to ``total``."""
    raw = {k: total * v / n for k, v in shares.items()}
    out = {k: int(x) for k, x in raw.items()}
    left = total - sum(out.values())
    for k in sorted(raw, key=lambda k: (-(raw[k] - out[k]), k))[:left]:
        out[k] += 1
    return out


def build_row(res: SourceResult) -> dict:
    """The output row of one listed source (measured or not)."""
    src = res.source
    row = {
        "name": src.name,
        "category": src.category,
        "role": src.role,
        "kind": src.kind,
        "status": res.status,
        "detail": res.detail,
        "measured_on": res.measured_on,
        "documents": 0,
        "undated": 0,
        "by_year": [],
        "first_year": None,
        "last_year": None,
        "mix": dict.fromkeys(GROUPS, 0),
        "sample_n": 0,
        "fields": None,
        "sample_groups": {},
    }
    if res.status == "carried" and res.carried_row is not None:
        carried = dict(res.carried_row)
        carried.update(status="carried", detail=res.detail,
                       measured_on=res.measured_on)
        return carried
    if res.status != "measured":
        return row
    years: Counter = Counter()
    undated = 0
    mix: Counter = Counter()
    field_num = dict.fromkeys(FIELDS, 0.0)
    weight = 0
    sample_n = 0
    pooled: dict[str, Counter] = {}
    for dist in res.dists:
        n_docs = len(dist.docs)
        for d in dist.docs:
            if d.year is None:
                undated += 1
            else:
                years[d.year] += 1
        summaries = [s["summary"] for s in dist.sample]
        n = len(summaries)
        sample_n += n
        if not n:
            mix["unsampled"] += n_docs
            continue
        groups = Counter(category_group(s["c"]) for s in summaries)
        for s in summaries:
            tally = pooled.setdefault(category_group(s["c"]), Counter())
            tally["n"] += 1
            for f in FIELDS:
                tally[f] += bool(s[f])
        for k, v in _largest_remainder(n_docs, dict(groups), n).items():
            mix[k] += v
        weight += n_docs
        for f in FIELDS:
            field_num[f] += n_docs * sum(1 for s in summaries if s[f]) / n
    by_year = [{"year": y, "n": years[y]} for y in sorted(years)]
    row.update(
        documents=sum(len(d.docs) for d in res.dists),
        undated=undated,
        by_year=by_year,
        first_year=by_year[0]["year"] if by_year else None,
        last_year=by_year[-1]["year"] if by_year else None,
        mix={g: mix.get(g, 0) for g in GROUPS},
        sample_n=sample_n,
        fields=({f: round(field_num[f] / weight * 100.0, 1) for f in FIELDS}
                if weight else None),
        sample_groups={g: {k: pooled[g][k] for k in ("n", *FIELDS)}
                       for g in GROUPS if g in pooled},
    )
    return row


def _sort_key(row: dict) -> tuple:
    measured = row["status"] in ("measured", "carried")
    return (not measured, -row["documents"], row["name"].lower())


def build_csaf_adoption(result: CsafCrawl, generated_at: str) -> dict:
    rows = sorted((build_row(r) for r in result.results), key=_sort_key)
    measured = [r for r in rows if r["status"] in ("measured", "carried")]
    docs_total = sum(r["documents"] for r in rows)
    mix_total = {g: sum(r["mix"][g] for r in rows) for g in GROUPS}

    years: dict[int, dict] = {}
    for r in measured:
        for y in r["by_year"]:
            e = years.setdefault(y["year"], {"year": y["year"], "n": 0,
                                             "providers": 0})
            e["n"] += y["n"]
            e["providers"] += 1
    year_rows = [years[y] for y in sorted(years)]

    top = max(measured, key=lambda r: (r["documents"], r["name"]),
              default=None)
    vex_top = max(measured, key=lambda r: (r["mix"]["vex"], r["name"]),
                  default=None)
    sampled = [r for r in measured if r["fields"] is not None]
    fields_summary = {
        f: {"nearly_all": sum(1 for r in sampled
                              if r["fields"][f] >= NEARLY_ALL),
            "none": sum(1 for r in sampled if r["fields"][f] == 0.0)}
        for f in FIELDS
    }
    by_group = {}
    for g in GROUPS:
        tally: Counter = Counter()
        for r in measured:
            tally.update(r.get("sample_groups", {}).get(g, {}))
        if tally["n"]:
            by_group[g] = {"n": tally["n"],
                           **{f: _pct(tally[f], tally["n"]) for f in FIELDS}}
    all_three = sum(1 for r in sampled
                    if all(r["fields"][f] >= NEARLY_ALL
                           for f in ("cvss", "cwe", "remediation")))
    return {
        "generated_at": generated_at,
        "current_year": int(generated_at[:4]),
        "lister": {
            **result.lister,
            "listed": len(rows),
            "providers": sum(1 for r in rows if r["kind"] == "provider"),
            "publishers": sum(1 for r in rows if r["kind"] == "publisher"),
        },
        "sampling": {"k": result.k, "new_cap": NEW_CAP,
                     "refresh_cap": REFRESH_CAP,
                     "nearly_all_pct": NEARLY_ALL},
        "sources": rows,
        "years": year_rows,
        "totals": {
            "listed": len(rows),
            "measured": len(measured),
            "carried": sum(1 for r in rows if r["status"] == "carried"),
            "unmeasured": len(rows) - len(measured),
            "documents": docs_total,
            "undated": sum(r["undated"] for r in rows),
            "mix": mix_total,
            "vex_pct": _pct(mix_total["vex"], docs_total),
            "top_name": top["name"] if top else None,
            "top_share_pct": _pct(top["documents"], docs_total) if top
            else None,
            "vex_top_name": vex_top["name"] if vex_top and
            vex_top["mix"]["vex"] else None,
            "vex_top_share_pct": _pct(vex_top["mix"]["vex"],
                                      mix_total["vex"]) if vex_top else None,
            "providers_with_vex": sum(1 for r in measured
                                      if r["mix"]["vex"] > 0),
            "sampled_providers": len(sampled),
            "sample_n": sum(r["sample_n"] for r in rows),
            "fields": fields_summary,
            "by_group": by_group,
            "all_three_nearly_all": all_three,
        },
    }


def source_block(obj: dict, generated_at: str, result: CsafCrawl) -> dict:
    t = obj["totals"]
    return {"fetched_at": generated_at, "listed": t["listed"],
            "measured": t["measured"], "documents": t["documents"],
            "requests": result.requests, "docs_fetched": result.docs_fetched}


def run_stage(cache_dir: Path, generated_at: str, *, offline_fixtures: bool,
              session=None, log: Callable[[str], None] = print
              ) -> tuple[dict, dict]:
    """(csaf_adoption.json, meta.sources.csaf). Raises ``OSError`` /
    ``ValueError`` when the lister fails; the caller carries the module
    forward stale."""
    today = generated_at[:10]
    if offline_fixtures:
        root = FIXTURES_DIR / "csaf"
        result = crawl(FixtureSession(root), None, today, k=2,
                       row_builder=build_row, sleep=lambda s: None, log=log)
    else:
        if session is None:
            import requests

            session = requests.Session()
        log("fetching CSAF providers from the BSI CSAF Lister ...")
        result = crawl(session, cache_dir, today, row_builder=build_row,
                       log=log)
    obj = build_csaf_adoption(result, generated_at)
    t = obj["totals"]
    log(f"  CSAF: {t['listed']} listed, {t['measured']} measured, "
        f"{t['documents']} documents, {result.requests} requests "
        f"({result.bytes / 1e6:.1f} MB), {result.docs_fetched} sampled "
        f"documents fetched")
    return obj, source_block(obj, generated_at, result)
