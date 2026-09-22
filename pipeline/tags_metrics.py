"""Record Tags metrics (cve_tags.json).

The CVE record format lets the CNA attach tags to its container. Three
values are defined by the schema — ``unsupported-when-assigned`` (the
product was already out of vendor support when the CVE ID was assigned),
``disputed`` (a party disputes that the record describes a vulnerability)
and ``exclusively-hosted-service`` (a cloud service with nothing for a
customer to patch). Anything prefixed ``x_`` is CNA-private.

This stage reads the tallies the core streaming pass already made
(pipeline/metrics.py, ``Aggregator._add_tags``): no new upstream. Three
views, all over PUBLISHED records and the CNA container's tags:

* per publication year, how many records carry each schema tag, against
  that year's published total (the site computes the share from the two
  counts, so tiny shares keep their precision);
* who applies ``unsupported-when-assigned`` and ``disputed`` over a recent
  window, and how concentrated that is — top-1 and top-3 share of the tag,
  and how many of the window's active CNAs used it at all;
* the severity mix of tagged records against two baselines over the same
  window: every published record, and the untagged records of the CNAs
  that applied the tag (so a board dominated by one CNA's scoring habits
  does not pass for a property of the tag).

What a tag is NOT: a verdict. It records what the CNA noted when it wrote
or updated the record; an untagged record is not "supported" or
"undisputed" — most CNAs never use the tags. The record carries no date for
when a tag was added, so every count here is by the record's publication
year, never by tagging time.
"""
from __future__ import annotations

from collections import Counter

from .metrics import SCHEMA_TAGS, Aggregator, _pct

SEVERITY_KEYS = ("critical", "high", "medium", "low", "unscored")
# The two tags the who-tags board and the severity comparison cover
# (exclusively-hosted-service is charted per year only — it is a
# classification of the product, not a claim about the record).
BOARD_TAGS = ("unsupported-when-assigned", "disputed")
# Board and severity window: the last WINDOW_YEARS publication years ending
# at the newest published year (the partial current year included, like
# the rejection leaderboard) — long enough for a tag used a few hundred
# times a year, recent enough to be about today's CNAs.
WINDOW_YEARS = 5
# A CNA joins a tag's board only with at least this many tagged records in
# the window; smaller users are counted in cna_count, not listed.
BOARD_MIN_N = 5
BOARD_TOP = 12
# The headline's "flat" window for disputed: the last FLAT_YEARS complete
# publication years.
FLAT_YEARS = 6
# CNA-private (x_) and ADP tags are listed as context, top N by count.
CONTEXT_TOP = 6


def _counts(counter: Counter[str] | dict) -> dict:
    return {k: int(counter.get(k, 0)) for k in SEVERITY_KEYS}


def _board(agg: Aggregator, tag: str, window: range, *,
           min_n: int) -> dict:
    per_cna: Counter[str] = Counter()
    for year in window:
        per_cna.update(agg.tag_year_cna[tag].get(year) or {})
    total = sum(per_cna.values())
    active: set[str] = set()
    cna_published: Counter[str] = Counter()
    for year in window:
        published = agg.cna_year_published.get(year) or {}
        active |= set(published)
        cna_published.update(published)
    ranked = sorted(per_cna.items(), key=lambda kv: (-kv[1], kv[0]))
    top = [n for _cna, n in ranked]
    return {
        "total": total,
        "cna_count": len(per_cna),
        "active_cnas": len(active),
        "top1_share_pct": _pct(sum(top[:1]), total),
        "top3_share_pct": _pct(sum(top[:3]), total),
        "min_n": min_n,
        "cnas": [{"cna": cna, "n": n,
                  "share_pct": _pct(n, total),
                  "cna_published": cna_published.get(cna, 0),
                  "rate_pct": _pct(n, cna_published.get(cna, 0))}
                 for cna, n in ranked[:BOARD_TOP] if n >= min_n],
    }


def _severity(agg: Aggregator, tag: str, window: range) -> dict:
    tagged: Counter[str] = Counter()
    for year in window:
        tagged.update(agg.tag_year_flood[tag].get(year) or {})
    taggers = {cna for year in window
               for cna in (agg.tag_year_cna[tag].get(year) or {})}
    same: Counter[str] = Counter()
    for cna in taggers:
        per_year = agg.cna_year_flood.get(cna) or {}
        for year in window:
            same.update(per_year.get(year) or {})
    same.subtract(tagged)
    return {"tagged": _counts(tagged), "same_cnas_untagged": _counts(same)}


def build_cve_tags(agg: Aggregator, generated_at: str, *,
                   window_years: int = WINDOW_YEARS,
                   min_n: int = BOARD_MIN_N) -> dict:
    """Assemble the cve_tags.json object. A corpus with no schema tag at
    all yields empty ``years`` / boards (the site shows its no-data card)."""
    current_year = int(generated_at[:4])
    tagged_years = [y for t in SCHEMA_TAGS
                    for y, n in agg.tag_year_counts.get(t, {}).items() if n]
    last_year = max(agg.published_by_year, default=current_year)
    years = []
    if tagged_years:
        for year in range(min(tagged_years), last_year + 1):
            years.append({
                "year": year,
                "published": agg.published_by_year.get(year, 0),
                "counts": {t: agg.tag_year_counts.get(t, Counter()).get(year, 0)
                           for t in SCHEMA_TAGS},
            })

    window = range(last_year - window_years + 1, last_year + 1)
    all_window: Counter[str] = Counter()
    for year in window:
        all_window.update(agg.flood.get(year) or {})

    private = Counter({t: sum(c.values())
                       for t, c in agg.tag_year_counts.items()
                       if t.startswith("x_")})

    out = {
        "generated_at": generated_at,
        "schema_tags": list(SCHEMA_TAGS),
        "years": years,
        "window": {"from": window.start, "to": window.stop - 1,
                   "years": window_years},
        "boards": {t: _board(agg, t, window, min_n=min_n)
                   for t in BOARD_TAGS},
        "severity": {"all": _counts(all_window),
                     **{t: _severity(agg, t, window) for t in BOARD_TAGS}},
        "context": {
            "private_tags": [{"tag": t, "n": n} for t, n in sorted(
                private.items(), key=lambda kv: (-kv[1], kv[0]))[:CONTEXT_TOP]],
            "private_tag_count": len(private),
            "adp_tags": [{"tag": t, "n": n} for t, n in sorted(
                agg.adp_tag_counts.items(),
                key=lambda kv: (-kv[1], kv[0]))[:CONTEXT_TOP]],
            "schema_totals": {t: sum(agg.tag_year_counts.get(
                t, Counter()).values()) for t in SCHEMA_TAGS},
        },
    }
    out["headline"] = _headline(years, current_year)
    return out


def _headline(years: list[dict], current_year: int) -> dict:
    """The numbers the page's stat line and copy quote. Growth reads from
    the first year the tag appears to the latest COMPLETE year; the partial
    current year is quoted separately and labelled as partial. The
    disputed range is over the last FLAT_YEARS complete years."""
    unsupported = "unsupported-when-assigned"
    full = [r for r in years if r["year"] < current_year]
    first = next((r for r in full if r["counts"][unsupported]), None)
    latest = full[-1] if full else None
    current = next((r for r in years if r["year"] == current_year), None)
    flat = full[-FLAT_YEARS:]
    disputed = [r["counts"]["disputed"] for r in flat]
    flat_published = sum(r["published"] for r in flat)
    return {
        "latest_year": latest["year"] if latest else 0,
        "unsupported_first_year": first["year"] if first else 0,
        "unsupported_first": first["counts"][unsupported] if first else 0,
        "unsupported_latest": latest["counts"][unsupported] if latest else 0,
        "unsupported_latest_share_pct":
            _pct(latest["counts"][unsupported], latest["published"])
            if latest else 0.0,
        "current_year": current_year,
        "unsupported_current": current["counts"][unsupported] if current else 0,
        "disputed_from": flat[0]["year"] if flat else 0,
        "disputed_to": flat[-1]["year"] if flat else 0,
        "disputed_min": min(disputed) if disputed else 0,
        "disputed_max": max(disputed) if disputed else 0,
        "disputed_share_pct": _pct(sum(disputed), flat_published),
    }
