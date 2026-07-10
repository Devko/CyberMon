"""Metric computation: CVE v5 records + EPSS + KEV + NVD -> the six outputs.

Streaming design: :func:`extract_facts` reduces each cvelistV5 record to a
tiny :class:`CveFacts`; :class:`Aggregator.add` folds facts into running
aggregates. The full corpus is never held in memory — only per-year score
lists and a ``cve_id -> score`` map (needed for the EPSS/KEV joins).

Score-selection rules (per docs/data-contracts.md):

* **CNA score** (charts 1 and 5): CNA-assigned base score from the record's
  ``containers.cna.metrics``. If a record carries several CVSS versions it
  appears in each per-version series, but exactly once in ``blended`` using
  the newest version's score (v4 > v3 > v2; 3.0 and 3.1 both count as "v3").
* **Effective score** (charts 2 and 3): newest-version base score found
  *anywhere in the record* (CNA container preferred, ADP containers as
  fallback) — chart 2's contract defines "unscored" as "no base score
  anywhere in the record".

Publication year = ``cveMetadata.datePublished`` year, falling back to the
year embedded in the CVE ID. REJECTED records count only toward
``volume_curve.rejected``; they are excluded from every scoring chart.
"""
from __future__ import annotations

import calendar
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

CVSS_BUCKETS = ["0.1-3.9", "4.0-6.9", "7.0-8.9", "9.0-10.0"]
EPSS_BUCKETS = ["<0.1%", "0.1-1%", "1-10%", ">10%"]
ANNOTATIONS = [
    {"year": 2015, "label": "CVSS v3.0 released"},
    {"year": 2023, "label": "CVSS v4.0 released"},
]
_FAMILY_ORDER = ("v4", "v3", "v2")  # newest first


# ------------------------------------------------------------- bucket math

def severity_bucket(score: float) -> str:
    """Severity bucket per contract: critical >=9.0, high 7.0-8.9,
    medium 4.0-6.9, low otherwise (scores of exactly 0.0 count as low)."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def cvss_bucket(score: float) -> str:
    """Grid CVSS bucket label for a base score."""
    return {"critical": "9.0-10.0", "high": "7.0-8.9",
            "medium": "4.0-6.9", "low": "0.1-3.9"}[severity_bucket(score)]


def epss_bucket(epss: float) -> str:
    """Grid EPSS bucket label for a 0-1 probability (lower edges inclusive)."""
    if epss >= 0.1:
        return ">10%"
    if epss >= 0.01:
        return "1-10%"
    if epss >= 0.001:
        return "0.1-1%"
    return "<0.1%"


def _pct(num: int, den: int) -> float:
    return round(100.0 * num / den, 1) if den else 0.0


def _r1(x: float) -> float:
    return round(float(x), 1)


def _quartiles(scores: list[float]) -> tuple[float, float, float]:
    """(p25, median, p75) with linear interpolation ("inclusive" method)."""
    if len(scores) == 1:
        s = scores[0]
        return s, s, s
    q = statistics.quantiles(scores, n=4, method="inclusive")
    return q[0], statistics.median(scores), q[2]


# --------------------------------------------------------- pace projection

# Below this elapsed fraction of the year (roughly before mid-February) a
# full-year pace is noise: the divisor is so small that one busy or quiet
# fortnight swings the projection by thousands, so none is emitted.
PACE_MIN_ELAPSED = 0.125

# The 9.8-flood era marker: the first year in which at least this share of
# published records carry a base score in the CVE record itself (CNA/ADP
# containers) rather than only downstream in NVD's database. 10% marks
# where in-record scoring stops being a rounding error (2.9% in 2017,
# 10.6% in 2018 in the real corpus).
RECORD_ERA_MIN_SHARE = 0.10


def year_elapsed(generated_at: str) -> float:
    """Fraction of the UTC calendar year elapsed at ``generated_at``:
    day-of-year / days-in-year, leap-year aware, day precision."""
    day = datetime.strptime(generated_at[:10], "%Y-%m-%d")
    days_in_year = 366 if calendar.isleap(day.year) else 365
    return day.timetuple().tm_yday / days_in_year


def pace_projection(count: int, generated_at: str) -> int | None:
    """Full-year value of a partial-year *flow* count at its current pace:
    ``round(count / year_elapsed(generated_at))``.

    Returns None when the year is less than :data:`PACE_MIN_ELAPSED`
    elapsed (see the comment above) or ``count`` is 0 — nothing to pace.

    Flow metrics only — counts of events per year. A median doesn't scale
    with elapsed time, a share is already normalized, and a distinct-entity
    count (an active-CNA roster) is a headcount; none of those may ever be
    fed through this helper.
    """
    elapsed = year_elapsed(generated_at)
    if elapsed < PACE_MIN_ELAPSED or count == 0:
        return None
    return round(count / elapsed)


# ------------------------------------------------------------ facts & agg

@dataclass
class CveFacts:
    """The handful of fields the metrics need from one cvelistV5 record."""

    cve_id: str
    state: str  # "PUBLISHED" or "REJECTED"
    year: int
    cna: str
    cna_scores: dict[str, float] = field(default_factory=dict)  # family -> score
    adp_scores: dict[str, float] = field(default_factory=dict)
    date_published: str | None = None  # day precision "YYYY-MM-DD"
    cwe: str | None = None  # first cweId in the record (CNA preferred)
    has_affected: bool = False  # any usable affected[] entry in the record

    @property
    def newest_cna_score(self) -> float | None:
        """CNA-assigned base score of the newest CVSS version, if any."""
        for family in _FAMILY_ORDER:
            if family in self.cna_scores:
                return self.cna_scores[family]
        return None

    @property
    def effective_score(self) -> float | None:
        """Newest-version base score anywhere in the record (CNA preferred)."""
        for family in _FAMILY_ORDER:
            if family in self.cna_scores:
                return self.cna_scores[family]
            if family in self.adp_scores:
                return self.adp_scores[family]
        return None


def _family(metric_key: str) -> str | None:
    if metric_key.startswith("cvssV2"):
        return "v2"
    if metric_key.startswith("cvssV3"):
        return "v3"  # 3.0 and 3.1 both count as v3
    if metric_key.startswith("cvssV4"):
        return "v4"
    return None


def _scores_from_metrics(metrics: Any) -> dict[str, float]:
    """family -> base score. Within a family, the highest minor version wins
    (cvssV3_1 over cvssV3_0 — key strings sort correctly)."""
    best: dict[str, tuple[str, float]] = {}
    if not isinstance(metrics, list):
        return {}
    for entry in metrics:
        if not isinstance(entry, dict):
            continue
        for key, val in entry.items():
            family = _family(key) if isinstance(val, dict) else None
            if family is None:
                continue
            score = val.get("baseScore")
            if not isinstance(score, (int, float)) or isinstance(score, bool):
                continue
            prev = best.get(family)
            if prev is None or key > prev[0]:
                best[family] = (key, float(score))
    return {family: score for family, (_key, score) in best.items()}


def _first_cwe(container: Any) -> str | None:
    """First cweId in a container's problemTypes, None when untagged.
    Text-only problemTypes entries (no cweId) do not count as tagged."""
    if not isinstance(container, dict):
        return None
    for pt in container.get("problemTypes") or []:
        if not isinstance(pt, dict):
            continue
        for desc in pt.get("descriptions") or []:
            if isinstance(desc, dict):
                cwe = desc.get("cweId")
                if isinstance(cwe, str) and cwe.startswith("CWE-"):
                    return cwe
    return None


# Version strings that carry no actual version information. Old records
# converted from the v4 format ship ``versions: [{"version": "n/a", ...}]``
# — counting those as structured version data would flatter the corpus.
_PLACEHOLDER_VERSIONS = frozenset({"", "n/a", "na", "unknown", "unspecified", "-"})
# defaultStatus makes a concrete claim only when it says which way.
_USABLE_DEFAULT_STATUS = frozenset({"affected", "unaffected"})


def _has_usable_affected(container: Any) -> bool:
    """True if any affected[] entry carries a concrete versions[] item or a
    definite defaultStatus ("affected"/"unaffected"; "unknown" says nothing)."""
    if not isinstance(container, dict):
        return False
    for aff in container.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        versions = aff.get("versions")
        if isinstance(versions, list):
            for v in versions:
                if isinstance(v, dict) and isinstance(v.get("version"), str) \
                        and v["version"].strip().lower() not in _PLACEHOLDER_VERSIONS:
                    return True
        if str(aff.get("defaultStatus", "")).lower() in _USABLE_DEFAULT_STATUS:
            return True
    return False


def extract_facts(record: dict) -> CveFacts | None:
    """Reduce one cvelistV5 JSON record to :class:`CveFacts`.

    Returns None for things that are not CVE records (delta files etc.).
    """
    meta = record.get("cveMetadata")
    if not isinstance(meta, dict):
        return None
    cve_id = meta.get("cveId")
    if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
        return None

    date_published = meta.get("datePublished")
    year: int | None = None
    if isinstance(date_published, str) and len(date_published) >= 4:
        try:
            year = int(date_published[:4])
        except ValueError:
            year = None
    if year is None:  # fall back to the year embedded in the CVE ID
        try:
            year = int(cve_id.split("-")[1])
        except (IndexError, ValueError):
            return None

    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    adps = [a for a in (containers.get("adp") or []) if isinstance(a, dict)]
    adp_scores: dict[str, float] = {}
    for adp in adps:
        for family, score in _scores_from_metrics(adp.get("metrics")).items():
            adp_scores.setdefault(family, score)

    cwe = _first_cwe(cna)
    if cwe is None:
        for adp in adps:
            cwe = _first_cwe(adp)
            if cwe is not None:
                break
    has_affected = _has_usable_affected(cna) or \
        any(_has_usable_affected(adp) for adp in adps)

    return CveFacts(
        cve_id=cve_id,
        state=str(meta.get("state", "PUBLISHED")).upper(),
        year=year,
        cna=str(meta.get("assignerShortName") or "unknown"),
        cna_scores=_scores_from_metrics(cna.get("metrics")),
        adp_scores=adp_scores,
        date_published=(date_published[:10]
                        if isinstance(date_published, str)
                        and len(date_published) >= 10 else None),
        cwe=cwe,
        has_affected=has_affected,
    )


class Aggregator:
    """Folds a stream of :class:`CveFacts` into the aggregates the
    six output builders need. Never stores whole records."""

    def __init__(self, kev_ids: Iterable[str] = ()) -> None:
        self.cve_count = 0
        self.published_by_year: Counter[int] = Counter()
        self.rejected_by_year: Counter[int] = Counter()
        # KEV latency join: KEV-listed ids -> day-precision publish date
        self.kev_ids: frozenset[str] = frozenset(kev_ids)
        self.kev_published_dates: dict[str, str] = {}
        # CNA concentration: year -> Counter of records per CNA
        self.cna_year_published: dict[int, Counter[str]] = defaultdict(Counter)
        self.cna_year_rejected: dict[int, Counter[str]] = defaultdict(Counter)
        # chart 1: year -> [score], per CVSS version family / blended
        self.version_scores: dict[str, dict[int, list[float]]] = {
            f: defaultdict(list) for f in ("v2", "v3", "v4")}
        self.blended_scores: dict[int, list[float]] = defaultdict(list)
        # chart 2: year -> severity-bucket counts
        self.flood: dict[int, Counter[str]] = defaultdict(Counter)
        # charts 3: effective score per scored CVE (EPSS / KEV joins)
        self.effective_by_cve: dict[str, float] = {}
        # chart 5: cna -> year -> [CNA-assigned newest score]
        self.cna_year_scores: dict[str, dict[int, list[float]]] = \
            defaultdict(lambda: defaultdict(list))
        # chart 7 (advisory quality): year -> missing-field counts over
        # published records ("cwe" / "cvss" / "affected")
        self.quality_missing: dict[int, Counter[str]] = defaultdict(Counter)
        # chart 8 (bug-class inertia): year -> Counter of first-listed CWE
        # per CWE-tagged published record
        self.cwe_year_counts: dict[int, Counter[str]] = defaultdict(Counter)

    def add(self, facts: CveFacts) -> None:
        self.cve_count += 1
        # KEV join first: a KEV listing is real even for records that were
        # later rejected — the publish date is whatever the record carries.
        if facts.date_published is not None and facts.cve_id in self.kev_ids:
            self.kev_published_dates[facts.cve_id] = facts.date_published
        if facts.state == "REJECTED":
            self.rejected_by_year[facts.year] += 1
            self.cna_year_rejected[facts.year][facts.cna] += 1
            return
        self.published_by_year[facts.year] += 1
        self.cna_year_published[facts.year][facts.cna] += 1

        for family, score in facts.cna_scores.items():
            self.version_scores[family][facts.year].append(score)

        newest = facts.newest_cna_score
        if newest is not None:
            self.blended_scores[facts.year].append(newest)
            self.cna_year_scores[facts.cna][facts.year].append(newest)

        effective = facts.effective_score
        if effective is None:
            self.flood[facts.year]["unscored"] += 1
            self.quality_missing[facts.year]["cvss"] += 1
        else:
            self.flood[facts.year][severity_bucket(effective)] += 1
            self.effective_by_cve[facts.cve_id] = effective

        if facts.cwe is None:
            self.quality_missing[facts.year]["cwe"] += 1
        else:
            self.cwe_year_counts[facts.year][facts.cwe] += 1
        if not facts.has_affected:
            self.quality_missing[facts.year]["affected"] += 1

    def consume(self, records: Iterable[dict]) -> None:
        for record in records:
            facts = extract_facts(record)
            if facts is not None:
                self.add(facts)

    def year_span(self) -> list[int]:
        """Every year from first to last publication, gap-filled."""
        years = set(self.published_by_year) | set(self.rejected_by_year)
        if not years:
            return []
        return list(range(min(years), max(years) + 1))


# --------------------------------------------------------- output builders

# A per-version data point may not predate its CVSS spec: CNAs backfill
# scores onto old records (a v4 score on a CVE published 2017), and charting
# that as "v4 median in 2017" would be historical nonsense.
VERSION_INTRODUCED = {"v2": 0, "v3": 2015, "v4": 2023}


def build_severity_inflation(agg: Aggregator, generated_at: str,
                             min_n: int = 100,
                             min_share: float = 0.2) -> dict:
    """Chart 1 (hero): per-version median/IQR per year + blended trend.

    Statistical honesty filters (documented in the chart's methodology
    footnote — change both together):

    * every plotted point needs at least ``min_n`` scored CVEs that year;
      CNA-container CVSS in cvelistV5 is sparse before ~2017 and a
      median-of-16 is noise, not trend;
    * per-version points cannot predate the version's spec release
      (``VERSION_INTRODUCED``) — backfilled scores land on old records;
    * blended points additionally need scores for at least ``min_share``
      of the CVEs published that year, because a year where 1% of records
      carry a score charts selection bias (which CVEs got backfilled),
      not the population.
    """
    series: dict[str, list[dict]] = {}
    for family in ("v2", "v3", "v4"):
        rows = []
        for year in sorted(agg.version_scores[family]):
            scores = agg.version_scores[family][year]
            if len(scores) < min_n or year < VERSION_INTRODUCED[family]:
                continue
            p25, median, p75 = _quartiles(scores)
            rows.append({"year": year, "n": len(scores), "median": _r1(median),
                         "p25": _r1(p25), "p75": _r1(p75)})
        series[family] = rows

    blended = []
    for year in sorted(agg.blended_scores):
        scores = agg.blended_scores[year]
        published = agg.published_by_year.get(year, 0)
        share = len(scores) / published if published else 0.0
        if len(scores) < min_n or share < min_share:
            continue
        high = sum(1 for s in scores if s >= 7.0)
        blended.append({"year": year, "n": len(scores),
                        "median": _r1(statistics.median(scores)),
                        "pct_high_critical": _pct(high, len(scores))})

    by_year = {row["year"]: row for row in blended}
    # The headline never leans on the current (partial) year: six months of
    # data would fake a trend the full-year series may not support. The
    # partial year still plots — the chart labels it as partial.
    current_year = int(generated_at[:4])
    full_years = [row for row in blended if row["year"] < current_year]
    latest = full_years[-1] if full_years else \
        (blended[-1] if blended else None)
    latest_year = latest["year"] if latest else 0
    # Prefer a ten-year lookback; else the earliest year that survived the
    # filters. Its year ships in the payload — the site must never imply a
    # baseline year the data doesn't actually contain.
    baseline = by_year.get(latest_year - 10, blended[0] if blended else None)
    return {
        "generated_at": generated_at,
        "series": series,
        "blended": blended,
        "annotations": list(ANNOTATIONS),
        "headline": {
            "latest_year": latest_year,
            "pct_high_critical_latest":
                latest["pct_high_critical"] if latest else 0.0,
            "baseline_year": baseline["year"] if baseline else 0,
            "pct_high_critical_baseline":
                baseline["pct_high_critical"] if baseline else 0.0,
        },
    }


def build_nine_eight_flood(agg: Aggregator, generated_at: str) -> dict:
    """Chart 2: stacked severity buckets per publication year (gap-filled),
    plus an optional full-year pace projection of the partial current
    year's total (all published records, unscored included)."""
    years = []
    for year in agg.year_span():
        counts = agg.flood.get(year, Counter())
        years.append({"year": year,
                      "critical": counts.get("critical", 0),
                      "high": counts.get("high", 0),
                      "medium": counts.get("medium", 0),
                      "low": counts.get("low", 0),
                      "unscored": counts.get("unscored", 0)})
    out = {"generated_at": generated_at, "years": years}
    # Era marker: the first year where at least RECORD_ERA_MIN_SHARE of
    # published records carry a score in the record itself (CNA/ADP
    # containers). Left of this line the corpus is nearly score-free not
    # because nothing was scored, but because scoring lived downstream in
    # NVD's database, which this chart deliberately does not ingest. The
    # marker puts that caveat on the chart instead of only in the footnote.
    for row in years:
        total_y = sum(row[k] for k in
                      ("critical", "high", "medium", "low", "unscored"))
        scored_y = total_y - row["unscored"]
        if total_y and scored_y / total_y >= RECORD_ERA_MIN_SHARE:
            out["record_era"] = {"year": row["year"],
                                 "min_share": RECORD_ERA_MIN_SHARE}
            break
    # agg.flood counts published records only (rejected never reach it),
    # across every bucket including "unscored" — the flow being paced.
    current_year = int(generated_at[:4])
    total = sum(agg.flood.get(current_year, Counter()).values())
    projected = pace_projection(total, generated_at)
    if projected is not None:
        out["projection"] = {"year": current_year, "total": projected,
                             "elapsed": round(year_elapsed(generated_at), 3)}
    return out


def build_score_vs_reality(agg: Aggregator, epss_scores: dict[str, float],
                           kev_cve_ids: list[str], generated_at: str) -> dict:
    """Chart 3: CVSS x EPSS grid, critical-but-unexploited headline, KEV cut."""
    cells: Counter[tuple[str, str]] = Counter()
    n_critical = below_1pct = 0
    for cve_id, score in agg.effective_by_cve.items():
        epss = epss_scores.get(cve_id)
        if epss is None:
            continue
        cells[(cvss_bucket(score), epss_bucket(epss))] += 1
        if score >= 9.0:
            n_critical += 1
            if epss < 0.01:
                below_1pct += 1
    grid = [{"cvss_bucket": cb, "epss_bucket": eb, "n": cells.get((cb, eb), 0)}
            for cb in CVSS_BUCKETS for eb in EPSS_BUCKETS]

    kev_scores = [agg.effective_by_cve[c] for c in kev_cve_ids
                  if c in agg.effective_by_cve]
    below_high = sum(1 for s in kev_scores if s < 7.0)
    dist: Counter[str] = Counter(cvss_bucket(s) for s in kev_scores)
    return {
        "generated_at": generated_at,
        "grid": grid,
        "cvss_buckets": list(CVSS_BUCKETS),
        "epss_buckets": list(EPSS_BUCKETS),
        "headline": {"pct_critical_epss_below_1pct": _pct(below_1pct, n_critical),
                     "n_critical_with_epss": n_critical},
        "kev": {"total": len(kev_cve_ids),
                "below_high": below_high,
                "pct_below_high": _pct(below_high, len(kev_cve_ids)),
                "cvss_distribution": [{"bucket": b, "n": dist.get(b, 0)}
                                      for b in CVSS_BUCKETS]},
    }


BACKLOG_STATUSES = ("Received", "Awaiting Analysis", "Undergoing Analysis")


def backlog_row(statuses: dict[str, int], date: str) -> dict:
    """One nvd_backlog.csv row (see pipeline.history.COLUMNS) for ``date``."""
    return {
        "date": date,
        "backlog_total": sum(statuses.get(s, 0) for s in BACKLOG_STATUSES),
        "awaiting_analysis": statuses.get("Awaiting Analysis", 0),
        "undergoing_analysis": statuses.get("Undergoing Analysis", 0),
        "received": statuses.get("Received", 0),
    }


def build_nvd_decay(statuses: dict[str, int], history_rows: list[dict],
                    generated_at: str) -> dict:
    """Chart 4: current vulnStatus counts + our snapshot time series."""
    return {
        "generated_at": generated_at,
        "current": {
            "statuses": [{"status": s, "n": n} for s, n in
                         sorted(statuses.items(), key=lambda kv: (-kv[1], kv[0]))],
            "backlog_total": sum(statuses.get(s, 0) for s in BACKLOG_STATUSES),
        },
        "history": [{"date": r["date"],
                     "backlog_total": int(r["backlog_total"]),
                     "awaiting_analysis": int(r["awaiting_analysis"])}
                    for r in history_rows],
    }


def build_cna_leaderboard(agg: Aggregator, generated_at: str, *,
                          window_years: int = 3, min_cves: int = 100,
                          as_of_year: int | None = None) -> dict:
    """Chart 5: CNAs ranked by share of assigned scores >= 9.0.

    Window = the last ``window_years`` calendar years ending at
    ``as_of_year`` (defaults to the newest publication year seen). ``n``
    counts *scored* CVEs — the chart is about scores CNAs assign.
    """
    if as_of_year is None:
        as_of_year = max(agg.published_by_year, default=0)
    window = range(as_of_year - window_years + 1, as_of_year + 1)

    cnas = []
    for cna, per_year in agg.cna_year_scores.items():
        scores = [s for year in window for s in per_year.get(year, [])]
        if len(scores) < min_cves:
            continue
        cnas.append({
            "cna": cna,
            "org": cna,  # full org name not resolvable from records alone
            "n": len(scores),
            "avg_cvss": _r1(statistics.fmean(scores)),
            "median_cvss": _r1(statistics.median(scores)),
            "pct_geq_9": _pct(sum(1 for s in scores if s >= 9.0), len(scores)),
            "pct_geq_7": _pct(sum(1 for s in scores if s >= 7.0), len(scores)),
        })
    cnas.sort(key=lambda row: (-row["pct_geq_9"], -row["n"], row["cna"]))
    return {"generated_at": generated_at, "window_years": window_years,
            "min_cves": min_cves, "cnas": cnas}


def build_volume_curve(agg: Aggregator, generated_at: str) -> dict:
    """Chart 6: CVEs published / rejected per year (gap-filled), plus an
    optional full-year pace projection for the partial current year.

    The projection is keyed off the published flow: it ships only when the
    current year has published records and the year is far enough along
    (see :func:`pace_projection`). Rejections pace alongside; a zero
    rejected count so far paces to a zero projection.
    """
    out = {"generated_at": generated_at,
           "years": [{"year": year,
                      "published": agg.published_by_year.get(year, 0),
                      "rejected": agg.rejected_by_year.get(year, 0)}
                     for year in agg.year_span()]}
    current_year = int(generated_at[:4])
    projected = pace_projection(agg.published_by_year.get(current_year, 0),
                                generated_at)
    if projected is not None:
        out["projection"] = {
            "year": current_year,
            "published": projected,
            "rejected": pace_projection(
                agg.rejected_by_year.get(current_year, 0), generated_at) or 0,
            "elapsed": round(year_elapsed(generated_at), 3),
        }
    return out


def build_meta(generated_at: str, *, cvelist_release: str, cve_count: int,
               epss_model_version: str, epss_score_date: str, epss_row_count: int,
               kev_catalog_version: str, kev_count: int,
               nvd_source: dict | None) -> dict:
    """meta.json. ``nvd_source`` may be None (--skip-nvd with no prior data);
    the nvd key is then omitted — contracts.py treats it as optional."""
    meta = {
        "generated_at": generated_at,
        "sample": False,
        "sources": {
            "cvelist": {"release": cvelist_release, "cve_count": cve_count},
            "epss": {"model_version": epss_model_version,
                     "score_date": epss_score_date,
                     "row_count": epss_row_count},
            "kev": {"catalog_version": kev_catalog_version, "count": kev_count},
        },
    }
    if nvd_source is not None:
        meta["sources"]["nvd"] = nvd_source
    return meta
