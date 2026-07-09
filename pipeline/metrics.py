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

import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
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
    adp_scores: dict[str, float] = {}
    for adp in containers.get("adp") or []:
        if isinstance(adp, dict):
            for family, score in _scores_from_metrics(adp.get("metrics")).items():
                adp_scores.setdefault(family, score)

    return CveFacts(
        cve_id=cve_id,
        state=str(meta.get("state", "PUBLISHED")).upper(),
        year=year,
        cna=str(meta.get("assignerShortName") or "unknown"),
        cna_scores=_scores_from_metrics(cna.get("metrics")),
        adp_scores=adp_scores,
    )


class Aggregator:
    """Folds a stream of :class:`CveFacts` into the aggregates the
    six output builders need. Never stores whole records."""

    def __init__(self) -> None:
        self.cve_count = 0
        self.published_by_year: Counter[int] = Counter()
        self.rejected_by_year: Counter[int] = Counter()
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

    def add(self, facts: CveFacts) -> None:
        self.cve_count += 1
        if facts.state == "REJECTED":
            self.rejected_by_year[facts.year] += 1
            return
        self.published_by_year[facts.year] += 1

        for family, score in facts.cna_scores.items():
            self.version_scores[family][facts.year].append(score)

        newest = facts.newest_cna_score
        if newest is not None:
            self.blended_scores[facts.year].append(newest)
            self.cna_year_scores[facts.cna][facts.year].append(newest)

        effective = facts.effective_score
        if effective is None:
            self.flood[facts.year]["unscored"] += 1
        else:
            self.flood[facts.year][severity_bucket(effective)] += 1
            self.effective_by_cve[facts.cve_id] = effective

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

def build_severity_inflation(agg: Aggregator, generated_at: str) -> dict:
    """Chart 1 (hero): per-version median/IQR per year + blended trend."""
    series: dict[str, list[dict]] = {}
    for family in ("v2", "v3", "v4"):
        rows = []
        for year in sorted(agg.version_scores[family]):
            scores = agg.version_scores[family][year]
            p25, median, p75 = _quartiles(scores)
            rows.append({"year": year, "n": len(scores), "median": _r1(median),
                         "p25": _r1(p25), "p75": _r1(p75)})
        series[family] = rows

    blended = []
    for year in sorted(agg.blended_scores):
        scores = agg.blended_scores[year]
        high = sum(1 for s in scores if s >= 7.0)
        blended.append({"year": year, "n": len(scores),
                        "median": _r1(statistics.median(scores)),
                        "pct_high_critical": _pct(high, len(scores))})

    by_year = {row["year"]: row for row in blended}
    latest_year = blended[-1]["year"] if blended else 0
    decade_ago = by_year.get(latest_year - 10, blended[0] if blended else None)
    return {
        "generated_at": generated_at,
        "series": series,
        "blended": blended,
        "annotations": list(ANNOTATIONS),
        "headline": {
            "latest_year": latest_year,
            "pct_high_critical_latest":
                blended[-1]["pct_high_critical"] if blended else 0.0,
            "pct_high_critical_decade_ago":
                decade_ago["pct_high_critical"] if decade_ago else 0.0,
        },
    }


def build_nine_eight_flood(agg: Aggregator, generated_at: str) -> dict:
    """Chart 2: stacked severity buckets per publication year (gap-filled)."""
    years = []
    for year in agg.year_span():
        counts = agg.flood.get(year, Counter())
        years.append({"year": year,
                      "critical": counts.get("critical", 0),
                      "high": counts.get("high", 0),
                      "medium": counts.get("medium", 0),
                      "low": counts.get("low", 0),
                      "unscored": counts.get("unscored", 0)})
    return {"generated_at": generated_at, "years": years}


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
    """Chart 6: CVEs published / rejected per year (gap-filled)."""
    return {"generated_at": generated_at,
            "years": [{"year": year,
                       "published": agg.published_by_year.get(year, 0),
                       "rejected": agg.rejected_by_year.get(year, 0)}
                      for year in agg.year_span()]}


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
