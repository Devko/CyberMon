# Data contracts: pipeline → site

The pipeline writes these files into `site/data/`. The site reads ONLY these
files, at these paths, with exactly these shapes. Committed sample files
conform to the contracts and carry `"sample": true` in `meta.json`; the
pipeline's first real run overwrites them and sets `"sample": false`.

General rules:
- All files carry `"generated_at"` (ISO-8601 UTC).
- Percentages are 0–100 floats (not 0–1), rounded to 1 decimal.
- CVSS scores are 0.0–10.0 floats, 1 decimal.
- Years are integers. Series are sorted ascending by year/date.
- The pipeline must validate its own output against these shapes before
  writing (see `pipeline/contracts.py` — single source of truth as JSON
  Schema; site does not validate).

## site/data/meta.json

```json
{
  "generated_at": "2026-07-09T02:14:00Z",
  "sample": true,
  "sources": {
    "cvelist": {"release": "cve_2026-07-08_at_end_of_day", "cve_count": 251342},
    "epss": {"model_version": "v4", "score_date": "2026-07-08", "row_count": 248101},
    "kev": {"catalog_version": "2026.07.08", "count": 1402},
    "nvd": {"fetched_at": "2026-07-09T01:50:00Z"}
  }
}
```

## site/data/severity_inflation.json  (chart 1, hero)

```json
{
  "generated_at": "...",
  "series": {
    "v2": [{"year": 2005, "n": 4931, "median": 6.8, "p25": 4.3, "p75": 7.5}],
    "v3": [{"year": 2016, "n": 6447, "median": 7.5, "p25": 6.1, "p75": 8.8}],
    "v4": [{"year": 2024, "n": 3120, "median": 7.3, "p25": 5.9, "p75": 8.6}]
  },
  "blended": [{"year": 2005, "n": 4931, "median": 6.8, "pct_high_critical": 31.4}],
  "annotations": [
    {"year": 2015, "label": "CVSS v3.0 released"},
    {"year": 2023, "label": "CVSS v4.0 released"}
  ],
  "headline": {
    "latest_year": 2026,
    "pct_high_critical_latest": 59.1,
    "baseline_year": 2020,
    "pct_high_critical_baseline": 31.4
  }
}
```

Notes: a CVE's score = CNA-assigned base score from cvelistV5 (highest
version available per record; if a record has both v3.1 and v4, it appears
in each version series it has a score for, but exactly once in `blended`
using the newest version's score). `pct_high_critical` = share of scored
CVEs that year with base score ≥ 7.0. `blended` includes only scored CVEs;
`n` = scored CVEs that year.

Statistical filters (production runs; disabled for fixture corpora): every
plotted point requires ≥ 100 scored CVEs that year; per-version points
cannot predate the version's spec release (v3: 2015, v4: 2023 — CNAs
backfill scores onto old records); `blended` points additionally require
scores on ≥ 20% of that year's published CVEs. The headline never uses
the generation year (it is partial — six months of data would fake a
trend): `latest_year` is the last complete year that survived the
filters. The baseline is `latest_year - 10` when that year survived,
else the earliest surviving year — `baseline_year` is authoritative;
consumers must never derive either year themselves.

## site/data/nine_eight_flood.json  (chart 2)

```json
{
  "generated_at": "...",
  "years": [
    {"year": 2010, "critical": 312, "high": 1204, "medium": 2417, "low": 502, "unscored": 89}
  ]
}
```

Buckets: critical ≥9.0, high 7.0–8.9, medium 4.0–6.9, low 0.1–3.9,
`unscored` = published that year with no base score anywhere in the record.

## site/data/score_vs_reality.json  (chart 3)

```json
{
  "generated_at": "...",
  "grid": [
    {"cvss_bucket": "9.0-10.0", "epss_bucket": "<0.1%", "n": 18234}
  ],
  "cvss_buckets": ["0.1-3.9", "4.0-6.9", "7.0-8.9", "9.0-10.0"],
  "epss_buckets": ["<0.1%", "0.1-1%", "1-10%", ">10%"],
  "headline": {"pct_critical_epss_below_1pct": 83.4, "n_critical_with_epss": 45210},
  "kev": {
    "total": 1402,
    "below_high": 118,
    "pct_below_high": 8.4,
    "cvss_distribution": [{"bucket": "9.0-10.0", "n": 512}]
  }
}
```

`grid` covers scored CVEs that have a current EPSS score; every
(cvss_bucket, epss_bucket) cell present, `n` ≥ 0.

## site/data/nvd_decay.json  (chart 4)

```json
{
  "generated_at": "...",
  "current": {
    "statuses": [{"status": "Awaiting Analysis", "n": 30412}],
    "backlog_total": 31102
  },
  "history": [
    {"date": "2026-07-09", "backlog_total": 31102, "awaiting_analysis": 30412}
  ]
}
```

`backlog_total` = Received + Awaiting Analysis + Undergoing Analysis.
History is read from `site/data/history/nvd_backlog.csv` (append-only,
columns: `date,backlog_total,awaiting_analysis,undergoing_analysis,received`),
one row per pipeline run date (last run per date wins).

## site/data/cna_leaderboard.json  (chart 5)

```json
{
  "generated_at": "...",
  "window_years": 3,
  "min_cves": 100,
  "cnas": [
    {"cna": "GitHub_M", "org": "GitHub, Inc.", "n": 1234,
     "avg_cvss": 7.9, "median_cvss": 8.1, "pct_geq_9": 22.4, "pct_geq_7": 61.0}
  ]
}
```

Sorted by `pct_geq_9` descending. Uses CNA-assigned scores only (that is the
point of the chart). `cna` = short name from the record's assigner, `org` =
full org name where resolvable, else same as `cna`.

## site/data/volume_curve.json  (chart 6)

```json
{
  "generated_at": "...",
  "years": [{"year": 1999, "published": 1579, "rejected": 12}]
}
```

`rejected` = records with state REJECTED, counted by original publication year.

## site/data/market_hype.json  (Security Market module, all 3 charts)

```json
{
  "generated_at": "...",
  "window_months": 60,
  "sources": ["gdelt", "hn", "arxiv"],
  "backfill_remaining": 812,
  "terms": [
    {
      "id": "zero_trust",
      "label": "Zero Trust",
      "series": {
        "gdelt": [{"month": "2023-04", "n": 812, "index": 12.4}],
        "hn":    [{"month": "2023-06", "n": 41,  "index": 8.0}],
        "arxiv": [{"month": "2023-05", "n": 4,   "index": 40.0}]
      },
      "yoy": {
        "gdelt": {"latest_month": "2026-06", "pct_change": 340.2,
                  "n_latest_12m": 41200, "n_prior_12m": 9360},
        "hn": null,
        "arxiv": {"latest_month": "2026-06", "pct_change": 118.6,
                  "n_latest_12m": 61, "n_prior_12m": 28}
      },
      "divergence": {
        "gdelt_index_avg3m": 88.1, "arxiv_index_avg3m": 61.4,
        "research_vs_media_index": -26.7, "direction": "media_leads"
      }
    }
  ],
  "headline": {
    "top_riser":  {"term_id": "agentic_ai", "label": "Agentic AI",
                   "source": "gdelt", "pct_change": 340.2},
    "top_faller": {"term_id": "sase", "label": "SASE",
                   "source": "hn", "pct_change": -41.8},
    "top_divergence": {"term_id": "post_quantum",
                       "label": "Post-Quantum Cryptography",
                       "research_vs_media_index": 55.6,
                       "direction": "research_leads"}
  }
}
```

Notes: `window_months` = rolling window ending at the current calendar
month. Each `series[source]` is sorted ascending by `month` (`YYYY-MM`),
unique months, and may be SPARSE — months not yet fetched (HN backfill in
progress) or outside a source's coverage are omitted, never zero-filled.
`backfill_remaining` = pending (term, month) HN fetches. `n` = raw count
from that source's API; `index` = `round(100 * n / max(n over the emitted
series), 1)` (all `0.0` when the peak is 0) — index-to-own-peak, NOT
share-of-total, so editing the tracked-term list never reshapes other
terms' history.

`yoy[source]` is `null` unless the pair has ≥ 24 populated months, a
nonzero prior-12-month sum, AND at least 30 raw hits across the two
compared windows (`MIN_YOY_VOLUME` — a percentage of almost nothing is a
rumor, not a rate); `pct_change` is computed on raw counts.
`divergence` is `null` unless both `gdelt` and `arxiv` have ≥ 3 populated
months; `research_vs_media_index` = arxiv 3-month index average minus
gdelt's; `direction` ∈ research_leads / media_leads / aligned with a ±10
dead zone. Every `headline` field is nullable — no eligible pair means
`null`, never a fabricated number; ties break by `term_id` ascending.

The term list (ids, labels, per-source query strings) lives in
`pipeline/market_terms.py`. Validator: `pipeline/market_contracts.py`
(registered into `pipeline/contracts.py`'s dispatch).

## site/data/kev_latency.json  (KEV Latency module, all 3 charts)

```json
{
  "generated_at": "...",
  "matched": {"total_kev": 1635, "matched_cve": 1601, "unmatched_cve": 34},
  "launch_backfill": {"date_added_before": "2023-01-01", "n": 866,
                      "median_days": 1808.0},
  "latency_by_year": [
    {"year": 2022, "n": 214, "median_days": 39.0, "p25_days": 6.0,
     "p75_days": 412.0, "pct_negative": 3.7, "pct_over_365d": 21.5}
  ],
  "latency_buckets": [
    {"bucket": "before_publish", "n": 39, "pct": 3.6},
    {"bucket": "0-7d", "n": 312, "pct": 28.9}
  ],
  "remediation_span_by_year": [
    {"year": 2021, "n": 291, "median_days": 180.0, "p25_days": 180.0,
     "p75_days": 180.0}
  ],
  "headline": {"latest_year": 2025, "median_days_latest": 27.0,
               "pct_over_365d_latest": 15.2,
               "baseline_year": 2022, "median_days_baseline": 39.0}
}
```

Notes: `latency_days = KEV dateAdded − CVE datePublished`, day precision;
negative values are KEPT (CISA sometimes lists a CVE before its record
publishes — that ordering is signal). Entries with `dateAdded` before
2023-01-01 are the catalog's seeding era — the November 2021 launch batch
plus the back-catalog import waves that ran through 2022 (empirically: the
median nominal "latency" of 2022 additions is 1,436 days vs 12 for 2023) —
whose nominal "latency" measures the age of the inherited backlog, not
triage speed; they are excluded from
`latency_by_year`/`latency_buckets`/`headline` and reported once as
`launch_backfill` (`median_days` null iff `n` = 0). KEV
ids with no `datePublished` join in the corpus are counted in
`matched.unmatched_cve` and excluded from all stats. Years plot only with
≥ 10 matched entries (fixture mode: 1). `remediation_span_by_year` =
`dueDate − dateAdded` by dateAdded year, INCLUDING the launch cohort (a
deadline is policy, real regardless of CVE age). Buckets are fixed, in
order: before_publish, 0-7d, 8-30d, 31-90d, 91-365d, 1-3y, 3y+ (lower
edge inclusive). `headline.latest_year` is the last complete year that
survived filters; `baseline_year` = latest − 3 when present, else the
earliest surviving year — payload-authoritative, never derived.

## site/data/cna_concentration.json  (CNA Concentration module, all 3 charts)

```json
{
  "generated_at": "...",
  "years": [
    {"year": 2025, "cna_count": 341, "newcomer_count": 47,
     "top5_share": 34.9, "top10_share": 48.2, "hhi": 782.1}
  ],
  "rejection_leaderboard": {
    "window_years": 5, "min_total": 50,
    "cnas": [{"cna": "mitre", "total": 4820, "rejected": 1104,
              "rejected_rate_pct": 22.9}]
  },
  "headline": {"latest_year": 2025, "cna_count_latest": 341,
               "top5_share_latest": 34.9, "hhi_latest": 782.1,
               "baseline_year": 2015, "top5_share_baseline": 71.8,
               "hhi_baseline": 2510.3}
}
```

Notes: `years` = the corpus's full publication span, gap-filled, NO
minimum-volume filter (a single-CNA 1999 with `hhi` 10000.0 is history,
not noise). `cna_count` = distinct CNAs with ≥ 1 published or rejected
record that year; `newcomer_count` = CNAs whose first-ever activity is
that year. `top5_share`/`top10_share` = the year's top-N CNAs by
published count as a share of the year's published total. `hhi` is the
standard Herfindahl-Hirschman index on its conventional **0–10000**
scale — a documented exception to the 0–100 percentage rule; site copy
must cite it on its own terms (top-N share and HHI can disagree).
`rejection_leaderboard`: window = last `window_years` calendar years
ending at the newest published year; `total = published + rejected`
in-window, CNAs under `min_total` excluded; `rejected_rate_pct` =
`100 * rejected / total` (bounded on purpose — the backlog's literal
"rejected/published" is unbounded and is not shipped). Deliberately NOT
shipped: any "reserved-but-never-published" rate — reserved-only IDs
produce no record in the cvelistV5 release, so that stat would be
survivorship-biased; it needs a different data source.
