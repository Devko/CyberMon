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
    "pct_high_critical_decade_ago": 31.4
  }
}
```

Notes: a CVE's score = CNA-assigned base score from cvelistV5 (highest
version available per record; if a record has both v3.1 and v4, it appears
in each version series it has a score for, but exactly once in `blended`
using the newest version's score). `pct_high_critical` = share of scored
CVEs that year with base score ≥ 7.0. `blended` includes only scored CVEs;
`n` = scored CVEs that year.

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
