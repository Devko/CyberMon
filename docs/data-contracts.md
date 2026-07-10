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

Pace projections (optional `"projection"` key): exactly three files —
`volume_curve.json`, `nine_eight_flood.json`, `cna_concentration.json` —
may carry a full-year pace projection for the partial current year:
`projected = round(count / elapsed)`, where `elapsed` = day-of-year ÷
days-in-year (UTC, leap-year aware) at `generated_at`. `elapsed` ships in
the block, rounded to **3** decimals — a documented exception to the
1-decimal float rule. The key is ABSENT when `elapsed` < 0.125 (before
roughly mid-February a pace is noise; the divisor is too small) or when
the current year has no records to pace — consumers must treat absence as
"no projection", never as zero. `projection.year` always equals the
`generated_at` year. Projections exist ONLY for flow metrics — counts of
events per year (records published, records rejected, first-appearance
newcomers). Nothing else may ever be projected: a median doesn't scale
with elapsed time, a share is already normalized to its year, and a
distinct-entity count (the active-CNA roster) is a headcount rather than
a flow. The math assumes the flow is uniform through the year and ignores
seasonality and late-year backfill; the site must render projections
visually distinct (dashed/hollow) and labeled.

## site/data/meta.json

```json
{
  "generated_at": "2026-07-09T02:14:00Z",
  "sample": true,
  "sources": {
    "cvelist": {"release": "cve_2026-07-08_at_end_of_day", "cve_count": 251342},
    "epss": {"model_version": "v4", "score_date": "2026-07-08", "row_count": 248101},
    "kev": {"catalog_version": "2026.07.08", "count": 1402},
    "nvd": {"fetched_at": "2026-07-09T01:50:00Z"},
    "apnic": {"fetched_at": "2026-07-09T02:05:00Z", "economy_count": 10,
              "spread_economy_count": 203}
  }
}
```

`sources.apnic` (Hygiene Index module) is validated additively — optional
because older committed meta files predate the module, but the hygiene
stage itself always emits it: `economy_count` = fixed-set economies with a
fetched series, `spread_economy_count` = economies that survived the
spread's sample floor.

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
  ],
  "projection": {"year": 2026, "total": 48210, "elapsed": 0.521},
  "record_era": {"year": 2018, "min_share": 0.1}
}
```

Buckets: critical ≥9.0, high 7.0–8.9, medium 4.0–6.9, low 0.1–3.9,
`unscored` = published that year with no base score anywhere in the record.
`projection` (optional; see "Pace projections" above): the current year's
published total — the sum across all five buckets, `unscored` included,
rejected records never counted — paced to a full year (`total` ≥ 1).
There is deliberately no per-bucket projection: bucket *shares* shift
within a year, and pacing each bucket separately would present the
current mix as a full-year claim.

`record_era` (optional): the first charted year in which at least
`min_share` (fixed at `RECORD_ERA_MIN_SHARE` = 0.10) of that year's
published records carry a base score in the record itself. The site draws
a vertical marker here: to its left, severity mostly lived downstream in
NVD's database (which this chart deliberately does not ingest), so the
near-empty severity bands are a record-format fact, not an ecosystem one.
Absent when no charted year clears the threshold (tiny fixture corpora);
`year` must be one of the charted years, `min_share` a float in (0, 1).

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
  "years": [{"year": 1999, "published": 1579, "rejected": 12}],
  "projection": {"year": 2026, "published": 51230, "rejected": 812,
                 "elapsed": 0.521}
}
```

`rejected` = records with state REJECTED, counted by original publication year.
`projection` (optional; see "Pace projections" above): the current year's
published and rejected counts paced to a full year. Keyed off the
published flow — it ships only when the current year has ≥ 1 published
record (so `published` ≥ 1); `rejected` may legitimately pace to 0.

## site/data/advisory_quality.json  (chart 7)

```json
{
  "generated_at": "...",
  "min_n": 500,
  "years": [
    {"year": 2018, "n": 16555,
     "missing_cwe": 9012, "pct_missing_cwe": 54.4,
     "missing_cvss": 8123, "pct_missing_cvss": 49.1,
     "missing_affected": 12002, "pct_missing_affected": 72.5}
  ]
}
```

Per publication year of *published* records (REJECTED excluded), how many
are missing each machine-readable field, checked against the record itself
(CNA and ADP containers): `missing_cwe` = no `problemTypes` description
with a `cweId` anywhere in the record; `missing_cvss` = no CVSS base score
in any metrics container (the same definition as `nine_eight_flood`'s
`unscored`); `missing_affected` = no `affected[]` entry carrying either a
`versions[]` item with a concrete version string (placeholders such as
"n/a"/"unspecified" don't count) or a definite `defaultStatus`
("affected"/"unaffected" — "unknown" doesn't count). Each `missing_*` ≤
`n`; `pct_missing_* = 100 * missing / n`. Years with fewer than `min_n`
published records are omitted (production 500; fixture mode 1). The
current year appears when it clears `min_n` and is partial — the site
labels it. Pre-2018 caveat: CWE and CVSS then lived downstream in NVD's
database, which this chart deliberately does not ingest — the early years
chart where the data lived, not sloppiness by today's CNAs.

## site/data/cwe_distribution.json  (chart 8)

```json
{
  "generated_at": "...",
  "min_n": 500,
  "window": {"start_year": 2016, "end_year": 2025},
  "top_cwes": [{"id": "CWE-79", "name": "Cross-site scripting"}],
  "years": [
    {"year": 2016, "n_tagged": 4102, "n_published": 6447, "pct_tagged": 63.6,
     "shares": {"CWE-79": 21.4, "other": 43.0}}
  ]
}
```

Each CWE-tagged published record contributes its **first-listed** cweId
(CNA container preferred, ADP fallback) — one class per record, so a
year's shares sum to ~100 (independent 1-decimal rounding). `window` =
the last 10 *complete* calendar years ending at `generated_at`'s year − 1;
the partial current year is excluded entirely (it cannot rank a decade).
`top_cwes` = up to 8 ids ranked by total tagged volume across the window,
ties broken by CWE number ascending; `name` comes from a small built-in
map (`pipeline/quality_metrics.py`), falling back to the bare id.
`years[].shares` carries **exactly** the `top_cwes` ids plus `"other"`
(everything not in the top 8), each a share of that year's `n_tagged`.
Shares describe the tagged subset only — `n_tagged`, `n_published` and
`pct_tagged` ship per year so consumers can state the coverage. Years
with fewer than `min_n` tagged records are omitted (production 500;
fixture mode 1).

## site/data/kev_ransomware.json  (KEV Latency module, chart 4)

```json
{
  "generated_at": "...",
  "min_n": 10,
  "years": [
    {"year": 2021, "total": 311, "known": 62, "pct_known": 19.9}
  ],
  "catalog": {"total": 1402, "known": 289, "pct_known": 20.6}
}
```

Per calendar year of KEV `dateAdded`: entries added (`total`), entries
whose `knownRansomwareCampaignUse` is "Known" (case-insensitive; a missing
or "Unknown" field never counts), and `pct_known = 100 * known / total`.
Unlike `kev_latency`, ALL cohorts belong here, the 2021–22 seeding era
included: the catalog is read as a current snapshot, so every entry
carries CISA's present assessment regardless of when it was listed — a
back-catalog import is as real a data point as a fresh listing (same
reasoning as the remediation spans). No CVE-corpus join is involved.
Entries with an unparseable `dateAdded` join no year but still count in
`catalog` (whole-catalog totals, unfiltered). Years with fewer than
`min_n` entries are omitted (production 10; fixture mode 1). `known` ≤
`total` everywhere. Validator: `pipeline/tier2_contracts.py` (registered
into `pipeline/contracts.py`'s dispatch, as are the two charts above).

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

## site/data/dnssec_adoption.json  (Hygiene Index module, all 3 charts)

```json
{
  "generated_at": "...",
  "window": "30_day",
  "world": {
    "cc": "XA",
    "series": [{"month": "2013-10", "validating_pc": 8.6}],
    "latest": {"date": "2026-07-07", "validating_pc": 38.5,
               "partial_pc": 8.8, "seen": 493075676},
    "baseline": {"month": "2016-07", "validating_pc": 14.6}
  },
  "economies": [
    {"cc": "PH", "name": "Philippines", "latest_pc": 93.5,
     "series": [{"month": "2014-03", "validating_pc": 41.2}]}
  ],
  "spread": {
    "min_seen": 10000,
    "n_economies": 203,
    "buckets": [{"bucket": "<10%", "n": 13}]
  }
}
```

Source: APNIC Labs' measured DNSSEC validation
(`stats.labs.apnic.net/cgi-bin/json-table.pl?x=<code>` for time series;
the `/dnssec` world-map page's inline table for the snapshot). Everything
reads APNIC's **30-day smoothed window** (`window` is pinned to
`"30_day"`); `validating_pc` = share of sampled users behind validating
resolvers, `partial_pc` = APNIC's "partially validating" share (mixed
resolver sets). Upstream publishes its full daily history, so the stage
is stateless — refetched in full nightly, no committed history file.

`world.series` = one point per calendar month (the month's last published
day), sorted ascending, unique, non-empty; `world.latest` is the exact
newest day and must fall inside the newest series month.
`world.baseline` is payload-authoritative (consumers never derive it):
the point 120 months before the newest month, else the series' first
month — its `month` must be one of the charted months.

`economies` = the FIXED ten-economy set (`pipeline/fetch_dnssec.py
ECONOMIES` — the ten largest by APNIC's weighted sample count, i.e. its
internet-user estimate, frozen at module creation 2026-07-10: CN IN US BR
ID JP MX RU PH NG), each with quarter-end-month sampling (Mar/Jun/Sep/Dec
last published day, plus the newest available month). Sorted by
`latest_pc` descending; at most 10 entries; unique codes. Fixture runs
may carry a subset (only the series with fixture files).

`spread` = one-economy-one-vote distribution from the world-map snapshot:
economies with `seen >= min_seen` (production 10,000) in the current
30-day window, bucketed by `validating_pc` into exactly
`["<10%", "10-25%", "25-50%", "50-75%", "75%+"]` (that order; lower edges
inclusive); bucket counts must sum to `n_economies`. APNIC's region
pseudo-codes (XA–XW, QM–QS) are excluded — QA (Qatar) is a real economy
and stays. Measurement caveat (stated in the site methodology): APNIC
measures via ad-delivered test fetches, so rates are sampled estimates
weighted to each economy's estimated internet population.
Validator: `pipeline/hygiene_contracts.py` (registered into
`pipeline/contracts.py`'s dispatch).

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
               "hhi_baseline": 2510.3},
  "projection": {"year": 2026, "newcomers": 52, "elapsed": 0.521}
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
`projection` (optional; see "Pace projections" above): the current year's
`newcomer_count` paced to a full year (`newcomers` ≥ 1). First
appearances are events — a flow — so a pace applies, on the strong
assumption that newcomers arrive uniformly through the year. `cna_count`
is a roster headcount and is never projected; nor are the shares or the
HHI. Validator: `pipeline/tier1_contracts.py`.
