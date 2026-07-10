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

Pace projections (optional `"projection"` key): exactly four files —
`volume_curve.json`, `nine_eight_flood.json`, `cna_concentration.json`,
`breach_ledger.json` —
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
    "hibp": {"fetched_at": "2026-07-09T02:05:00Z", "breach_count": 1015}
    "attack": {"fetched_at": "2026-07-09T01:52:00Z",
               "latest_version": "19.1", "version_count": 40}
    "apnic": {"fetched_at": "2026-07-09T02:05:00Z", "economy_count": 10,
              "spread_economy_count": 203}
  }
}
```

`sources.hibp` is optional in the validator so older meta files stay
valid, but the pipeline always emits it — the HIBP stage has no skip flag
and no carry-forward: if the fetch fails, the run fails.
`sources.attack` is optional for the same reason as `nvd`/`market`
(`--skip-attack` with no prior data omits it); when present it carries
`fetched_at` (ISO-8601 UTC), the newest enterprise release's
`latest_version`, and `version_count` ≥ 1 (releases in the index), plus
`"stale": true` on carry-forward runs.
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

## site/data/breach_ledger.json  (Breach Ledger module, all 3 charts)
## site/data/extortion_ledger.json  (Extortion Ledger module, all 3 charts)
## site/data/attack_churn.json  (ATT&CK Churn module, all 3 charts)

```json
{
  "generated_at": "...",
  "min_n": 10,
  "catalog": {
    "total": 1015, "cohort": 982,
    "excluded": {"fabricated": 3, "spam_list": 16, "malware": 8,
                 "stealer_log": 6}
  },
  "import_era": {"added_before": "2014-01-01", "n": 7, "median_days": 511.0},
  "lag_by_year": [
    {"year": 2014, "n": 27, "median_days": 5.0, "p25_days": 1.0,
     "p75_days": 222.0, "pct_negative": 0.0, "pct_over_365d": 25.9}
  ],
  "volume_by_year": [
    {"year": 2013, "breaches": 7, "records": 155137175}
  ],
  "class_shares": {
    "classes": ["Email addresses", "Passwords", "Names", "Usernames",
                "IP addresses", "Phone numbers"],
    "years": [
      {"year": 2016, "n": 109,
       "shares": {"Email addresses": 100.0, "Passwords": 74.3,
                  "Names": 45.0, "Usernames": 39.4,
                  "IP addresses": 33.9, "Phone numbers": 22.9}}
    ]
  },
  "headline": {"trend_n": 975, "median_days": 144.0, "pct_over_365d": 35.5,
               "latest_year": 2025, "median_days_latest": 194.0},
  "projection": {"year": 2026, "breaches": 149, "elapsed": 0.523}
}
```

Source: the Have I Been Pwned public breaches feed (one JSON GET, no key;
attribution carried in the site footer). Cohort rule, applied everywhere:
`IsFabricated` (never happened) and `IsSpamList` (address collections, no
breached organization) are excluded; `IsMalware` and `IsStealerLog` are
excluded for the same reason as spam lists — real credential theft, but
harvested device-by-device with no single breached organization, and a
nominal `BreachDate` that describes the compilation of the corpus, which
would poison the lag stats. Each excluded entry counts under its FIRST
matching reason, in that order, so `cohort + sum(excluded) == total`
always holds — `catalog` is the audit trail. `excluded` carries exactly
those four keys.

All per-year series group by the `AddedDate` calendar year (years ≥ 2013,
sorted, unique). Entries with an unparseable `AddedDate` join no year but
still count in `catalog`; lag stats additionally require a parseable
`BreachDate`.

`lag_by_year` (hero): `lag = AddedDate − BreachDate` in days, per catalog
year, median + p25/p75. Negative lags (a breach catalogued before its
self-reported, usually month-rounded, breach date) are KEPT, never
floored — same rule as `kev_latency`, they flag source date quality.
Entries with `AddedDate` before `import_era.added_before` (fixed at
`2014-01-01`) are the catalog's opening import — HIBP launched 2013-12-04
by loading breaches that were already public (empirically: six of its
seven December 2013 entries predate the service itself, median nominal
lag 511 days, vs a 5-day median for 2014 additions) — and are excluded
from `lag_by_year` and `headline`, reported once as `import_era`
(`median_days` null iff `n` = 0). Pre-2014 *breaches* surfacing later
stay in the trend: surfacing late is the measured phenomenon; only the
opening import is an artifact of the catalog's birthday. Years with fewer
than `min_n` cohort breaches are omitted (production 10; fixture mode 1).

`volume_by_year`: cohort breaches catalogued per year (`breaches` ≥ 1 —
a year exists only because something was catalogued) and `records` = the
year's `PwnCount` sum (compromised accounts per breach; a person appears
once per breach they are in, so the sum counts exposures, not people).
No `min_n` filter and no import-era exclusion — counts are counts.

`class_shares`: `classes` = up to 6 data classes ranked by the number of
cohort breaches listing them, all-time, ties broken alphabetically —
derived from the data nightly, never hardcoded, so the list may reshape
as the catalog grows. `years[].shares` carries exactly those classes;
each value is the share of that year's cohort breaches listing the class
(counted at most once per breach). Multi-label: shares are independent
per class — there is deliberately no "other" key and no 100% sum. Years
under `min_n` are omitted.

`headline`: `trend_n`/`median_days`/`pct_over_365d` pool every trend-era
lag (import era excluded, all years, unfiltered by `min_n`);
`latest_year`/`median_days_latest` echo the last complete plotted year,
falling back to the partial current year only when nothing else survived
(`kev_latency` rule). An empty trend is `trend_n` 0, zeros elsewhere and
`latest_year` 0 — consumers must treat `latest_year` 0 as "no data",
never as a year.

`projection` (optional; see "Pace projections" above): the current year's
catalogued-breach count paced to a full year (`breaches` ≥ 1). Breaches
catalogued are a flow, so a pace applies; `records` is deliberately never
projected — one mega-dump can outweigh the rest of the year, so a records
pace would dress one upload up as a forecast. Validator:
`pipeline/breach_contracts.py` (registered into `pipeline/contracts.py`'s
dispatch).
  "revenue_by_quarter": [
    {"year": 2020, "quarter": 3, "usd": 139502184}
  ],
  "payments_by_year": [
    {"year": 2016, "payments": 9324, "usd": 68400000, "median_usd": 575.5}
  ],
  "families": {
    "top": [
      {"family": "Conti", "usd": 101561482, "payments": 128,
       "first_year": 2017, "last_year": 2022}
    ],
    "other": {"families": 96, "usd": 12345678, "payments": 990},
    "unattributed": {"usd": 682149269, "payments": 850}
  },
  "catalog": {"addresses": 11186, "families": 106, "transactions": 21802,
              "payments": 18902, "total_usd": 1018573922},
  "headline": {"total_usd": 1018573922,
               "peak_quarter": {"year": 2020, "quarter": 3, "usd": 139502184},
               "first_year": 2012, "last_year": 2024}
}
```

Source: the Ransomwhere export (`api.ransomwhe.re/export`, CC0) —
crowdsourced, verified ransomware payment addresses with their on-chain
transactions. Everything in this file is a FLOOR: a payment enters the
dataset only after someone reported the address and the transfers were
verified, so site copy must always claim "at least this much", never
"the market is this big".

All `usd` values are **integers (whole dollars)** at the HISTORICAL
BTC/USD rate of each transaction's date (upstream's `amountUSD`; the
implied rate per transaction year tracks the price history) — a 2016
payment stays in 2016 dollars. `median_usd` is the one float, rounded to
**2** decimals — a documented exception to the 1-decimal rule: early
mass-campaign years have sub-dollar medians ($0.03 in 2013), which
1-decimal rounding would crush to a false zero. Years are bounded below
by 2008 (pre-Bitcoin "payments" are parser breakage); any single USD
value above 10^10 fails validation as a unit error (satoshi summed as
dollars).

`revenue_by_quarter`: transaction `amountUSD` summed by the UTC calendar
quarter of the on-chain timestamp, over ALL ledger entries as published
(the export lists a transaction once per receiving tracked address;
exact repeated entries carry ~1% of total USD and are trusted rather
than second-guessed without chain data). Quarters are **contiguous** from
first to last observed payment — gaps chart as zero, the axis never
silently skips time.

`payments_by_year`: a payment is one distinct on-chain transaction
(unique `hash`, outputs to tracked addresses summed — multi-wallet
transfers collapse). `payments` ≥ 1 per row; `median_usd` is present
only when the year has at least `min_n` payments (production 10; fixture
mode 1) — absence means "not charted", never zero. `catalog.payments` ≤
`catalog.transactions` always.

`families`: Ransomwhere's own labels, neutral identifiers. `top` = up to
8 labeled families ranked descending by all-time confirmed USD; the
literal `"Unlabeled"` bucket (verified but unattributed — the largest
single slice) must NEVER appear in `top`: it ships as
`families.unattributed` and the site discloses it beside the board.
Remaining labeled families pool into `families.other`.
`catalog.families` counts labeled families only. A ranked board is
shipped instead of a per-year share series on purpose: wallets are often
reported long after a campaign ran, so yearly family shares would chart
reporting dates, not activity.

NO `projection` key, ever, although yearly payment counts are a flow:
crowdsourced reports arrive with a lag, so the partial current year
structurally undercounts and the uniform-flow assumption behind "Pace
projections" (above) does not hold. `headline.total_usd` must equal
`catalog.total_usd`; `headline.peak_quarter.usd` must equal the series
maximum. `meta.json` gains an optional `sources.ransomwhere`
`{fetched_at, address_count, tx_count}` block (validated when present).
Validator: `pipeline/extortion_contracts.py` (registered into
`pipeline/contracts.py`'s dispatch).
  "versions": [
    {"version": "1.0", "released": "2018-01-17",
     "techniques": 187, "subtechniques": 0, "groups": 68, "software": 328,
     "churn": null},
    {"version": "19.1", "released": "2026-05-12",
     "techniques": 222, "subtechniques": 475, "groups": 174, "software": 821,
     "churn": {"added": 9, "deprecated": 2, "revoked": 1}}
  ],
  "headline": {
    "latest_version": "19.1", "released_latest": "2026-05-12",
    "techniques_latest": 222, "subtechniques_latest": 475,
    "first_version": "1.0", "released_first": "2018-01-17",
    "techniques_first": 187, "subtechniques_first": 0
  }
}
```

One entry per release of the MITRE ATT&CK **enterprise** collection
(`mitre-attack/attack-stix-data`), sorted ascending by numeric
`major.minor` version, unique versions, `released` (the date part of the
version's `modified` timestamp in the repo's `index.json`) never
decreasing. Counting rules, applied to the release's STIX 2.1 bundle:
`techniques` = `attack-pattern` objects with `x_mitre_is_subtechnique`
false or absent; `subtechniques` = the flag true; `groups` =
`intrusion-set`; `software` = `malware` + `tool`. All four count **active**
objects only — an object carrying `revoked: true` or
`x_mitre_deprecated: true` is excluded. `churn` diffs the release against
its predecessor by STIX object id over all `attack-pattern` objects
(techniques and sub-techniques together, active or not): `added` = ids new
to the release; `deprecated`/`revoked` = ids present in both whose flag
flipped false→true (an object arriving already deprecated counts once, as
an addition; nothing is ever re-counted). `churn` is `null` when the
release has no predecessor in the index (normally only v1.0). `headline`
restates the first and latest entries (payload-authoritative; consumers
never derive it) and is `null` iff `versions` is empty. `"stale": true`
appears only on `--skip-attack` carry-forwards.

**Reconstruct-losslessly guarantee:** the per-version objects in
`versions[]` are byte-for-byte the pipeline's sync-state entries
(`.cache/attack_state.json`) plus the version string — nothing in the
state is omitted from the output and nothing in the output is derived
beyond `headline`. `pipeline/fetch_attack.reconstruct_state` rebuilds the
full state from this file, so a lost CI cache costs one JSON read instead
of re-downloading ~40 immutable bundles (tens of MB each); only versions
absent from both the cache and this file are ever fetched. Changing this
file's per-version shape therefore REQUIRES updating `reconstruct_state`
and its round-trip test in the same commit. Validator:
`pipeline/attack_contracts.py` (registered into `pipeline/contracts.py`'s
dispatch).

## site/data/kev_guards.json  (Security Products module, all 3 charts)

```json
{
  "generated_at": "...",
  "min_n": 10,
  "min_vendor_entries": 5,
  "years": [
    {"year": 2021, "total": 311, "security": 44, "pct_security": 14.1}
  ],
  "vendors": [
    {"vendor": "Fortinet", "entries": 26, "security_entries": 26,
     "pct_security": 100.0, "first_added": "2021-11-03",
     "last_added": "2026-04-13", "median_gap_days": 42.0}
  ],
  "ransomware": {
    "security": {"total": 188, "known": 70, "pct_known": 37.2},
    "other": {"total": 1447, "known": 259, "pct_known": 17.9}
  },
  "catalog": {"total": 1635, "security": 188, "pct_security": 11.5,
              "classifier_version": 1, "classifier_rules": 32}
}
```

Every KEV entry is classified by `pipeline/security_products.py` — a
curated, versioned table of security vendors plus product-keyword rules
for mixed vendors (the decision rule and every judgment call live in
that module's docstring; the table is data, reviewable in the repo).
`catalog` is the audit block: whole-catalog totals plus the
`classifier_version`/`classifier_rules` that produced them, so any
published share is traceable to the classifier revision behind it.

`years` (hero): per `dateAdded` calendar year, entries added (`total`),
entries classified as security products (`security` ≤ `total`), and
`pct_security`. ALL cohorts belong, the 2021–22 seeding era included —
like `kev_ransomware`, the catalog is read as a snapshot and the
classification rides on the entry itself. Years with fewer than `min_n`
entries are omitted (production 10; fixture mode 1); sorted, unique.
Entries with an unparseable `dateAdded` join no year but still count in
`catalog` and `ransomware`.

`vendors` (recidivism board): every vendor label with at least
`min_vendor_entries` catalog entries (production 5; fixture mode 1).
Labels are whitespace-normalized but NEVER merged (Pulse Secure stays
distinct from Ivanti — the catalog's attribution is the record).
`median_gap_days` is the median of day gaps between consecutive
`dateAdded` values (0.0 = same-day bulk additions), `null` iff the
vendor has a single dated entry. `first_added` ≤ `last_added`. Sorted by
`entries` descending, ties by casefolded vendor name; vendor names
unique. The site flags rows with `pct_security` ≥ 50 as security-vendor
rows.

`ransomware`: the `knownRansomwareCampaignUse` split ("Known" vs
anything else, missing never counts — `kev_ransomware`'s rule) across
the classifier's two halves; `security.total + other.total` must equal
`catalog.total`, so nothing is dropped silently. No CVE-corpus join
anywhere in this file. Validator: `pipeline/guards_contracts.py`
(registered into `pipeline/contracts.py`'s dispatch).
