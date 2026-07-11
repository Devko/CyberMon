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
`sources.epss_history` (EPSS Report Card module) is optional for the same
reason as `attack` (`--skip-epss-report` with no prior data omits it);
when present it carries `fetched_at` (ISO-8601 UTC), `graded` (KEV entries
with a day-before score) and `pending_backfill` (pairs not yet looked up),
plus `"stale": true` on carry-forward runs.
`sources.kev_changelog` (KEV Changelog module) is validated additively —
optional because older committed meta files predate the module, but the
stage itself always emits it (no skip flag; it rides on the KEV fetch):
`fetched_at` (ISO-8601 UTC), `events_total` (rows in the committed event
log, additions included) and `last_observed` (date of the newest catalog
observation; empty string only in the degenerate no-record-yet case).

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

## site/data/cve_calendar.json  (CVE Calendar module, all 3 charts)

```json
{
  "generated_at": "...",
  "min_n": 500,
  "id_age": {
    "years": [
      {"year": 2025, "n": 48168, "same_year": 38337, "one_year": 5495,
       "two_plus": 4336, "pct_same_year": 79.6, "pct_one_year": 11.4,
       "pct_two_plus": 9.0, "pct_prior_year": 20.4}
    ],
    "clamped_negative": 0,
    "headline": {"latest_year": 2025, "pct_prior_year_latest": 20.4,
                 "baseline_year": 2015, "pct_prior_year_baseline": 14.3}
  },
  "weekday": {
    "years": [
      {"year": 2025, "n": 48168,
       "counts": [7447, 11783, 9375, 8961, 7009, 2104, 1489],
       "pct": [15.5, 24.5, 19.5, 18.6, 14.6, 4.4, 3.1]}
    ],
    "comparison": {"latest_year": 2025, "baseline_year": 2015}
  },
  "patch_tuesday": {
    "calendar_pct": 3.3,
    "years": [
      {"year": 2025, "n": 48168, "on_pt": 4737, "pct": 9.8,
       "top_day": {"date": "2025-02-26", "n": 790}}
    ],
    "headline": {"latest_year": 2025, "pct_latest": 9.8}
  }
}
```

Everything covers PUBLISHED records only, grouped by publication year, and
every date judgment is **UTC** (the date the record carries; a Tuesday
evening in California is a Wednesday UTC, so any timezone skew pushes
counts toward the *next* day — the direction is documented, never hidden).

`id_age`: how old the CVE ID's year prefix was at publication —
`same_year` / `one_year` / `two_plus` (the three always sum to `n`).
The ID year is reservation paperwork, not a discovery date; that is the
chart's point. An ID year *after* the publication year (late-December
reservations published under January's clock) clamps to `same_year` and
increments `clamped_negative` (whole-corpus count; 0 in the real corpus
today — the rule exists so a future occurrence is visible, not silent).
Records with no `datePublished` take their publication year from the ID
and are `same_year` by construction; records whose ID year doesn't parse
are skipped. `pct_prior_year` = `100 * (n - same_year) / n`, computed on
counts (never by summing rounded percentages). `headline` compares the
latest complete charted year against `latest_year - 10` when charted,
else the earliest charted year — payload-authoritative, consumers never
derive either year. `headline` is null iff no year is charted.

`weekday`: `counts`/`pct` are exactly 7 entries, **Monday-first**
(`datetime.weekday()` order), over records with a day-precision
`datePublished`; `counts` sums to `n`, so `n` here can sit below the
hero's (the undated join no day tally). `comparison` names the two years
the site contrasts (same latest/baseline rule as the hero headline; null
iff no year is charted).

`patch_tuesday`: `on_pt` counts records published on the month's second
Tuesday — defined precisely as the Tuesday whose day-of-month is 8–14,
UTC; there are exactly 12 such days every year. `calendar_pct` is pinned
to 3.3 (= 12/365 rounded to 1 decimal; 12/366 rounds to the same 3.3) —
the uniform-calendar baseline the site draws, so every chart states the
comparison it is making: these are days holding N× their calendar share.
`top_day` (tooltip only, never copy) is the year's single busiest
publication day, ties broken by earliest date. This section charts
exactly the `weekday` years — both derive from one day tally. Years with
fewer than `min_n` records (per section, on that section's own
denominator) are omitted (production 500; fixture mode 1). The partial
current year charts when it clears `min_n` — the site labels it — but
never feeds a headline or comparison. No pace projection: every series
here is a share, already normalized to its year. Validator:
`pipeline/calendar_contracts.py` (registered into
`pipeline/contracts.py`'s dispatch).

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
## site/data/epss_report.json  (EPSS Report Card module, all 3 charts)

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
  "model_eras": [
    {"label": "v1", "model_version": "v1 (pre-header daily CSVs)",
     "from": "2021-04-14", "to": "2022-02-03"},
    {"label": "v5", "model_version": "v2026.06.15",
     "from": "2026-06-15", "to": null}
  ],
  "grade_by_year": [
    {"year": 2023, "graded": 160,
     "n_below_1pct": 90, "n_1_to_10pct": 40, "n_above_10pct": 30,
     "pct_below_1pct": 56.3, "pct_1_to_10pct": 25.0,
     "pct_above_10pct": 18.8, "ungradeable": 21, "pending": 6}
  ],
  "distribution": {
    "buckets": ["<0.1%", "0.1-1%", "1-10%", ">10%"],
    "by_model": [
      {"model": "v3", "n": 340,
       "counts": {"<0.1%": 88, "0.1-1%": 112, "1-10%": 84, ">10%": 56}}
    ]
  },
  "percentiles": {
    "buckets": [{"bucket": "0-25", "n": 120, "pct": 8.6}],
    "n": 1390, "bottom_half": {"n": 480, "pct": 34.5},
    "median_percentile": 68.4
  },
  "catalog": {
    "total": 1635, "graded": 1400,
    "ungradeable": {"pre_epss": 0, "listed_before_publication": 150,
                    "no_prior_score": 55},
    "pending_backfill": 30
  },
  "headline": {"graded": 1400, "pct_below_1pct": 43.1,
               "latest_year": 2025, "graded_latest": 180,
               "pct_below_1pct_latest": 61.1},
  "entries": [
    {"cve": "CVE-2021-40438", "date_added": "2021-11-03",
     "score_date": "2021-11-02", "epss": 0.35064, "percentile": 0.98923,
     "model": "v1", "reason": null},
    {"cve": "CVE-2021-44228", "date_added": "2021-12-10",
     "score_date": "2021-12-09", "epss": null, "percentile": null,
     "model": null, "reason": "no_score_for_date"}
  ]
}
```

The grade: for every KEV catalog entry, the EPSS score of the **day
before** its `dateAdded` (`score_date = dateAdded − 1 day`), fetched from
FIRST's historical API (`api.first.org/data/v1/epss?cve=…&date=…`) exactly
once per `(cve, date_added)` pair — historical scores are immutable. The
API returns no model version; `model` is derived from `score_date` via
`model_eras` (encoded in `pipeline/fetch_epss_history.py`, verified
against the version headers of the daily CSVs; the newest era is
open-ended, `to` null, and the nightly warns loudly when the current
feed's `model_version` is one the table does not know).

`entries[]` carries the raw per-pair facts, sorted by
`(date_added, cve)`, unique: either a scored fact (`epss`/`percentile`
raw 0–1 floats at up to **5 decimals** — a documented exception to the
1-decimal rule, since sub-10% probabilities are the whole point;
`percentile` may be null on early-era rows) or an explicit
null-score fact (`epss`/`percentile`/`model` all null, `reason` ∈
`pre_epss` / `no_score_for_date` — what was known at fetch time).
`score_date` must equal `date_added − 1 day` on every entry.

`grade_by_year` groups by `dateAdded` year (ascending, unique): band
counts over **graded** entries (`epss < 0.01` / `< 0.10` / `>= 0.10`,
lower edges inclusive; counts sum to `graded`), plus that year's
`ungradeable` and `pending` counts for coverage honesty. Years with fewer
than `min_n` graded entries are omitted (production 10; fixture mode 1).
`distribution` reuses score_vs_reality's EPSS buckets, split by model era
(eras in release order, only eras with graded entries, per-era counts sum
to `n`, per-era `n` sums to `catalog.graded`) — v1..v5 are different
models and are never pooled silently. `percentiles` pools eras
deliberately (percentiles rank each day's whole scored corpus, so they ARE
comparable across models): fixed buckets `0-25, 25-50, 50-75, 75-90,
90-99, 99-100` over graded entries carrying a percentile;
`median_percentile` null iff `n` 0.

`catalog` is the audit trail: `graded + Σungradeable + pending_backfill ==
total` always. `ungradeable` carries exactly three keys: an entry listed
before (or the day) its CVE record published can have no prior score and
is NEVER a miss (`listed_before_publication`, classified via the corpus's
datePublished join); `no_prior_score` is everything else the API had no
row for (unmatched CVEs included); `pre_epss` is a score date before
2021-04-14 (impossible for real KEV dates, kept for honesty).
`pending_backfill` = pairs not yet looked up — the one-time historical
backfill is batch-capped (`--epss-backfill-batch`, default 30/run), and
the site renders pending counts rather than pretending coverage.
`headline` is payload-authoritative (latest complete `grade_by_year` year,
falling back to the newest charted year; null iff `graded` 0). `"stale":
true` appears only on `--skip-epss-report` carry-forwards.

**Reconstruct-losslessly guarantee** (attack-module pattern): the
per-entry objects in `entries[]` are exactly the pipeline's sync-state
records (`.cache/epss_report_state.json`) plus the key fields — nothing in
the state is omitted and nothing in the output's `entries[]` is derived.
`pipeline/fetch_epss_history.reconstruct_state` rebuilds the full state
from this file, so a lost CI cache costs one JSON read instead of ~450 API
requests. Changing the per-entry shape therefore REQUIRES updating
`reconstruct_state` and its round-trip test in the same commit. Validator:
`pipeline/epss_report_contracts.py` (registered into
`pipeline/contracts.py`'s dispatch).

## site/data/kev_changelog.json  (KEV Changelog module, all 3 charts)

```json
{
  "generated_at": "...",
  "min_n": 10,
  "months": [
    {"month": "2023-12", "due_date": 0, "ransomware_flag": 206,
     "text": 134, "removed": 6, "total": 346}
  ],
  "flips": {
    "total": 285, "reversals": 0,
    "by_month": [{"month": "2023-12", "flips": 206, "cumulative": 206}],
    "lag": {"n": 285, "median_days": 626.0,
            "p25_days": 400.0, "p75_days": 768.0}
  },
  "board": {
    "most_edited": [
      {"cve": "CVE-2019-11510", "vendor": "Ivanti",
       "product": "Pulse Connect Secure", "edits": 12,
       "last_change": "2025-12-22"}
    ],
    "removals": [
      {"cve": "CVE-2022-31460", "vendor": "Owl Labs",
       "product": "Meeting Owl Pro and Whiteboard Owl",
       "listed": "2022-06-08", "removed": "2023-12-11"}
    ]
  },
  "catalog": {
    "entries": 1637, "removed_total": 9,
    "events_total": 4240, "edits_total": 2905,
    "additions_excluded": 1335,
    "first_observed": "2021-12-23", "last_observed": "2026-07-11",
    "backfill_captures": 53
  },
  "headline": {"edits_total": 2905, "edits_per_100_entries": 177.5,
               "pct_flag_flips": 9.8}
}
```

CISA edits the KEV catalog in place and publishes no changelog; this
module keeps one. Every run fingerprints each catalog entry — `dueDate`,
`knownRansomwareCampaignUse` (normalized Known/Unknown; a missing field
never reads as Known), `vendorProject`, `product`, `vulnerabilityName`
verbatim; `shortDescription`, `requiredAction`, `notes` as 12-hex-char
sha256 hashes of the whitespace-normalized text — and diffs the fresh
catalog against the committed state. Each difference is one event:
`added`, `removed`, `field_changed` (old/new logged verbatim) or
`text_changed` (hash-tracked; the event never carries the text).

**Committed history files (both under `site/data/history/`):**

* `kev_changelog.csv` — the append-only event log (columns:
  `observed_date,cve,change_type,field,old,new,granularity`). Like
  `nvd_backlog.csv`, this is an **original dataset accumulated by this
  project and it CANNOT be regenerated**: CISA publishes only the current
  snapshot. The Wayback-seeded prefix could be rebuilt from the Internet
  Archive at capture granularity; everything observed live has this repo
  as its only copy (the weekly `data-backup-*` tags cover it).
* `kev_state.json` — the compact per-entry fingerprint state
  (`version`, `baseline_date`, `last_observed`, `backfill`
  `{captures, watermark, complete}`, `entries`, and a `removed` ledger
  that remembers every entry observed leaving the catalog: removals are
  logged AND retained, never silently dropped).

Both are written by `__main__.run()` **only after every output validates**
(the `nvd_backlog.csv` discipline), via `pipeline.kev_changelog.persist`.

**Granularity semantics** (per event, last CSV column): `daily` events
are dated to the nightly run that first observed them (missed nights pool
changes on the next run's date); `capture` events come from the one-time
Wayback backfill (`--kev-changelog-backfill N`, integrator-run once, CI
never — default 0 contacts nothing) and are dated to the FIRST Internet
Archive capture showing the change — the true date lies between that
capture and the one before. The record's first observation is a baseline:
state written, zero events. While a batch-capped backfill is incomplete,
the live diff is skipped (diffing today's catalog against a
half-backfilled state would date years of edits to one night); snapshot
bodies are cached in `.cache/kev_wayback/` so a rerun never refetches.

`months` (hero): edits per month by category — `due_date`,
`ransomware_flag`, `text` (text-field hash changes plus
vendor/product/name wording changes), `removed` — contiguous ascending
labels (gap months at zero), per-month categories sum to `total`, month
totals sum to `catalog.edits_total`. **Additions are logged but never
charted as edits** (catalog growth is the system working; the exclusion
is disclosed as `catalog.additions_excluded`, and
`edits_total + additions_excluded == events_total` always).

`flips`: Unknown→Known changes of the ransomware flag. `by_month` is the
cumulative series (running sum ends at `total`); `lag` measures
`observed_date − dateAdded` in days per flip — `median/p25/p75` are
published only with `n >= min_n` flips (production 10; fixture mode 1),
null below (thin data renders honestly). Known→Unknown changes are
counted as `reversals`, disclosed, never netted. Note the structural
step: CISA added the flag column in October 2023, so the first capture
carrying it flips every already-flagged entry at once.

`board`: `most_edited` — top entries by logged edit count (field changes
+ text revisions; additions/removals never inflate it), sorted
descending, ties by CVE id, with `last_change`; `removals` — every entry
in the state's removed ledger (`listed` may be an empty string when the
removed entry's dateAdded was unusable), sorted by removal date, one row
per CVE, `len == catalog.removed_total`. `headline` is null iff there
are no entries or no edits. Validator:
`pipeline/kev_changelog_contracts.py` (registered into
`pipeline/contracts.py`'s dispatch).
