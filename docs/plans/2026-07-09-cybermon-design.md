# CyberMon — CVE Ecosystem Health Dashboard

**Date:** 2026-07-09
**Status:** Approved design (brainstormed + validated with user)

## Thesis

A public, provocative, data-backed dashboard arguing that the CVE severity
ecosystem is degrading: CVSS scores inflate, most "Critical" vulnerabilities
are never exploited, NVD enrichment is decaying, and some CNAs rubber-stamp
high severities. Every claim is reproducible from open data.

**Brand rule:** provocative headline, auditable methodology. Every chart has
an editorial caption AND an expandable "how this is computed" footnote
linking to pipeline source. The site is *meta* — it never lists individual
CVEs as news.

Direction: blend — this (A) is the core; a hype-cycle tracker (B) becomes a
second page later, reusing the same nightly-pipeline pattern.

## Architecture

Zero servers. Nightly GitHub Actions job runs a Python pipeline, emits
pre-aggregated JSON into `site/data/`, commits, deploys `site/` to GitHub
Pages. The site is pure static HTML/JS + ECharts; every chart reads a few-KB
JSON. No runtime queries.

### Data sources

| Source | What | How |
|---|---|---|
| cvelistV5 (GitHub) | Authoritative CVE corpus, full history | Download latest release zip (not git clone — repo is huge) |
| EPSS (FIRST) | Exploitation probability, daily CSV | `https://epss.cyentia.com/epss_scores-current.csv.gz` |
| CISA KEV | Known exploited vulns | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| NVD API 2.0 | Enrichment status only (`vulnStatus`) | Paged API, polite rate limiting, no key required (slower) |

cvelistV5 is the **primary corpus**; NVD is consulted only for its own
enrichment-status metadata (the decay metric). NVD publishes no backlog
history — our nightly snapshots become the historical record
(`site/data/history/nvd_backlog.csv`, append-only, committed).

## The six v1 charts (page order = rhetorical order)

1. **Severity inflation (hero)** — median + IQR of CVSS base score per year,
   split by scoring version (v2/v3/v4), blended trend overlaid, annotations
   at 2015 (v3) and 2023 (v4). Headline stat: % High/Critical now vs 10y ago.
2. **The 9.8 flood** — stacked area of severity buckets per year.
3. **Score vs. reality** — CVSS × EPSS density grid. Big number: "% of
   Critical CVEs with <1% exploitation probability." Inverse: KEV entries
   rated below High.
4. **NVD decay** — current backlog counts by `vulnStatus` + our snapshot
   time series.
5. **CNA rubber-stamp board** — CNAs ranked by avg assigned severity and
   % ≥ 9.0; minimum-volume threshold (default 100 CVEs in 3y window).
6. **Volume curve** — CVEs published/rejected per year.

## Credibility landmines (handle or get debunked)

- **v2→v3→v4 methodology changes:** v3 scores run structurally higher than
  v2. Never show a blended line without per-version series + annotations.
- **CNA scores vs NVD scores can differ:** the CNA board uses *CNA-assigned*
  scores from cvelistV5 (that's the point — who assigns what), stated in the
  methodology footnote.
- **Sample data:** site shows a warning banner when `meta.json` has
  `"sample": true` so synthetic data is never mistaken for the real claim.

## Repo layout & ownership

```
pipeline/        Python package: fetchers, metrics, tests   (agent: pipeline)
site/            static HTML/CSS/JS + ECharts                (agent: site)
site/data/       JSON emitted by pipeline (samples committed)
.github/         nightly workflow + Pages deploy             (agent: ci)
docs/            this design, data contracts
```

Data contracts between pipeline and site: `docs/data-contracts.md`.
