# CyberMon build round — 5 November 2026

The owner asked for the improvements and additions proposed after the
4 November review, all of them. Eleven builders worked in parallel, each
in its own worktree, from one shared brief: house copy rule, claims
guards, data honesty, no new failure modes in the nightly. A builder whose
source did not hold up was to write up why instead of shipping. None had
to. Every branch was reviewed and merged by hand. The lead built the
Field change.

## What shipped

### Fixes across the site
- **Missed nights are gaps.** A shared helper (`site/js/gaps.js`) puts
  nightly records on their full calendar. A missed night gets no bar, a
  broken line and a "no reading" tooltip. It applies to C2, CNA roster
  size, both EPSS Volatility charts, NVD backlog and throughput, and the
  Observatory stream. `observatory.json` now carries `missed_nights`.
- **Data links.** Every section on the module pages links the JSON
  file(s) it reads (`buildSection(..., { dataFiles })`).
- **Social preview images.** `tools/make_og_images.py` renders a
  1200×630 card per page at deploy time (`site/og/`, gitignored). Every
  page carries `og:image`, `twitter:image` and `summary_large_image`. CI
  runs it with `--check`.
- **Nav.** Instruments are one group button with their own row, like the
  module groups. Five instrument links had wrapped the desktop bar below
  1280 px.
- `--cvelist-zip` for local runs, because GitHub's releases API refuses
  unauthenticated calls from some networks.

### New sections on existing pages
- **KEV Latency 05, CVE age at listing.**
  - The 3y+ bucket is split into 3–5y / 5–10y / 10y+.
  - Each listing year is shown by CVE age, with a table of the oldest
    CVEs added in the last 12 months.
  - Headline: about a quarter of each year's 2023–2025 additions had been
    published more than a year earlier (24.6%, 24.2%, 22.9%).
- **CVE Ecosystem 06, how long CVEs wait in NVD's queue.**
  - A Kaplan–Meier curve from a new per-CVE exit log in the NVD state.
    CVEs still waiting are censored at their current wait.
  - It needs 28 days of the log and 30 exits, so it shows an empty state
    until then. Its five guards skip until the data exists.
- **CNA Concentration 04, CNA profile.**
  - Pick any of the 107 CNAs with 100+ records in 2021–2025 and see eight
    measures against the median CNA, with its rank.
  - Only fields in the CNA's own container count.
  - Headline: some CNAs name a CWE on fewer than one record in twenty
    (12 of them), others on every record (17).

### New modules
| # | Module | Source | Headline (guarded) |
| --- | --- | --- | --- |
| 27 | AI Product CVEs | cvelistV5 + a curated table of 154 AI products, 276 rules (`pipeline/ai_products.py`) | AI products' share of published CVEs has risen in every complete year since 2023 (1.4% of 2025's CVEs, 3.5% of 2026's so far). |
| 28 | Detection Rules | SigmaHQ (Detection Rule License 1.1), joined to every ATT&CK release | Rules dated 2025 number about a fifth of 2022's peak. Rule coverage of ATT&CK techniques fell from 82.8% (2023Q1) to 75.3%. 30 of the 35 techniques added since 2023 have no rule. |
| 29 | Support Windows | endoflife.date (MIT) | For the same 195 products, lines from 2022–2024 have a median support window about a fifth shorter than lines from 2014–2016. |
| 30 | Open-Source Maintainers | npm, PyPI, crates.io, RubyGems, OpenSSF Scorecard; package list from ecosyste.ms (CC BY-SA 4.0) | More than a fifth of each registry's 250 most-used packages can be published by a single account (26.0–41.2%). |
| 31 | Machine-Readable Advisories | BSI CSAF Lister and the CSAF feeds it lists | Most documents in the listed feeds are VEX documents (61.6% of 122,714), and Red Hat publishes nearly all of them. |

Judgement calls worth knowing:
- **AI Product CVEs**
  - It classifies on the CNA's first affected vendor/product only, never
    on descriptions.
  - A general product with an AI feature counts only when the CNA lists
    the AI part as its own product.
  - Counts are a lower bound; the methodology states the recall limits.
- **Support Windows**
  - The headline compares a panel of the same products, because the
    pooled medians compare different products in the two periods (a 42%
    drop pooled, about 20% like for like).
  - Each product counts once.
  - Lines with no announced end are censored, not dropped.
- **Open-Source Maintainers**
  - The universe is the top 250 per registry by dependents that are
    also in its 5,000 most-downloaded, because spam rings inflate
    dependent counts.
  - It counts accounts, not people, and defines them per registry,
    never pooled. Go and Maven are out: neither publishes who can
    publish.
  - The package list (`pipeline/oss_universe.json`) and the module's
    figures are under CC BY-SA 4.0 because they derive from ecosyste.ms.
    The footer and README say so.
  - The nightly never calls ecosyste.ms. It re-reads a seventh of the
    universe each night.
- **Machine-Readable Advisories**
  - The universe is the BSI CSAF Lister's providers. 12 of 15 could be
    counted: CISA answers 403 from the build network, Huawei's
    robots.txt disallows everything, and Hitachi Energy's feed is empty.
  - Field completeness comes from a fixed hash-chosen sample of 30
    documents per feed.
  - About 57 requests a night, robots and crawl delays obeyed.

### New instruments
- **Adversary Atlas** (`atlas.html`).
  - Groups, software and techniques from the current ATT&CK release
    (v20.0: 178 groups, 842 software, 706 techniques, 17,589 "uses"
    edges), cached per release.
  - One group's neighbourhood by tactic; compare two groups (shared
    entries, Jaccard); the ten closest groups; a table and CSV.
- **Claims Ledger** (`ledger.html`).
  - Lists every guarded sentence with its page and section, its guard's
    source line, tonight's result and, where the guard records it, the
    value, bound and margin.
  - `claims_support.record()` was added to the 106 guards behind every
    headline and home card.
  - The nightly regenerates the ledger after the claims gate. Tonight:
    316 guards, 311 pass, 5 skip, 0 fail; 35 within 10% of a bound.
- **Alias Graph** (`alias.html`, the draft whose script was missing).
  - A versioned rule table (`pipeline/naming_schemes.py`) assigns each
    ATT&CK alias to the vendor naming scheme it follows. It covers ten
    vendors, each rule citing that vendor's naming documentation.
  - 297 of 539 names are classified (55%). Ambiguous names are never
    guessed.

### The Field
In "Days to PoC and KEV", a record with both a dated exploit and a KEV
listing now appears in both rows, joined by a faint line, so the order of
the two events is visible.

## How it was checked
- `python -m pytest pipeline/tests`: 1,888 before this round, **2,529
  passed, 6 skipped** after. The skips are the queue-wait guards waiting
  for data.
- January rehearsals (plain, TINY low and high): unchanged. The only
  failure is the documented `check_last_verified_payment_quarter` noise
  in the TINY modes.
- All passing:
  - `site_smoke` (35 pages) and the offline fixture pipeline;
  - `field_smoke`, `observatory_smoke`, and the new `atlas_smoke`,
    `ledger_smoke` and `alias_smoke`;
  - `make_og_images --check` (37 cards) and `make_motion --check`.
- Rendered text of all 36 reader pages with every `<details>` open: no
  `{placeholder}`, `undefined`, `NaN` or `null`.
- Every new module's first edition comes from a real run of its stage:
  the cvelistV5 release of 2026-11-05 06:00Z through `--cvelist-zip`,
  and live fetches for the rest.

- First run on GitHub's runners: a manually started nightly (run 197, on
  `c5647bc`) passed the pipeline and the claims gate and deployed the
  2026-11-05 07:56Z edition. Every new source fetched fresh, none carried
  forward stale:
  - Support Windows: 489 products
  - Sigma: 3,980 rules at 77145ed8
  - Open-Source Maintainers: 1,867 lookups, 0 failed
  - CSAF: 15 listed sources, 122,714 documents
  - ATT&CK atlas and aliases refreshed
  
  The queue-wait exit log has started. All nine new pages, the preview
  images and the ledger data serve 200.

## Merging
Eleven branches touched the same shared lists: nav, home cards, sections,
validators, the integrity and e2e lists, the smoke list, carousel,
README, data-contracts and meta.sources. Most conflicts were appends,
resolved by keeping both sides and syntax-checking every file. Three kinds
needed hand work:
- `editorial.js` hunks that git split mid-object, rejoined with their
  shared closing lines;
- the footer's source line, disclaimer and attribution sentences, which
  four modules each extended, combined into single sentences;
- `test_e2e_offline.py`, where git aligned different modules' outage
  tests line by line. It was rebuilt from one side plus the other's own
  additions.

Two cross-builder fixes:
- the CNA profile section first linked the page's default data file;
- modules 27–31 were put back in number order after merging out of order.

## Left open
- **NVD queue waits:** the curve appears once the exit log covers 28
  days and 30 exits.
- **Open-Source Maintainers:** no committed time series yet (backlog
  follow-up). 2FA is not measured; no registry publishes it.
- **Machine-Readable Advisories:** no affected-version-range column. Red
  Hat lists fixed versions, so it would measure style. There are no
  listing dates, because the lister keeps none.
- **Alias Graph:** the IBM X-Force, Proofpoint and Recorded Future rules
  cite statements in reports or blog posts rather than naming pages.
- **Claims Ledger:**
  - complete-year claims count toward "within 10%" although only an
    upstream revision can move them (said on the page);
  - guard line numbers in the committed ledger go stale until the next
    nightly regenerates it.
- **AI Product CVEs:** the headline guard needs rewording in 2028 if
  2027's share does not beat 2026's.
- **Atlas:** 15 tactics exceed one colour scale. The palette uses five
  hues with three shades each, with position and the legend carrying the
  tactic too.

## Follow-up (same day)

- **CNA profile carousel slide.** The picker cannot fit a 1080×1350
  slide, so the slide draws the headline's finding instead: three strips
  (records with a CWE, with a CVSS score, with usable affected-version
  data), one tick per listed CNA, the median CNA dashed, and the counts
  under 5% and on every record. `cna_profile.renderSlide`.
- **Broken carousel, found while adding it.** Since the AI Product CVEs
  merge, `carousel.js` had not parsed. Each keep-both merge had dropped
  the closing `],` / `},` of the module entry before it (aisurface,
  sigma, oss, csaf). `node --check` did not catch it because it does not
  parse these files as ES modules. The deploy job's PDF step is
  `continue-on-error`, so the carousels quietly stopped building. Fixed,
  and `tools/make_carousels.py --check` now renders every module's
  carousel in CI: a hard gate on template errors, console errors and
  overflowing slides. All 31 render with none.
