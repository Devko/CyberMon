# Module backlog

Candidate monitoring modules, beyond the twenty-two that exist today
(01 CVE Ecosystem, 02 Security Market, 03 KEV Latency, 04 CNA
Concentration, 05 Breach Ledger, 06 Extortion Ledger, 07 ATT&CK Churn,
08 Hygiene Index, 09 Security Products, 10 EPSS Report Card, 11 CVE
Calendar, 12 KEV Changelog, 13 Silent Rescores, 14 Naming Chaos,
15 CWE Top 25, 16 Vulnrichment, 17 EPSS Volatility, 18 CNA Roster,
19 Time to PoC, 20 Botnet Weather, 21 The AI Alibi, 22 AI Credits — all
live).

## Maintenance — one upstream outage costs the whole night — RESOLVED

Filed and fixed 2026-08-30, after abuse.ch served `503 certificate has expired`
for `feodotracker.abuse.ch/downloads/ipblocklist.json` and took the entire
refresh down 74 seconds in. All twenty-one modules went stale because one
blocklist was unreachable; the endpoint was healthy again by morning, and the
site had sat three days behind over an outage that fixed itself.

The loud-failure policy is **unchanged and was never the problem**.
`fetch_feodo.py`, `fetch_dnssec.py`, `fetch_epss.py` and `fetch_cna_roster.py`
all state the rule — a broken source must break the run, no carry-forward,
nothing stale ever deploys. GDELT remains the one sanctioned exception. Silent
carry-forward for blocklists was considered and rejected: the invariant is worth
more than one night of freshness.

The actual defect was arithmetic. `_get_with_retry` allows 3 attempts at 15s/30s
backoff — about 45 seconds of patience — against an expired origin certificate,
which is a multi-hour outage. The retries were never going to win, and the run
burned its single daily attempt at 02:46 UTC. Widening the ladder to five
minutes would still have lost.

**Shipped:** a second `schedule:` entry at 08:43 UTC, in front of a `gate` job
that decides whether the attempt is needed. On a night that already went green
the gate is a ~10 second no-op; on a night that failed it runs the full refresh
again, six hours later, by which time a transient upstream is usually back. No
invariant moved: a broken source still breaks the run, nothing stale deploys,
and a genuinely broken night still ends red — twice.

Two design notes worth keeping:

* The gate is **fail-safe toward running**. `refresh` skips only on an explicit
  `should_run == 'false'`; a missing output or a failed gate falls through to
  running, guarded by `!cancelled()`. The dangerous direction here is a silent
  skip — a nightly that quietly stops refreshing raises no alert at all, which
  would be strictly worse than the outage this fixes.
* The gate counts *successful runs started today* rather than looking for
  today's data commit, because a night with no upstream changes legitimately
  commits nothing ("No data changes to commit") and would otherwise re-run the
  whole pipeline for no reason.

Rejected alternatives: widening the retry ladder (does not reach a multi-hour
outage) and fail-soft with a staleness marker on the site (needs a contract
field plus render support, and concedes the never-deploy-stale line).

## Maintenance — claims guards facing the 2027-01-01 rollover — RESOLVED

Filed 2026-08-29 while fixing the rejection-share failure. `complete_years()` /
`GENERATION_YEAR` in `pipeline/tests/test_claims_audit.py` make many guards read
the latest *complete* year, so on 1 January the tested value steps to a new year
with no data drift at all. Measured against the 2026-08-27 data, these are the
2026 values that take over in 2027:

| guard | 2026 value taking over | threshold | verdict |
|---|---|---|---|
| `check_kev_three_week_rule` | median 14.0d | band 14-28 | exactly on the floor |
| `check_severity_headline` | 53.5% | band 33-55 | 1.5pp of ceiling left |
| `check_concentration_reversal` | top5 48.1% | needs >56.6% and >50% | fails as it stands |
| `check_entrants_top3_recruiting` | 2026 newcomers 41 | must beat 2023's 75 | cannot pass |
| `check_volume_belongs_to_a_handful` | top5 48.1% | floor 40 | 8.1pp, drifting down |
| `check_cna_nine_plus` | window slides off 2024 | floor 30 | max drops to ~30.9 |
| `check_kev_getting_slower` | 2026 17.0d vs 2023 12.0d | strict > | margin 14d -> 5d |

`check_flood_partial_year_mark` and `check_entrants_top3_recruiting` already
document the January failure as intentional ("false every January ... reword the
caption seasonally"). The other five do not — that exposure is unplanned.

Also drifting on data rather than the calendar: `check_epss_disconnect`
(~77 days of headroom) and `check_flood_critical_volume` (~92 days).

**Resolved 2026-09-08.** The September review found twelve such guards, not
seven: five more read the latest complete year through the same seam
(`check_rejection_share_story`, `check_wednesday_baseline_and_clamps`,
`check_old_id_share`, `check_newest_milestones_sit_past_the_testable_edge`,
and the offline e2e test's hardcoded CWE window 2016–2025, which also read the
machine clock). Every one now uses the backlog's third option — the claim is
pinned to a named year, or reworded so it holds on both sides of the rollover
— with the guard re-pointed to the same years and the anchors re-quoted:

| guard | copy now says | guard now judges |
|---|---|---|
| severity_headline | "About half of all CVEs ship as High or worse" | 40–60% |
| kev_three_week_rule | "from 2022 through 2025 … three weeks — and the 2026 listings are coming in at two" | 2022–25 in 14–28 d; 2026 in 7–21 d |
| rejection_share_story | "2024 and 2025 bent it back up" | those two rows vs 2023 |
| flood_critical_volume / partial_year_mark | "in 2024 and 2025 … 2026 passed that mark with months to spare" | 2024–25 in 3,000–4,400; 2026 ≥ 4,400 |
| concentration_reversal | "seventeen-fold between 2015 and 2025 … in 2025 … a majority … a third straight year" | 2025 > 50%; 2023 < 2024 < 2025; 2015→2025 growth 15–20× |
| entrants_top3_recruiting | "2023, 2024 and 2025" | top-3 over complete years == those |
| cna_nine_plus | "a third or more" | max ≥ 28% (window slides ~31% in January) |
| old_id_share | "In 2025, one in five … 2026 is running lower" | 2025 in 15–27; 2026 < 2025 |
| wednesday_baseline | "a decade earlier the peak sat later in the week" | baseline peak after Tuesday |
| patch_tuesday_multiple | "two to three times" | 1.8–3.8× |
| most_recent_below_1pct | "roughly half or more" | 40–90% |
| top25 "several" | "a few never crack" | 2–20 |
| e2e CWE window | — | relative to the run's own generated_at |

Deliberately left to fail on 2027-01-01: `check_newest_milestones_sit_past_the_testable_edge`
is pinned to "the 2026 milestones" because the AI Alibi's argument must be
re-examined against 2026's completed data when the clock absorbs it — that
failure is the reminder, and the test says so. `check_kev_getting_slower`,
`check_more_assignors_than_ever` and `check_volume_belongs_to_a_handful`
pass on the 2026 values as they stand.

Rehearsal: `CYBERMON_REHEARSE_YEAR=2027 python -m pytest pipeline/tests/test_claims_audit.py`
judges every raw-series guard as if the edition were generated next year.
Headline blocks are computed by the pipeline and cannot be rehearsed from
committed data; those guards are the pinned ones above.

## Shipped outside the backlog

### AI Credits — SHIPPED as module 22
Live as **22 · AI Credits** ([credits.html](../site/credits.html)). Not a
backlog candidate — it started 2026-09-20 as a reader's question (what do
Anthropic, OpenAI and Google actually have to show in the CVE record?) and
earned a page because the answer needs computation no other module does: a
graded match of every credit line against a committed finder registry.
- **Thesis:** thousands announced, hundreds credited in CVE records — and the page is about that
  attribution record, not about what AI "really" found.
- **Editorial decisions (2026-09-20):** LLM labs and AI-security vendors
  are split and never summed; labs count only when the credit names the
  model, vendors whenever named; finders' own announced numbers ARE drawn
  (hatched, sourced, to scale only when the unit is CVEs) — a deliberate
  break from module 21's no-external-numbers rule, because the gap is the
  thesis.
- **Second pass (same day):** an exploratory join against EPSS, the
  exploit corpora, CWEs and affected products turned up three findings
  worth charts — labs find memory-safety and crypto bugs at several times
  the baseline rate, attacker interest (EPSS / exploit code / KEV) is flat
  across all three populations, and half the lab record is five partnered
  projects — so the page grew a profile table, a weakness chart, a targets
  list and a public-exploit funnel stage. Considered and declined:
  correlating monthly credits with module 02's hype lanes (a 15-month
  series; any correlation would be noise) and per-lab EPSS comparisons
  (OpenAI's column is 13 CVEs).
- **External review (same day), all verified before acting:** (1) the
  "no AI finder before 2025" headline was false — CVE-2024-9143 credits
  "Google OSS-Fuzz-Gen" and the registry did not know the name; (2) credit
  roles were ignored, so 31 records crediting Claude as *remediation
  developer* were counted as finds — Anthropic 177 -> 146; (3) the copy read
  attribution as discovery and KEV absence as non-exploitation. Fixed: the
  `fix` tier, the OSS-Fuzz-Gen pattern, a cohort-age row, every funnel share
  on one denominator, a published ledger, and a full copy rewrite under one
  rule — write "credited", never "found"; state what was measured, not why.
  Still open from that review: outcomes measured at a fixed follow-up (e.g.
  90 days after publication) and matched on product and CNA; Nuclei
  detection templates counted separately from exploit code.
- **Open, as of close of day 2026-09-20** (in rough priority order):
  1. *Fixed follow-up comparison.* The exploit-corpus and KEV rows compare
     cohorts of very different ages (54% of lab-credited CVEs are under 90
     days old vs 24% of the baseline). The page now says so, but the honest
     fix is to measure outcomes N days after publication (KEV `dateAdded`
     and the Exploit-DB / Metasploit dates exist; Nuclei has none) and to
     match on product and CNA. Until then the comparison stays labelled
     descriptive.
  2. *Split Nuclei from exploit code.* "In an exploit corpus" lumps Nuclei
     detection templates with Exploit-DB and Metasploit. `PocData` already
     keeps the three id sets apart; emit them separately.
  3. *Match announced CVE ids.* "Credited here to date" sits beside an
     announcement with a different cut-off. OpenAI (14 ids), depthfirst (9)
     and AISLE's discoveries page publish their CVE ids — commit those lists
     and report the real overlap with the ledger instead of two loose totals.
  4. *Vendor evidence rule — Roland's call.* Vendors count at the `org`
     tier; 43% of vendor credits name a person, not the tool. The reviewer
     would not promote those to AI-assisted. Options: keep (current, stated
     on the page), add a system-tier-only toggle to the vendor funnel, or
     count vendors like labs.
  5. *Re-probe the registry.* OSS-Fuzz-Gen was missed because nobody looked
     for it. Probe 2025-26 credits for other unlisted systems (Copilot,
     Cursor, Devin, Jules, Amazon Q, Grok, DeepSeek, Qwen, "AI-assisted",
     "LLM") and promote what is real. The pre-2025 probe found nothing else.
  6. *Small:* the registry label "Google (Big Sleep)" should mention
     OSS-Fuzz-Gen like the lanes label does; the printed board slide clips
     its right-hand columns (KEV, first credit, CNAs); the copy review
     covered credits.html only, not the rest of the site.
  7. *Deploy race (site-wide, not this module).* A nightly that started
     before a push deploys its older checkout after CI has deployed the
     newer one — it happened 2026-09-20 16:19 UTC and blanked this page's
     new sections until CI was re-run. Skip the nightly deploy when `main`
     has moved past the run's checkout.
  8. *The Alias Graph draft* (`site/alias.html`) still loads a
     `js/alias.js` that is not in the repo.
- **Upkeep:** `pipeline/ai_credits_data.py` is hand-curated. New finders
  appear monthly — re-probe the corpus with a broad net now and then and
  promote what is real. `CLAIMS` entries marked `live` (running counters)
  go stale by design; re-read them when editing. The claims guards in
  `test_claims_credits.py` WILL trip as the record grows ("a few hundred"
  first); that is a copy edit, not a bug.

### The AI Alibi — SHIPPED as module 21
Live as **21 · The AI Alibi** ([ai.html](../site/ai.html)). Not a backlog
candidate — it started as a reader's argument that the exploitation-speed
collapse is mostly a pre-AI phenomenon, and survived the house rules
because it adds computation rather than framing: a committed, per-row
sourced AI milestone table, an inflection test (three levels per metric
per cutoff, with the direction signed in the pipeline), and a cross-module
join of module 02's attention lanes against module 19's clock that no
existing page performs. That last point is what kept it clear of the
one-page-one-thesis rule the "KEV vintage" candidate below died on: a
milestone overlay alone would have been module 19 with annotations.
- **Thesis:** the industry blames AI for a clock that stopped moving a
  decade ago — and CyberMon's own series say so, at every cutoff a critic
  might prefer.
- **Findings on the launch edition:** 0 of 6 judged metric-era cells
  accelerated; 3 decelerated; ~100% of the gap metric's total travel was
  banked before ChatGPT, and 92% of it before 2013.
- **Landmines defused:** KEV latency excluded (its series starts 2023,
  inside the era under test); 5-year window means instead of endpoint
  years (1999 is 109 CVEs at a -800-day median); cut years never straddle
  a cutoff; eras under two complete years are withheld rather than judged
  off one anomalous cohort. Vendor figures that cannot be reproduced from
  the pipeline (Mandiant TTE, DBIR edge-device share) are prose-only and
  a test asserts they never reach the payload.
- **Open follow-up:** the timeline's month-precision rows could be
  tightened to day precision against their primary documents; and "AI as
  attack surface" (CVEs in AI/ML products per year) was scoped out — it
  needs `CveFacts` extended with vendor/product strings plus a curated
  classifier, and keyword-matching product names is a real landmine, so
  it belongs in its own pass. See the Tier 1 candidate note below.

## Scheduled 2026-09-22 — the next build round

Chosen by the owner from the 2026-09-22 ideas pass. Four new modules, three
additions to existing pages, and one instrument. Numbering continues from 22;
every item keeps the house rules — open data only, every number reproducible,
copy guarded by the claims audit, and time shown as the kind of time it is
(event, publication, or first observation by CyberMon).

### 23 · Record Tags — CVEs for software nobody supports
- **Thesis (revised after the count probe):** more and more CVE ids are
  issued for software its vendor had already stopped supporting. The record
  format lets a CNA tag a CVE `unsupported-when-assigned`; those tags went
  from 21 records (2020) to 423 (2025) and 373 by 2026-09-22. The `disputed`
  tag — the first-draft thesis, "argument is the fastest-growing category" —
  is flat: 85–137 records a year, ~0.3% of the corpus. The page says so
  rather than hiding it.
- **Probe (corpus cve_2026-09-22_0200Z, published records, CNA container):**
  `x_open-source` 2,442 · `x_freeware` 1,870 · `disputed` 1,499 ·
  `unsupported-when-assigned` 1,237 · `exclusively-hosted-service` 397 ·
  `x_known-exploited-vulnerability` 154; ADP containers carry only
  `x_bundling-flagged-by-CVE-Program` (39). The three unprefixed tags are
  the schema's; `x_` tags are CNA-private and reported only as context.
- **Signals:** per-year count and share for each schema tag; the CNAs that
  apply `unsupported-when-assigned` and `disputed` (who tags, and how
  concentrated tagging is); tagged records' severity against the year's
  baseline.
- **Source:** `containers.cna.tags` in the cvelistV5 corpus already read
  nightly.
- **Caveats for the copy:** a tag records that a dispute or end-of-life
  status was *noted by the CNA*, not that it is correct; untagged is not
  "supported" or "undisputed" — most CNAs never use the tags. The record
  carries no tag date, so no "time disputed" chart until CyberMon's own
  snapshots accrue.

### 24 · Incident Clock — SEC cyber-incident filings — SHIPPED as module 24
- **Shipped 2026-09-22 (first edition pending):** `incidents.html`, group
  "industry". Fetcher `pipeline/fetch_sec_incidents.py` (module 02's EDGAR
  URL + User-Agent, 0.25s pacing, bounded retry; month windows halved at the
  10,000-hit cap; paged by `from`; dedup by accession number), stage
  `pipeline/sec_incidents_metrics.py`, contract
  `pipeline/sec_incidents_contracts.py`. Queries: `q="Item 1.05"`
  forms `8-K,8-K/A`, counted by EDGAR's item list; `q="cybersecurity
  incident"` forms `8-K`, counted when items hold 8.01 and not 1.05 and the
  phrase hit the primary document. Three sections: monthly/quarterly
  filings, amendment lag (CIK + nearest prior original, first amendment),
  receipts board with EDGAR links. The build sandbox could not reach
  efts.sec.gov, so the committed edition is `status: "empty"` (nodata cards,
  meta `{"status": "empty"}`) and the response shape is assumed from the
  documented EFTS format.
- **Open:** (1) the first nightly must confirm the assumed response shape
  — read `diagnostics` in `sec_incidents.json`: `phrase_fallback_*` should
  be 0 (items present), `dropped_*` ~0, `hits_* > filings_*` (one hit per
  document), `filings_105`/`filings_801` plausible, `requests` in the low
  hundreds; spot-check a handful of receipt links. (2) The 8.01 phrase is a
  first definition; tune it only with a before/after count in the commit.
  (3) Once real, add tolerant claims guards for any prose that states a
  trend (the thesis's "trickle" and "drift toward 8.01" are deliberately
  not asserted in the copy yet). (4) The footer disclaimer now names the
  receipts board as the one place an affected organisation is named —
  owner to confirm that editorial line.
- **Thesis:** since December 2023 a US public company must disclose a
  material cybersecurity incident on Form 8-K Item 1.05 within four business
  days of deciding it is material. The filing record shows how the rule is
  actually used: a trickle of Item 1.05 filings, amendments that arrive
  months later, and a drift toward voluntary Item 8.01 disclosures after the
  SEC's May 2024 guidance.
- **Signals:** Item 1.05 8-Ks per month/quarter; 8-K/A amendments and the lag
  from the original filing to its amendment; Item 8.01 cyber-incident
  filings beside them; distinct companies filing.
- **Source:** EDGAR full-text search (`efts.sec.gov/LATEST/search-index`),
  already used by module 02's EDGAR lane (same client, User-Agent and pacing
  rules). No key.
- **Caveats:** full-text matching finds filings that *mention* the item; the
  item list EDGAR indexes per filing is the filter. The incident date is
  prose, not a field, so the page measures filing cadence and amendment lag,
  never "time from breach to disclosure".
- **Feasibility:** medium — pagination and de-duplication by accession
  number; carry-forward on an EDGAR outage like HIBP/Ransomwhere.

### 25 · Advisory Gap — GitHub advisories vs CVE
- **Thesis:** the software ecosystems grade their own vulnerabilities now.
  A large share of GitHub-reviewed advisories never gets a CVE id, so a
  program that watches only CVE misses them (the "registries are faster"
  framing was tested earlier and killed — this is about coverage, not speed).
- **Signals:** reviewed GHSA advisories per year and ecosystem, split by
  whether a CVE alias exists; the no-CVE share by ecosystem; severity of
  advisories with and without a CVE.
- **Source:** OSV per-ecosystem exports
  (`osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`), which
  carry GitHub-reviewed advisories with their aliases. Reachable, no key.
- **Caveats:** OSV mirrors reviewed advisories only; a CVE alias can be added
  later, so a young advisory's "no CVE" can change (young cohorts flagged).
- **Feasibility:** medium — shares one fetcher with module 26.

### 26 · Registry Malware — malicious packages
- **Thesis:** package registries are the new watering hole, and the takedown
  log is public.
- **Signals:** `MAL-*` reports per ecosystem per month (npm, PyPI, crates.io,
  RubyGems, NuGet, Go…); withdrawn reports; share of the year's reports by
  ecosystem.
- **Source:** the same OSV exports (OpenSSF malicious-packages feed).
- **Caveats:** counts reports, not installs or victims; a report's date is
  when it was published to the feed, not when the package went live.
- **Feasibility:** easy once module 25's fetcher exists.

### CVSS 4.0 adoption — a section on module 01
- **Thesis:** CVSS 4.0 shipped in November 2023; the record shows who
  actually moved to it.
- **Signals:** share of each month's newly published records carrying a
  v4.0 score (v4 only / v3 and v4 / v3 only / neither) — probe: 30 records
  in 2022, 3,577 in 2024, 12,419 in 2025, 21,509 of 68,708 (31%) in 2026 so
  far; the CNAs that
  switched; on records scored in both, how v4 compares with v3.
- **Source:** the corpus pass (metrics already separates the versions).

### Ransomware-flag lag — a section on module 12
- **Thesis:** CISA's "known ransomware use" flag is often set long after an
  entry is listed; the changelog already logs every flip.
- **Signals:** days from `dateAdded` to the Unknown→Known flip, as a
  distribution and per listing year; flips that went back.
- **Caveats:** the 2023-12 column-introduction step is excluded (as in the
  flag-flip section); capture-granularity dates are upper bounds.

### Linux-kernel toggle — modules 01 and 04
- **Thesis check, not a thesis:** the kernel became a CNA in 2024 and
  published 4,287 records that year, 5,675 in 2025 and 6,547 in 2026 so far
  (~9.5% of the year). A toggle that removes it
  shows which trends survive without it.
- **Where:** the additive charts only — volume curve, the 9.8 flood, CNA
  concentration (top-5/top-10 share, HHI). Medians are not subtractable and
  stay as they are; the toggle says so.

### Mutation Observatory — instrument
- **What:** a per-CVE event trail built from the histories CyberMon keeps:
  rescores (`rescore_log.csv`), KEV additions / edits / removals
  (`kev_changelog.csv`), and the nightly biggest EPSS move
  (`epss_volatility.csv`). A daily event stream you can brush, a CVE search
  that shows one record's trail, and the events in the brushed window as a
  table with CSV export.
- **Rule:** every event is dated by first observation, labelled as such;
  nothing is drawn before monitoring began, and the page says which
  histories start when.

## Fresh candidates — probed 2026-07-18

Six ideas probed live this round (every endpoint fetched, not taken from
docs). Four land as new modules — two with a thesis the data forced us to
sharpen; one folds into an existing module instead of duplicating it.

### The Vulnrichment handoff (ADP enrichment coverage) — SHIPPED as module 16
Live as **16 · Vulnrichment** ([adp.html](../site/adp.html)). Ships the
monthly CISA-ADP enrichment curve (bucketed by the container's own
`dateUpdated`, not the CVE publish date — CISA back-fills legacy records),
the SSVC/CVSS/CWE add-shares, and the sole-enricher board. The
NVD-2024-collapse overlay was dropped: the site's own NVD history starts at
launch, so there's no 2024 flow to chart honestly — NVD's slowdown is prose,
the live backlog is client-side scale context. See `pipeline/adp_metrics.py`
and data-contracts.md. Original candidate note:
- **Thesis:** when NVD's analysis pipeline stalled in 2024, CISA's
  Vulnrichment program quietly became the de-facto enricher of the CVE
  record — here is the handoff, month by month, against the curve of NVD's
  own retreat (module 01).
- **Signals:** share of each month's CVEs carrying a `CISA-ADP` container
  (the handoff curve) overlaid on NVD's analysis-rate collapse; what ADP
  adds most (SSVC near-universal, CVSS/CWE selective patch-ins); the "is
  anyone else an ADP?" answer — effectively no, CISA is the sole
  substantive enricher.
- **Source:** `containers.adp[]` in the cvelistV5 corpus already ingested
  nightly — no new fetch. Spot-probed via `cveawg.mitre.org/api/cve/<ID>`
  (HTTP 200): `CISA-ADP` is a stable provider (orgId 134c704f…) carrying an
  SSVC decision point plus KEV/CVSS/CWE where present. Licensing already
  cleared (CVE Program terms; corpus republished by modules 01/04/11/13).
- **Feasibility:** easy — reuses ingested data; the new work is one coverage
  metrics builder, not a fetch. Landmine: bucket by the CISA-ADP container's
  own `dateUpdated`, not the CVE's `datePublished` — CISA back-fills legacy
  KEV records (a 2019 CVE's ADP block is stamped 2025), so a publish-date
  axis would smear a false pre-2024 signal.

### EPSS volatility — SHIPPED as module 17
Live as **17 · EPSS Volatility** ([epssvol.html](../site/epssvol.html)).
Committed-history diff collector: each night the pipeline diffs the EPSS feed
(probability and percentile) against the night before and appends one row per
snapshot to `site/data/history/epss_volatility.csv` — a new irreplaceable
dataset (FIRST publishes only the current snapshot). Three charts: the
percentile-vs-probability gap, weekly material threshold crossings, and the
biggest single-day movers; model-version resets quarantined. Like Silent
Rescores the record starts at first deploy — the CSV ships empty and the page
renders "not enough data yet" until diffs accumulate. Distinct from module 10
(stability, not accuracy). See `pipeline/epss_volatility.py`. Original
candidate note:
- **Thesis:** teams triage by EPSS *percentile* — a number that moves under
  ~98% of CVEs every night while the model's actual probability holds for
  ~99% of them. The churn is real, largely a population artifact, and nobody
  keeps the log. *(Probe relocated the thesis: the raw score barely twitches;
  the spin is in the percentile teams actually gate on.)*
- **Signals:** daily share of CVEs whose raw score crosses movement
  thresholds (the "material churn" line, a few hundred/day); top single-day
  swings; the headline gap between percentile movement (~98%/day) and
  probability movement (~1%/day); model-version reset shocks quarantined
  from the trend (a header `model_version` change is a whole-distribution
  jump), the same treatment as the KEV launch-batch quarantine.
- **Source:** `epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz` (301 →
  `empiricalsecurity.com`, 200); gzip, header carries `model_version` and
  `score_date`, columns `cve,epss,percentile`; ~349k CVEs/day. Dated files
  backfill for years, so the whole history seeds on day one. CyberMon
  already fetches the current CSV nightly (`fetch_epss.py`). License: FIRST
  grants EPSS free with attribution.
- **Feasibility:** easy — diff-yesterday-against-today-then-append is the
  `rescore_tracker` / `kev_changelog` pattern. Distinct from module 10
  (accuracy, not stability). Two honest caveats: title it "volatility," not
  "churn" (module 07 owns that word); and the moat is softer than the KEV
  changelog — the daily snapshots are publicly archived, so CyberMon becomes
  the only *maintained* per-CVE churn log, not the only possible source.

### Threat-actor naming chaos — SHIPPED as module 14
Live as **14 · Naming Chaos** ([naming.html](../site/naming.html)). Shipped
the current-release snapshot: a most-renamed leaderboard plus the
alias-count distribution over the active intrusion-sets, reusing the ATT&CK
fetch primitives (no new upstream). Real v19.1 numbers: 174 active groups,
105 carrying an alias, APT28 and Mustang Panda tied at 15 alternates. The
alias-**inflation time series** (aliases per release) is the documented
follow-up — it needs a one-time per-version alias backfill, the module-07
pattern — and MISP stays the optional broadening. See
`pipeline/naming_metrics.py` and data-contracts.md. Original candidate note:
- **Thesis:** one adversary, sixteen names — every vendor rebrands the same
  actor in its own house taxonomy, so the "naming standard" is a marketing
  surface. APT28 answers to Fancy Bear, Forest Blizzard, Sofacy, STRONTIUM,
  IRON TWILIGHT.
- **Signals:** most-renamed leaderboard (alias count per actor); alias
  inflation over time — a genuine series off the versioned bundles module 07
  already caches (348 → 592 alias strings v10.0 → v19.1, outpacing actor
  growth); how many distinct vendor taxonomies collapse onto one MITRE
  group.
- **Source:** MITRE ATT&CK enterprise STIX bundle (attack-stix-data,
  `enterprise-attack.json`, HTTP 200, v19.1): 189 intrusion-sets, 187 with
  an `aliases` array. Already fetched and version-cached by module 07 — a
  parse pass over data on disk. Optional broadening: MISP threat-actor
  galaxy (1,017 clusters, dual CC0/BSD-2). ATT&CK ToU already cleared.
- **Feasibility:** easy — no new fetch for the core; MISP is a cheap
  optional stretch, though ATT&CK↔MISP name-matching is fuzzy (keep it a
  labeled side signal). Caveat: ATT&CK's alias list is MITRE's own curation
  and ~40% of actors carry no alias, so the leaderboard reflects the famous
  ~30 — state it in the footnote.

### GHSA vs CVE — ecosystem coverage gap
- **Thesis:** the software ecosystem grades its own vulnerabilities now, and
  roughly one in six GitHub-reviewed advisories never becomes a CVE the
  government records. *(The "registries grade faster than the CVE program"
  framing was probe-tested and killed — GHSA and NVD publish in near-
  lockstep, median lag ≈ 0 days. The durable story is coverage, not speed.)*
- **Signals:** lead chart — share of GHSA reviewed advisories with no CVE
  alias, per month (~17% in the sample), the slice the CVE program never
  sees; reviewed advisories per ecosystem per month (npm/PyPI/Maven/Go/…),
  the ecosystem-native tagging CVE never had; ecosystem mix over time.
- **Source:** `github/advisory-database` git repo, OSV JSON under
  `advisories/github-reviewed/YYYY/MM/GHSA-…`. Tree API (not truncated):
  33,347 reviewed advisories, 2017–2026; each file carries `aliases`→CVE,
  ecosystem, and both `github_reviewed_at` and `nvd_published_at` (both lag
  legs in one file). License: CC-BY 4.0. Distinct from the OSV
  registry-malware item below — that counts MAL-* takedowns; this is GHSA-*
  reviewed vulnerability advisories.
- **Feasibility:** medium — bulk git (~3.5 GB), clone-once + incremental
  pull (the ATT&CK pattern; the unauthenticated API is 60/hr, too tight to
  ingest with). Landmine: the directory year is the ingestion date, not
  disclosure — bulk backfills spike 2022 and 2026 — so every series must key
  off the JSON date fields.

### Detection-rule churn (Sigma)
- **Thesis:** detections chase last year's technique — Sigma coverage lags
  the ATT&CK catalog it claims to defend.
- **Signals:** Sigma rules added vs. deprecated per quarter (`date`,
  `status`, the dedicated `deprecated/` tree); ATT&CK technique coverage
  over time — share of module 07's technique list with at least one rule
  (sub-technique tags rolled up to the parent); median lag from a
  technique's ATT&CK debut (module 07 has release dates) to its first Sigma
  rule.
- **Source:** `github.com/SigmaHQ/sigma` (git, no auth): ~3,142 active rules
  under `rules/` (~4,238 repo-wide), tree not truncated; rules carry
  `date`/`modified`/`status`/`tags` including `attack.tXXXX`. License:
  Detection Rule License 1.1 — MIT-style permissive, publish/distribute
  granted (checked against the DRL text); credit SigmaHQ + DRL in the
  footnote.
- **Feasibility:** medium — clean nightly git fetch; work is a YAML parse of
  ~4k files plus the join to module 07's technique list. Caveats: not every
  rule carries a technique-level tag (compute coverage only over those that
  do); a rule's `date` is not its git-commit date, so treat "added" as
  approximate.

### KEV vintage — fold into module 03, not a new module
Probed and deliberately **not** promoted. "How old is a CVE when CISA adds
it to KEV" is the same `dateAdded − datePublished` subtraction module 03
already computes, buckets, and quarantines; a separate page replotting it
under a "vintage" caption is a one-page-one-thesis violation. The live data
also kills the "old inventory" thesis at the median — post-quarantine the
2025 median KEV add is ~27 days old, and only a durable ~15% tail is 1y+ old
(2007-era CVEs still land). Ship the survivor as a **counterpoint chart in
module 03**: split the lumped `3y+` latency bucket into `3–5y / 5–10y /
10y+`, add a per-year "vintage share" line (generalising the `pct_over_365d`
field module 03 already emits), and an "oldest CVEs still landing" callout.
No new fetch, no new contract file.

## Snapshot collectors — become the historical record (probed 2026-07-11)

The NVD backlog history proved the pattern: when an upstream publishes
only current state, a nightly snapshot makes CyberMon the only
historical record in existence. Candidates below were endpoint-probed;
each accumulated dataset is irreplaceable by construction (covered by
the weekly data-backup tags). Shipping now as modules: the KEV
changelog, the silent rescoring tracker, and NVD throughput.

### CNA roster history — SHIPPED as module 18
Live as **18 · CNA Roster** ([roster.html](../site/roster.html)). Shipped the
snapshot-collector: a nightly diff of the CVE Program's published org roster
into a committed churn log (onboarded / departed / scope_changed) plus a size
series, alongside the current composition by type, top-level root, reporting
root and country — the one section that is real from day one. The churn record
starts at first deploy because no accreditation date is published (onboarding =
first observed in our snapshots), so the size and flux charts are launch-thin
by design and say so, exactly like Silent Rescores. Real source: the roster
that powers cve.org's List of Partners
(`raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json`,
~530 orgs). See `pipeline/fetch_cna_roster.py`, `pipeline/cna_roster.py` and
data-contracts.md. Original candidate note:
- **Thesis:** the CVE federation's true growth and churn — accreditation
  dates aren't published as history.
- **Signals:** onboardings/departures per quarter, scope changes,
  country and type mix over time.
- **Source:** cve.org org API (`/api/?action=getOrgs` responded 200);
  daily snapshot + diff.
- **Feasibility:** easy — one small JSON, compact committed state.

### Botnet weather (Feodo tracker) — SHIPPED as module 20

Shipped 2026-07 as the Botnet Weather module (`c2.html`): nightly snapshot
of the Feodo Tracker C2 blocklist into an append-only per-family count log
(`site/data/history/botnet_c2.csv`, listed + online per day), with today's
composition and infrastructure-age sections real from day one. Zero counts
are recorded, never refused — the tracker's FAQ credits its empty
stretches to the Emotet 2021 / Operation Endgame 2024 takedowns, and the
cliffs are the story. Aggregates only; no address is republished. See
`pipeline/fetch_feodo.py`, `pipeline/botnet_metrics.py` and
data-contracts.md. Original candidate note:
- **Thesis:** the C2 weather report — takedowns visible as cliffs.
- **Signals:** active C2 count by malware family, daily; family
  birth/death.
- **Source:** `feodotracker.abuse.ch/downloads/ipblocklist.json`
  (tested: live JSON, CC0, per-C2 family + first_seen). Count is small
  (single digits on quiet days) — which is itself the story.
- **Feasibility:** easy — tiny feed, append-only daily counts.

### TLD DNSSEC signing (registry-side hygiene lane)
- **Thesis:** pairs APNIC's resolver-side measurement with the
  registry side: which TLDs sign at all.
- **Source:** ICANN research pages respond but are HTML — needs a
  parse-feasibility pass before committing.
- **Feasibility:** medium — parsing risk; complements module 08.

### Bounty attack surface (Chaos dataset)
- **Thesis:** how much of the internet is formally in-scope for
  bounties, over time.
- **Source:** ProjectDiscovery Chaos public dataset; snapshot
  program/domain counts.
- **Feasibility:** easy-medium — weakest thesis of the four.

## Probed 2026-07-10 — verified sources, not yet scheduled

### Registry malware ledger (OSV)
- **Thesis:** package registries are the new watering hole, and the
  takedown log is public.
- **Signals:** malicious-package advisories (MAL-*) per ecosystem per
  month (npm, PyPI, crates); takedown volume trends.
- **Source:** OSV bulk zips per ecosystem (tested: npm all.zip serves,
  ~210 MB — ATT&CK-style cache-once pattern).
- **Feasibility:** medium — bulk size needs the state-cache pattern.

### CWE Top 25 vs reality — SHIPPED as module 15
Live as **15 · CWE Top 25** ([top25.html](../site/top25.html)). Shipped as
its own module: the latest official MITRE CWE Top 25 (hand-committed in
`pipeline/cwe_top25_data.py`, the only new source) set against raw
first-listed-CWE prevalence over a five-complete-year window and the
KEV-exploited cut, both read from the shared streaming aggregate (one
additive accumulator, `agg.kev_cwe_counts`). Two charts — official rank
vs. measured prevalence rank (the divergence board), and the KEV share of
each official class. Honesty note carried in the methodology: MITRE's own
Top-25 formula derives from NVD CVEs + CISA KEV, so the divergence from the
published rank is the story, not the list. Contract
`pipeline/top25_contracts.py`; see data-contracts.md. Original candidate
note:
- **Thesis:** the official Top 25 vs what actually gets exploited.
- **Signals:** MITRE's annual Top 25 lists against CyberMon's measured
  KEV/EPSS-weighted CWE distribution (data already ingested).
- **Source:** cwe.mitre.org Top 25 archive pages (tested: reachable).
- **Feasibility:** easy-medium — annual lists are small and stable;
  could ship as a chart in CVE Ecosystem or beside bug-class inertia.

### Support-window economics (endoflife.date)
- **Thesis:** how much software the world is told to run goes
  unsupported, and support windows keep shrinking.
- **Source:** endoflife.date API (tested: 460 products, one JSON).
- **Feasibility:** easy — thinnest thesis in this group.

### CA concentration (Certificate Transparency)
- **Thesis:** the web's trust layer is consolidating into a handful of
  issuers — the CNA-concentration story, one layer down; plus the
  47-day certificate-lifetime cliff.
- **Source:** needs a feasibility pass — Cloudflare Radar API
  (free-tier key, allowed) or another stable public aggregate; raw CT
  volume is out of reach.
- **Feasibility:** medium-hard, gated on the aggregate source.

## Tier 0 — non-CVE sources, live-tested 2026-07-09

Every endpoint below was fetched and inspected on that date; record counts
and field lists are from the live responses, not documentation.

### Breach disclosure ledger (HIBP) — SHIPPED as module 05
- **Thesis:** "Dwell time is a marketing number. The public record of
  breach disclosure is measurable, and it is right here."
- **Signals:** breach→cataloguing lag (`BreachDate` → `AddedDate`) per
  year; breaches and records exposed per year; leaked data classes over
  time.
- **Source:** `https://haveibeenpwned.com/api/v3/breaches` — tested: 1,015
  breaches, no API key, fields incl. BreachDate/AddedDate/PwnCount/
  DataClasses/IsFabricated. Attribution required (HIBP).
- **Feasibility:** easy — one JSON fetch, KEV-latency storytelling pattern.

### Extortion economy, on-chain (Ransomwhere) — SHIPPED as module 06
- **Thesis:** "Ransom revenue is the one security statistic nobody can
  spin — it settles on a public ledger."
- **Signals:** confirmed payments and USD revenue per quarter; median
  payment drift; family concentration and churn.
- **Source:** `https://api.ransomwhe.re/export` — tested: 11,186 payment
  records, CC0, fields incl. family/balanceUSD/transactions.
- **Feasibility:** easy — single export, CC0 licensing. Honest caveat to
  carry: crowdsourced and verified means a *floor*, not the market.

### Taxonomy churn (MITRE ATT&CK) — SHIPPED as module 07
- **Thesis:** "The map of attacker behavior grows every release;
  detections are graded against a moving target."
- **Signals:** technique/sub-technique counts per version; added,
  deprecated, revoked per release; group/software catalog growth.
- **Source:** `github.com/mitre-attack/attack-stix-data` — tested: all 41
  enterprise versions present as STIX bundles. Whole history backfillable
  on day one; versions are immutable, so per-version stats cache cleanly
  (market-state reconstruction pattern).
- **Feasibility:** medium — STIX parsing and a version-state cache, but no
  rate-limit or licensing pain (ATT&CK terms permit use with attribution).

### The boring-hygiene index (APNIC DNSSEC validation) — SHIPPED as module 08
Live as **08 · Hygiene Index** ([hygiene.html](../site/hygiene.html)).
Source exploration found richer endpoints than the candidate note
assumed: `cgi-bin/json-table.pl?x=<code>` serves the FULL daily history
per economy (2013-10-07 onward, ~3.9 MB), so the stage is stateless; the
all-economies snapshot comes from the world-map page's inline table
(no JSON equivalent exists — parsed with a loud-failure floor). See
`pipeline/fetch_dnssec.py` and data-contracts.md.

**Verified spare data sources for Security Market v1.1** (live-tested
2026-07-09, re-verified and SHIPPED as the module's 4th and 5th lanes
2026-07-21): SEC EDGAR full-text search (free JSON API, mandatory
User-Agent header, history to 2001 — an "enterprise/investor attention"
lane) and Wikipedia Pageviews REST API (server-side monthly aggregates,
one request per term for the whole history, the most reliable API tested —
designated fallback if GDELT's rate limiting becomes intolerable).
Both lanes are stateless nightly full-window refetches; the first run
needs no special backfill step (~13 Wikipedia requests plus ~840 EDGAR
term-month cells, roughly 15–25 minutes at the polite pacing baked into
`pipeline/fetch_market.py`). Rejected: Stack Exchange (too sparse),
GitHub search (workable but rate-limit-cramped; future 6th source at
best).

House rules for any module that ships (same bar as the existing two):

1. **The subject is the industry's own machinery** — scoring systems,
   institutions, registries, markets — never individual-victim news.
2. **Open data only**, fetchable nightly by an unattended pipeline, with
   licensing that survives republication of aggregates.
3. **Auditable**: every chart gets an expandable "how this is computed"
   footnote and a binding entry in [data-contracts.md](data-contracts.md).
4. **A thesis, not a feed.** If the module can't sustain a provocative
   one-line claim that the data either proves or kills, it's not ready.

Feasibility legend: **easy** = reuses data the pipeline already ingests;
**medium** = new public source, bounded scraping; **hard** = source is messy,
rate-limited, paid, or legally delicate.

---

## Tier 1 — near-term (mostly reuses data we already ingest)

### AI as attack surface (scoped out of module 21)
- **Thesis:** AI is becoming attack surface far faster than it is becoming
  attack capability — the inverse of the story the industry tells. Module
  21 shows exploitation speed didn't move; this would show what did.
- **Signals:** CVEs in AI/ML products and frameworks per year; their CWE
  mix against the corpus baseline (are these new bug classes or the same
  old injection and deserialization?); KEV membership rate.
- **Source:** the cvelistV5 corpus already ingested nightly — no new
  fetch. The work is an extractor change plus a classifier.
- **Feasibility:** medium. Two real costs: `CveFacts` currently carries no
  vendor/product/description strings (it deliberately stores only what the
  metrics need, and never whole records), so the streaming pass needs
  extending; and deciding what counts as an "AI product" is a curation
  problem exactly like `security_products.py`. Landmine: keyword-matching
  descriptions will over-match ("machine learning" in a changelog) — the
  defensible version classifies on vendor/product strings with a
  reviewable, commented list in-repo, and states its own recall limits.

### KEV latency ledger — SHIPPED as module 03
- **Thesis:** "By the time the government confirms it's exploited, you've
  been exposed for months."
- **Signals:** days from CVE publication to KEV listing (distribution per
  year, per vendor); remediation deadlines vs. patch availability at listing
  time; share of KEV entries that predate their own CVE record.
- **Sources:** CISA KEV JSON + cvelistV5 (both already ingested).
- **Feasibility:** easy — one new metrics builder and contract section.

### CVE program concentration — SHIPPED as module 04
- **Thesis:** "The CVE database is becoming a handful of vendors grading
  themselves at scale."
- **Signals:** CNA count over time; share of annual CVEs from the top 5/10
  CNAs (HHI-style concentration index); reserved-but-never-published rate;
  rejection rate per CNA; time from reservation to publication.
- **Sources:** cvelistV5 (already ingested — record states and CNA metadata
  are in the corpus).
- **Feasibility:** easy.

### Exploit availability lag ("time to PoC")
- **Thesis:** "The window between disclosure and public exploit code is the
  only deadline that matters, and it's shrinking."
- **Signals:** days from CVE publication to first public PoC per year;
  share of KEV entries with public PoC before KEV listing; PoC coverage by
  severity bucket (are 9.8s actually the ones that get weaponized?).
- **Sources:** Exploit-DB (public CSV mirror), Metasploit module metadata
  (GitHub), Nuclei templates repo (CVE-tagged YAML). All public git/CSV.
- **Feasibility:** medium — three small fetchers, but all are clean
  machine-readable corpora with CVE IDs attached.

---

## Tier 2 — new public sources, bounded effort

### Breach disclosure clock
- **Thesis:** "Dwell time is a marketing number; disclosure lag is a policy
  choice. Both are measurable."
- **Signals:** days from 'incident discovered' to public disclosure across
  SEC 8-K Item 1.05 filings; filings per quarter since the SEC rule;
  materiality hedging language frequency; state-registry breach counts.
- **Sources:** SEC EDGAR full-text search API (free, machine-readable);
  state AG breach registries that publish structured lists (California,
  Maine, Washington).
- **Feasibility:** medium — EDGAR is a solid API; state registries vary.

### Patch gap board
- **Thesis:** "Vendors publish CVEs when the fix ships, not when they knew.
  The gap is the story."
- **Signals:** per-vendor lag between 'first known' evidence (in-the-wild
  flags, researcher credits with dates) and advisory publication; Patch
  Tuesday load curve (CVEs per release, trending up); share of advisories
  with no CVSS vector or no CWE.
- **Sources:** cvelistV5 date fields (already ingested), Project Zero's
  public disclosure tracker (published spreadsheet), vendor CSAF feeds.
- **Feasibility:** medium — date-quality is the risk; needs a defensible
  "first known" definition per chart footnote.

### Advisory quality index
- **Thesis:** "Security advisories are press releases with CVE numbers.
  Machine-readable ones are still the exception."
- **Signals:** CSAF adoption per vendor over time; share of advisories with
  complete CVSS vectors, CWE, affected-version ranges; VEX availability.
- **Sources:** vendor CSAF/`provider-metadata.json` endpoints (a public,
  enumerable ecosystem by design), cvelistV5 field completeness (already
  ingested — field-completeness stats need no new fetching at all).
- **Feasibility:** medium; the cvelistV5-only version is **easy** and could
  ship as a chart inside CVE Ecosystem first.

### OSS supply-chain concentration
- **Thesis:** "The software everyone depends on is maintained by almost
  nobody, and the industry keeps re-discovering this annually."
- **Signals:** maintainer counts for top-N most-depended-on packages;
  OpenSSF Scorecard score distributions over time; share of critical
  packages with 2FA/signing (sigstore) adoption.
- **Sources:** deps.dev API (free, Google-operated), OpenSSF Scorecard
  public results, ecosyste.ms APIs.
- **Feasibility:** medium — APIs are good; picking a stable "top-N
  packages" universe is the methodological landmine to defuse in writing.

---

## Tier 3 — strong theses, harder data

### Compliance clock
- **Thesis:** "Compliance frameworks now ship faster than the industry can
  implement them — regulation has its own hype curve."
- **Signals:** count of active security regulations/frameworks over time
  (NIS2, DORA, CRA, SEC rules, state privacy laws); time from enactment to
  enforcement; overlap/conflict counts across jurisdictions.
- **Sources:** EUR-Lex API, US Federal Register API, IAPP state-law tracker
  (verify licensing before use).
- **Feasibility:** hard — sources are open but heterogeneous; "count of
  frameworks" needs a rigorous inclusion rule to be defensible.

### Extortion economy ledger
- **Thesis:** "Ransomware groups publish better breach statistics than the
  industry does — because extortion requires publication."
- **Signals:** victim posts per month by group; group birth/death/rebrand
  rate; sector distribution shifts; claimed-vs-confirmed ratio where
  registries allow cross-checking.
- **Sources:** open leak-site trackers (e.g. ransomwatch/RansomLook —
  public projects with JSON output).
- **Feasibility:** medium-hard — data is public and structured, but needs
  careful editorial handling: aggregate counts only, no victim names on the
  site, and an explicit methodology note about claim inflation.

### Exposed attack surface index
- **Thesis:** "The internet's misconfiguration rate is flat no matter how
  much the industry sells."
- **Signals:** counts of exposed RDP/databases/admin panels over time;
  EOL-software share among exposed services; default-port exposure trends.
- **Sources:** Shodan facet counts (free tier is tight; paid for real use),
  Shadowserver public dashboards (free, aggregate, permissively shareable).
- **Feasibility:** hard — depends on third-party scanners' terms;
  Shadowserver's aggregate feeds are the realistic path.

### Security research attention curve
- **Thesis:** "Research follows fashion. The bugs don't."
- **Signals:** vulnerability-class distribution in conference talks
  (Black Hat/DEF CON/USENIX archives) vs. actual CWE distribution in
  published CVEs; lag between research wave and exploitation wave.
- **Sources:** conference archive pages (public), cvelistV5 CWE data
  (already ingested).
- **Feasibility:** medium-hard — archive scraping is bounded, but talk
  classification needs a documented, reproducible taxonomy.

---

## Non-goals (deliberately excluded)

- **Individual CVE news, IOC feeds, victim naming** — CyberMon is meta;
  other sites do feeds.
- **Anything requiring paid or ToS-restricted data** (Crunchbase, Gartner,
  commercial threat intel) — every number must be reproducible by a
  stranger with `git clone` and zero API budget (a free-tier key at most).
- **Live scanning or probing** — CyberMon consumes published data; it never
  touches other people's infrastructure.
