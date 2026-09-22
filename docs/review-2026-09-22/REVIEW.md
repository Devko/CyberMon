# CyberMon full-site review — 22 September 2026

A working-and-correctness review of every page against the committed edition
(`generated_at` 2026-09-22T02:50Z, baseline `75cf158`). Every headline figure
and prose number was recomputed from `site/data`, the page JS was read against
the JSON it renders, and the pipeline was read against its stated
methodology. Findings already recorded in `docs/review-2026-09-20/DISPOSITION.md`
or `docs/review-2026-09-10/` were not re-reported.

## How it was checked

- `python -m pytest pipeline/tests` — 1,424 passed before, **1,433 passed**
  after (1 skipped), plus the offline fixture run.
- `tools/site_smoke.py` (23 pages), `tools/field_smoke.py`,
  `tools/make_motion.py --check` — all pass, before and after.
- A rendered-text sweep of all 27 HTML pages at 1440 px and 390 px (every
  `<details>` opened): no leaked `NaN` / `undefined` / `{placeholder}`, no
  empty chart, no horizontal overflow. Expected exceptions: the Field binary
  is a deploy-time artifact (404 locally), `alias.html` is the known unwired
  draft, `motion.html` is a fixed 1080 px export stage.
- Screenshots of every chart changed below, and failed-load renders
  (`kev.html?fail=kev_latency`, `cve.html?fail=cna_leaderboard`).

Legend: **Fixed** = changed in this pass; **Disclosed** = copy now states a
limitation the code keeps; **Open** = verified, left for a follow-up.

## Wrong numbers or claims shown to readers

| Page | Finding | Verdict |
| --- | --- | --- |
| Concentration | "Top-5 share climbing for a third straight year" — 2023 is the low (45.3 → 53.1 → 56.6); two rises. Audit only checked two. | Fixed: "second straight year"; claim test re-quoted. |
| AI Alibi | Raw metrics (gap / week / negative) counted the still-indexing 2025 cohort as a settled post year, against the page's own rule; GPT-4 raw cells were judged on it. | Fixed in `ai_metrics.py` (every clock row carries `provisional`, same rule as the like-for-like series); contract re-derives `post.years`. Headline **0 of 7 → 0 of 4** judged; GPT-4 raw cells now withheld; ChatGPT cells still "slowed". `ai_alibi.json` regenerated from the committed inputs. Withheld copy now says "complete, settled year(s)". |
| AI Alibi | Methodology caveat "the 2025 cohort is anomalous — twice 2024's size, p25 years negative" is stale (197 vs 154, p25 +7 d) and not why the era is withheld. | Fixed: caveat removed (three caveats remain). |
| AI Alibi | "Series spans -800 days to single digits"; "1999 cohort is 109 CVEs at -800 days" (data: -765 d to +166.5 d; n = 107). | Fixed, worded so it does not go stale. |
| Time to PoC | KEV-preempt denominator "roughly four in ten of the catalog" — 450 / 1,717 = 26.2 %. Guard accepted 25–55 %. | Fixed: "roughly a quarter"; guard 20–32 %. |
| Time to PoC | Headline "The exploit rarely waits for the record" over a 38-day 2025 median (4 % negative); home card likewise. | Fixed: "The exploit used to beat the record. Now it trails by weeks." |
| CVE Calendar | "Ordinary Tuesday" line drawn at the 2025 value across all years; caption "the gap … is what the release train adds" false elsewhere. | Fixed: per-year step line; caption now "every year since 2019 the bar has cleared its own ordinary Tuesdays" (2018 is below), guarded by a per-year test. |
| NVD throughput (cve) | Resweep ring/tooltip flagged the frozen-snapshot day; the catch-up lump lands the next night (`after_resweep`, published but unread). | Fixed: ring and tooltip on `after_resweep`; distinct tooltip for the resweep day; methodology says where the lump lands. Stray `_resweep` legend entry removed. |
| Extortion | Median-payment log axis and tooltips printed "$0" for sub-dollar medians (2013: $0.03). | Fixed: cents kept below $1. |
| Top 25 | Exploited-classes methodology still said MITRE builds the list partly from KEV (withdrawn 09-20 #18; same page contradicted itself). | Fixed. |
| CNA board | "Some CNAs hand a 9+ to a third or more" — one does (39.8 %); guard floor was 28 %. | Fixed: "The most aggressive hand a 9+ to three or four in ten"; guard 27–45 %. |
| KEV changelog | "The day CISA added that column … did not log a fake edit wave" — it logged 206 flips (2023-12), in the hero total. | Fixed: copy says what the step month did and that the edit total counts it. |
| Carousel PDFs | `{animation:false}` was overridden by `mkChart`'s `baseOption`, so PDFs could print mid-animation. | Fixed (flag applied last); verified `animation === false` on every carousel chart. |
| Every page | "Source of truth" link pointed to `pipeline/metrics.py` for all ~75 sections. | Fixed: per-section map `editorial.sourceFiles` → the module that builds it. |

## Misleading or fragile

| Page | Finding | Verdict |
| --- | --- | --- |
| Rescores | Raises/cuts (single digits) shared an axis with thousands of backfills and were invisible. | Fixed: two panels on a shared week axis. |
| Rescores | Copy says "effective score"; the tracker diffs the CNA score only. "Cached state" vs committed. | Fixed. |
| EPSS Volatility | "nights on record" = 53 in the hero, 62 on the board. Movers show 1-decimal % and a raw-fraction move. | Fixed: "clean nights"; 3-decimal % and moves in pp (threshold too). |
| C2 | Missed nights (08-02, 08-28, 08-29) silently closed up on a category axis. | Fixed: calendar gap-filled; empty slot with a "no reading" tooltip. |
| C2 | One AS split across two `as_name` spellings. | Fixed: tallied by AS number (next nightly). |
| ATT&CK | A retired object later revoked (or flipping both flags) counted twice, against the methodology. Not triggered in current data. | Fixed + test. |
| Vulnrichment | Current month drawn as a full bar. | Fixed: faded, "month in progress" tooltip. |
| Naming | Top-30 cut split a 9-way tie alphabetically. Caption "ten, twelve, fifteen" (12 bucket empty). | Fixed: cut extends through the tie; "ten, fourteen, fifteen". |
| CNA / rejection boards | "Last N years" windows include the partial current year silently. | Disclosed in the window line. |
| Roster | The one "departure" (The Qt Company, 2026-08-05) is likely a rename that predates cnaID fingerprints; cannot be proven without the old cnaID (Qt Group's is CNA-2025-0016). | Disclosed in the methodology; history not rewritten on inference. |
| Roster | Launch-night text ("begins as a single point tonight"); flux note dated from first event, not record start. | Fixed. |
| KEV | Remediation methodology said no CVE match is needed; code (and its tests) deliberately exclude unmatched entries. "About three weeks" vs 14 d in 2026. Page description said only 2021 is set aside (cutoff is 2023-01-01). | Fixed copy (code intent confirmed by tests). |
| EPSS | "Nearly three in ten" at 30.1 %. | Fixed: "about three in ten"; guard tightened. |
| Market | Divergence note blamed collection; the 7 omitted terms fail the volume floor. | Fixed. |
| AI Credits | "first credit" column spans all tiers; zero shown as "—"; methodology described hatched rows that no longer exist. | Fixed (relabelled "first named"; `fmtInt`; copy). |
| Field | Deep links `#cve=` and Find-CVE + Enter never moved the camera (ResizeObserver reset it); canvas click left a stale record card; smoke URL round-trip was same-document and tested nothing. | Fixed; new smoke checks proven to fail on the old behaviour. |
| Failed loads | Raw `{placeholders}` left in captions/methodology when a data file fails (cve, kev). | Fixed centrally in `showError`. |
| Nightly / CI deploy | Browser installs were `continue-on-error`, but the required Field check needs the browser — a transient install failure failed the job after the data commit. | Fixed: installs required, retried 3×. Duplicated comment block in `nightly.yml` merged. |
| Chrome | Nav opened the Field in a new tab; footer had no carried-forward flag for EPSS history; "graded" footer wording; home cards for Rescores/Roster contradicted 09-20 #16/#20; noscript list lacked the Field; resize registry kept disposed charts. | Fixed. |
| Docs | `data-contracts.md` had the Time to PoC example (old numbers, unclosed) under the botnet heading; HIBP/Ransomwhere docstrings denied the carry-forward `__main__` performs. | Fixed. |

## Follow-up round (same day)

| Item | Resolution |
| --- | --- |
| NVD throughput flow asymmetry | Fixed: Received → Analyzed now counts as a queue exit, symmetric with Deferred; only exits seen awaiting analysis are timed. Committed rows before 2026-09-23 are not rewritten; methodology and data contract date the change. Test added. |
| Market freshness per lane, not per term | Fixed: per-(source, term) `term_success` stamps; a term whose own fetch failed across the month rollover has its previous-month cell withheld (YoY and divergence follow). Old states seed from the lane stamps, so the first night marks nothing new. Output shape unchanged. 9 tests added. |
| Roster "departure" | Verified against CVEProject/cve-website history: commit `a03548e` (2026-08-03) renamed TQtC / The Qt Company to Qt / Qt Group under the same, unique cnaID CNA-2025-0016 (country and type unchanged, scope text reworded) — the rename rule is met. With the owner's go-ahead the two `cna_roster.csv` rows were rewritten to what `diff_orgs` logs today (one `renamed` + one `scope_changed`) and `roster_flux` rebuilt with the pipeline's builder: totals now 19 joined · 0 departed · 1 renamed · 7 scope changes. |
| Credits carousel overflow | Confirmed with the real Newsreader font: the funnel slide overflowed its sheet by 330 px, so `credits.pdf` was never built. The fit pass now lowers the zoom (floored at 1.4×) for sections with no chart host to shrink; every deck builds. The slide's "credited here" label was also clipped by its bar (column widened). |
| AI clock raw series | Provisional years now draw hollow on the raw line too. |
| "Grading" wording | Prose in `epss_report_metrics.py`, `epss_volatility.py` and `epss_grade.js` reworded; the `graded` / `ungradeable` field names are contract names and stay. |
| Rescores hero stat | Left as is (label accurate; the chart now separates backfills from rescores). |

## What moves in the published data

Only `site/data/ai_alibi.json` was regenerated here (from the committed
`time_to_poc.json` and `market_hype.json`, same `generated_at`). The C2
network tally and the ATT&CK retirement rule take effect on the next
nightly; neither changes a figure in the current edition except the C2
"networks" list, which merges the two DigitalOcean spellings.
