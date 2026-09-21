# CyberMon review disposition — 20 September 2026

The external "full-site review and implementation handoff" dated 20 September
2026 was checked finding by finding against the source at `324a7fe` (one commit
past the review's own baseline `2195b6f`). Every claim was reproduced or
refuted from the code before anything was changed. This file records the
disposition; the numbers section says what moves in the published data and
what cannot be known until the next nightly rebuild.

Conventions: **Confirmed** = observable in the source; **Refuted** = the source
already said the opposite or the claim was wrong; **Disclosed** = a real
limitation the methodology copy already owned, so the change (if any) is
labelling, not arithmetic.

## Disposition

| # | Finding | Verdict | Change |
| --- | --- | --- | --- |
| G2 | `epss_bucket()` files exactly 0.10 under `>10%` | Confirmed (stale label on one chart; Field/copy already said ≥10%) | Label is `≥10%` in `metrics.py`, contracts, docs, tests and the committed `score_vs_reality.json` / `epss_report.json` (same numbers, corrected label). |
| G2 | `severity_bucket(0.0)` is `low` but labelled `0.1–3.9` | Confirmed | Bucket is `0.0-3.9` everywhere (metrics, PoC coverage, docs, committed JSON). Missing scores stay the separate `unscored` state. |
| G2 | Effective-score policy described inconsistently | Refuted | Every description already says "newest family, CNA before ADP within it". No change. |
| G2 | `_pct()` renders empty populations as 0% | Confirmed in code, mostly gated by consumers | Not changed: the helper is shared by every contract; the unguarded render paths are noted for follow-up. |
| 1 | Metasploit `disclosure_date` feeds the PoC clock | Confirmed | `fetch_poc.py` keeps Metasploit disclosure dates for the audit block only; `first_poc_dates` is Exploit-DB only. Metasploit modules are classified by `type`: only `exploit` modules are exploit code; auxiliary/post modules are a separate set. Nuclei is a separate detection tally (`with_detection`) and never exploit coverage. Aggregator, Field export (`poc_ids=exploit_ids`), contracts, docs, all copy and tests updated. |
| 2 | AI cutoff off by one: post window began at `cut + 1`, i.e. with the straddling year | Confirmed | `post_start_year_for()` starts the post window at the first year beginning after the cutoff (January 1 handled explicitly); emitted as `post_start_year`, re-derived by the contract. `MIN_POST_YEARS` now counts settled (non-provisional) years only. "Censoring-free" renamed "fixed-window". |
| 2 | 10% threshold, ±90-day series, available-source average | Disclosed | Copy already discloses each; no arithmetic change. |
| 3 | EPSS Volatility quarantines high-churn nights from headlines; weekly sums are events not CVEs; unobserved weeks chart as zero | Confirmed, all disclosed in the methodology | Not changed in this pass (see "Not done"). |
| 4 | Market `yoy()` / `divergence()` use positional windows | Confirmed | Both are anchored at the latest complete calendar month; YoY needs all 24 contiguous months, divergence the same three months in both sources; a gap withholds the figure. "Same twelve months" headline is now true by construction. Copy, docs, tests updated. |
| 4 | Copy calls sources "independent" / divergence "maturity" | Refuted | No such copy. |
| 5 | NVD wait clock restarts at Awaiting→Undergoing | Confirmed | `diff_transitions()` carries the since-date across the two queue statuses (one queue episode); "lower bound" framing kept; "Deferred = cancelled" softened to "set aside". |
| 5 | Site says the clock starts at "first sighting in the queue" | Confirmed imprecision | True after the code fix. |
| 6 | KEV copy claims exploitation timing / universal deadline / Unknown→No | Refuted | No change. |
| 6 | Hardcoded year-to-year numbers in KEV prose | Confirmed | Latency caption and methodology, and the remediation caption, are templated and filled from the payload by the renderers, with direction words chosen from the data. The bucket headline ("four in ten", "one in seven") stays as prose guarded by the nightly claims audit. |
| 7 | Concentration caption "reservations formally withdrawn" contradicts the exclusion | Confirmed | Caption now describes published records later marked REJECTED. |
| 8 | Breach copy: dwell time, people, confirmed incidents | Refuted | Copy already distinguishes each. No change. |
| 9 | Extortion sums repeated rows, groups by hash, no "victim payments" claim | Confirmed and disclosed / refuted | No change; outpoint (`txid`, `vout`) evidence is not in the upstream data, so the ambiguity stays explicit as the review asks. |
| 12 | Calendar: no other-Tuesday control | Confirmed (substantive) | `tuesday_baseline_pct` per year and `tuesday_baseline_latest` in the headline: records on the other Tuesdays in the year's observation window, per Tuesday, scaled to the window's patch-Tuesday count. Chart draws it as a second baseline; copy compares against both and claims no cause. |
| 12 | Reservation age from ID year; 12/365 | Disclosed | No change. |
| 15 | Changelog: "no upstream history" | Confirmed false (`cisagov/kev-data` has commit history) | Copy and docstrings now say the catalog feeds carry no changelog, CISA's kev-data repository holds commit-level history, and this module's value is the normalized per-field ledger. |
| 15 | Ransomware column introduction counted as ordinary flips | Confirmed | Step-month flips are excluded from `flips.total`-derived headline figures and reported separately (`step_month_flips`, `total_after_step`). |
| 16 | Rescore fingerprint collapses 3.0/3.1 | Confirmed | Fingerprint carries the exact version; 3.0→3.1 is a version shift. Legacy "v3" state migrates without spurious shifts. Copy no longer claims unique possession of history or that the assigner is the proven author. |
| 17 | Naming: aliases as exact identities | Partially confirmed | One clause added: MITRE's associated names may be overlapping clusters. |
| 18 | Top 25 methodology described as KEV-joined and re-scored | Confirmed | Rewritten in both pipeline docstrings and the page: normalized NVD frequency × average CVSS v3 severity over the edition's one-year window; KEV counts shown beside, not an input. README's edition list corrected. |
| 19 | ADP last-modified grouping | Disclosed | No change. |
| 20 | Roster: renames read as departure + join; roles unused; "no history exists" | Confirmed | `renamed` event when a departed and onboarded shortName share a `cnaID` unique on both nights and agree on identity; `by_role` and `assigning_n` added; copy says the roster file's git history exists and that the headcount includes non-assigners. |
| 21 | C2 "How long a C2 lives" | Confirmed | Retitled as time on the tracker's list. |
| 13 | EPSS grading language in README and the Volatility page | Confirmed | README, `epss.html` metadata and the Volatility methodology now describe a day-before-KEV snapshot, not a grade. |
| alias | `js/alias.js` missing | Known draft | The introducing commit says the page is unlinked and unwired; already in `docs/backlog.md`. No change. |

## Numbers

The committed `site/data` edition is real nightly data and was not regenerated
here (the pipeline needs the live corpora). What changes on the next nightly:

- **Time to PoC**: the dated cohort shrinks to Exploit-DB-dated CVEs (the
  committed catalog says 25,041 Exploit-DB-dated vs 26,182 mixed), and
  Metasploit-only CVEs leave the hero, arming and KEV-preempt cohorts.
  Coverage bars count exploit code only; Nuclei moves to `with_detection`.
  On the offline fixture the dated cohort goes from 8 to 7 CVEs and the 2014
  cohort from two CVEs (median −348 d) to one (30 d).
- **AI Alibi**: every era's post window loses its straddling year (2022 for
  ChatGPT, 2023 for GPT-4, 2025 for the uplift era). The GPT-4 era keeps two
  complete post years (2024, 2025); the uplift era has none until 2027.
- **Security Market**: any pair with a gap inside the 24-month window, or
  whose anchor month is unpublished, posts no YoY that night; divergence
  needs the same three anchor months in both sources.
- **Silent Rescores**: the first night after deploy upgrades stored "v3"
  labels to exact versions without logging shifts; afterwards 3.0→3.1 moves
  file as version shifts.
- **KEV Changelog**: `pct_flag_flips` and the headline flip count exclude the
  December 2023 column-introduction step (206 of the first 308 flips).
- **CNA Roster**: unchanged totals until a rename occurs; `assigning_n` will
  read one below the headcount on the live roster (CISA is Top-Level Root +
  ADP only).
- Bucket relabels change no number.

## What the corrected clock actually showed (2026-09-21)

The first nightly after the merge built cleanly and then refused to
publish: five editorial claims calibrated on the old mixed clock failed
the claims audit. Rebuilt locally from the live corpora (cvelistV5 at
HEAD, Exploit-DB, Metasploit, Nuclei, KEV via CISA's kev-data mirror):

| Measure | Old mixed clock (edition 2026-09-21 03:36) | Exploit-DB-dated clock |
| --- | --- | --- |
| Dated CVEs / matched | 26,182 / 26,139 | 25,086 / 25,043 |
| Hero median, 2021–2025 | 1, 4, 1, 2.5, −11.5 d | 8, 20, 15.5, 166.5, 38 d |
| Hero cohort, 2024 / 2025 | 262 / 504 | 154 / 197 |
| KEV listings preempted (trend cohort) | 80.7% of 247 | 55.4% of 121 |
| Like-for-like, settled 2005–2024 | −8 to +14.5 d | −8 to +11 d |
| AI Alibi, ChatGPT cutoff (like-for-like) | no inflection | slowed: pre 2 d, settled post 9 d |
| Judged cells accelerated | 0 of 6 | 0 of 7 (all 7 slowed) |

Copy withdrawn or narrowed accordingly: "Since the mid-2000s the median
has hugged zero" (now: within a month of zero through 2020, weeks after
publication since 2021, 2024 an outlier at months); "the 2025 cohort is
twice 2024's with a lower quartile years in the negative" (gone);
"roughly four in five listings … beaten to the announcement" (now: just
over half); "The clock stopped moving before the models arrived" (now:
did not speed up when the models arrived); "a line that does nothing in
particular once it enters" (now: moves later if it moves at all);
"Nothing bends at the cutoff" (now: nothing bends toward faster);
"inside a fortnight-wide band since 2005" (now: every settled year since
2005 inside a three-week band); the attention overlay now uses the
settled like-for-like clock rather than the raw median, whose newest
cohorts are a few hundred CVEs each. Two pipeline follow-ups landed with
it: the AI Alibi's post-cutoff level averages settled years only, and the
new claim checks skip on editions that predate the corrected clock.

## Verification

Run on 2026-09-21 in the implementation container (Python 3.11; CI uses 3.12):

- `python -m pytest -q pipeline/tests -p no:cacheprovider` — 1421 passed,
  2 skipped, 1 pre-existing deprecation warning (baseline before this work:
  1390 passed, 1 skipped).
- `python -m pipeline --offline-fixtures --out <tmp>` — all outputs written
  and validated.
- `python3 tools/site_smoke.py` (via a wrapper pointing Playwright at the
  preinstalled Chromium) — every page booted and loaded its data, but the
  implementation sandbox's outbound proxy returns 403 for cdn.jsdelivr.net,
  so ECharts never loaded and every chart section showed its designed
  "chart library did not load" card. Chart rendering therefore could NOT be
  verified here; CI's site-smoke job must be the gate. As a fallback, every
  edited JavaScript module passed `node --check`, and the new caption
  templates were exercised in Node to confirm every placeholder fills.

## Not done, and why

- **EPSS Volatility default view** still quarantines anomaly nights and the
  weekly bars remain event counts; both are disclosed on the page. Changing
  the default series is a product decision the review labels P0 but that
  would also invalidate the committed claims audit; deferred for a separate
  pass.
- **Extortion outpoint reconciliation** needs `(txid, vout)` from upstream,
  which Ransomwhere does not publish.
- **AI Credits** keeps its `poc` funnel stage defined as "referenced by any of
  the three corpora" (its own docs say so, with the Nuclei caveat).
- **Shared `_pct()`** still returns 0.0 for an empty denominator; the two
  unguarded renderers (`adp_providers.js`, `reality.js`) are the follow-up.
- **Hygiene** "free of charge" and the qualitative "decades away" remark are
  editorial opinion and were left.
- **Edition manifest / claim predicates (G6, G7)** are new infrastructure,
  not fixes to existing claims; not started.
