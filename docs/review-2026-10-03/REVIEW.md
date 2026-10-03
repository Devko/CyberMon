# CyberMon content review — 3 October 2026

Started by a red nightly. From 2026-09-30 to 2026-10-03 every refresh failed
the claims audit, so nothing was committed or deployed and the site stayed
on the 09-29 edition. Once the nightly was green again (`8dbd8f5`, the
10-03 edition), six parallel auditors read every sentence of
`site/js/editorial.js` (28 pages, the home cards, the footer and the motion
scenes) against that edition and against the git history of earlier
nightlies, and five fixers worked through the findings in separate
worktrees. Every finding was re-checked against the data before it was
acted on.

## The red nightlies

| Guard | Cause | Resolution |
| --- | --- | --- |
| AI Credits 02, "each AI column is within a handful of records" | Real change: vendor-credited CVEs in an exploit corpus rose from 13 to 15 against 8.5 at the baseline rate (09-30). | Copy says the vendor column has more listed records than that rate would give (`36fb984`); later reworded again with margin (below). |
| AI Credits 06, "a browser, a Java crypto library and an operating system lead the list" | Real change: a batch of Bouncy Castle C# CVEs moved FreeBSD out of the top three (10-03); the lab count went 205 → 257 in four days. | Rewritten (`36fb984`, then below). |
| Market risers, "Agentic AI has the steepest year-over-year rise in news" | Not a change in the world. GDELT answers about one request in five from a GitHub runner (35 of 168 first attempts over twelve runs), and after the month rolls over a term's YoY is withheld until its own fetch lands once (`market_metrics.term_partial`). The market sync state was cached only on a green job, so each failed night discarded the terms that had landed. | The market state is now saved even when the job fails. A withheld GDELT figure may ship in the first ten days of a month while the lane is not stale; anything else withheld still fails (`36fb984`). The 10-03 run passed under that rule with Agentic AI's GDELT fetch still rate-limited. |

History rows for 09-30, 10-01 and 10-02 were never written and cannot be
recreated; 10-03 was recovered by a manual run.

## How it was checked

- `python -m pytest pipeline/tests` — 1,722 passed before, **1,873 passed**
  after.
- New: `tools/claims_history.py --last 9` runs the guards against every
  nightly edition since 09-23. All pass except the first 09-23 edition
  (`d5831a9`), which carries the EDGAR comma-forms bug fixed in that day's
  review.
- New: the January rehearsal now has a second mode, `CYBERMON_REHEARSE_TINY`
  (see `docs/backlog.md`). Before the review it showed 3 failures in the
  plain mode and 12 in the new one; after, 2 and 3, all documented.
- `tools/site_smoke.py`, `tools/observatory_smoke.py`,
  `tools/make_motion.py --check` — all pass.
- Rendered-text sweep of all 28 pages in a fresh headless browser with every
  `<details>` open: no `{placeholder}`, `undefined`, `NaN` or `null`.

## Statements that were wrong

| Page | Was | Data | Now |
| --- | --- | --- | --- |
| KEV, remediation | "entries added since typically carry two to three weeks" | 2026 median 3 days (p75 14); 21 days in 2022–2025 | "three weeks in 2022–2025 and two weeks or less in 2026" |
| CVE, weaknesses | "cross-site scripting by more than a dozen" (points) | +9.4 points 2017→2025 (9.0 → 18.4); SQL injection +8 | "cross-site scripting rose from about 9% to about 18% … SQL injection from about 1% to about 9%" |
| EPSS Before KEV, percentile methodology | entries without a percentile "appear in the probability charts … their count is in the data file" | every scored entry has a percentile (1,414 = 1,414); no such field | "Every scored entry carries a day-before percentile …" |
| Vulnrichment, section 03 | "other publishers … currently supplier ADPs" | one: Red Hat's supplier ADP, 0.31% of records | "One other publisher clears the bar: Red Hat's supplier ADP …" |
| Vulnrichment, NVD context | a carried-forward backlog figure was labelled "tonight's" | `adp.js` ignored `stale` | the line is dropped when the NVD data is stale |
| AI Credits 02, headline | "similar EPSS, exploit and KEV figures" | lab exploit-corpus rate 0.4% against 1.6% | "Lab-credited CVEs have a higher median CVSS score than all credited CVEs." |
| AI and PoC Timing, 02 methodology | "almost entirely because volume grew" | volume grew 7×; the dated cohort shrank 17× | cause removed; years named (2008–09, 2024) |
| Breach Catalog, leaks | "Email addresses appear in nearly every breach each year" | 2014: 88.9% | "at least 95% of each year's breaches since 2015" |
| CVE, severity | "the per-version lines start earlier"; "v3 scores run higher than v2" | only v3 starts early; medians equal in 2024–25 | fixed |
| EPSS Volatility card, caption, title | percentiles change "for almost every CVE each night" | 83.5% on 09-20 | "on an average night" |
| CNA board caption | "with a hundred times as many scored CVEs" | true today, but a ratio to the top CNA's size | "with thousands of scored CVEs each", guarded |

## Guards that were about to turn the nightly red

| Claim | Margin found | Now |
| --- | --- | --- |
| Advisories: guard required Rust to have the highest no-CVE share | one GitHub Actions advisory (14 of 55) | ranks ecosystems with 1,000+ advisories |
| CNA board "three or four in ten" | SolarWinds 44.0% against a cap of 45 | "more than a third" (two CNAs above 33.3%, top below 50) |
| AI Credits "about half a point" | lab count 257 against a cap of 280 | "half a point or less" |
| AI Credits median EPSS "close to the baseline" | vendor gap 4.5 against 5 | "within ten points of the baseline" |
| AI Credits 06 "each well ahead of the third row" (written 10-03) | three records | "more concentrated by affected product than vendor-credited CVEs" (42.0% vs 26.6%) |
| AI Credits "about four in ten" vendor credits through a person | 44.8% against 48 | "four or five in ten" |
| ATT&CK "grown every year since 2018" | +6 entries, release due late October | "more than tripled since v1.0 in 2018" (697/188) |
| Exploits "just over half" | 54.5%, only moves down | "about half" (40–60) |
| Exploits "rises with severity" | one low-rated record | highest for critical, more than ten times medium |
| Roster "smaller" | one organization | "Nearly all … hold an assigning role" |
| EPSS v5 "same pattern so far" | about three entries | "more than half of its small cohort" |
| Time to PoC "since 2021 … a week or more" | 2021 at 8.0 days | "since 2022 … two weeks or more" |
| CVE card "close to half … each year" | 2026 partial at 54.5 against 56 | "between four and six in ten … since 2020" |
| Malware "six in ten" | guard floor 54 | "more than half" |

## January 2027

Nine guards read a brand-new partial year and would have gone red in the
first week of January; "CVE volume rises every year" would have stayed red
for most of 2027. The 09-08 rehearsal did not see them: it models the
partial year becoming complete, not a new year that has barely started,
and `test_claims_copy.py` ignored the rehearsal variable. All claims suites
now share `pipeline/tests/claims_support.py`; a guard that reads the current
year goes through `judged(year, n, min_n=...)`. Headlines that named 2025
for a chart that moves to 2026 now say "the latest complete year" (weekday,
Patch Tuesday) or name their span (ID age, concentration, severity). The
footer's MITRE copyright years come from the edition's `generated_at`. The
malware caption names the largest non-npm registry for the latest year with
a median month's reports.

## Also fixed

- Guards much looser than their copy were tightened: "Almost every" (Top
  25) from 15 of 25 to 22; "almost all" (CISA ADP) to a 90% share; "a
  handful" (C2) from 60 to 10; "groups … each" (aliases) to two groups;
  "About a third" (incidents) from 25% to 29%; "almost every report" (npm)
  from 85% to 90%; DNSSEC card now says "fully validate".
- Every quantitative home card now has a CLAIMS row quoting the card's own
  text, so the anchor test protects it.
- The hype-race motion clip threw when terms' GDELT month grids differed,
  which happens for a few nights after every rollover; it failed in the
  10-03 nightly. It now ends at the last month every term shares.

## Left as is

- The arXiv half of the risers headline has no rollover grace: a stale
  arXiv lane is an outage and should block.
- Ransom Payments "more than a billion dollars" ($1,018.6M, 1.9% over):
  the dataset has not changed since 07-10.
- The advisories caption's ~400 malware notices rest on GitHub's API
  (23 September), which the export cannot test.
- The calendar's `clamped_negative` guard can trip over the holidays if a
  2027 ID publishes in late December; that is its job.
- Top 25 methodology names the 2025 list's dates; it stays true until the
  2026 list is transcribed by hand.
- Planned trips and the mid-December rehearsal are listed in
  `docs/backlog.md`.
