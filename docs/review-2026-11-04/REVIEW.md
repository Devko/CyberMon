# CyberMon content and Field review — 4 November 2026

The owner asked for a review of all content and of the Field's display,
with everything improved and AI slop removed. Baseline: `a99808f`, the
2026-11-04 nightly edition. Seven reviewers each took a set of pages
(every `editorial.sections` key, the landing page and frame, page heads,
the Observatory, motion and carousel copy) in separate worktrees. They
worked from the style rule of the 23 September plain-language pass and
checked every number and quantifier against `site/data`. The README had a
pass of its own. The Field display review is in [FIELD.md](FIELD.md).

## How it was checked

- `python -m pytest pipeline/tests`: 1,875 passed before, **1,888 passed**
  after.
- January rehearsals (`CYBERMON_REHEARSE_YEAR=2027`, plain / `TINY=low` /
  `TINY=high`). Before, `check_unscored_is_kernel` failed in all three
  modes and would have turned the nightly red in the first week of
  January. After, the only failure is the documented
  `check_last_verified_payment_quarter` noise in the two TINY modes.
- `tools/claims_history.py` over the last 14 to 45 editions (each reviewer
  for their own guards). Every new or re-anchored guard also holds on
  earlier nightlies.
- Passing: `tools/site_smoke.py` (28 pages), `tools/observatory_smoke.py`,
  `tools/make_motion.py --check`, and `tools/field_smoke.py` against both
  the fixture and an assembled copy with the live 400,091-record Field.
- Rendered-text sweep of all 28 pages, every `<details>` open: no
  `{placeholder}`, `undefined`, `NaN` or `null`. Words 53,370 → 48,644;
  "CyberMon's own" 13 → 0; ", not " contrasts 76 → 65. Within each
  reviewer's own copy keys, words fell by 7% to 24% (30,400 → 25,488 in all, as each reviewer counted them).

## Statements that were wrong

| Page | Was | Data | Now |
| --- | --- | --- | --- |
| The Field, CVSS × EPSS grid | "no diagonal is expected" | CVE page: the ≥10% EPSS share rises about twentyfold from Low to Critical | each axis described, no relationship claimed |
| CVE, severity counts | "Critical count for 2026 passed four thousand" | 10,041 against 4,111 in 2025 | "passed double the 2025 count" (guarded) |
| CVE, volume | rejections "under two percent in 2023, then rose" | 0.48%, then 0.87% and 0.65% | "under one percent … higher in 2024 and 2025" |
| CVE, NVD backlog | log axis because Modified is "more than an order of magnitude" larger than the queue | 15.6×; the queue grew 2,242 → 15,711 since July | the axis's purpose is stated without the ratio |
| CVE, NVD throughput | waits timed from first sighting "in the queue" | code times from Awaiting Analysis | corrected; headline is now a finding: NVD deferred 44.6% of queue exits (guarded) |
| CVE, unscored records | "nearly every" unscored record is the kernel's | 87% in 2026; failed the January rehearsal | "most" |
| cve.html `<title>` | "close to half … each year" | 41.6–54.0% over 2020–26 | matches the guarded card |
| KEV Latency, buckets | "Nearly four in ten KEV listings come within a week" | the buckets hold only 2023+ listings (901 of 1,767) | "Since 2023, …" (guard checks the cohort) |
| EPSS Before KEV | "Roughly half or more of recent KEV additions" | 2026: 105 of 283 (37%) of all additions; since 2023, 380 of 645 scored (58.9%) | "More than half of scored KEV additions since 2023 …" (page, card, title) |
| Security Products in KEV | "A gap of 0 means CISA added two or more … on the same day" | it is a median | "at least half of the vendor's listings came on the same day as its previous one" |
| Security Products in KEV | "Zoho ManageEngine stays unclassified" | excluded entirely | "is not counted" |
| CVSS Score Changes | every rescore compares "the same exact CVSS version" | 86 of 148 rescores logged before 2026-09-20 stored the family only | exact version since 09-20, family before, and what that changed (guarded) |
| Vulnrichment | "about half" (hero and home card) | 52.9%, rising 1–2 points a month toward the 55% guard bound | "more than half" (one guard for both) |
| Vulnrichment | CVSS and CWE added "mostly where the CNA left the field blank" | never measured | "about a fifth each" (21.6%, 20.3%) |
| AI Credits 02 | "higher median CVSS score" | 7.5 vs 6.9 against a +0.5 floor, falling | "rated high or critical more often" (55.9% vs 42.3%) |
| AI Credits 04 | OpenAI named "several times more" than its models | 161 against a 3× line of 147 | "named without a model on most of the records" (112 of 161) |
| AI Credits 05 | "several times the baseline share" | ×3.4 against a ×2.5 floor; new lab CVEs ~11% memory safety | "more than twice" |
| Advisories Without a CVE | "About one in twelve" | 7.99% against a 7.69 floor, falling ~0.1 point a month | "Fewer than one … in ten" (6.25–10% guard) |
| EPSS Volatility | crossings "fewer than one for every hundred" percentile changes | 1 in 5,800 | "fewer than one for every thousand" (guard tightened 1% → 0.1%) |
| AI and PoC Timing | hollow years "read slow"; module named "Security Market" | right-censoring makes them read fast; renamed in September | dropped; "Buzzword Attention" |
| AI and PoC Timing | no-uplift sources "two of the largest" vendor teams | unmeasured | named (Microsoft with OpenAI, Feb 2024; Google GTIG, Jan 2025) |
| AI timeline (Glasswing) | "any effect on exploitation speed" | the page measures public exploit code | "whether public exploit code has appeared sooner" (source and edition) |
| Time to PoC | a Nuclei "detection line" | the chart has none | corrected |
| Breach Catalog | passwords "a lower share every year since 2019"; "every year since 2014 … tens of millions" | a partial 2027 can break both | "each complete year" (guards now cover every complete year) |
| DNSSEC | "until the record is ten years long" | 13 years long | cut |
| SEC Incident Filings | "bars count … per month" | the chart also has a quarterly view | fixed |
| Buzzword Attention card/title | "each buzzword … in five sources" | CNAPP has no Wikipedia series | "security buzzwords" |
| Motion clips | "CVEs rated Critical went from a handful"; five largest "still" issue about half | pre-2018 scores sat in NVD; the share fell from 100% | "CVE records carrying a Critical score"; "still" removed |
| Observatory | old module name "Silent Rescores" | renamed in September | "CVSS Score Changes" |

## Guards that were close to tripping

Reworded so the copy states a measured value with margin. No guard was
widened.

| Claim | Margin found | Expected trip | Now |
| --- | --- | --- | --- |
| Vulnrichment "about half" | 52.9% vs 55 | December | "more than half" (50–66.7%) |
| Advisories "one in twelve" | 7.99% vs 7.69 | December | "fewer than one in ten" |
| AI Credits "higher median CVSS" | 7.5 vs 6.9 + 0.5 | next medium-severity batch | high/critical share (≥ 5 points) |
| AI Credits "several times more" | 161 vs 147 | weeks | most records name no model |
| AI Credits "top five about a quarter" | 31.0% vs 33 | weeks | cut (the chart prints the share) |
| AI Credits card "hundreds each" | vendors 630, +85/month | March 2027 | largest announcement exceeds all credited records (10,000 vs 995) |
| `test_claim_reading_is_fresh` | AISLE and ZeroPath read 09-20, 45-day limit | **2026-11-05** | both re-read 11-04 (AISLE 400 → 528, ZeroPath 13) |
| `check_unscored_is_kernel` | January rehearsal | January 2027 | judged years only; copy says "most" |

## Slop removed

Kinds, in order of frequency: captions that restated the headline (about
30); caveats repeated across caption, note, stat note and methodology
(more than 60 removals; e.g. the KEV seeding-era reason three times, the
throughput lower bound four times, "no accreditation dates" five times);
signposting ("Section 04 counts the queue; this section counts the
changes", "see the methodology", "this note will change"); self-reference
("CyberMon's own" 13 → 0); hedge stacks (the EPSS Before KEV caveats went
from six to one); unmeasured causes and arguments; vague intensifiers
("sharply", "far", "very uneven", "a wide margin"); idioms and colon
reveals; sentences over 40 words split. Jargon is defined once
per page where first used (CNA, CVSS, KEV, EPSS, NVD, ADP, IQR, HHI, CWE,
BOD 22-01, UTM, CIK, cs.CR).

Seven headlines that described the method now state a guarded finding
(NVD throughput, C2 history, C2 age, ATT&CK catalogs, ransom payments,
CNA Roster card, C2 card). The 09-23 "owner's voice" items had mostly gone
already; "arithmetic, not a forecast" became "They are not a forecast", and
no EPSS "grade" wording is left in rendered copy (the `grade` key stays).

## README

Rewritten to the same rule (7,017 → 6,835 words; about 600 cut, with
missing developer detail added). Every module tagline now equals its
landing-page headline verbatim (12 were stale), and the opening slogans
are gone ("grades its own homework … keeps the receipts", "Provocative
headline"). Corrections:

- The CWE Top 25 score is NVD frequency × average CVSS; KEV is not an input.
- Time to PoC: the median gap was within a month of zero through 2020 and
  has been positive since 2021; it did not "hug zero".
- The EPSS Volatility quarantine rule includes the 5% floor.
- The history logs are not all unrecoverable: cvelistV5 and the roster's
  upstream repository keep git history. Start dates and paths are now given.
- The roster size, the Observatory file size and event count, and the
  Exploit-DB coverage figures were updated. The 08:43 UTC catch-up run,
  the claims gate, the NVD full-sweep fallback and the missing sources were
  added to the architecture notes.
- `tools/make_sample_data.py` overwrites committed `site/data` files with
  synthetic data. The README called it a way to "regenerate the committed
  sample data"; it now warns against running it in a checkout you commit
  from. The tool itself is unchanged (left open).

## Maintenance done on the way

- `pipeline/ai_credits_data.py`: AISLE and ZeroPath counters re-read.
- `pipeline/ai_timeline_data.py` and the committed `ai_alibi.json`:
  Glasswing note scoped to public exploit code.
- `pipeline/nvd_throughput.py`: the docstring said "last run per date
  wins"; `merge_row` adds same-date rows.

## Follow-up (same day)

The owner asked for the items left open to be fixed as well.

- **Strings outside `editorial.js`.** 150 strings moved: 137 chart labels
  (series and axis names, tooltip phrases) into `sections.<id>.labels`
  blocks across 55 sections; 9 shared strings into a new `ui` block; and
  the 55 hard-coded "Not enough data yet." lines now read
  `ed.nodata || editorial.ui.nodata`. The motion clip reads its band
  names from the flood chart's labels, so the two cannot drift. The
  header now states exactly what lives in `editorial.js` and what stays
  in code (internal ids, bare units, number formatting, proper names,
  developer messages, the two instruments). No wording changed. Every
  page, carousel slide and clip rendered identically before and after,
  tooltips included.
- **Claims due to fail, reworded with margin.**
  - Advisories: "About one Rust advisory in four" → Rust lacks a CVE id
    more often than any other large registry (1,000+ advisories).
  - SEC incidents: "About a third … amended" → "More than one in four"
    (19 of 59; holds to 76 originals with no new amendment).
  - AI Credits hero: "credit each kind with hundreds" → the largest
    announcement exceeds all credited records combined (10,000 vs 995).
    "The AI columns are small:" cut from the methodology.
  - The C2 flat note no longer repeats the start date.
- **Buzzword Attention headlines are findings:**
  - Hero, home card and `<title>`: "Most tracked buzzwords had their
    busiest month of news coverage more than two years ago." (10 of 14
    terms on every edition since 09-23.)
  - Divergence: "More terms sit above the diagonal, with research nearer
    its five-year peak than news coverage, than below it." (Above has led
    below by two or more every night since 09-23.)
- **Alias Graph draft:** title, meta and theses rewritten. Its body grid
  now lays out without a toolbar row.
- **`tools/make_sample_data.py`** requires `--out` and refuses
  `site/data`.
- **The Field:** a sortable records table (see FIELD.md).
- **Carousels:** the deploy of `7b709fc` rebuilt them with the new
  headlines.

## Left open

- `site/alias.html` loads a `js/alias.js` that is not in the repo
  (backlog). The page shows its header and controls but no graph.
- The C2 median-age guard fails if the tracker starts listing new
  servers. That is a change in the world, and the copy should change then.
- The ransomware flag's "often more than a year later" (60 of 111 flips,
  floor a third) drifts down as recent listings flip faster (2026
  listing-year median 34 days). It has wide margin today.
- The nightly workflow's "CANNOT be regenerated" comments stand: they
  describe the files, which exist only in this repository, even where an
  upstream git history holds the raw edits.
