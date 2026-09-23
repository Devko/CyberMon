# CyberMon content review — 23 September 2026

A content-and-text correctness pass over every page against the committed
edition (`generated_at` 2026-09-23T02:50Z, baseline `d5831a9`), including
the modules and instruments added after the 22 September review (Record
Tags, Incident Clock, Advisory Gap, Registry Malware, the Mutation
Observatory, KEV Changelog flag lag, CVSS 4.0 adoption, the Linux-kernel
toggle). Eight parallel reviewers read the rendered text of every page
(headless, every `<details>` open) and recomputed each number and
quantifier from `site/data`; every finding below was re-verified before it
was acted on. Findings already dispositioned in `docs/review-2026-09-22/`
and `docs/review-2026-09-20/` were not re-reported unless the copy was now
wrong.

## How it was checked

- `python -m pytest pipeline/tests` — 1,627 passed before, **1,642 passed**
  after (1 skipped). New guards: Incident Clock originals, breach password
  trend, extortion 250-fold median, kernel share of the rejection rebound,
  "a level, not a climb", per-kind credits concentration, market moved
  articles (two fetch tests). The quote-anchor guard now also covers
  `test_adp_claims.py` and `test_top25_claims.py`, which it used to skip.
- `tools/site_smoke.py`, `tools/observatory_smoke.py`,
  `tools/make_motion.py --check` — all pass.
- Rendered-text sweep of all pages before and after: no leaked `NaN` /
  `undefined` / `{placeholder}`, no console errors.
- Live checks: EDGAR full-text search (form filter), the MediaWiki API
  (redirects), Wikimedia pageviews, GitHub's advisory API (malicious-package
  advisories), Anthropic's Glasswing pages, Feodo Tracker.

## Wrong numbers or data shown to readers

| Page | Finding | Resolution |
| --- | --- | --- |
| Incident Clock (+ footer) | The Item 1.05 query sent `forms=8-K,8-K/A`; EDGAR answers a comma list with the amendments only. The page printed **0 original filings "from 20 companies"** beside 26 amendments. Probed live: Jan–Feb 2024 gives 3 hits that way, 9 (six originals) with `forms=8-K`, which matches on the root form and returns both. | Fixed: `forms=8-K`; `companies_105` counts filers of originals only; new guard (originals > 0, ≥ amendments). Edition regenerated from EDGAR with the same stamp: **57 originals from 56 companies**, 26 amendments, 74 Item 8.01; median 22 days to a first amendment (19 of 57 amended). |
| Security Market (+ AI Alibi attention) | Three mapped Wikipedia titles are redirects (`Zero_trust_security_model` → Zero trust architecture 2024-11-21, `Software_bill_of_materials` → Software supply chain 2022-05-03, `Agentic_AI` → AI agent 2025-12-18). After a move the Pageviews API counts only redirect traffic, so each lane collapsed at the move — the "Steepest faller: Zero Trust · Wikipedia −44%" card was the rename. | Fixed: `wiki_former` titles are fetched and summed month by month (a request is counted under one title, so nothing is double-counted). The whole curve is refetched nightly, so the next nightly repairs `market_hype.json` and `ai_alibi.json`. SBOM follows its renamed article (judgment call, commented). |
| AI Credits | "Credited most by" counted every tier, including fix-only and org-tier records (Anthropic: CIRCL 63, of which 52 fix-only; OpenAI: JFROG 34, none counted). | Fixed in the builder and the contract; `top_cnas` rebuilt in the committed edition from the committed ledger with the same rule (Anthropic now mozilla 32 · bcorg 30 · apache 23; Orbis shows "—"). |
| AI Credits | Page title "what the CVE record says AI actually found" broke the page's own copy rule. | Fixed. |
| Botnet Weather | Every snapshot since 2026-07-21 reads 5 listed / 1 online; the tracker's files have not changed since March. The page read this as live weather ("online tonight", "not a broken gauge", age "moves with the weather"). | Fixed: data-driven note once ≥ 7 identical snapshots ("a quiet sky or a tracker that has stopped updating; the counts cannot tell which"); stat relabelled "the tracker marks online"; age section says age on the tracker, not time listed. |
| CVE Calendar | "That year names the moment the identifier was reserved" — CVE rules allow the reservation year or the public-disclosure year, and the kernel CNA files years-old fixes under their original year. | Fixed (caption, methodology, Vulnrichment sweep note); negative-age example corrected. |
| CVE Ecosystem | Volume: "the apparent dip at the right edge" (2026 is 44% above 2025). Hero: "About half of **all** CVEs" (it is scored CVEs). CNA board: "same spec — the gap is scoring policy" (mixed v4/v3, causal). | Fixed; guards re-anchored; methodology states the newest-version rule and "scored CVEs". |
| Security Products | "Pulse Secure entries predate Ivanti's acquisition and keep that label" — CISA relabelled 8 of 9 as Ivanti. | Fixed (copy and `guards_metrics.py` docstring). |
| AI Alibi | GPT-4 withheld note said "after 2022" (the post window starts 2024); "where the two lines part company … old exploits" (true only before ~2014); "three percent of the chart" (a fifth); Glasswing "in a month" (since the 7 April launch, ~six weeks; the 1,752 assessed are Anthropic's own scan). | Fixed; timeline rows and the claim note corrected at source and in the committed editions. |
| Breach Ledger | "BreachDate is self-reported and usually rounded to the first" (17% fall on the 1st; it is HIBP's estimate); "seven opening-import entries predate the service" (six do); "passwords included, swings" (passwords fall every year since 2019). | Fixed; password trend guarded. |
| Home / meta | "twenty-two modules" (26); noscript list missed Record Tags, Incident Clock and the Observatory; concentration card ("vendors", "reservations"); ATT&CK "grows every release" (22 of 40 releases added nothing); hygiene "still not deployed" (38.7% validate); epssvol "the record starts now". | Fixed (cards, page titles, README). |
| Observatory | The empty-trail sentence was false for CVEs whose only EPSS events fall on quarantined nights (CVE-2016-3251, the log's most frequent top mover). | Fixed; methodology now states EPSS dating (FIRST score date), pooled post-gap runs, weekly archive captures, legacy version labels; plurals. |

## Misleading, stale or code-text mismatches (all fixed)

Advisory Gap severity headline now says many no-CVE Criticals are
malicious-package notices (≈400 by GitHub's API, 367 of them npm 2020; set
aside, the no-CVE set is rated Critical less often). Record Tags: "More CVEs
are *tagged as* issued …", "second lags the corpus", "mostly by one CNA",
top-12 cap stated, row weighting described correctly. Registry Malware:
"open-source malware log", "report log", log-view and unattributed notes.
Time to PoC: provisional-year note, "by day 7" tooltip, "more often than
not", "more than ten times" (guard ≥ 10), partial-year asterisk. Naming,
Top 25, ATT&CK v7.0 date disclosed. Vulnrichment: SSVC decision points,
the CVE Program Container, supplier ADPs. Concentration: HHI is quoted, not
drawn; "year's records"; entrants claim made durable. Rescores: board line
states the 90 rescores behind it; bucket edge; true minus sign. Roster:
rename note. KEV: current-year latency clause, remediation units,
ransomware lower bounds. KEV Changelog: 438 vs 437.5, column-capture date,
flip stat description, receipts include the 2023 step. EPSS: comparator
labelled "all model eras pooled"; page title "the day before a KEV
listing". EPSS Volatility: cache (not committed state), clean-night count
and quarantine rule on the movers board, stale launch caption. CVE page:
Linux-toggle note, kernel share of the rejection rebound (guarded), quality
"all three fields" and the kernel's missing scores, CWE fixed-top-eight,
CVSS 4.0 adopters and band moves, throughput series list, decay log axis,
meta description. Industry: market failure behaviour and Wikipedia gaps,
extortion dust medians and "every total", footer "ledger entries", HIBP
catalog wording. AI Credits tier wording (system tier includes bare vendor
names), per-kind board headline, "than its models are". Carousel sources
for ai / exploits / top25; load-error text; Field score-rule and crossings
notes.

## Left open (in `docs/backlog.md`)

- Charts that still close up missed nights on a category axis: CNA roster
  size, EPSS Volatility gap, NVD backlog history, the Observatory stream.
- Pipeline: tag malicious-package GHSA advisories (so the Advisory Gap
  malware share is measured and guarded); a fetch-time MediaWiki redirect
  check; capture Feodo's last-updated stamp; label pooled KEV/rescore runs
  and restamp EPSS events to the run date in the Observatory; drop
  quarantined nights from the Field's crossing count; exclude the 2023
  ransomware step from KEV receipt edit counts and extend its cut through
  ties; ID age from `dateReserved`.
- Owner's voice, deliberately untouched: "CVE severity has become
  meaningless", "the scorekeeper walked off / stopped keeping score",
  "Nobody publishes the curve", "nobody can spin", the EPSS "grade"
  vocabulary, "every edit … field by field", nine page titles without the
  module name.
- Guards that will trip on purpose: credits lab ceiling (~November),
  vendor exploit-corpus gap (~2–3 months), crates.io vs GitHub Actions
  no-CVE lead (thin margin), CVE concentration "reversed" (January 2027).

## Plain-language pass (same day)

The owner asked for the wording to be fixed with no AI slop. The copy rule
the AI Credits page already followed (state what was measured, not why; no
metaphors) now applies site-wide. Every section, the landing page, the
footer, the carousel and motion copy, the Observatory and Field text, every
page's `<title>`/meta tags and the README taglines were rewritten by eight
editors working from the style guide in the session notes, each on a
private copy of `editorial.js` whose blocks were spliced back.

- Removed: metaphors (receipts, homework, referee/scorekeeper,
  weather/forecast/postcard, flood, product line, vintage, landmine, dust,
  roomful, top shelf), slogan and two-sentence headlines, rhetorical
  questions, "honest/deliberately/quietly/nobody" signposting, unmeasured
  causes, and most em-dash chains. Rendered-text counts: em dashes
  855 → 205, "honest*" 12 → 0, "deliberately" 21 → 1, "nobody" 13 → 0,
  "receipts" 63 → 0, rhetorical questions 8 → 0.
- Headlines are now one plain sentence stating the measured finding; every
  new quantitative headline is guarded (`test_claims_copy.py`, 29 checks)
  and 60+ existing guard quotes were re-anchored.
- The rewrite corrected facts on the way: throughput rows *sum* on a same-day
  re-run (the copy said "last run wins"); "any year before it" (2023 had more
  newcomers than 2024–25); Tuesday is the busiest weekday only since 2022;
  Glasswing's launch partners are eleven besides Anthropic; the Observatory
  methodology no longer contradicts itself on dating.
- Titles now follow "CyberMon — <Module>: <finding>" on every module page.
- Kept on purpose: module names (Botnet Weather, The AI Alibi, Naming
  Chaos), short contrasts that prevent a specific misreading ("the filing
  date, not the incident date"), and MITRE's required attribution text.

## Module names (same day)

Fourteen module names and three nav groups were renamed where the name was
a metaphor or described something the module does not measure (e.g.
"Security Market" charts buzzword attention, not market data; "Hygiene
Index" is not an index). The mapping is in `docs/backlog.md`. Twelve names
already said what the module measures and stayed: CVE Ecosystem, KEV
Latency, CNA Concentration, CVE Calendar, KEV Changelog, CWE Top 25,
Vulnrichment (CISA's program name), EPSS Volatility, CNA Roster, Time to
PoC, AI Credits, Record Tags. Page files and ids are unchanged, so links
keep working.

## What moves in the published data

Regenerated here with the edition's own stamp: `sec_incidents.json` and
`meta.sources.sec_incidents` (live EDGAR, filings dated before the edition
day). Edited in place from committed sources: `ai_credits.json`
(`top_cnas` from the ledger; one claim note), `ai_alibi.json` (three
timeline labels and notes). The market fix lands with the next nightly.
