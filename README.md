# CyberMon

CyberMon measures the security industry's public records and publishes the
method behind every number. It covers scoring systems, institutions and the
market rather than individual vulnerabilities. Everything is rebuilt nightly
from open data by the pipeline in this repo.

**Live site:** https://devko.github.io/CyberMon/

Every chart has a caption and an expandable "How this is computed" note that
links to the pipeline source.

## Modules

Each module is its own page with its own pipeline stage and
[data contracts](docs/data-contracts.md). The landing page
([index.html](site/index.html)) lists the modules in the same four groups as
the site nav (CVE records, Exploitation, Industry, Threats); both are built
from the `group` tags in `site/js/editorial.js`. The italic line under each
heading is the module's headline on the landing page.

### 01 · CVE Ecosystem — [cve.html](https://devko.github.io/CyberMon/cve.html)

*Between four and six in ten scored CVEs have been rated High or Critical each year since 2020.*

Ten charts from the cvelistV5 corpus, joined to EPSS, KEV and NVD where named:

1. **CVSS scores by year** — median and IQR of CNA-assigned CVSS base
   scores per year, one line per CVSS version (v2/v3/v4), because each
   version computes the score with its own formula.
2. **Severity by year** — published CVEs per year by severity bucket.
3. **Severity vs. exploitation** — a CVSS × EPSS grid, plus KEV entries by
   CVSS bucket.
4. **NVD backlog** — every CVE by its current NVD status, plus CyberMon's
   nightly snapshots of the queue (NVD publishes no backlog history).
5. **NVD throughput** — daily status changes from diffing nightly per-CVE
   NVD snapshots: CVEs received, and CVEs leaving the analysis queue as
   Analyzed or Deferred, with the observed queue wait (a lower bound).
6. **Scores by CNA** — CNAs ranked by the share of their own scores at 9.0
   or above, with average and median (at least 100 scored CVEs in a 3-year
   window).
7. **CVE volume** — CVEs published and rejected per year.
8. **Record completeness** — the share of each year's records missing a
   CWE, a CVSS score or usable affected-version data, checked against the
   record itself.
9. **Weakness classes** — the eight most common weakness classes of the last
   ten complete years, as shares of each year's CWE-tagged records.
10. **CVSS 4.0 adoption** — each month's new records by the CVSS versions
    their CNA scored (v4.0 only / v3.x and v4.0 / v3.x only / neither; ADP
    scores not counted), the largest v4.0 adopters, and the v4.0 − v3.x
    difference on records scored in both.

CVE volume and Severity by year have a **Linux-kernel toggle**. The kernel
CNA (assigner `Linux`, a CNA since 2024) publishes thousands of records a
year, so both charts ship a `without_linux` variant with its own pace
projection. Medians cannot be split this way, so the other charts keep all
records.

Stages: `pipeline/metrics.py` (the shared streaming pass over the corpus
that later modules reuse), `quality_metrics.py`, `nvd_throughput.py`,
`cvss_v4_metrics.py`.

### 02 · Buzzword Attention — [market.html](https://devko.github.io/CyberMon/market.html)

*Attention to security buzzwords is tracked monthly in five public sources.*

Monthly counts for 14 curated terms from GDELT (news articles), Hacker News
(stories and comments), arXiv cs.CR (papers), Wikipedia (pageviews of one
curated article per term) and SEC EDGAR full-text search (filings). Each
source's series for a term is indexed to its own five-year peak. Charts:
attention curves, year-over-year risers and fallers, and a research-vs-news
quadrant (arXiv against GDELT). Terms and their Wikipedia articles are in
`pipeline/market_terms.py`. Fetcher `pipeline/fetch_market.py`, stage
`pipeline/market_metrics.py`.

### 03 · KEV Latency — [kev.html](https://devko.github.io/CyberMon/kev.html)

*Most KEV entries were listed a week or more after their CVE was published.*

Four charts on CISA's Known Exploited Vulnerabilities (KEV) catalog: days from
CVE publication to KEV listing (median/IQR per listing year, and in buckets),
remediation-deadline spans, and the share of each year's listings flagged for
known ransomware use. Listings from the 2021–22 seeding era are kept out of
the latency trend and summarized separately; the deadline and ransomware
charts include them. Negative latencies (listed before the CVE record was
published) are kept. Stage `pipeline/kev_metrics.py`.

### 04 · CNA Concentration — [concentration.html](https://devko.github.io/CyberMon/concentration.html)

*Hundreds of CNAs assign CVEs; since 2021 the five largest have issued about half.*

Active CNAs per year against the top-5 and top-10 share of published records,
new CNAs per year, and a rejection-rate board. The Herfindahl–Hirschman Index
(HHI) is in the data file and quoted, not drawn. The trend chart has the
Linux-kernel toggle (shares and HHI recomputed without the kernel CNA). Stage
`pipeline/concentration_metrics.py`.

### 05 · Breach Catalog — [breaches.html](https://devko.github.io/CyberMon/breaches.html)

*Breaches typically reach Have I Been Pwned months after their recorded breach date.*

Three charts over the Have I Been Pwned (HIBP) breach catalog:

- days from the breach date to HIBP's listing, median/IQR per catalog year,
  with the December 2013 launch import kept out of the trend;
- breaches and accounts per year, with a pace projection for the partial year;
- the share of each year's breaches that include the six most common data
  classes.

Fabricated entries, spam lists, malware corpora and stealer logs are
excluded, and the data file counts each exclusion. Stage
`pipeline/breach_metrics.py`.

### 06 · Ransom Payments — [extortion.html](https://devko.github.io/CyberMon/extortion.html)

*Ransomware payments recorded by Ransomwhere total more than a billion dollars.*

Three charts from the Ransomwhere dataset (crowdsourced addresses, with
payments verified on the blockchain): revenue per quarter in dollars at the
day of transfer, payment counts and median payment per year, and revenue by
ransomware family. Revenue with no family label is reported beside the board,
not ranked. A payment counts only after someone reported the receiving
address, so every figure is a lower bound. Stage
`pipeline/extortion_metrics.py`.

### 07 · ATT&CK Releases — [attack.html](https://devko.github.io/CyberMon/attack.html)

*Active ATT&CK techniques and sub-techniques have more than tripled since v1.0 in 2018.*

Three charts from MITRE's versioned enterprise STIX bundles: active
techniques and sub-techniques per release (on the release dates in MITRE's
`index.json`), what each release added, deprecated or revoked (compared by
STIX id), and active groups and software. Released bundles never change, so
each version's stats are computed once and cached; a normal night fetches
only `index.json`. Stage `pipeline/attack_metrics.py`, fetcher
`pipeline/fetch_attack.py`.

### 08 · DNSSEC Validation — [hygiene.html](https://devko.github.io/CyberMon/hygiene.html)

*About four in ten internet users sit behind resolvers that fully validate DNSSEC.*

Three charts from APNIC Labs' DNSSEC measurement: the world rate since 2013,
the ten economies with the most internet users, and the distribution across
every measured economy, each counted once. The ten are a fixed list, chosen
by APNIC's user weighting in July 2026. APNIC publishes its full daily history,
so the stage refetches it every night and keeps no state. Stage
`pipeline/hygiene_metrics.py`.

### 09 · Security Products in KEV — [guards.html](https://devko.github.io/CyberMon/guards.html)

*More than one in nine KEV entries is in a security product.*

Every KEV entry is classified by a curated, versioned table of security
products ([pipeline/security_products.py](pipeline/security_products.py),
which documents the rule and each judgment call; the output carries the
classifier version). Three charts:

- the security-product share of each year's listings, seeding era included,
  since the classification belongs to the entry;
- vendors with at least five KEV entries, with their first and last listing
  and the median gap between listings;
- the ransomware-flag rate for security products against the rest of the
  catalog.

It reads the KEV feed the pipeline already fetches. Stage
`pipeline/guards_metrics.py`.

### 10 · EPSS Before KEV — [epss.html](https://devko.github.io/CyberMon/epss.html)

*More than half of scored KEV additions since 2023 had an EPSS score under 1% the day before listing.*

For every CVE in KEV, the EPSS score FIRST published the day before the
listing. Three charts: probability bands (under 1% / 1–10% / 10%+) per
listing year, the distribution by EPSS model version (v1–v5 are different
models and are never pooled), and percentiles, which compare across
versions. KEV gives no exploitation date, so this cannot test the 30-day
forecast or its calibration. Entries listed on or before their CVE's
publication day have no prior score and are counted separately.

Historical scores do not change, so each (CVE, listing date) pair is fetched
from FIRST's API once; a normal night makes 1–2 requests.
`--epss-backfill-batch` (default 30 lookups per run) caps the one-time
historical backfill so CI cannot run it. Fetcher
`pipeline/fetch_epss_history.py`, stage `pipeline/epss_report_metrics.py`.

### 11 · CVE Calendar — [calendar.html](https://devko.github.io/CyberMon/calendar.html)

*Since 2022, more CVEs have been published on Tuesday than on any other day.*

Three charts on publication timing from the cvelistV5 corpus, all dates in UTC:

1. **ID age** — per publication year, the share of records whose CVE ID
   carries the same year, the year before, or an earlier year.
2. **Weekday pattern** — publication by weekday, the latest complete year
   against the year a decade before.
3. **Patch Tuesday** — the share of each year's records published on the
   twelve second Tuesdays, against the 3.3% an even spread would give and
   against the year's ordinary Tuesdays.

Stage `pipeline/calendar_metrics.py`.

### 12 · KEV Changelog — [changelog.html](https://devko.github.io/CyberMon/changelog.html)

*CISA changes KEV entries after listing them, including due dates and ransomware flags.*

Four views of CyberMon's diff record of the KEV catalog:

- edits per month by kind: due-date moves, ransomware-flag changes, text
  revisions and removals (additions are logged but not charted);
- cumulative Unknown→Known ransomware-flag flips;
- days from `dateAdded` to each flip, by dating granularity and listing
  year, with capture-dated lags as upper bounds and the December 2023 step
  (the first capture carrying the flag column) left out;
- the most-edited entries, plus every entry observed leaving the catalog.

Each nightly run fingerprints the catalog (tracked fields verbatim, free-text
fields as short hashes), diffs it against the committed state
`site/data/history/kev_state.json`, and appends events to
`site/data/history/kev_changelog.csv`. Events before 2026-07-11 come from a
one-time backfill from Internet Archive captures (`--kev-changelog-backfill
N`, cached in `.cache/kev_wayback/`; CI never runs it). Backfilled events
carry `granularity: "capture"` and are dated to the first capture showing the
change; nightly events carry `"daily"`. Stage `pipeline/kev_changelog.py`.

### 13 · CVSS Score Changes — [rescores.html](https://devko.github.io/CyberMon/rescores.html)

*CNAs change CVSS scores on published CVE records, mostly by adding a missing score.*

Each night the pipeline fingerprints every published CVE's CNA-assigned base
score (read the same way as the CVSS scores chart) and diffs it against the
previous night's state, `site/data/history/rescore_state.json`. The state is
committed beside the log so the two cannot drift apart. Changes append to
`site/data/history/rescore_log.csv` as one of four types:

- `rescore`: same CVSS version, new score (the only type with a direction);
- `version_shift`: a different CVSS version, never charted as a score change;
- `first_score`: a first score on an existing record;
- `score_removed`.

Three charts: edits per week, the size of rescores (drawn once 30 are
logged), and CNAs by rescore count. The cvelistV5 git history holds the raw
edits; this log starts on 2026-07-15. A lost state rebuilds from that night's
corpus, so that night logs nothing. A re-run on the same corpus release is
detected and not counted twice. Stage `pipeline/rescore_tracker.py`.

### 14 · Threat Group Aliases — [naming.html](https://devko.github.io/CyberMon/naming.html)

*The ATT&CK groups with the most aliases carry more than a dozen other names each.*

Two charts over the active groups (intrusion sets) in MITRE's current
enterprise ATT&CK bundle: the groups with the most alternate names (aliases
other than the canonical name: APT28 is also Fancy Bear, Forest Blizzard,
Sofacy and STRONTIUM), and the distribution of alias counts. The alias list
is MITRE's curation, so the counts are a lower bound. Only the latest release
is read. The stage makes its own `index.json` request each night and
downloads the bundle only when a new release appears. Aliases per release is
a follow-up in [docs/backlog.md](docs/backlog.md). Stage
`pipeline/naming_metrics.py`, reusing the fetch code in `fetch_attack.py`.

### 15 · CWE Top 25 — [top25.html](https://devko.github.io/CyberMon/top25.html)

*Most of MITRE's CWE Top 25 also rank among the 25 most frequent weaknesses in CVEs.*

Two charts set MITRE's annual CWE Top 25 against the corpus. The lists are
copied by hand from cwe.mitre.org into `pipeline/cwe_top25_data.py` (2023,
2024 and 2025; the newest is compared). The first chart pairs each class's
official rank with its rank by first-listed-CWE frequency over the last five
complete calendar years; an official class can rank anywhere or not appear.
The second counts KEV entries per official class. MITRE ranks by a class's
frequency among NVD CVEs in one year multiplied by their average CVSS score,
and KEV is not an input, so the two ranks measure different things. Both
charts read the shared corpus pass (`agg.cwe_year_counts`,
`agg.kev_cwe_counts`). Stage `pipeline/top25_metrics.py`.

### 16 · Vulnrichment — [adp.html](https://devko.github.io/CyberMon/adp.html)

*CISA's Vulnrichment program has added data to more than half of all published CVEs.*

CISA writes Vulnrichment data into CVE records through an Authorized Data
Publisher (ADP) container, `CISA-ADP`. Three charts over the
`containers.adp[]` blocks the corpus pass already parses (no new fetch):

- enriched records per month, by the CISA-ADP container's own `dateUpdated`,
  not the CVE's publication date, because CISA back-fills old records. A
  month with at least 50 enrichments is flagged as back-fill when at least
  half went to CVEs whose ID year is two or more years earlier;
- the share of CISA-ADP records carrying SSVC decision points (nearly all),
  a CVSS score, or a CWE (about a fifth each);
- ADP publishers by records enriched. CISA-ADP does almost all of it; Red
  Hat's supplier ADP (`redhat-SADP`) adds data to well under 1% of records,
  and the CVE Program Container adds only references.

CyberMon's NVD history starts in July 2026, so there is no 2024 NVD series to
draw beside these. The page quotes the current NVD backlog from
`nvd_decay.json` and leaves it out when that file was carried forward. Stage
`pipeline/adp_metrics.py`.

### 17 · EPSS Volatility — [epssvol.html](https://devko.github.io/CyberMon/epssvol.html)

*On an average night, EPSS percentiles change for nearly all CVEs and probabilities for about 1%.*

Each night the pipeline fingerprints the EPSS feed it already fetches (each
CVE's probability and percentile) and diffs it against the previous night's.
One row per snapshot appends to `site/data/history/epss_volatility.csv`: how
many compared CVEs had their percentile and their probability change, how
many crossed 0.1%, 1% and 5%, and the night's largest probability change.
Three charts: percentile vs. probability changes, weekly threshold crossings,
and the largest single-night changes.

Three kinds of night are excluded from every chart and listed with their
reason in the data file:

- model-version changes, when a new model rescores every CVE;
- pooled nights, whose diff spans more than one snapshot after failed runs;
- anomalies, when the share of probabilities that moved is more than five
  times the clean-night median and over 5%, with no model change.

FIRST archives its daily score files but publishes no per-CVE change log;
this log starts on 2026-07-18. EPSS Before KEV (module 10) shows where scores
stood before a listing; this module measures how often they change. Neither
measures accuracy. Stage `pipeline/epss_volatility.py`.

### 18 · CNA Roster — [roster.html](https://devko.github.io/CyberMon/roster.html)

*Organizations joining the CVE roster have outnumbered those leaving since July 2026.*

The CVE Program publishes its current partner list (`CNAsList.json`, the data
behind cve.org's List of Partners) with no join dates. CyberMon snapshots it
nightly. Joins, departures, renames and scope changes append to
`site/data/history/cna_roster.csv`, and the nightly roster size to
`site/data/history/cna_roster_state.json`. The roster file's git history
(CVEProject/cve-website) holds earlier edits, which the log has not imported.

Three charts: roster size over time and joins vs. departures per month (both
from the log, which starts on 2026-07-18), and the current roster by type,
top-level root (MITRE or CISA), reporting root and country. A join is dated
to the first snapshot that shows it, since the program publishes no
accreditation date. State and log are written only after every output
validates, in the same nightly commit. Fetcher `pipeline/fetch_cna_roster.py`,
stage `pipeline/cna_roster.py`.

### 19 · Time to PoC — [exploits.html](https://devko.github.io/CyberMon/exploits.html)

*Since 2022 the median public exploit has appeared two weeks or more after the CVE.*

Three charts joining public exploit trackers to the CVE corpus:

- days from CVE publication to the first dated public exploit, median/IQR
  per publication year, negative gaps kept;
- the share of KEV listings whose exploit code was public before the
  listing, with the 2021–22 seeding era shown apart;
- the share of each CVSS bucket with public exploit code in the latest
  complete year.

Sources:

- Exploit-DB's index CSV: `date_published` is the only date the clock uses.
- Metasploit's `modules_metadata_base.json`: the module `type` decides what
  counts as exploit code. `disclosure_date` is the vulnerability's
  disclosure, not the module's, so it never dates the clock.
- Nuclei's CVE template index: detection checks with no dates, counted
  separately in the severity chart's tooltip.

All three publish their full history, so the stage refetches them every night
and keeps no state (`pipeline/fetch_poc.py`, cached per UTC day in
`.cache/poc/`). Stage `pipeline/poc_metrics.py`.

### 20 · Botnet C2 Servers — [c2.html](https://devko.github.io/CyberMon/c2.html)

*Feodo Tracker's botnet C2 blocklist holds a handful of servers.*

abuse.ch's Feodo Tracker publishes only its current botnet C2 blocklist.
Each night CyberMon appends per-family counts (listed and online) to
`site/data/history/botnet_c2.csv`. Three charts: C2 servers over time by
family; tonight's list by family, hosting country and network; and how long
ago the tracker first saw each listed server. Low or zero counts are normal
(the tracker's FAQ attributes its empty periods to the Emotet takedown in 2021
and Operation Endgame in 2024), so there is no minimum-count check. A
malformed or unreachable feed stops the run and records nothing. Only counts
by family, country and AS are published; the output contract rejects IP
addresses, ports and hostnames. Fetcher `pipeline/fetch_feodo.py`, stage
`pipeline/botnet_metrics.py`.

### 21 · AI and PoC Timing — [ai.html](https://devko.github.io/CyberMon/ai.html)

*Public exploit code in Exploit-DB has not appeared sooner since ChatGPT's release.*

Tests whether public exploit code appeared sooner after LLMs arrived. It
measures public exploit code as Exploit-DB dates it, not exploitation in the
wild. For contrast, the page quotes Mandiant's time-to-exploit from its own
incident data: 63 days in 2018–19, five days in 2023. Three charts:

- days from publication to the first public exploit (1999 onward) against a
  dated AI timeline, with the chosen AI era shaded;
- an inflection test: for each timing metric, the opening level, the five
  years before a cutoff and the settled years since, and the share of the
  total movement after the cutoff, with the CVE count behind each level;
- AI-security attention (Buzzword Attention's *AI Security* and *Agentic AI*
  terms) against the like-for-like clock.

The cutoff is a reader control: ChatGPT, GPT-4, or the first documented
AI-run operation. The year containing a cutoff counts for neither side, and a
cutoff with fewer than two settled years after it is not judged. KEV latency
is left out because its series starts in 2023.

Limits: Exploit-DB dates far fewer CVEs than it used to (2,745 CVEs published
in 2007; fewer than 300 a year since 2021). Exploits published only on GitHub
or elsewhere are not counted, and the post-ChatGPT level rests on a few
hundred CVEs. No fetch of its own: the clock comes from `time_to_poc.json`
and the attention lanes from `market_hype.json`. The AI timeline is
`pipeline/ai_timeline_data.py`, a hand-maintained table in which every row
has a source URL and a date precision. Vendor figures from private incident
data (Mandiant, the DBIR's edge-device share) are quoted with attribution and
never plotted (`ai_timeline_data.EXTERNAL_CONTEXT`; a unit test keeps them
out of the payload). Stage `pipeline/ai_metrics.py`.

### 22 · AI Credits — [credits.html](https://devko.github.io/CyberMon/credits.html)

*The largest single AI finder announcement counts more vulnerabilities than CVE records credit to all AI labs and vendors combined.*

This module measures **attribution, not discovery**. Every credit in the
corpus is matched against a hand-curated registry of AI finders
(`pipeline/ai_credits_data.py`); nothing checks how a bug was found. The
registry is narrow because a loose match catches Capgemini, a researcher
named Ai and every `.ai` domain, and it misses names it does not list (its
first version missed Google's OSS-Fuzz-Gen).

Each match gets a tier:

- **system**: the credit names a model or AI system;
- **org**: it names only the organisation, usually as an employer;
- **fix**: the name appears only under a non-discovery CVE role such as
  remediation developer, reviewer, verifier, coordinator or sponsor. Never
  counted.

**LLM
labs and AI-security vendors are kept apart and never summed.** A lab counts
at the system tier only, a vendor at system or org, which is weaker evidence.

Seven charts:

- a funnel per kind (announced number, credited CVEs, high or critical, in
  Exploit-DB / Metasploit / Nuclei, on KEV) beside the same funnel for every
  credit-carrying CVE;
- nine measurements against that baseline, the last being cohort age,
  because exploit listings and KEV entries accumulate over time;
- monthly counts, the finder board, first-listed CWEs in six families, the
  first affected product per record, and the share of CVEs with any credit.

The comparisons are descriptive: not adjusted for publication age, target
mix or crediting practice, and the baseline is not a human-only control
group.

The announced numbers are the only figures on the site that CyberMon does not
compute. Each is committed with the finder's wording, date, first-party
source and a `unit_kind`. It is drawn on the measured scale only when its
unit is CVEs, and a test fails once a reading passes its maximum age. Raw
credit strings carry personal names and addresses and are never published;
`ai_credits_ledger.json` lists the CVE id, matched finder, tier and credit
roles for every matched record instead. No fetch of its own: `CreditCollector`
runs as a second observer on the shared corpus pass. The copy was rewritten
and the role handling fixed on 2026-09-20 after an outside review. The page
methodology discloses that the registry and copy were drafted with Claude, an
Anthropic model. Stage `pipeline/ai_credits_metrics.py`.

### 23 · Record Tags — [tags.html](https://devko.github.io/CyberMon/tags.html)

*More CVEs are tagged as issued for products the vendor no longer supports.*

The CNA can tag its container in a CVE record. The schema defines three tags:
`unsupported-when-assigned`, `disputed` and `exclusively-hosted-service`
(`x_` tags are private to a CNA and listed only as context). Three charts:

- each schema tag per publication year, as a count and as a share;
- which CNAs set `unsupported-when-assigned` and `disputed` over the last
  five years, and how few of the active CNAs use them;
- the severity of tagged records against the same CNAs' other records and
  against all records.

A tag records
what the CNA stated and is not checked; an untagged record is not
"supported". The record carries no tag date, so everything is by publication
year. No fetch of its own: the tallies come from the shared corpus pass
(`Aggregator._add_tags`). Stage `pipeline/tags_metrics.py`.

### 24 · SEC Incident Filings — [incidents.html](https://devko.github.io/CyberMon/incidents.html)

*US public companies have filed dozens of material-incident 8-Ks since December 2023.*

Since 18 December 2023 a US public company must disclose a material
cybersecurity incident on Form 8-K under Item 1.05. Each night the pipeline
re-reads SEC EDGAR full-text search month by month over the whole window,
with the client, User-Agent and pacing of module 02's EDGAR lane. It counts,
by filing date:

- Item 1.05 originals;
- Item 1.05 amendments (8-K/A);
- Item 8.01 filings describing a cybersecurity incident, the voluntary route
  after the SEC's May 2024 guidance.

The full-text phrase only finds candidates: a filing counts by EDGAR's own
item list, and the 8.01 phrase must appear in the 8-K itself, not only in an
exhibit. Both queries are printed on the page and in `docs/data-contracts.md`.
EDGAR applies the form filter to the root form, so `forms=8-K` also returns
amendments. A `forms=8-K,8-K/A` query returns amendments only; the first
editions sent it and counted no originals until 2026-09-23.

Three charts: filings per month or quarter; days from an original to its
first amendment (matched by filer CIK, right-censored); and the latest Item
1.05 filings, linked to EDGAR. These are the companies' own public filings,
and the only place the site names an affected organisation. The incident
date is in the filing text, not in a field, so nothing here measures
breach-to-disclosure time. The stage keeps no history or cache. An EDGAR
outage carries the last edition forward, marked stale; before the first
nightly read the output is an empty edition (`status: "empty"`). Fetcher
`pipeline/fetch_sec_incidents.py`, stage `pipeline/sec_incidents_metrics.py`.

### 25 · Advisories Without a CVE — [advisories.html](https://devko.github.io/CyberMon/advisories.html)

*Most GitHub-reviewed advisories carry a CVE id; Rust's lack one more often than those of any other large registry.*

GitHub-reviewed security advisories (GHSA ids) for open-source packages,
read from OSV.dev's exports for the twelve GitHub advisory ecosystems.
Withdrawn advisories are excluded and multi-ecosystem advisories counted
once. Three charts:

- advisories per GitHub publication year with and without a CVE alias, with
  an ecosystem picker and a share view. No-CVE advisories from the last 90
  days are drawn as provisional, since a CVE can be added later;
- the no-CVE share per ecosystem;
- GitHub's severity rating with and without a CVE.

OSV mirrors only reviewed advisories; the pipeline checks the
flag on every record and a claims test guards it. Fetcher
`pipeline/fetch_osv.py` (shared with module 26), stage
`pipeline/osv_metrics.py`.

### 26 · Malicious Packages — [malware.html](https://devko.github.io/CyberMon/malware.html)

*More than half of the reports in the OpenSSF malicious-packages feed were published in a single month.*

The OpenSSF malicious-packages feed (MAL ids) for nine registries, from the
same OSV exports: reports per registry per month of feed publication
(stacked, or one line per registry on a log scale), each year's reports by
registry, and withdrawn reports. Counts are reports, not installs or
victims; the date is when the report entered the feed. One OSV fetch serves
both modules. The nightly sends conditional GETs (ETag / Last-Modified),
downloads only the changed zips and keeps a compact summary. An OSV outage
carries both modules forward, marked stale. Stage `pipeline/osv_metrics.py`.

### 28 · Detection Rules — [sigma.html](https://devko.github.io/CyberMon/sigma.html)

*The share of ATT&CK techniques with at least one Sigma rule has fallen since 2023, from more than four in five to about three in four.*

Sigma detection rules in SigmaHQ's public repository (Detection Rule
License 1.1), joined to the ATT&CK enterprise release list and dates the
ATT&CK Releases stage publishes. Four charts: rules added (by the `date`
written in each rule) and deprecated (by the last edit of rules in
`deprecated/`) per quarter; the share of today's ATT&CK techniques that
had entered ATT&CK and carried at least one rule at each quarter end
(sub-technique tags rolled up to the parent, revoked ids followed to their
replacement); how long techniques new to ATT&CK waited for a first rule,
with the median over those followed for two years; and coverage by
tactic. Rule dates are the authors' own, not commit dates, so every date
is approximate. Each night costs one `git ls-remote`; a shallow clone
(~10 MB) happens only when the head moved, and each ATT&CK release's
bundle is read once. A SigmaHQ or ATT&CK outage carries the module forward,
marked stale. Only counts and ATT&CK ids are published, never rules.
Fetcher `pipeline/fetch_sigma.py`, technique timeline
`pipeline/attack_techniques.py`, stage `pipeline/sigma_metrics.py`.

## The Field — [field.html](https://devko.github.io/CyberMon/field.html)

*Every published CVE as one point in a 3D view.*

An instrument, not a module: it has its own Instruments link and is not part
of module or carousel generation. It arranges the corpus by publication date,
severity and EPSS; by days to the first public exploit and to the KEV
listing; on a CVSS × EPSS grid; or by assigner, vendor, weakness or NVD
status. Publication playback shows the records published through a chosen
month with the current edition's values. It does **not** reconstruct
historical scores, EPSS forecasts or KEV status. KEV is a separate overlay.

Filters, the publication cut, group limits, counters, selections and the
paginated **Browse records** table all describe the same population. The
assigner and vendor views place the 48 largest groups and the weakness view
the 30 most common, by matching records; sorting changes only their order.
The UI also reports the matching count before those limits. Changing a
filter, the arrangement or the publication cut clears the selection.

Search by CVE ID, inspect a record by click, tap or the keyboard-accessible
list, and download the shown or selected records as JSON with their edition.
Arrow keys orbit the canvas, +/− zoom and Home resets the camera. A flat view
and a mobile controls drawer are also available. The URL keeps filters,
arrangement, flat view and point size against the latest edition, but not
the camera or box selections. `#cve=CVE-2024-3400` focuses one record.

The nightly builds `site/field/field.json` and a content-addressed gzip
binary with `python -m pipeline --out site/data --field-out site/field`.
Layout v4 keeps the 24-byte record and uses byte 23 for the **exact EPSS
bucket, computed before rounding**. Vendor names keep the full u16
dictionary. The loader verifies the SHA-256 digest and requires v4; older
blobs must be rebuilt, not relabelled. All Field files are gitignored, and
deployment rejects sample fixture output.

`tools/fetch_field.py` finds the latest successful nightly that produced a
valid current-layout `field-latest` artifact (catch-up runs that did nothing
carry none). A push deploy requires that artifact and a Field browser check,
so after a layout change, run the nightly before a push can deploy.

`python tools/field_smoke.py --site site` checks an assembled real build;
without `--site` it uses an isolated synthetic fixture.

## Mutation Observatory — [observatory.html](https://devko.github.io/CyberMon/observatory.html)

*The Observatory puts CyberMon's CVE-level change logs on one timeline.*

It reads three logs:

- CNA score changes (`rescore_log.csv`);
- KEV additions, field and text edits and removals (`kev_changelog.csv`,
  with its capture/daily granularity);
- each night's largest EPSS probability change (`epss_volatility.csv`),
  leaving out nights EPSS Volatility excludes as a model change or an
  anomaly.

Brush a date range on the stacked chart to list its events in a sortable
table (the first 100 rows shown, the whole range as CSV). Or search a CVE
(deep link `#cve=CVE-…`) to see its events as a vertical timeline, with a
link to the same record in the Field. Events are dated by the night CyberMon
first observed them; EPSS events use FIRST's score date and capture-era KEV
events the first capture showing them. The page states when each history
begins and draws nothing earlier.

Data: `site/data/observatory.json`, built nightly by `pipeline/observatory.py`
from the logs the pipeline already writes (no fetch, no state). On
2026-11-04 it was about 490 KB raw / 60 KB gzipped for about 10,300 events,
one `|`-joined string per event. Like the Field it is an instrument: an entry
under Instruments on the home page and in the nav, with no carousel and no
claims audit (its copy has no hard-coded numbers). Browser check:
`python tools/observatory_smoke.py` (searches a real CVE from the data,
checks its timeline, the deep link at 390 px and the CSV download).

## Architecture

No servers. The nightly workflow (`.github/workflows/nightly.yml`) runs the
Python pipeline, checks the refreshed data against the claims tests, commits
`site/data/` and deploys the static site to GitHub Pages. Pages read
pre-aggregated JSON; there are no runtime queries.

```
         (02:43 UTC; retried at 08:43 UTC if no run succeeded that day)
 GitHub Action ──▶ python -m pipeline ──▶ site/data/*.json
                     │                         │  validated against
                     ├─ cvelistV5 release zip  │  docs/data-contracts.md
                     ├─ EPSS daily CSV         ▼
                     ├─ FIRST EPSS API     pytest pipeline/tests
                     ├─ CISA KEV JSON      (claims gate)
                     ├─ NVD API + feeds        │
                     ├─ HIBP · Ransomwhere     ▼
                     ├─ ATT&CK STIX        commit to main
                     ├─ APNIC DNSSEC       (cybermon-bot, [skip ci])
                     ├─ GDELT · HN · arXiv     │
                     ├─ Wikipedia · EDGAR      ▼
                     ├─ Exploit-DB · Metasploit · Nuclei
                     ├─ CVE.org roster     site/ ──▶ GitHub Pages
                     ├─ Feodo Tracker      https://devko.github.io/CyberMon/
                     └─ OSV.dev exports
```

After the commit the job tags a weekly `data-backup-<ISO week>` snapshot,
builds the carousel PDFs and motion clips, validates and uploads the Field
artifact, and deploys. A failure in the pipeline or the claims tests stops
the run before anything is committed or deployed. Any failure opens or
updates an issue labelled `nightly-failure`, and the next fully green run
closes it.

`.github/workflows/ci.yml` runs the tests, an offline fixture run and the
browser checks on every push and pull request, and deploys on pushes to main
(fetching the Field from the latest nightly).

## Data sources

| Source | What we use | License / terms |
|---|---|---|
| [cvelistV5](https://github.com/CVEProject/cvelistv5) (CVE Program) | Authoritative CVE corpus incl. CNA-assigned CVSS scores | [CVE terms of use](https://www.cve.org/Legal/TermsOfUse); CVE is a registered trademark of The MITRE Corporation |
| [EPSS](https://www.first.org/epss/) (FIRST) | Daily exploitation-probability scores (current CSV feed), plus historical day-before scores fetched per date from the [FIRST API](https://api.first.org/) (`/data/v1/epss?cve=…&date=…`) for EPSS Before KEV; each (CVE, date) is looked up once | Free with attribution per [EPSS usage guidance](https://www.first.org/epss/user-guide) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities catalog | US Government work; [CC0-style license](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt) |
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) (NIST) | Enrichment status (`vulnStatus`) only, from the API and NVD's yearly JSON feeds | Public domain (US Government); [NVD terms](https://nvd.nist.gov/general/faq) request attribution and prohibit implying endorsement |
| [GDELT 2.0 DOC API](https://blog.gdeltproject.org/gdelt-doc-2-0-api-debuts/) | Monthly news-article volume per tracked term | Free with attribution per [GDELT terms of use](https://www.gdeltproject.org/about.html#termsofuse) |
| [HN Search API](https://hn.algolia.com/api) (Algolia) | Monthly story+comment counts per tracked term | Free API provided by Algolia; attribution appreciated |
| [arXiv API](https://info.arxiv.org/help/api/index.html) | Monthly cs.CR preprint counts per tracked term | Free per [arXiv API ToU](https://info.arxiv.org/help/api/tou.html); thank you to arXiv for use of its open access interoperability |
| [Wikimedia Pageviews REST API](https://wikimedia.org/api/rest_v1/) | Monthly pageviews of one curated en.wikipedia article per tracked term (`agent=user`, bot traffic excluded); the term→article mapping is reviewable data in `pipeline/market_terms.py` | Aggregate pageview data is [CC0](https://creativecommons.org/publicdomain/zero/1.0/); accessed per the [Wikimedia API policy](https://foundation.wikimedia.org/wiki/Policy:Wikimedia_Foundation_API_Policy) (descriptive User-Agent with contact info) |
| [SEC EDGAR full-text search](https://efts.sec.gov/LATEST/search-index?q=%22example%22) | Monthly counts of filings matching each tracked term as a quoted phrase (`hits.total.value`, one request per term-month; the corpus reaches back to 2001); for SEC Incident Filings, the paged hits of two 8-K queries (Item 1.05, Item 8.01 cyber incident) since 2023-12-18: accession number, filer CIK/name, filing date, form, item list | Public U.S. Government data; accessed per the [SEC fair-access guidelines](https://www.sec.gov/os/accessing-edgar-data) (declared User-Agent with contact address, well under 10 req/s) |
| [Have I Been Pwned](https://haveibeenpwned.com/API/v3#AllBreaches) | Public breach catalog: breach/added dates, account counts, data classes, classification flags | Free, no key; [CC BY 4.0 with attribution](https://haveibeenpwned.com/API/v3#License): breach catalog courtesy of Have I Been Pwned (credited in the site footer) |
| [Ransomwhere](https://ransomwhe.re/) (Jack Cable) | Crowdsourced, verified ransomware payment addresses and their on-chain transactions | [CC0](https://creativecommons.org/publicdomain/zero/1.0/) |
| [MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data) (attack-stix-data) | Versioned enterprise STIX bundles: technique/sub-technique/group/software counts, per-release churn, group aliases | [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/): royalty-free license requiring MITRE's copyright designation (reproduced in the site footer); ATT&CK is a registered trademark of The MITRE Corporation |
| [APNIC Labs DNSSEC measurement](https://stats.labs.apnic.net/dnssec) | Measured DNSSEC validation rates: per-code daily time series (`cgi-bin/json-table.pl?x=<code>`) + the world-map snapshot table | © APNIC Pty Ltd; "re-use with attribution permitted" (stated in every JSON response), provided on a hold-harmless basis with attribution |
| [Internet Archive Wayback Machine](https://web.archive.org/) | Historical captures of the CISA KEV JSON (CDX index + snapshot bodies), fetched once for the KEV Changelog backfill; paced ~1 req/s, cached in `.cache/kev_wayback/`, never touched by CI | Archived US Government (CC0-style) content, served by the Internet Archive; capture metadata via the [CDX API](https://archive.org/developers/wayback-cdx-server.html) |
| [MITRE CWE Top 25](https://cwe.mitre.org/top25/) | The published annual CWE Top 25 rankings (static, copied by hand per year into `pipeline/cwe_top25_data.py`), set against the corpus's first-listed-CWE frequency and KEV entries | [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html); CWE is a trademark of The MITRE Corporation |
| [CVE.org organization roster](https://www.cve.org/PartnerInformation/ListofPartners) | The CVE Program's partner list (`CNAsList.json` from the [cve-website](https://github.com/CVEProject/cve-website) repo): org short names, type, scope, top-level/reporting roots and country, snapshotted nightly for CNA Roster | [CVE terms of use](https://www.cve.org/Legal/TermsOfUse); same CVE Program data family as cvelistV5 |
| [Exploit-DB](https://www.exploit-db.com/) (OffSec) | The exploit archive's index CSV (`files_exploits.csv` from the [exploitdb](https://gitlab.com/exploit-database/exploitdb) repo): per-exploit `date_published` and CVE references from the `codes` column; metadata only, no exploit code is fetched | Archive maintained by OffSec as a public service; index metadata used as facts with attribution (credited in the site footer); not affiliated |
| [Metasploit Framework](https://github.com/rapid7/metasploit-framework) (Rapid7) | Module metadata (`db/modules_metadata_base.json`): `type`, `disclosure_date` and CVE `references` per module; the disclosure date is not the module merge date | [BSD-3-Clause](https://github.com/rapid7/metasploit-framework/blob/master/LICENSE); Metasploit is a Rapid7 project (credited in the site footer) |
| [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates) (ProjectDiscovery) | The CVE template index (`cves.json`): which CVEs have a detection template; the index publishes no dates | [MIT](https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE.md) (credited in the site footer) |
| [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) | Botnet C2 IP blocklist (`downloads/ipblocklist.json`): per-C2 status, malware family, first-seen date, country and AS, snapshotted nightly for Botnet C2 Servers; only aggregates are republished, never addresses | [CC0 per the blocklist page's Terms of Services](https://feodotracker.abuse.ch/blocklist/) ("commercial and non-commercial purpose without any limitations"); attribution appreciated. Public endpoint, no auth-key (verified 2026-07-21) |
| [OSV.dev ecosystem exports](https://google.github.io/osv.dev/data/#data-dumps) (`osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`) | GitHub-reviewed advisories (GHSA ids: publication date, aliases, GitHub severity, withdrawn flag) and OpenSSF malicious-packages reports (MAL ids: publication date, withdrawn flag, contributing sources); aggregates only, no package names republished | GitHub Advisory Database: [CC-BY 4.0](https://github.com/github/advisory-database/blob/main/LICENSE.md); OpenSSF malicious-packages: [Apache-2.0](https://github.com/ossf/malicious-packages/blob/main/LICENSE); both credited in the site footer. No key |
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) (SigmaHQ) | Sigma detection rules, read over the git protocol (`git ls-remote`, then a depth-1 clone only when the head moved): each rule's `date`, `modified`, `status` and `attack.tNNNN` tags under `rules*/` and `deprecated/`; only counts and ATT&CK ids are republished, never rules, titles or authors | [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License) (use, copy, publish and distribute permitted); SigmaHQ and the DRL credited on the page and in the site footer. No key |

## State and history

**Caches.** Uncommitted sync state lives in `.cache/` (`--cache-dir`). In CI,
`actions/cache` keeps the first six files below between nights and saves them
only after a green run; the market state is saved even after a failed night.
Losing a file never changes data already published; the table gives the cost.

| File | Module | When lost |
|---|---|---|
| `nvd_status_state.json.gz` | CVE Ecosystem (NVD) | One full sweep from the yearly feeds; that night the throughput diff has no baseline and logs no row, and queue waits are timed afresh |
| `market_state.json` | Buzzword Attention | Rebuilt from `market_hype.json`; HN gaps refill through a queue (`--market-backfill-batch`, default 8 requests a run) |
| `attack_state.json` | ATT&CK Releases | Rebuilt from `attack_churn.json` |
| `epss_report_state.json` | EPSS Before KEV | Rebuilt from `epss_report.json` |
| `epss_volatility_state.json.gz` | EPSS Volatility | One baseline night with no log row. Committed until 2026-09-07, when the 2.6 MB file rewritten nightly had grown to about 90% of the repository |
| `osv_state.json.gz` | Advisories, Malicious Packages | One full download of all thirteen exports (~290 MB) |
| `naming_state.json` | Threat Group Aliases | Rebuilt from `naming.json`, which is what CI does every night |
| `poc/` | Time to PoC | Same-day cache only |
| `kev_wayback/` | KEV Changelog backfill | Local only; CI never uses it |
| `sigma_state.json` | Detection Rules | Kept by `actions/cache` in CI. The rules cost one shallow clone of SigmaHQ/sigma (~10 MB); the ATT&CK technique timeline is rebuilt from `sigma_coverage.json`, so the ~40 bundles are never re-read |

**NVD sync.** The NVD stage keeps a per-CVE status map. Nightly runs fetch
only records modified since the last sync, which takes seconds. A full
resweep from NVD's static yearly JSON feeds (CDN-served flat files, minutes
in total) runs every `FULL_RESYNC_DAYS` (7) days, whenever the state is
missing or unreadable, and whenever the incremental API pull fails.

**History.** `site/data/history/` holds the records CyberMon builds by
comparing nightly snapshots. A missed night cannot be filled in later, so
they are committed and covered by the weekly `data-backup-*` tags:

- `nvd_backlog.csv`: nightly NVD backlog counts, since 2026-07-09;
- `nvd_throughput.csv`: daily NVD status transitions and queue waits, since
  2026-07-12;
- `kev_changelog.csv` + `kev_state.json`: KEV edits, flag changes and
  removals, nightly since 2026-07-11, with earlier events reconstructed once
  from Internet Archive captures;
- `rescore_log.csv` + `rescore_state.json`: CNA score changes, since
  2026-07-15;
- `epss_volatility.csv`: one row per EPSS snapshot, since 2026-07-18;
- `cna_roster.csv` + `cna_roster_state.json`: roster changes and nightly
  size, since 2026-07-18;
- `botnet_c2.csv`: nightly per-family Feodo Tracker counts, since 2026-07-21.

You are welcome to reuse them with credit to "CyberMon
(https://github.com/Devko/CyberMon)".

## Local development

```bash
# Recommended: work in a virtualenv
python3 -m venv .venv && source .venv/bin/activate

# Install pipeline dependencies (+ dev tools: pytest, playwright, imageio-ffmpeg)
python3 -m pip install -r pipeline/requirements.txt -r pipeline/requirements-dev.txt

# Run the tests (unit tests and the claims audits of the site copy)
python3 -m pytest pipeline/tests -q

# Full offline run against bundled fixtures (no network)
python3 -m pipeline --offline-fixtures --out /tmp/out

# Serve the site locally
cd site && python3 -m http.server 8000
# then open http://localhost:8000/          (landing page)
#      or  http://localhost:8000/cve.html   (CVE Ecosystem module)

# Browser checks (one-time browser install)
playwright install chromium
python3 tools/site_smoke.py          # every page of the committed site
python3 tools/field_smoke.py         # the Field, on an isolated synthetic fixture
python3 tools/observatory_smoke.py   # the Mutation Observatory

# Animated social clips (1080×1350 MP4 plus a half-size GIF, one per scene)
python3 tools/make_motion.py --check          # fast pre-flight, no encode
python3 tools/make_motion.py --out site/motion # full render (~1 min/scene)
python3 tools/make_motion.py --scene hype-race --keep-frames  # one scene, keep PNGs
```

A real (networked) run is `python3 -m pipeline --out site/data`. Set
`NVD_API_KEY` for faster NVD paging and `GITHUB_TOKEN` to lift GitHub's
anonymous rate limit on the cvelistV5 release lookup. `--skip-nvd`,
`--skip-market`, `--skip-attack` and `--skip-epss-report` skip a slow stage
and carry its previous output forward, marked stale.

`tools/make_sample_data.py --out <dir>` writes synthetic CVE Ecosystem
data (marked `"sample": true`, which the claims audit skips) for UI work
without a pipeline run. It refuses to write into the committed
`site/data`.

`site/carousels/` (LinkedIn PDFs) and `site/motion/` (animated clips) are
deploy-time build products: gitignored, rebuilt into the Pages artifact on
every deploy, never committed. Their build steps are `continue-on-error` in
both workflows, so a broken social asset never holds the site on stale data.

## Methodology

Chart-by-chart data shapes and computation rules are in
[docs/data-contracts.md](docs/data-contracts.md); the pipeline validates its
output against those contracts before writing. Design rationale, including
how v2/v3/v4 scores and CNA and NVD scores are kept apart, is in
[docs/plans/2026-07-09-cybermon-design.md](docs/plans/2026-07-09-cybermon-design.md).

## Roadmap

Candidate modules, each with its thesis, open data sources and feasibility,
are in [docs/backlog.md](docs/backlog.md). New modules follow the same
pattern: one pipeline stage, one contracts section, one page.

## One-time setup (repo settings)

For a fresh fork or clone of this repo, an admin must do these once in GitHub:

1. **Settings → Pages → Build and deployment → Source: "GitHub Actions"**
   (the workflows deploy via `actions/deploy-pages`, not a branch).
2. **Settings → Actions → General → Workflow permissions: "Read and write
   permissions"**, required if the org default is read-only, so the nightly
   job can commit `site/data/` back to main.
3. *(Optional)* **Settings → Secrets and variables → Actions → New repository
   secret: `NVD_API_KEY`**. Request a free key at
   https://nvd.nist.gov/developers/request-an-api-key. Without it the NVD
   stage still works; the key only speeds up the incremental API pulls (full
   resweeps use the static yearly feeds and need no key).

## Disclaimer & license

CyberMon is **not affiliated with, endorsed by, or sponsored by MITRE, the
CVE Program, NIST/NVD, CISA, FIRST, GDELT, Y Combinator/Algolia, arXiv, the
Wikimedia Foundation, the U.S. Securities and Exchange Commission, Have I
Been Pwned, Ransomwhere, APNIC, OffSec, Rapid7, ProjectDiscovery, abuse.ch,
GitHub, the OpenSSF, Google (OSV.dev), or the Internet Archive**. All
upstream data is © its respective sources under their own terms (see the
table above). Code in this repository is [MIT licensed](LICENSE).

Charts and aggregate numbers may be reused freely; **link back to CyberMon**
(the live site or this repo) as the source. CyberMon is a spare-time project
maintained on a best-effort basis. Everything is provided **as-is, without
warranty of any kind**: there is **no guarantee the data is correct,
complete, or current**, and an unattended nightly pipeline can and
occasionally will break. Verify against the primary sources before relying
on any number.
