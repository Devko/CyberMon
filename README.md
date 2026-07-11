# CyberMon — a nightly ledger of security industry health

**The security industry grades its own homework. CyberMon keeps the receipts.**

CyberMon monitors the machinery of the security industry itself — the scoring
systems, the institutions, the market — not the vulnerability of the week.
Everything is rebuilt nightly from open data, and every number is reproducible
from the pipeline in this repo.

**Live site:** https://devko.github.io/CyberMon/

Provocative headline, auditable methodology: every chart carries an editorial
caption *and* an expandable "how this is computed" footnote linking back to
the pipeline source.

## Modules

Each module is its own directly linkable page with its own pipeline stage and
[data contracts](docs/data-contracts.md). The landing page
([index.html](site/index.html)) is the module directory.

### 01 · CVE Ecosystem — [cve.html](https://devko.github.io/CyberMon/cve.html) (live)

*CVE severity has become meaningless — here are the receipts.* Nine charts:

1. **Severity inflation (hero)** — median and IQR of CVSS base scores per
   year, split by scoring version (v2/v3/v4) so methodology changes can't
   masquerade as trend.
2. **The 9.8 flood** — stacked area of severity buckets per year: watch
   Critical eat the chart.
3. **Score vs. reality** — CVSS × EPSS density grid; the share of "Critical"
   CVEs with under 1% exploitation probability, and KEV entries rated below
   High.
4. **NVD decay** — NVD's current enrichment backlog by status, plus our own
   accumulated snapshot time series (NVD publishes no backlog history — we
   are the historical record).
5. **NVD throughput** — daily status transitions derived by diffing our own
   nightly per-CVE snapshots: CVEs received, entering the analysis queue,
   leaving it as Analyzed or Deferred, plus the observed queue wait (NVD
   publishes totals only, never flow — again, we are the record; all
   durations are observed-by-CyberMon lower bounds).
6. **CNA rubber-stamp board** — CNAs ranked by average assigned severity and
   share of scores ≥ 9.0 (minimum 100 CVEs in a 3-year window).
7. **Volume curve** — CVEs published and rejected per year.
8. **Advisory quality** — share of each year's records missing a CWE, a
   CVSS score, or usable affected-version data, checked against the record
   itself.
9. **Bug-class inertia** — the top-8 weakness classes of the last decade
   and each one's share of the year's CWE-tagged records.

### 02 · Security Market — [market.html](https://devko.github.io/CyberMon/market.html) (live)

*The security industry runs on a hype curve. Nobody publishes the curve.*
A data-driven hype-cycle tracker for 14 curated buzzwords across three
independent attention signals — news coverage (GDELT), practitioner
chatter (Hacker News), research output (arXiv cs.CR) — each term indexed
to its own five-year peak. Hype curves, YoY risers/fallers, and a
research-vs-media divergence quadrant.

### 03 · KEV Latency — [kev.html](https://devko.github.io/CyberMon/kev.html) (live)

*By the time the government confirms it's exploited, the exploit had a
head start.* Four charts: days from CVE publication to CISA KEV listing
(median/IQR by year, distribution buckets), remediation-deadline spans,
and the share of each year's listings flagged for known ransomware
campaign use — with the 2021 launch back-catalog quarantined from the
latency trend (launch batch plus the 2022 back-catalog import waves), and
negative latencies (listed before the CVE record existed) kept as the
signal they are.

### 04 · CNA Concentration — [concentration.html](https://devko.github.io/CyberMon/concentration.html) (live)

*The CVE database is becoming a handful of vendors grading themselves at
scale.* CNA roster growth vs. top-5/top-10 volume share, a formal HHI
concentration index, newcomer counts, and a rejection-rate leaderboard.

### 05 · Breach Ledger — [breaches.html](https://devko.github.io/CyberMon/breaches.html) (live)

*Dwell time is a marketing number. Breach disclosure is a public record.*
Three charts over the Have I Been Pwned breach catalog: days from breach
to public cataloging (median/IQR per catalog year, with the December
2013 launch import quarantined from the trend), breaches and accounts
exposed per year (with a pace projection for the partial year), and the
share of each year's breaches spilling the top data classes. Fabricated
entries, spam lists, malware corpora and stealer logs are excluded, and
the exclusion arithmetic ships in the data file.

### 06 · Extortion Ledger — [extortion.html](https://devko.github.io/CyberMon/extortion.html) (live)

*Ransom revenue is the one security statistic nobody can spin — it
settles on a public ledger.* Three views of the crowdsourced,
on-chain-verified Ransomwhere dataset: confirmed ransom revenue per
quarter (in day-of-transfer dollars), payment counts and median payment
size per year, and a family concentration board with the unattributed
majority disclosed rather than ranked. Every figure is a lower bound by
construction — a payment counts only after someone reported the address
and the transfers were verified.

### 07 · ATT&CK Churn — [attack.html](https://devko.github.io/CyberMon/attack.html) (live)

*The map of attacker behavior grows every release; detections are graded
against a moving target.* Three charts from MITRE's versioned enterprise
STIX bundles: active techniques and sub-techniques per ATT&CK release over
real release dates, what each release added vs. deprecated or revoked
(diffed by STIX id), and the group/software catalog behind the matrix.
Released bundles are immutable, so per-version stats are computed once and
cached (`.cache/attack_state.json`); a lost cache is reconstructed from the
previously published `attack_churn.json`, and a normal night costs one
`index.json` fetch.

### 08 · Hygiene Index — [hygiene.html](https://devko.github.io/CyberMon/hygiene.html) (live)

*The fix is twenty years old, free, and still not deployed.* Three charts
on measured DNSSEC validation (APNIC Labs): the world adoption line since
2013, a fixed set of the ten largest online populations compared (frozen
by APNIC's own internet-user weighting at module creation), and the
one-economy-one-vote distribution across every measured economy. APNIC
publishes its full daily history, so this stage refetches statelessly
every night — no accumulated state, no committed history file.

### 09 · Security Products — [guards.html](https://devko.github.io/CyberMon/guards.html) (live)

*The products guarding the network keep landing on the exploited list.*
Three views over the CISA KEV catalog, with every entry classified by a
curated, versioned security-product table
([pipeline/security_products.py](pipeline/security_products.py) — the
decision rule and every judgment call are documented in the module, and
the emitted data carries the classifier version): the share of each
year's new listings that are security products (seeding era included —
the classification rides on the entry itself), a vendor recidivism
board with first/last listing dates and the median gap between
consecutive listings, and the ransomware-flag split between exploited
security products and the rest of the catalog. No new upstream source:
everything derives from the KEV feed the pipeline already fetches.

### 10 · EPSS Report Card — [epss.html](https://devko.github.io/CyberMon/epss.html) (live)

*The industry's exploit forecast rarely gets an outside grade. CyberMon grades it.*
Three charts grading EPSS — the site's own yardstick for CVSS — against
the outcome it exists to predict: for every CVE that CISA later confirmed
exploited (KEV), the EPSS score published **the day before** the listing.
Grade bands (under 1% / 1–10% / 10%+) per catalog year, the day-before
score distribution split by EPSS model version (v1–v5 are different
models and are never pooled silently), and the percentile view — the one
scale comparable across model eras. Entries listed before their CVE even
published can have no prior score and are counted separately, never as
misses. Historical scores are immutable, so each (CVE, listing-date) pair
is fetched from FIRST's API exactly once and cached
(`.cache/epss_report_state.json`); a lost cache reconstructs losslessly
from the published `epss_report.json`, and a normal night costs 1–2 API
requests. The one-time historical backfill is batch-capped
(`--epss-backfill-batch`) so CI can never accidentally run it.

### 11 · CVE Calendar — [calendar.html](https://devko.github.io/CyberMon/calendar.html) (live)

*The CVE stream keeps vendor time.* Three charts on publication timing,
from the same cvelistV5 corpus (all date judgments UTC):

1. **Reservation aging (hero)** — per publication year, the share of
   records whose CVE ID was minted that same year, one year earlier, or
   two-plus years earlier: the ID's vintage is reservation paperwork,
   and about one in five "new" CVEs arrives on an earlier-year ID.
2. **The weekly beat** — the weekday distribution of publication, the
   latest complete year against a decade before; the Tuesday spike
   belongs to release calendars.
3. **Patch Tuesday** — the share of each year's records published on the
   twelve second Tuesdays, against the 3.3% those days would hold under
   a calendar-blind uniform flow.

### 13 · Silent Rescores — [rescores.html](https://devko.github.io/CyberMon/rescores.html) (live)

*Severity is not just assigned — it is edited after the fact, quietly, on
live records.* Every night the pipeline fingerprints each published CVE's
CNA-assigned base score (the exact extraction the severity-inflation
chart uses, so the two can never disagree) and diffs it against the
previous night's corpus (`.cache/rescore_state.json.gz`). Changes land on
a committed, append-only event log
(`site/data/history/rescore_log.csv`) as one of four types: `rescore`
(same CVSS version, new score — the only type with an up/down direction),
`version_shift` (moved to another CVSS version; never charted as a score
change, because v2/v3/v4 are different scales), `first_score` (an old
record backfilled with its first score) and `score_removed`. Three
charts: edits per week (up vs. down, the other types as separate muted
series), the rescore-delta distribution (behind a min-n gate until the
record is deep enough), and a CNA board of who edits. **No upstream
publishes this history — the record starts at first deploy and grows
every night.** A lost diff state rebuilds from that night's corpus (zero
events that night, at worst one night's diffs lost); a re-run on the same
corpus release is detected and never double-counts.
### 12 · KEV Changelog — [changelog.html](https://devko.github.io/CyberMon/changelog.html) (live)

*CISA edits the exploited list without a changelog — CyberMon keeps the
diffs.* Three views over the project's own diff record of the CISA KEV
catalog: edits per month by kind (due-date moves, ransomware-flag flips,
text revisions, removals — additions are excluded, because a growing
catalog is the system working), the cumulative Unknown→Known ransomware
flips with the median listing-to-flip gap, and a receipts board of the
most-edited entries plus every entry observed leaving the catalog. Each
nightly run fingerprints the fresh catalog (tracked fields verbatim,
free-text fields as short hashes) and diffs it against the committed
state (`site/data/history/kev_state.json`), appending events to the
committed, append-only `site/data/history/kev_changelog.csv`. The record
was seeded once from Internet Archive captures of the feed
(`--kev-changelog-backfill`, batch-capped, cached in
`.cache/kev_wayback/`; CI never runs it) — backfilled events carry
`granularity: "capture"` and are dated to the first capture showing the
change; nightly events carry `"daily"`.

### Next

Candidate modules are collected in [docs/backlog.md](docs/backlog.md) —
each entry names its thesis, open data sources, and feasibility.

## Architecture

Zero servers. A nightly GitHub Action runs the Python pipeline, commits the
pre-aggregated JSON, and deploys the static site to GitHub Pages. Every chart
reads a few-KB JSON file; there are no runtime queries.

```
            (02:43 UTC nightly)
 GitHub Action ──▶ python -m pipeline ──▶ site/data/*.json
      │              │                        │
      │              ├─ cvelistV5 release zip │  commit back to main
      │              ├─ EPSS daily CSV        │  (cybermon-bot, [skip ci])
      │              ├─ CISA KEV JSON         ▼
      │              ├─ HIBP breaches JSON   site/  ──▶ GitHub Pages
      │              ├─ Ransomwhere export
      │              ├─ ATT&CK STIX index      https://devko.github.io/CyberMon/
      │              ├─ APNIC DNSSEC series
      │              ├─ GDELT · HN · arXiv
      │              └─ NVD API (status)
      └─ on failure: workflow fails, nothing is deployed
```

## Data sources

| Source | What we use | License / terms |
|---|---|---|
| [cvelistV5](https://github.com/CVEProject/cvelistv5) (CVE Program) | Authoritative CVE corpus incl. CNA-assigned CVSS scores | [CVE terms of use](https://www.cve.org/Legal/TermsOfUse); CVE is a registered trademark of The MITRE Corporation |
| [EPSS](https://www.first.org/epss/) (FIRST) | Daily exploitation-probability scores (current CSV feed), plus historical day-before scores fetched per-date from the [FIRST API](https://api.first.org/) (`/data/v1/epss?cve=…&date=…`) for the EPSS Report Card — each (CVE, date) looked up once, ever | Free with attribution per [EPSS usage guidance](https://www.first.org/epss/user-guide) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities catalog | US Government work; [CC0-style license](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt) |
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) (NIST) | Enrichment status (`vulnStatus`) only | Public domain (US Government); [NVD terms](https://nvd.nist.gov/general/faq) request attribution and prohibit implying endorsement |
| [GDELT 2.0 DOC API](https://blog.gdeltproject.org/gdelt-doc-2-0-api-debuts/) | Monthly news-article volume per tracked term | Free with attribution per [GDELT terms of use](https://www.gdeltproject.org/about.html#termsofuse) |
| [HN Search API](https://hn.algolia.com/api) (Algolia) | Monthly story+comment counts per tracked term | Free API provided by Algolia; attribution appreciated |
| [arXiv API](https://info.arxiv.org/help/api/index.html) | Monthly cs.CR preprint counts per tracked term | Free per [arXiv API ToU](https://info.arxiv.org/help/api/tou.html); thank you to arXiv for use of its open access interoperability |
| [Have I Been Pwned](https://haveibeenpwned.com/API/v3#AllBreaches) | Public breach catalog: breach/added dates, account counts, data classes, classification flags | Free, no key; [CC BY 4.0 with attribution](https://haveibeenpwned.com/API/v3#License) — breach catalog courtesy of Have I Been Pwned (credited in the site footer) |
| [Ransomwhere](https://ransomwhe.re/) (Jack Cable) | Crowdsourced, verified ransomware payment addresses and their on-chain transactions | [CC0](https://creativecommons.org/publicdomain/zero/1.0/) |
| [MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data) (attack-stix-data) | Versioned enterprise STIX bundles: technique/sub-technique/group/software counts and per-release churn | [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) — royalty-free license requiring MITRE's copyright designation (reproduced in the site footer); ATT&CK is a registered trademark of The MITRE Corporation |
| [APNIC Labs DNSSEC measurement](https://stats.labs.apnic.net/dnssec) | Measured DNSSEC validation rates: per-code daily time series (`cgi-bin/json-table.pl?x=<code>`) + the world-map snapshot table | © APNIC Pty Ltd; "re-use with attribution permitted" (stated in every JSON response), provided on a hold-harmless basis with attribution |
| [Internet Archive Wayback Machine](https://web.archive.org/) | Historical captures of the CISA KEV JSON (CDX index + snapshot bodies), fetched once for the KEV Changelog backfill — paced ~1 req/s, cached in `.cache/kev_wayback/`, never touched by CI | Archived US Government (CC0-style) content, served by the Internet Archive; capture metadata via the [CDX API](https://archive.org/developers/wayback-cdx-server.html) |

The NVD stage is **incremental**: a per-CVE status map is kept as cached
sync state (`.cache/nvd_status_state.json.gz`, cached across CI runs), and
nightly runs only fetch records modified since the last sync — seconds
instead of a full corpus sweep. A full resweep is forced weekly (and
whenever the state is missing or unreadable) so drift can never outlive
`FULL_RESYNC_DAYS`; full sweeps read NVD's static yearly JSON feeds
(CDN-served flat files, minutes total) instead of paging the API.

`site/data/history/` holds **original datasets accumulated by this
project**: the nightly NVD backlog snapshots (`nvd_backlog.csv` — NVD
publishes no backlog history) and the silent-rescore event log
(`rescore_log.csv` — no upstream publishes score-edit history). Both are
append-only and cannot be regenerated from any source; the weekly
`data-backup-*` tags are their rollback insurance. You are welcome to
reuse them, CC-BY style: just credit "CyberMon
(https://github.com/Devko/CyberMon)".
`site/data/history/` holds two **original datasets accumulated by this
project**: the nightly NVD backlog snapshots (`nvd_backlog.csv` — NVD
publishes no such history) and the KEV changelog
(`kev_changelog.csv` + `kev_state.json` — CISA publishes only the current
catalog snapshot, so the diff record of its edits, flag flips and
removals exists nowhere else; the pre-launch prefix was reconstructed
once from Internet Archive captures, everything since is observed live
and cannot be regenerated). You are welcome to reuse them, CC-BY style:
just credit "CyberMon (https://github.com/Devko/CyberMon)".

## Local development

```bash
# Recommended: work in a virtualenv
python3 -m venv .venv && source .venv/bin/activate

# Install pipeline dependencies (+ dev tools: pytest, playwright)
python3 -m pip install -r pipeline/requirements.txt -r pipeline/requirements-dev.txt

# Run the tests
python3 -m pytest pipeline/tests -q

# Full offline run against bundled fixtures (no network)
python3 -m pipeline --offline-fixtures --out /tmp/out

# Regenerate the committed sample data (marks meta.json "sample": true)
python3 tools/make_sample_data.py

# Serve the site locally
cd site && python3 -m http.server 8000
# then open http://localhost:8000/          (landing page)
#      or  http://localhost:8000/cve.html   (CVE Ecosystem module)

# Browser smoke test against the committed site (one-time browser install)
playwright install chromium
python3 tools/site_smoke.py
```

A real (networked) run is `python3 -m pipeline --out site/data`; set
`NVD_API_KEY` in the environment for faster NVD paging, or pass `--skip-nvd`
to skip the NVD sweep entirely.

## Methodology

Chart-by-chart data shapes and computation rules live in
[docs/data-contracts.md](docs/data-contracts.md); the pipeline validates its
own output against those contracts before writing. Design rationale — and
the credibility landmines we deliberately defuse (v2/v3/v4 score
comparability, CNA-vs-NVD scoring) — is in
[docs/plans/2026-07-09-cybermon-design.md](docs/plans/2026-07-09-cybermon-design.md).

## Roadmap

The candidate list for further modules — with thesis, open data sources,
and feasibility per module — lives in [docs/backlog.md](docs/backlog.md).
New modules follow the same pattern: one pipeline stage, one contracts
section, one page.

## One-time setup (repo settings)

For a fresh fork/clone of this repo, an admin must do these once in GitHub:

1. **Settings → Pages → Build and deployment → Source: "GitHub Actions"**
   (the workflows deploy via `actions/deploy-pages`, not a branch).
2. **Settings → Actions → General → Workflow permissions: "Read and write
   permissions"** — required if the org default is read-only, so the nightly
   job can commit `site/data/` back to main.
3. *(Optional)* **Settings → Secrets and variables → Actions → New repository
   secret: `NVD_API_KEY`** — request a free key at
   https://nvd.nist.gov/developers/request-an-api-key. Without it the
   NVD stage still works; the key only speeds up the incremental API
   pulls (full resweeps use the static yearly feeds and need no key).

## Disclaimer & license

CyberMon is **not affiliated with, endorsed by, or sponsored by MITRE, the
CVE Program, NIST/NVD, CISA, FIRST, GDELT, Algolia, arXiv, Have I Been
Pwned, Ransomwhere, or APNIC**. All upstream data is © its
respective sources under their own terms (see table above). Code in this
repository is [MIT licensed](LICENSE).

Charts and aggregate numbers may be reused freely — **link back to
CyberMon** (the live site or this repo) as the source. CyberMon is a
spare-time project maintained on a best-effort basis. Everything is
provided **as-is, without warranty of any kind**: there is **no guarantee
the data is correct, complete, or current** — an unattended nightly
pipeline can and occasionally will break. Verify against the primary
sources before relying on any number.
