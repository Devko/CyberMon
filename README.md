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

*CVE severity has become meaningless — here are the receipts.* Eight charts:

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
5. **CNA rubber-stamp board** — CNAs ranked by average assigned severity and
   share of scores ≥ 9.0 (minimum 100 CVEs in a 3-year window).
6. **Volume curve** — CVEs published and rejected per year.
7. **Advisory quality** — share of each year's records missing a CWE, a
   CVSS score, or usable affected-version data, checked against the record
   itself.
8. **Bug-class inertia** — the top-8 weakness classes of the last decade
   and each one's share of the year's CWE-tagged records.

### 02 · Security Market — [market.html](https://devko.github.io/CyberMon/market.html) (live)

*The security industry runs on a hype curve. Nobody publishes the curve.*
A data-driven hype-cycle tracker for 14 curated buzzwords across three
independent attention signals — news coverage (GDELT), practitioner
chatter (Hacker News), research output (arXiv cs.CR) — each term indexed
to its own five-year peak. Hype curves, YoY risers/fallers, and a
research-vs-media divergence quadrant.

### 03 · KEV Latency — [kev.html](https://devko.github.io/CyberMon/kev.html) (live)

*By the time the government confirms it's exploited, you've been exposed
for months.* Four charts: days from CVE publication to CISA KEV listing
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
to public cataloguing (median/IQR per catalog year, with the December
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
| [EPSS](https://www.first.org/epss/) (FIRST) | Daily exploitation-probability scores | Free with attribution per [EPSS usage guidance](https://www.first.org/epss/user-guide) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities catalog | US Government work; [CC0-style license](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt) |
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) (NIST) | Enrichment status (`vulnStatus`) only | Public domain (US Government); [NVD terms](https://nvd.nist.gov/general/faq) request attribution and prohibit implying endorsement |
| [GDELT 2.0 DOC API](https://blog.gdeltproject.org/gdelt-doc-2-0-api-debuts/) | Monthly news-article volume per tracked term | Free with attribution per [GDELT terms of use](https://www.gdeltproject.org/about.html#termsofuse) |
| [HN Search API](https://hn.algolia.com/api) (Algolia) | Monthly story+comment counts per tracked term | Free API provided by Algolia; attribution appreciated |
| [arXiv API](https://info.arxiv.org/help/api/index.html) | Monthly cs.CR preprint counts per tracked term | Free per [arXiv API ToU](https://info.arxiv.org/help/api/tou.html); thank you to arXiv for use of its open access interoperability |
| [Have I Been Pwned](https://haveibeenpwned.com/API/v3#AllBreaches) | Public breach catalog: breach/added dates, account counts, data classes, classification flags | Free, no key; [CC BY 4.0 with attribution](https://haveibeenpwned.com/API/v3#License) — breach catalog courtesy of Have I Been Pwned (credited in the site footer) |
| [Ransomwhere](https://ransomwhe.re/) (Jack Cable) | Crowdsourced, verified ransomware payment addresses and their on-chain transactions | [CC0](https://creativecommons.org/publicdomain/zero/1.0/) |
| [MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data) (attack-stix-data) | Versioned enterprise STIX bundles: technique/sub-technique/group/software counts and per-release churn | [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) — royalty-free license requiring MITRE's copyright designation (reproduced in the site footer); ATT&CK is a registered trademark of The MITRE Corporation |
| [APNIC Labs DNSSEC measurement](https://stats.labs.apnic.net/dnssec) | Measured DNSSEC validation rates: per-code daily time series (`cgi-bin/json-table.pl?x=<code>`) + the world-map snapshot table | © APNIC Pty Ltd; "re-use with attribution permitted" (stated in every JSON response), provided on a hold-harmless basis with attribution |

The NVD stage is **incremental**: a per-CVE status map is kept as cached
sync state (`.cache/nvd_status_state.json.gz`, cached across CI runs), and
nightly runs only fetch records modified since the last sync — seconds
instead of a full corpus sweep. A full resweep is forced weekly (and
whenever the state is missing or unreadable) so drift can never outlive
`FULL_RESYNC_DAYS`; full sweeps read NVD's static yearly JSON feeds
(CDN-served flat files, minutes total) instead of paging the API.

`site/data/history/` — the nightly NVD backlog snapshots — is an **original
dataset accumulated by this project**; NVD publishes no such history. You are
welcome to reuse it, CC-BY style: just credit "CyberMon
(https://github.com/Devko/CyberMon)".

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
CVE Program, NIST/NVD, CISA, or FIRST**. All upstream data is © its
respective sources under their own terms (see table above). Code in this
repository is [MIT licensed](LICENSE).

Charts and aggregate numbers may be reused freely — **link back to
CyberMon** (the live site or this repo) as the source. CyberMon is a
spare-time project maintained on a best-effort basis. Everything is
provided **as-is, without warranty of any kind**: there is **no guarantee
the data is correct, complete, or current** — an unattended nightly
pipeline can and occasionally will break. Verify against the primary
sources before relying on any number.
