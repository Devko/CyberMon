# CyberMon — CVE Ecosystem Health Dashboard

**CVE severity has become meaningless — here are the receipts.**

CVSS scores inflate year over year, most "Critical" vulnerabilities are never
exploited, NVD enrichment is decaying, and some CNAs rubber-stamp high
severities. CyberMon tracks all of it nightly, from open data, with every
number reproducible from the pipeline in this repo.

**Live dashboard:** https://devko.github.io/CyberMon/

Provocative headline, auditable methodology: every chart carries an editorial
caption *and* an expandable "how this is computed" footnote linking back to
the pipeline source. The site is meta — it never lists individual CVEs as
news.

## The six charts

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
      │              └─ NVD API (status)   site/  ──▶ GitHub Pages
      │                                              https://devko.github.io/CyberMon/
      └─ on failure: workflow fails, nothing is deployed
```

## Data sources

| Source | What we use | License / terms |
|---|---|---|
| [cvelistV5](https://github.com/CVEProject/cvelistv5) (CVE Program) | Authoritative CVE corpus incl. CNA-assigned CVSS scores | [CVE terms of use](https://www.cve.org/Legal/TermsOfUse); CVE is a registered trademark of The MITRE Corporation |
| [EPSS](https://www.first.org/epss/) (FIRST) | Daily exploitation-probability scores | Free with attribution per [EPSS usage guidance](https://www.first.org/epss/user-guide) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities catalog | US Government work; [CC0-style license](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt) |
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) (NIST) | Enrichment status (`vulnStatus`) only | Public domain (US Government); [NVD terms](https://nvd.nist.gov/general/faq) request attribution and prohibit implying endorsement |

`site/data/history/` — the nightly NVD backlog snapshots — is an **original
dataset accumulated by this project**; NVD publishes no such history. You are
welcome to reuse it, CC-BY style: just credit "CyberMon
(https://github.com/Devko/CyberMon)".

## Local development

```bash
# Install pipeline dependencies
pip install -r pipeline/requirements.txt

# Run the tests
python -m pytest pipeline/tests -q

# Full offline run against bundled fixtures (no network)
python -m pipeline --offline-fixtures --out /tmp/out

# Regenerate the committed sample data (marks meta.json "sample": true)
python tools/make_sample_data.py

# Serve the site locally
cd site && python -m http.server 8000
# then open http://localhost:8000/
```

A real (networked) run is `python -m pipeline --out site/data`; set
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

A **hype-cycle tracker** (named-vuln media attention vs. actual exploitation)
is planned as a second page, reusing the same nightly-pipeline pattern.

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
   nightly NVD sweep still works, just slower.

## Disclaimer & license

CyberMon is **not affiliated with, endorsed by, or sponsored by MITRE, the
CVE Program, NIST/NVD, CISA, or FIRST**. All upstream data is © its
respective sources under their own terms (see table above). Code in this
repository is [MIT licensed](LICENSE).
