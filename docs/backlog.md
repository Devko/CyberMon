# Module backlog

Candidate monitoring modules, beyond the eighteen that exist today
(01 CVE Ecosystem, 02 Security Market, 03 KEV Latency, 04 CNA
Concentration, 05 Breach Ledger, 06 Extortion Ledger, 07 ATT&CK Churn,
08 Hygiene Index, 09 Security Products, 10 EPSS Report Card, 11 CVE
Calendar, 12 KEV Changelog, 13 Silent Rescores, 14 Naming Chaos,
15 CWE Top 25, 16 Vulnrichment, 17 EPSS Volatility, 18 CNA Roster —
all live).

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
