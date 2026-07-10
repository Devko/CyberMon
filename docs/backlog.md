# Module backlog

Candidate monitoring modules, beyond the four that exist today
(01 · CVE Ecosystem, 02 · Security Market, 03 · KEV Latency,
04 · CNA Concentration — all live).

## Tier 0 — non-CVE sources, live-tested 2026-07-09

Every endpoint below was fetched and inspected on that date; record counts
and field lists are from the live responses, not documentation.

### Breach disclosure ledger (HIBP)
- **Thesis:** "Dwell time is a marketing number. The public record of
  breach disclosure is measurable, and it is right here."
- **Signals:** breach→cataloguing lag (`BreachDate` → `AddedDate`) per
  year; breaches and records exposed per year; leaked data classes over
  time.
- **Source:** `https://haveibeenpwned.com/api/v3/breaches` — tested: 1,015
  breaches, no API key, fields incl. BreachDate/AddedDate/PwnCount/
  DataClasses/IsFabricated. Attribution required (HIBP).
- **Feasibility:** easy — one JSON fetch, KEV-latency storytelling pattern.

### Extortion economy, on-chain (Ransomwhere)
- **Thesis:** "Ransom revenue is the one security statistic nobody can
  spin — it settles on a public ledger."
- **Signals:** confirmed payments and USD revenue per quarter; median
  payment drift; family concentration and churn.
- **Source:** `https://api.ransomwhe.re/export` — tested: 11,186 payment
  records, CC0, fields incl. family/balanceUSD/transactions.
- **Feasibility:** easy — single export, CC0 licensing. Honest caveat to
  carry: crowdsourced and verified means a *floor*, not the market.

### Taxonomy churn (MITRE ATT&CK)
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

### The boring-hygiene index (APNIC DNSSEC validation) — SHIPPED
Live as **08 · Hygiene Index** ([hygiene.html](../site/hygiene.html)).
Source exploration found richer endpoints than the candidate note
assumed: `cgi-bin/json-table.pl?x=<code>` serves the FULL daily history
per economy (2013-10-07 onward, ~3.9 MB), so the stage is stateless; the
all-economies snapshot comes from the world-map page's inline table
(no JSON equivalent exists — parsed with a loud-failure floor). See
`pipeline/fetch_dnssec.py` and data-contracts.md.

**Verified spare data sources for Security Market v1.1** (live-tested
2026-07-09): SEC EDGAR full-text search (free JSON API, mandatory
User-Agent header, history to 2001 — an "enterprise/investor attention"
lane) and Wikipedia Pageviews REST API (server-side monthly aggregates,
one request per term for the whole history, the most reliable API tested —
designated fallback if GDELT's rate limiting becomes intolerable).
Rejected: Stack Exchange (too sparse), GitHub search (workable but
rate-limit-cramped; future 4th source at best).

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

### KEV latency ledger
- **Thesis:** "By the time the government confirms it's exploited, you've
  been exposed for months."
- **Signals:** days from CVE publication to KEV listing (distribution per
  year, per vendor); remediation deadlines vs. patch availability at listing
  time; share of KEV entries that predate their own CVE record.
- **Sources:** CISA KEV JSON + cvelistV5 (both already ingested).
- **Feasibility:** easy — one new metrics builder and contract section.

### CVE program concentration
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
