// =============================================================================
// editorial.js — EVERY user-facing string on the site lives here.
// Rewrite the voice in this one file; nothing editorial is hardcoded elsewhere.
//
// Templates use {placeholders}; values are filled from site/data/*.json at
// render time so the copy never carries stale numbers.
// =============================================================================

const METRICS_URL = "https://github.com/Devko/CyberMon/blob/main/pipeline/metrics.py";
const REPO_URL = "https://github.com/Devko/CyberMon";

export const editorial = {
  repoUrl: REPO_URL,
  metricsUrl: METRICS_URL,

  masthead: {
    kicker: "A nightly ledger of security industry health · rebuilt from open data every 24h",
    thesis: "The security industry grades its own homework. CyberMon keeps the receipts.",
    sub: "Every number on this site pairs a claim with the exact method that produced it. Disagree with one? The pipeline is open; rerun it.",
  },

  // Thematic nav groups, in display order. Each entry: a short label for the
  // nav row, and a one-line lede for the landing page's group header. The
  // LAST entry ("more") is the automatic catch-all: any nav entry with a
  // missing or unrecognized `group` id lands there, so a module merged
  // without a tag still ships navigable and a new group never needs code.
  navGroups: [
    {
      id: "machine",
      label: "The CVE machine",
      lede: "The pipeline behind the record: who mints it, who scores it, what gets edited after the fact.",
    },
    {
      id: "exploitation",
      label: "Exploitation",
      lede: "What actually gets exploited, and how the forecasts and catalogs tracking it keep up.",
    },
    {
      id: "industry",
      label: "The industry",
      lede: "Market hype, breach disclosure, ransom payments, and the state of everyday hygiene.",
    },
    {
      id: "attackmap",
      label: "Attacker's map",
      lede: "How the industry maps and names its adversaries — and how often the map gets redrawn.",
    },
    {
      id: "more",
      label: "More",
      lede: "Just landed — not yet filed under a theme.",
    },
  ],

  // Tabs in the shared top-nav. href values stay RELATIVE (GitHub Pages subpath).
  // Every tab is its own page — direct-linkable and bookmarkable.
  //
  // This array stays FLAT on purpose — carousel.js and the deploy tools read
  // it as a plain module list. Grouping is one `group` field per entry (an id
  // from navGroups above); groupNav() in common.js does the render-time fold
  // for both the nav and the landing page. Ungrouped entries at the HEAD of
  // the array (Overview) render as standalone leading tabs.
  //
  // Group assignments follow where each module's DATA lives, not its topic:
  //   machine      — read from the CVE record pipeline itself: the cvelistV5
  //                  corpus, NVD's database, and the CVE Program's own CNA
  //                  roster. CNA Roster sits here, next to CNA Concentration
  //                  — two views of the same federation — not under
  //                  "The industry".
  //   exploitation — read from the exploited-in-the-wild record: CISA's KEV
  //                  catalog and FIRST's EPSS feed (Security Products and
  //                  KEV Changelog are both KEV-derived).
  //   industry     — read from outside-world ledgers: GDELT/HN/arXiv (hype),
  //                  HIBP (breaches), Ransomwhere (ransoms), APNIC (hygiene).
  //   attackmap    — read from MITRE ATT&CK's STIX bundles (Naming Chaos is
  //                  ATT&CK alias data, not CVE data — it lives here).
  nav: [
    { id: "home", href: "index.html", label: "Overview" },
    { id: "cve", href: "cve.html", label: "CVE Ecosystem", group: "machine" },
    { id: "market", href: "market.html", label: "Security Market", group: "industry" },
    { id: "kev", href: "kev.html", label: "KEV Latency", group: "exploitation" },
    { id: "concentration", href: "concentration.html", label: "CNA Concentration", group: "machine" },
    { id: "breaches", href: "breaches.html", label: "Breach Ledger", group: "industry" },
    { id: "extortion", href: "extortion.html", label: "Extortion Ledger", group: "industry" },
    { id: "attack", href: "attack.html", label: "ATT&CK Churn", group: "attackmap" },
    { id: "hygiene", href: "hygiene.html", label: "Hygiene Index", group: "industry" },
    { id: "guards", href: "guards.html", label: "Security Products", group: "exploitation" },
    { id: "epss", href: "epss.html", label: "EPSS Report Card", group: "exploitation" },
    { id: "calendar", href: "calendar.html", label: "CVE Calendar", group: "machine" },
    { id: "changelog", href: "changelog.html", label: "KEV Changelog", group: "exploitation" },
    { id: "rescores", href: "rescores.html", label: "Silent Rescores", group: "machine" },
    { id: "naming", href: "naming.html", label: "Naming Chaos", group: "attackmap" },
    { id: "top25", href: "top25.html", label: "CWE Top 25", group: "machine" },
    { id: "adp", href: "adp.html", label: "Vulnrichment", group: "machine" },
    { id: "epssvol", href: "epssvol.html", label: "EPSS Volatility", group: "exploitation" },
    { id: "roster", href: "roster.html", label: "CNA Roster", group: "machine" },
  ],

  // ------------------------------------------------- index.html (landing)
  home: {
    kicker: "Overview",
    headline: "Pick a module.",
    caption:
      "CyberMon watches the machinery of the security industry itself — the scoring systems, " +
      "the institutions, the market — not the vulnerability of the week. Each module below is " +
      "a separate page with its own nightly pipeline stage, data contracts, and expandable " +
      "“how this is computed” footnotes.",
    statusLive: "live",
    statusSoon: "coming soon",
    backlogNote:
      "More modules are queued — the candidate list lives in the repo under docs/backlog.md.",
    modules: [
      {
        id: "cve",
        href: "cve.html",
        num: "01",
        label: "CVE Ecosystem",
        headline: "CVE severity has become meaningless — here are the receipts.",
        blurb:
          "CVSS inflation, the 9.8 flood, scores vs. real-world exploitation, NVD backlog " +
          "decay, NVD throughput, CNA scoring habits, the volume curve, advisory quality, " +
          "bug-class inertia. Nine charts, " +
          "rebuilt every night.",
        live: true,
      },
      {
        id: "market",
        href: "market.html",
        num: "02",
        label: "Security Market",
        headline: "The security industry runs on a hype curve. Nobody publishes the curve.",
        blurb:
          "Buzzword hype curves across five attention signals — news coverage (GDELT), " +
          "practitioner chatter (Hacker News), research output (arXiv), public curiosity " +
          "(Wikipedia pageviews), and investor filings (SEC EDGAR) — every term graded " +
          "against its own five-year peak, rebuilt nightly.",
        live: true,
      },
      {
        id: "kev",
        href: "kev.html",
        num: "03",
        label: "KEV Latency",
        headline: "By the time the government confirms it's exploited, the exploit had a head start.",
        blurb:
          "Days from CVE publication to CISA's Known Exploited Vulnerabilities listing, " +
          "remediation deadlines, the share of listings tied to known ransomware campaigns, " +
          "and the catalog's 2021–22 seeding era kept honestly separate from the real trend.",
        live: true,
      },
      {
        id: "concentration",
        href: "concentration.html",
        num: "04",
        label: "CNA Concentration",
        headline: "A handful of vendors still ship most of the CVE database — grading themselves at scale.",
        blurb:
          "CNA count, top-5/10 volume share, a formal concentration index, and who rejects " +
          "more of their own reservations than they publish — rebuilt nightly from the same " +
          "corpus as CVE Ecosystem.",
        live: true,
      },
      {
        id: "breaches",
        href: "breaches.html",
        num: "05",
        label: "Breach Ledger",
        headline: "Dwell time is a marketing number. Breach disclosure is a public record.",
        blurb:
          "Every breach in Have I Been Pwned, read as a ledger: how long breaches take to " +
          "reach the public record, how many accounts spill per year, and which data " +
          "classes leak most — with the catalog's launch import kept out of the trend.",
        live: true,
      },
      {
        id: "extortion",
        href: "extortion.html",
        num: "06",
        label: "Extortion Ledger",
        headline: "Ransom revenue is the one security statistic nobody can spin — it settles on a public ledger.",
        blurb:
          "Confirmed ransomware payments from the crowdsourced, on-chain-verified " +
          "Ransomwhere dataset: revenue per quarter in day-of-transfer dollars, payment " +
          "counts and median sizes, and which families collect. Every figure is a lower " +
          "bound by construction, rebuilt nightly.",
        live: true,
      },
      {
        id: "attack",
        href: "attack.html",
        num: "07",
        label: "ATT&CK Churn",
        headline: "The map of attacker behavior grows every release.",
        blurb:
          "Active techniques and sub-techniques per MITRE ATT&CK enterprise release, what " +
          "each version added, deprecated, or revoked, and the group-and-software catalog " +
          "underneath — parsed nightly from MITRE's own STIX bundles.",
        live: true,
      },
      {
        id: "hygiene",
        href: "hygiene.html",
        num: "08",
        label: "Hygiene Index",
        headline: "The fix is two decades old, free, and still not deployed.",
        blurb:
          "DNSSEC validation as measured by APNIC Labs — the world adoption line since " +
          "2013, the ten biggest online populations compared, and how many economies " +
          "actually check their DNS answers. Rebuilt nightly.",
        live: true,
      },
      {
        id: "guards",
        href: "guards.html",
        num: "09",
        label: "Security Products",
        headline: "The products guarding the network keep landing on the exploited list.",
        blurb:
          "Every CISA KEV entry classified with a curated, versioned list of security " +
          "vendors and products: the guard share of the catalog year by year, the vendors " +
          "that keep coming back, and how hard the ransomware flag leans on exploited " +
          "security products. Rebuilt nightly.",
        live: true,
      },
      {
        id: "epss",
        href: "epss.html",
        num: "10",
        label: "EPSS Report Card",
        headline: "The industry's exploit forecast rarely gets an outside grade. CyberMon grades it.",
        blurb:
          "For every CVE that CISA later confirmed exploited, the EPSS score published " +
          "the day before the KEV listing — the forecast's last chance to sound the " +
          "alarm. Grade bands per catalog year, the day-before distribution split by " +
          "model version, and where the model ranked the confirmed-exploited cohort.",
        live: true,
      },
      {
        id: "calendar",
        href: "calendar.html",
        num: "11",
        label: "CVE Calendar",
        headline: "The CVE stream keeps vendor time.",
        blurb:
          "How old a CVE's ID already is the day it publishes, which weekday the " +
          "stream actually spikes, and how much of each year lands on the twelve " +
          "patch Tuesdays — publication timing, read straight off the corpus every " +
          "night.",
        live: true,
      },
      {
        id: "changelog",
        href: "changelog.html",
        num: "12",
        label: "KEV Changelog",
        headline: "CISA edits the exploited list without a changelog. CyberMon keeps the diffs.",
        blurb:
          "Every night the Known Exploited Vulnerabilities catalog is diffed " +
          "against the last observed one: due dates that moved, ransomware flags " +
          "that flipped, descriptions that were rewritten, entries that quietly " +
          "vanished — seeded backwards with Internet Archive captures of the " +
          "feed, then extended one nightly diff at a time.",
        live: true,
      },
      {
        id: "rescores",
        href: "rescores.html",
        num: "13",
        label: "Silent Rescores",
        headline: "Severity gets edited after publication. Nobody announces the edits.",
        blurb:
          "Every night CyberMon diffs each CVE's CNA-assigned score against the " +
          "previous night's corpus and logs what moved: scores raised, scores " +
          "lowered, and scores added after the fact — occasionally years after " +
          "the record published, more often in bulk batches days later. No " +
          "upstream keeps this history; the record started July 2026 and " +
          "deepens every night.",
        live: true,
      },
      {
        id: "naming",
        href: "naming.html",
        num: "14",
        label: "Naming Chaos",
        headline: "One adversary, a roomful of names.",
        blurb:
          "MITRE ATT&CK files each threat group under one name and lists the " +
          "aliases every other vendor uses for it — a most-renamed leaderboard " +
          "and the alias-count distribution across the active roster, read from " +
          "the current enterprise STIX bundle each night.",
        live: true,
      },
      {
        id: "top25",
        href: "top25.html",
        num: "15",
        label: "CWE Top 25",
        headline: "The official worst-bugs list, checked against what ships and gets exploited.",
        blurb:
          "MITRE's annual CWE Top 25 set beside raw first-listed-CWE prevalence " +
          "in the CVE corpus and the exploited (CISA KEV) cut: the official rank " +
          "of each class against the rank it actually earns, and which of the 25 " +
          "get weaponized. Rebuilt nightly.",
        live: true,
      },
      {
        id: "adp",
        href: "adp.html",
        num: "16",
        label: "Vulnrichment",
        headline: "When the scorekeeper walked off, CISA picked up the pen.",
        blurb:
          "As NVD's enrichment stalled through 2024, CISA's Vulnrichment " +
          "program — the CISA-ADP container — quietly became the CVE " +
          "record's de-facto enricher. The monthly handoff curve by the " +
          "container's own update date, what it adds (SSVC almost always, " +
          "CVSS and CWE as patch-ins), and the board where one agency does " +
          "nearly all of it. Read nightly from the CVE List.",
        live: true,
      },
      {
        id: "epssvol",
        href: "epssvol.html",
        num: "17",
        label: "EPSS Volatility",
        headline: "Teams triage on a number that reshuffles under most CVEs every night.",
        blurb:
          "Every night CyberMon diffs the EPSS feed against the night before. " +
          "The model's actual probability holds for nearly every CVE; the " +
          "percentile teams gate on moves under almost all of them, because the " +
          "corpus keeps growing and the whole population re-ranks. Material " +
          "threshold crossings, the percentile-vs-probability gap, and the " +
          "biggest single-day moves — a change log no upstream maintains, so " +
          "the record starts now.",
        live: true,
      },
      {
        id: "roster",
        href: "roster.html",
        num: "18",
        label: "CNA Roster",
        headline: "The CVE federation grows and churns. Nobody keeps the history.",
        blurb:
          "The CVE Program publishes who can assign a CVE today but no record " +
          "of how the roster got there. CyberMon snapshots it every night and " +
          "keeps the diff: onboardings, departures, scope changes, and the " +
          "current composition by type, root and country — a churn history that " +
          "starts at first deploy because no accreditation date is published.",
        live: true,
      },
    ],
  },

  sampleBanner:
    "SYNTHETIC SAMPLE DATA — first real pipeline run pending. " +
    "Numbers below are shaped placeholders, not claims.",

  staleBanner:
    "THIS EDITION IS {age_days} DAYS OLD — the nightly refresh has not landed " +
    "since {generated_at}. Numbers below are real but not current.",

  loadError: {
    title: "This section's data failed to load.",
    // {file} is rendered as an inline <code> element by the error card builder.
    body: "Couldn't fetch {file}. The rest of the page still works — reload to retry.",
  },

  methodologyLabel: "How this is computed",
  chartSourcePrefix: "Data: ",
  chartSourceLinkText: "all sources & licenses ↓",
  methodologySourcePrefix: "Source of truth: ",
  methodologySourceLinkText: "pipeline/metrics.py",

  // Shared by every chart that draws a full-year pace projection for the
  // partial current year (volume curve, 9.8 flood, new entrants). The
  // pipeline emits the projection only for flow metrics — see
  // docs/data-contracts.md, "Pace projections".
  projection: {
    note:
      "Dashed or hollow marks: the partial year carried forward at its " +
      "current pace — calendar arithmetic, not a forecast.",
    tooltipProjected: "{name} · projected full year ≈ {n}",
    tooltipElapsed: "{pct} of the year elapsed",
    floodLabel: "≈ {n} projected",
    floodTooltipName: "All severities",
  },

  sections: {
    // ------------------------------------------- market.html · 1 · hero
    hype: {
      num: "01",
      kicker: "Hype curves",
      source: "GDELT 2.0 · Hacker News via Algolia · arXiv cs.CR · Wikipedia pageviews · SEC EDGAR full-text search",
      headline: "Every term is graded against its own best month.",
      caption:
        "Media mentions (GDELT news coverage), practitioner chatter (Hacker News), " +
        "research output (arXiv cs.CR preprints), public curiosity (Wikipedia " +
        "pageviews), and investor-facing filings (SEC EDGAR) for one term at a time, " +
        "each indexed to its own five-year peak so a slow-burning research topic and a " +
        "marketing blitz can share an axis without one drowning the other. Pick a term; " +
        "the cards are shortcuts.",
      selectLabel: "Term",
      termCountNote: "Tracking {n} terms — curated list: pipeline/market_terms.py",
      sparklineNote:
        "Click a card to load it above. Sparklines show the media (GDELT) index only — terms " +
        "still waiting on a media fetch show an honest blank, not an invented curve.",
      methodology:
        "For each tracked term and each of five sources — GDELT 2.0 (news article volume), " +
        "Hacker News (Algolia search API, stories and comments), arXiv (cs.CR preprint " +
        "count), Wikipedia (monthly pageviews of one curated on-topic article per term, " +
        "bot traffic excluded; the term-to-article mapping is reviewable data in " +
        "pipeline/market_terms.py, and a term with no on-topic article has no Wikipedia " +
        "series), and SEC EDGAR full-text search (filings matching the term as a quoted " +
        "phrase, acronyms spelled out to dodge finance collisions) — the pipeline pulls a " +
        "monthly count over a rolling five-year window. Each " +
        "series is indexed to its own highest month in that window (peak = 100); this is " +
        "recomputed nightly, so a new peak nudges every earlier point down proportionally. " +
        "Raw counts ride along in the tooltip for every point. Series are deliberately not " +
        "shown as a share of the tracked term list — adding or retiring a term would " +
        "silently reshape every other term's history under that scheme. If a source's fetch " +
        "fails or is rate-limited (GDELT throttles aggressively), that stretch stays blank " +
        "until a nightly run heals it — a line that starts partway through the window is a " +
        "gap in collection, not in the world. The month in progress is collected but never " +
        "charted, ranked, or averaged until it closes: ten days of a month would read as a " +
        "cliff at the end of every curve.",
    },

    // ------------------------------------------- market.html · 2
    risers: {
      num: "02",
      kicker: "Risers & fallers",
      source: "GDELT 2.0 · Hacker News via Algolia · arXiv cs.CR · Wikipedia pageviews · SEC EDGAR full-text search",
      headline: "Same twelve months, opposite direction.",
      caption:
        "Year-over-year change in mention volume, term by term and source by source — the " +
        "last twelve collected months against the twelve before that. A term can rise in " +
        "the press while falling on Hacker News; the board keeps sources separate on " +
        "purpose, because hype and adoption are not the same claim.",
      statRiserLabel: "Steepest riser",
      statFallerLabel: "Steepest faller",
      statTemplate: "{label} · {source}",
      colTerm: "Term",
      colSource: "Source",
      colChange: "YoY change",
      colVolume: "Last 12 months",
      eligibilityNote:
        "Rows need a full two years of collected data and a minimum volume to post a YoY " +
        "figure; terms whose fetch hasn't completed for a source — new, mid-backfill, or " +
        "waiting out an upstream rate limit — are omitted until then.",
      methodology:
        "For each (term, source) pair, sum raw monthly counts for the most recent twelve " +
        "populated complete months (the month in progress never counts) and the twelve months before that; YoY change is the percentage " +
        "difference between the two sums. Pairs with fewer than twenty-four populated " +
        "months, a zero-count prior-year baseline, or fewer than thirty raw hits across " +
        "both windows are excluded — a percentage computed on a handful of hits means " +
        "nothing. Sort any column; default is steepest riser first.",
    },

    // ------------------------------------------- market.html · 3
    divergence: {
      num: "03",
      kicker: "Research vs. media divergence",
      source: "GDELT 2.0 · arXiv cs.CR",
      headline: "Some terms are ahead of the papers. Others are ahead of the proof.",
      caption:
        "Each term placed by how close it currently sits to its own research peak (arXiv, " +
        "vertical) versus its own media peak (GDELT, horizontal). Above the line, academia " +
        "is further into the cycle than the press has noticed. Below the line, marketing " +
        "has outrun the research base. On the line, the two move together.",
      statLabel: "Widest divergence",
      statTemplate: "{label} · {direction}, {points} index points apart",
      directionResearchLeads: "research leads",
      directionMediaLeads: "media leads",
      directionAligned: "aligned",
      xAxisLabel: "Media attention index (GDELT, % of own 5y peak)",
      yAxisLabel: "Research attention index (arXiv, % of own 5y peak)",
      legendResearchLeads: "Research leads",
      legendMediaLeads: "Media leads",
      legendAligned: "Aligned",
      coverageNote:
        "{plotted} of {total} tracked terms currently have enough data in both sources to " +
        "plot; the rest join as collection fills in.",
      methodology:
        "Each axis is the term's own attention index (see Hype curves methodology), " +
        "averaged over the three most recent populated complete months (the month in progress never counts), for GDELT (x) and arXiv " +
        "(y). Of the five collected sources, this chart deliberately stays with GDELT " +
        "versus arXiv: they remain the cleanest media-versus-research pair — Wikipedia " +
        "pageviews mix both audiences, SEC filings track investor language, and Hacker " +
        "News sits somewhere between all of them, so none of the three sharpens the " +
        "comparison. A term's divergence score is the y-axis value minus the x-axis value, in " +
        "index points; scores beyond ±10 are labeled “research leads” or “media leads,” " +
        "everything inside that band is “aligned” — a deliberately wide dead zone, since " +
        "both indices carry real month-to-month noise. Terms missing three recent " +
        "populated months in either source — usually a source still waiting on " +
        "collection — are omitted, as are terms with fewer than ten raw hits across a " +
        "source's three averaged months: a couple of papers against a tiny peak makes " +
        "an index of 100, not a divergence.",
    },

    // -------------------------------------------------------------- 1 · hero
    inflation: {
      num: "01",
      kicker: "Severity inflation",
      source: "cvelistV5 (MITRE) — CNA-assigned scores",
      headline: "Four of every ten CVEs ship as “High” or worse.",
      caption:
        "Median CVSS base score of newly published CVEs, year by year, split by scoring " +
        "version — v3 runs structurally higher than v2, so the version-split lines keep a " +
        "methodology change from masquerading as drift. The chart begins where CNA-assigned " +
        "scores become dense enough to chart honestly (the footnote has the bar). What the " +
        "dense years show: medians parked at the doorstep of “High,” and four to five of " +
        "every ten scored CVEs rated 7.0 or worse, year after year. A scale whose midpoint " +
        "lives that far up has stopped ranking anything.",
      statLabel: "Share of scored CVEs rated High or Critical (base score ≥ 7.0)",
      statLatest: "{latest_year}",
      statAgo: "{ago_year}",
      methodology:
        "For every CVE in the cvelistV5 corpus we take the CNA-assigned base score, split by " +
        "CVSS version (v2 / v3.x / v4). Lines are the median score of CVEs published each year; " +
        "shaded bands span the 25th–75th percentile (IQR). A record scored under several versions " +
        "appears in each version's series, but exactly once in the blended line, using its newest " +
        "version's score. “% High or Critical” is the share of scored CVEs that year with base " +
        "score ≥ 7.0; unscored CVEs are excluded. Vertical markers are CVSS spec releases " +
        "(those that fall inside the charted span). " +
        "Honesty filters: a point is plotted only if that year has at least 100 scored CVEs in " +
        "that series; per-version points cannot predate the version's spec release (CNAs " +
        "backfill scores onto old records); and the blended line additionally requires scores " +
        "on at least 20% of the CVEs published that year — years with 1% coverage chart which " +
        "records got backfilled, not what was published. The headline compares the latest " +
        "COMPLETE year against the year ten years before it (or the earliest year that clears "
        + "these filters, until the record is that deep) — the current year " +
        "plots (labeled partial, refilled nightly) but never headlines: six months of data " +
        "would fake a trend.",
    },

    // ------------------------------------------------------------------- 2
    flood: {
      num: "02",
      kicker: "The 9.8 flood",
      source: "cvelistV5 (MITRE)",
      headline: "“Critical” was an exception. Now it's a product line.",
      caption:
        "Published CVEs per year, bucketed by the base score embedded in the CVE record. " +
        "Watch the red band: close to four thousand records a year now ship stamped Critical " +
        "— the half-written current year has already passed that mark — and nearly " +
        "everything arrives pre-labeled, so the label does all the triage. Read " +
        "the years left of the vertical marker through it: severity existed there too, but " +
        "it lived downstream in NVD's database, which this chart deliberately does not " +
        "read — the wide gray band is a fact about the record format, not about the era's " +
        "vulnerabilities. The current year is partial; its bars are still filling in.",
      eraMarker: "← scored in NVD, not in the record",
      toggleAbsolute: "Absolute",
      toggleShare: "Share of year",
      methodology:
        "CVEs are bucketed by their base score (highest CVSS version available per record): " +
        "Critical ≥ 9.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.0–3.9. “No score in record” " +
        "counts CVEs published that year with no base score anywhere in the CVE record " +
        "itself — CNA or CISA-ADP container. The vertical marker is computed, not " +
        "decorative: it sits at the first year in which at least 10% of published records " +
        "carry an in-record score. Read the early years carefully: before ~2018 scoring wasn't " +
        "done in the record at all — CNAs filed bare entries and NVD assigned CVSS " +
        "downstream, in its own database (which this chart deliberately does not ingest). " +
        "The unscored band's collapse since is the scoring duty migrating to the source: " +
        "CNA self-scoring rose from under 2% of records (2017) to roughly four in five " +
        "(as of mid-2026), and when NVD's enrichment stalled in 2024, CISA's Vulnrichment " +
        "program (the ADP container) began backstopping the rest — as of mid-2026, about " +
        "a quarter of 2024's records carry only a CISA score, a share CNA backfill keeps " +
        "eroding. " +
        "The share view normalizes each year to 100%. The current year (marked *) is " +
        "partial and refills nightly. In the absolute view, a dashed marker at the " +
        "current-year edge paces the partial year's total — all published records, " +
        "unscored included — to twelve months: the count so far divided by the fraction " +
        "of the UTC calendar year elapsed at generation time, shown only once 12.5% of " +
        "the year has elapsed (roughly mid-February). The pace assumes uniform " +
        "publication through the year and ignores seasonality and late-year backfill; " +
        "the severity mix is deliberately unprojected, and the share view carries no " +
        "marker because shares are already normalized to their year.",
    },

    // ------------------------------------------------------------------- 3
    reality: {
      num: "03",
      kicker: "Score vs. reality",
      source: "cvelistV5 (MITRE) · EPSS (FIRST.org) · CISA KEV",
      headline: "Severity is not risk. The two barely correlate.",
      caption:
        "Every scored CVE with a current EPSS estimate, placed on a grid: CVSS severity on one " +
        "axis, real-world exploitation probability on the other. If scores tracked risk, the mass " +
        "would sit on the diagonal. It doesn't — six in ten Critical-rated CVEs carry less than " +
        "a 1% probability of exploitation, while the catalog of vulnerabilities actually being " +
        "exploited (CISA KEV) includes entries CVSS rates below High.",
      statCriticalTemplate: "{pct} of Critical-rated CVEs have <1% probability of exploitation",
      statCriticalNote: "per EPSS, across {n} Critical CVEs with a current score",
      statKevTemplate: "{pct} of actively exploited vulnerabilities are rated below High",
      statKevNote: "{below_high} of {total} scored CISA KEV entries rate under 7.0",
      kevBarTitle: "KEV entries by CVSS bucket",
      methodology:
        "The grid covers scored CVEs that have a current EPSS score; each cell counts CVEs in " +
        "that (CVSS bucket × EPSS probability bucket). Cell color uses a log-like scale so " +
        "sparse cells stay visible. The first stat is the share of CVEs rated ≥ 9.0 whose EPSS " +
        "probability is below 1%. The KEV stat is the share of CISA Known Exploited " +
        "Vulnerabilities catalog entries whose CVSS base score is below 7.0. EPSS estimates the " +
        "probability of exploitation in the next 30 days; it is a model, not ground truth — but " +
        "it is the best public one.",
    },

    // ------------------------------------------------------------------- 4
    decay: {
      num: "04",
      kicker: "NVD decay",
      source: "NVD API 2.0 (NIST) · CyberMon's own nightly snapshots",
      headline: "The scorekeeper stopped keeping score.",
      caption:
        "NVD's job is to enrich CVEs — analyze, score, tag. The bars show every CVE by NVD's " +
        "own status label; the live queue is the sliver at the bottom, and it looks small for " +
        "a reason: tens of thousands of CVEs were quietly stamped “Deferred” — analysis not " +
        "pending, analysis cancelled. The queue wasn't worked off; it was reclassified away. " +
        "The line tracks the remaining queue, one nightly snapshot at a time. When the " +
        "referee stops grading, the industry grades itself.",
      note:
        "NVD publishes no backlog history — CyberMon started keeping this nightly record on " +
        "{first_date}.",
      barsTitle: "All CVEs by NVD status (log scale — queue statuses in red)",
      lineTitle: "Backlog total, nightly snapshots",
      methodology:
        "Statuses come from NVD's vulnStatus field at fetch time (full corpus, synced " +
        "incrementally against the API and reswept weekly from NVD's yearly feeds). “Backlog " +
        "total” = Received + Awaiting Analysis + Undergoing Analysis; “Deferred” is NVD's " +
        "label for CVEs it has decided not to enrich. The bar axis is logarithmic — the " +
        "Modified pile is two orders of magnitude larger than the live queue and would " +
        "otherwise erase it. Because NVD exposes no historical series, CyberMon appends one " +
        "row per nightly run to its own committed CSV (data/history/nvd_backlog.csv, last " +
        "run per date wins) — the history you see starts when this record did.",
    },

    // ------------------------------------------------------------------- 5
    throughput: {
      num: "05",
      kicker: "NVD throughput",
      source: "NVD API 2.0 (NIST) · CyberMon's own nightly snapshots",
      headline: "NVD publishes the pile, never the pace.",
      caption:
        "The chart above counts the backlog; this one watches it move. Every night " +
        "CyberMon diffs its snapshot of every CVE's NVD status against the previous " +
        "night's, and the differences are the day's traffic: new CVEs arriving and records " +
        "leaving the analysis queue as Analyzed or as Deferred. Held " +
        "long enough, the same diffs also clock the queue — how many days a CVE visibly " +
        "waits before its analysis lands. All of it is measured from the outside; NVD " +
        "itself reports only the totals.",
      note:
        "NVD publishes no transition history — CyberMon's record of these flows starts " +
        "{first_date}. Waits are clocked between our own nightly snapshots, so every " +
        "duration is a lower bound.",
      lineTitle: "CVEs moved per day, one point per nightly diff",
      seriesAnalyzed: "Analyzed (left the queue)",
      seriesDeferred: "Deferred (waved off)",
      seriesReceived: "Newly received",
      statMedianLabel: "median observed wait in the analysis queue",
      statMedianBig: "{days} days",
      statMedianNote:
        "across {n} timed queue exits — each one a lower bound; the clock starts at " +
        "our first sighting of the CVE in the queue. A young record can only have " +
        "timed short waits so far: expect this figure to grow as the record ages.",
      statCountLabel: "timed queue exits collected so far",
      statCountNote:
        "the median publishes at {min_known} timed exits — fewer would let one odd " +
        "week pose as a trend",
      resweepFlag: "full-resweep day — may include catch-up from healed sync gaps",
      methodology:
        "Each nightly run syncs NVD's per-CVE vulnStatus (incremental API pulls; a full " +
        "resweep from NVD's yearly feeds at least weekly) and diffs the fresh snapshot " +
        "against the previous one. A status change between snapshots is a transition; the " +
        "chart counts them per day: CVEs entering “Received,” entering “Awaiting " +
        "Analysis,” leaving the live queue for “Analyzed,” and leaving it for “Deferred.” " +
        "Dates attach at observation: NVD publishes no status-change timestamps, so a " +
        "CVE's status is stamped with the day CyberMon first saw it. A queue wait is " +
        "therefore the span between our sighting of the entry and our sighting of the " +
        "exit — lower-bounded by the nightly cadence, and blind to hops that happen " +
        "between two snapshots. Statuses recorded before this tracker shipped carry no " +
        "entry date; their transitions count in the flow but are never timed — an " +
        "unknown date stays unknown rather than being backfilled. The median stat stays " +
        "unpublished until {min_known} timed exits have accumulated — below that a median " +
        "is noise wearing a unit. Weekly full resweeps can heal missed sync windows and " +
        "land several days of catch-up transitions on one date; those rows are flagged in " +
        "the record and in the tooltip. One row per run date is appended to a committed " +
        "CSV (data/history/nvd_throughput.csv, last run per date wins) — like the backlog " +
        "record above, it is append-only and irreplaceable: the history starts when we " +
        "started keeping it.",
    },

    // ------------------------------------------------------------------- 6
    cna: {
      num: "06",
      kicker: "CNA rubber-stamp board",
      source: "cvelistV5 (MITRE) — CNA-assigned scores",
      headline: "Who grades their own homework hardest?",
      caption:
        "CVE Numbering Authorities score the vulnerabilities they publish. These are their own " +
        "assigned numbers — not NVD's — ranked by how often they reach for 9-point-something. " +
        "Some CNAs hand a 9+ to two of every five CVEs they score; others, at a hundred times " +
        "the volume, almost never reach that shelf. Same scale, same spec — the gap is " +
        "scoring policy.",
      colCna: "CNA",
      colN: "CVEs",
      colAvg: "avg CVSS",
      colMedian: "median",
      colGeq9: "% ≥ 9.0",
      colGeq7: "% ≥ 7.0",
      windowTemplate: "CNA-assigned scores · last {window_years} years · min {min_cves} scored CVEs",
      methodology:
        "For each CNA (the record's assigner in cvelistV5) we aggregate the base scores that CNA " +
        "itself assigned over a rolling {window_years}-year window — that is the point of the " +
        "board: who assigns what. CNAs with fewer than {min_cves} scored CVEs in the window are " +
        "excluded so small samples can't top the table. Default sort: share of scores ≥ 9.0, " +
        "descending. Click any column header to re-sort.",
    },

    // ------------------------------------------------------------------- 7
    volume: {
      num: "07",
      kicker: "Volume curve",
      source: "cvelistV5 (MITRE)",
      headline: "More CVEs than anyone can read.",
      caption:
        "CVE records published per year, with rejections alongside. The curve explains the rest " +
        "of the page: at this volume, triage runs on the severity label alone — which is exactly " +
        "why an inflated label is expensive. The rejection line is the system's error-correction " +
        "budget: it collapsed from a fifth of everything shipped in 2017 to under two percent " +
        "by 2023 — and the last two complete years bent it back up. The current year is " +
        "partial — the apparent dip at the right edge is a year still being written.",
      toggleLinear: "Linear",
      toggleLog: "Log scale",
      methodology:
        "Counts come from the cvelistV5 corpus: “published” is CVE records by original " +
        "publication year; “rejected” is records with state REJECTED, counted by the same year. " +
        "The log toggle only rescales the axis — same data. The current year is labeled " +
        "partial and refills nightly; it is not comparable to a finished year. The dashed " +
        "segment and hollow marker pace that partial year to twelve months: the count so far " +
        "divided by the fraction of the UTC calendar year elapsed at generation time. The " +
        "projection appears only once 12.5% of the year has elapsed (roughly mid-February — " +
        "earlier, the divisor is too small to mean anything), assumes publication runs " +
        "uniformly through the year, and ignores seasonality and late-year backfill. The " +
        "solid line keeps showing the actual partial count.",
    },

    // ------------------------------------------------------------------- 8
    quality: {
      num: "08",
      kicker: "Advisory quality",
      source: "cvelistV5 (MITRE)",
      headline: "A CVE record is still allowed to say almost nothing.",
      caption:
        "For each year's published CVE records, the share missing each of three " +
        "machine-readable fields: a weakness class (CWE), a CVSS base score, and structured " +
        "affected-version data. A gap on any line is work exported downstream — every " +
        "scanner, triage queue, and dependency checker that meets the record has to " +
        "reconstruct the same missing field by hand. The methodology note matters more than " +
        "usual here: for two of these fields, the early corpus kept the data in NVD instead.",
      legendCwe: "No CWE",
      legendCvss: "No CVSS score",
      legendAffected: "No usable version data",
      methodology:
        "For every published record in the cvelistV5 corpus (rejected records excluded), " +
        "three checks against the record itself, CNA and ADP containers both: a CWE counts " +
        "as present if any problemTypes description carries a cweId; a CVSS score counts if " +
        "any metrics container carries a base score of any CVSS version; affected-version " +
        "data counts if any affected[] entry has either a versions[] item with a concrete " +
        "version string — placeholders like “n/a” and “unspecified” do not count — or a " +
        "defaultStatus that commits to “affected” or “unaffected” (“unknown” commits to " +
        "nothing). Each line is that year's missing count over its published total; the " +
        "tooltip carries the counts. A year plots only with at least 500 published records. " +
        "Read the CWE and CVSS lines against the corpus's history: before ~2018, " +
        "classification and scoring happened downstream in NVD's own database, which this " +
        "chart deliberately does not ingest — the early plateau charts where the data lived, " +
        "and the decline since is the duty migrating into the record (the 9.8 flood chart " +
        "tells the scoring half of that story). The current year (marked *) is partial and " +
        "refills nightly.",
    },

    // ------------------------------------------------------------------- 9
    cwe: {
      num: "09",
      kicker: "Bug-class inertia",
      source: "cvelistV5 (MITRE)",
      headline: "The bug classes outlast the news cycle.",
      caption:
        "The eight most common weakness classes of the last ten complete years, each " +
        "tracked as its slice of that year's CWE-tagged records, with everything else " +
        "pooled as “Other.” Memory-safety errors and the injection classics anchor the " +
        "list across the whole window — a decade of churn in tooling, funding, and " +
        "research agendas shows up here as swings of a few points to a dozen-plus at the " +
        "extreme — never as a class leaving the board.",
      // rendered as a panel-note by cve.js (same slot the decay chart uses)
      note:
        "Shares are of CWE-tagged records only; each year's tooltip shows how much of " +
        "that year's corpus carried a tag at all.",
      otherLabel: "Other",
      methodology:
        "Each CWE-tagged published record contributes its first-listed CWE id (CNA " +
        "container preferred, CISA-ADP as fallback) — one class per record, so a year's " +
        "shares sum to roughly 100 after rounding. The top 8 are ranked by total tagged " +
        "volume across the last ten complete calendar years; the partial current year is " +
        "excluded from both the window and the ranking, because six months cannot rank a " +
        "decade. Shares are of CWE-tagged records only, and coverage varies enormously by " +
        "year — each year's tooltip carries its tagged count and its share of all " +
        "published records, so the denominator is never hidden. A year plots only with at " +
        "least 500 tagged records. Class names come from a small built-in map in the " +
        "pipeline; ids the map doesn't know are shown as bare CWE numbers.",
    },

    // --------------------------------------------- kev.html · 1 · hero
    latency: {
      num: "01",
      kicker: "Listing latency",
      source: "CISA KEV · cvelistV5 (MITRE)",
      headline: "By the time CISA confirms it, the exploit had a head start.",
      caption:
        "For every CVE the government lists as Known Exploited, the gap from the CVE's own " +
        "publication date to the day CISA added it to the catalog — median and interquartile " +
        "range, one point per year CISA made the addition. The catalog's 2021–22 seeding era " +
        "is excluded here (see the callout): it launched by inheriting a backlog of years-old " +
        "CVEs and kept importing back-catalog through 2022, which would flatten the whole " +
        "trend into one artificial spike. What's left is the catalog's actual cadence since — " +
        "and it has been getting slower, not faster.",
      statLabel: "Median days from CVE publication to KEV listing",
      statLatest: "{latest_year}",
      statAgo: "{ago_year}",
      backfillNote:
        "{n} entries were added in the catalog's seeding era (November 2021 launch through " +
        "2022, before {date_added_before}) — median nominal latency {median_days} days. That " +
        "figure is a catalog-import artifact, not a triage measurement, and is excluded from " +
        "the chart above.",
      methodology:
        "For every entry in CISA's Known Exploited Vulnerabilities catalog that matches a CVE " +
        "record in the cvelistV5 corpus, latency is the KEV dateAdded minus the CVE record's " +
        "datePublished, in days. The trend cohort starts in 2023: the catalog launched in " +
        "November 2021 by inheriting a backlog of years-old CVEs and kept bulk-importing its " +
        "back-catalog through 2022 (the data shows the regime change — the median 'latency' " +
        "of 2022 additions ran over a thousand days; of 2023 additions, twelve), so a seeding-era entry's " +
        "nominal latency measures the age of the backlog, not the speed of triage — it is " +
        "reported in the callout, never plotted in the trend. Negative " +
        "latencies are kept as negative, not floored at zero: a KEV listing that predates its " +
        "own CVE record is a real event — exploitation confirmed before the paperwork " +
        "existed — and flooring it would quietly flatter the system. A year plots only if it " +
        "has at least 10 matched entries. KEV entries with no matching CVE record in the " +
        "corpus carry no publication date and are counted separately in the data file rather " +
        "than silently dropped.",
    },

    // --------------------------------------------- kev.html · 2
    buckets: {
      num: "02",
      kicker: "Latency distribution",
      source: "CISA KEV · cvelistV5 (MITRE)",
      headline: "Nearly four in ten KEV listings land inside a week. One in seven lands three years late.",
      caption:
        "The same matched cohort as the trend above, folded into buckets: how many listings " +
        "arrive before the CVE is even published, how many inside a week, a month, a quarter, " +
        "a year — and how many take one to three years, or longer. A median hides its tails; " +
        "this chart is the tails. The red bucket is the one worth staring at: exploitation " +
        "confirmed before the vulnerability formally existed.",
      methodology:
        "Every matched entry in the trend cohort (added 2023 or later; the 2021–22 seeding " +
        "era is excluded here for the same reason as above) is placed in exactly one bucket by " +
        "its latency: before publish (latency below zero), 0–7d, 8–30d, 31–90d, 91–365d, " +
        "1–3y, 3y+. Each bucket's lower edge is inclusive — a listing on day 8 is 8–30d, not " +
        "0–7d. Percentages are shares of the matched cohort, not of the full catalog: an " +
        "entry with no matching CVE record has no publication date, so it can't have a " +
        "latency and isn't assigned one.",
    },

    // --------------------------------------------- kev.html · 3
    remediation: {
      num: "03",
      kicker: "Remediation deadlines",
      source: "CISA KEV",
      headline: "The deadline shrank as the list grew.",
      caption:
        "How long federal agencies get to fix each KEV entry: the gap from the day CISA " +
        "lists a vulnerability to the remediation deadline it attaches, median and " +
        "interquartile range per year of listing. Unlike the latency chart, the seeding era " +
        "belongs here — the deadline is set the day the entry lands, back-catalog included, " +
        "so this is a policy timeline, not a backlog artifact. The early catalog handed out " +
        "months; the standing rule since has been three weeks — and the listings of the " +
        "half-written current year are so far coming in tighter still.",
      methodology:
        "Remediation span is the KEV dueDate minus dateAdded, in days, for every catalog " +
        "entry carrying both fields — no CVE match is needed, so this covers the catalog " +
        "itself, 2021 launch cohort included. The launch batch is excluded from the latency " +
        "trend because its nominal latency measures backlog age; its remediation spans, by " +
        "contrast, are real policy decisions made on the listing date and belong in this " +
        "chart. Lines are the median span of entries added each year; shaded bands span the " +
        "25th–75th percentile. For context: BOD 22-01 gave agencies six months for the older " +
        "launch-batch CVEs and two weeks for recent ones, and entries added since typically " +
        "carry about three weeks — the chart shows what CISA actually assigned, not what the " +
        "directive prescribes.",
    },

    // --------------------------------------------- kev.html · 4
    ransomware: {
      num: "04",
      kicker: "Ransomware share",
      source: "CISA KEV",
      headline: "The exploited list has a ransomware column.",
      caption:
        "CISA marks every KEV entry with whether the vulnerability is known to have been " +
        "used in ransomware campaigns. Bars show the share of each year's new listings " +
        "carrying that “Known” flag; the year's counts ride in the tooltip. The 2021–22 " +
        "seeding years belong on this chart, same as the remediation deadlines: the flag " +
        "rides on the entry itself, so a back-catalog import answers the question as well " +
        "as a fresh listing does. Inside a catalog that is already a priority list, this " +
        "flag is the sharpest tiebreaker it offers.",
      methodology:
        "Every entry in CISA's Known Exploited Vulnerabilities catalog carries " +
        "knownRansomwareCampaignUse (“Known” or “Unknown”). Per calendar year of dateAdded: " +
        "entries added, entries flagged “Known,” and the share. Entries missing the field " +
        "count as “Unknown.” The catalog is read as a current snapshot — each entry shows " +
        "CISA's present assessment, whichever year it was listed — which is why the seeding " +
        "era charts here alongside the rest while the latency trend quarantines it. No " +
        "CVE-record join is involved; the chart needs nothing beyond the catalog itself. A " +
        "year plots only with at least 10 entries. The current year (marked *) is partial " +
        "and refills nightly.",
    },

    // --------------------------------- concentration.html · 1 · hero
    concentration: {
      num: "01",
      kicker: "Volume concentration",
      source: "cvelistV5 (MITRE)",
      headline: "More assignors than ever. The volume still belongs to a handful.",
      caption:
        "Three lines from one corpus: how many CVE Numbering Authorities published at least " +
        "one record each year, and what share of the year's volume came from the top 5 and " +
        "top 10 of them. The CNA program keeps growing — federation is the point — and for a " +
        "decade output slowly dispersed with it. Since 2023 that trend has reversed: the " +
        "roster grew seventeen-fold, yet five of its hundreds of names still ship a majority " +
        "of the database, and their share is climbing again — under a design in which every " +
        "assigner, vendor or not, grades its own submissions.",
      statLabel: "Share of published CVEs from the year's top 5 CNAs",
      statLatest: "{latest_year}",
      statAgo: "{ago_year}",
      methodology:
        "Each CVE record's assigner (the CNA of record in cvelistV5) is counted by original " +
        "publication year; a CNA is active in a year if it published or rejected at least one record. " +
        "Top-5/top-10 share is the fraction of that year's volume from its five or ten " +
        "largest assignors, membership recomputed every year — the names in the top 5 " +
        "change even when the share doesn't move. The pipeline also computes a " +
        "Herfindahl–Hirschman Index per year (the sum of squared volume shares, on the " +
        "0–10,000 scale antitrust regulators use; {hhi_latest} for the latest complete year) as a " +
        "formal concentration measure that sees the whole distribution, not just the head. " +
        "HHI and top-N share can diverge — a fat head over a long tail moves them " +
        "differently — so this chart reports both rather than picking the more dramatic " +
        "one. Years with no published records still appear, at zero, so the axis never " +
        "silently skips time. The current year is partial and refills nightly.",
    },

    // --------------------------------- concentration.html · 2
    entrants: {
      num: "02",
      kicker: "New entrants",
      source: "cvelistV5 (MITRE)",
      headline: "New CNAs keep arriving. Most of them don't move the needle.",
      caption:
        "Bars count CNAs publishing their first-ever CVE record that year; the line is the " +
        "total active roster. Recruitment is real — the three biggest recruiting years on " +
        "record are the last three complete ones. Hold that against the chart above: the " +
        "newcomers add count, not share. The head of the table absorbs the growth.",
      methodology:
        "A newcomer in year Y is a CNA whose earliest record in the entire corpus (published or rejected) " +
        "falls in Y — first appearance in the data, not accreditation date, which the corpus " +
        "doesn't carry. The active-roster line counts CNAs with at least one published or " +
        "rejected record that year, the same definition as the concentration chart. Because first " +
        "appearance is computed against the full corpus, the first charted year counts " +
        "every CNA as new by construction — read the left edge accordingly. The current " +
        "year is partial and refills nightly. The hollow extension above the current-year " +
        "bar paces the newcomer count to twelve months: newcomers so far divided by the " +
        "fraction of the UTC calendar year elapsed at generation time, shown only once " +
        "12.5% of the year has elapsed (roughly mid-February). First appearances are " +
        "events, so a pace applies — under the strong assumption that newcomers arrive " +
        "uniformly through the year, ignoring seasonality and late-year backfill. The " +
        "active-roster line is never projected: a roster is a headcount, and a headcount " +
        "has no pace.",
    },

    // --------------------------------- concentration.html · 3
    rejection: {
      num: "03",
      kicker: "Rejection board",
      source: "cvelistV5 (MITRE)",
      headline: "Who rejects more than they publish?",
      caption:
        "Over the last {window_years} years, each CNA's published records against its " +
        "rejected ones — reservations formally withdrawn, duplicates collapsed, assignments " +
        "walked back. A high rate isn't necessarily bad practice: rejection is the system's " +
        "error-correction working in public, and a CNA that never rejects anything may " +
        "simply never re-check its own work. The board exists because the rate varies by an " +
        "order of magnitude across the program, and nobody publishes it.",
      colCna: "CNA",
      colTotal: "CVEs (pub+rej)",
      colRejected: "rejected",
      colRate: "rejection rate",
      windowTemplate:
        "CVE record states by assigner · last {window_years} years · min {min_total} records (published + rejected)",
      methodology:
        "For each assigner in cvelistV5, count records dated in the last " +
        "{window_years} years by state: PUBLISHED versus REJECTED. Rejection rate is " +
        "rejected over (published + rejected). CNAs with fewer than {min_total} total " +
        "records in the window are excluded — a two-for-two rejection record is an " +
        "anecdote, not a rate. Reserved-but-never-published IDs don't appear in the public " +
        "corpus at all and can't be counted here: this board measures what was shipped and " +
        "then withdrawn, not what was quietly never used. Default sort: rejection rate, " +
        "descending. Click any column header to re-sort.",
    },
    // ------------------------------------------------ breaches.html · 1 · hero
    disclosure: {
      num: "01",
      kicker: "Disclosure lag",
      source: "Have I Been Pwned breach catalog",
      headline: "The breach is old news before it makes the news.",
      caption:
        "For every breach in the public catalog, the gap between the date the breach " +
        "happened and the day Have I Been Pwned cataloged it — median and interquartile " +
        "range, grouped by the year of cataloging. The launch-month import stays in the " +
        "callout below, out of the trend. What the live-era record shows: the typical gap " +
        "is measured in months, and roughly a third of entries take more than a year to " +
        "surface. Vendors sell dwell-time figures measured on their own customers; this " +
        "chart measures a different clock — breach to public record — and it is the one " +
        "clock anyone can audit.",
      statLabel: "Median days from breach to public catalog",
      statWhole: "since {trend_start}",
      statLatest: "{latest_year}",
      importNote:
        "{n} breaches entered the catalog around its December 2013 launch (added before " +
        "{added_before}) — with a median nominal lag of {median_days} days. That figure " +
        "measures the opening import of already-public breaches, not disclosure speed, " +
        "and it stays out of the trend above.",
      methodology:
        "Lag is the breach's AddedDate minus its BreachDate, in days, for every cohort " +
        "breach in the Have I Been Pwned catalog (the volume chart's methodology has the " +
        "cohort arithmetic). BreachDate is self-reported and usually rounded to the first " +
        "of a month, so individual lags carry day-level noise; medians absorb it. The line " +
        "is the median lag of breaches cataloged each year; the shaded band spans the " +
        "25th–75th percentile. The trend starts in 2014, and the cutoff comes from the " +
        "data: HIBP launched on 2013-12-04 by importing breaches that were already " +
        "public — six of its seven opening-import entries predate the service itself, with " +
        "a median nominal lag of 511 days — while in 2014, the first full calendar year " +
        "the catalog ran live, the median collapses to 5 days. Old breaches keep " +
        "entering the catalog in every later year, and those stay in the trend on " +
        "purpose: a breach surfacing years late is exactly the phenomenon this chart " +
        "measures, and only the opening import is an artifact of the catalog's own " +
        "birthday. A lag can be negative — a breach cataloged before its stated breach " +
        "date — and is kept as negative rather than floored at zero (the KEV latency " +
        "chart applies the same rule): it flags date quality in the source record, and " +
        "flooring it would quietly hide that. A year plots only with at least 10 cohort " +
        "breaches. The current year (marked *) is partial and refills nightly.",
    },

    // ------------------------------------------------ breaches.html · 2
    exposure: {
      num: "02",
      kicker: "Volume",
      source: "Have I Been Pwned breach catalog",
      headline: "The breach business has no slow years.",
      caption:
        "Breaches cataloged per year, and the accounts exposed inside them — bars count " +
        "incidents, the line counts accounts, on a log axis because a single mega-dump " +
        "can outweigh a whole ordinary year. Read the line's floor: even the quietest " +
        "year of the live era spilled tens of millions of accounts. And read the whole " +
        "chart as a floor on reality — the catalog holds what surfaced publicly and got " +
        "loaded, nothing more. The current year is partial and refills nightly.",
      catalogNote:
        "Cohort: {cohort} of {total} cataloged breaches. Excluded: {fabricated} " +
        "fabricated, {spam_list} spam lists, {malware} malware corpora, {stealer_log} " +
        "stealer-log batches — real data in the last two cases, but a breached " +
        "organization is the unit this ledger counts.",
      legendBreaches: "Breaches cataloged",
      legendRecords: "Accounts exposed",
      methodology:
        "Counts come from the full Have I Been Pwned breach catalog, grouped by the " +
        "calendar year of AddedDate. The cohort excludes, in precedence order: fabricated " +
        "entries (IsFabricated — the incident never happened), spam lists (IsSpamList — " +
        "address collections with no breached organization), malware corpora (IsMalware) " +
        "and stealer logs (IsStealerLog). The last two are real credential theft, but " +
        "harvested device-by-device from malware victims: there is no single breached " +
        "organization, and their nominal breach date describes the compilation of the " +
        "corpus rather than an incident, which would poison the lag chart above. Each " +
        "excluded entry counts under its first matching reason, so the exclusions plus " +
        "the cohort always sum to the catalog total — the note under the chart is the " +
        "audit trail. Accounts per year is the sum of PwnCount, HIBP's count of " +
        "compromised accounts per breach; the same person appears once per breach " +
        "they're in, so the sum counts exposures rather than people. The import-era " +
        "additions of December 2013 chart here like any other year — a cataloged breach " +
        "is a cataloged breach; only the lag chart quarantines the import. In the bars, " +
        "a dashed hollow extension paces the partial current year's breach count to " +
        "twelve months: the count so far divided by the fraction of the UTC calendar " +
        "year elapsed at generation time, shown only once 12.5% of the year has elapsed " +
        "(roughly mid-February), under the strong assumption that cataloging runs " +
        "uniformly through the year. The accounts line is deliberately never projected: " +
        "one mega-dump can carry more accounts than the rest of the year combined, so a " +
        "records pace would dress one upload up as a forecast.",
    },

    // ------------------------------------------------ breaches.html · 3
    leaks: {
      num: "03",
      kicker: "What leaks",
      source: "Have I Been Pwned breach catalog",
      headline: "Email is in nearly every bag. The rest of the take varies.",
      caption:
        "The six data classes that appear most often across the whole catalog, each " +
        "tracked as the share of that year's breaches containing it. A breach lists " +
        "every class it spilled, so the lines are independent — they will never sum to " +
        "anything. Email addresses are the constant; every other class, passwords " +
        "included, swings by tens of points from year to year.",
      methodology:
        "The class list is derived from the data every night: all data classes across " +
        "the cohort are ranked by the number of breaches listing them, and the top six " +
        "chart (the catalog distinguishes well over a hundred classes; the tail is " +
        "sparse). Each line is the share of that year's cohort breaches — grouped by " +
        "AddedDate year, import era included — whose DataClasses field lists that class, " +
        "counted at most once per breach. Because a breach can list many classes, shares " +
        "are per-class and independent: there is no “other” bucket and no 100% stack. " +
        "The ranking can shift as the catalog grows, and a rank change reshapes which " +
        "lines chart — intended, because what leaks most is itself part of the data. A " +
        "year plots only with at least 10 cohort breaches. The current year (marked *) " +
        "is partial and refills nightly.",
    },

    // --------------------------------------- extortion.html · 1 · hero
    revenue: {
      num: "01",
      kicker: "Confirmed revenue",
      source: "Ransomwhere (CC0)",
      headline: "Over a billion dollars, settled in public view.",
      caption:
        "Ransom payments verified on the Bitcoin blockchain, summed by the quarter the " +
        "money moved and valued at that day's exchange rate. The dataset behind this chart " +
        "is Ransomwhere: crowdsourced reports of extortion addresses, each verified before " +
        "it counts. That design makes every bar a floor, not a market estimate — a payment " +
        "appears here only after somebody reported the wallet, so the true total sits above " +
        "every number on this page. Read the right edge accordingly: volunteer reporting " +
        "has stalled — the ledger's last verified payment landed in Q3 2024 — and the chart " +
        "ends where the reporting does, unable to separate a quiet ledger from the " +
        "extortion economy itself cooling off.",
      statLabel: "Confirmed ransom revenue on the public ledger, all-time",
      statNote: "at least — {payments} verified payments to {addresses} tracked addresses",
      methodology:
        "Ransomwhere's CC0 export lists tracked extortion addresses, each with its " +
        "verified inbound transactions. The pipeline sums each transaction's amountUSD " +
        "into the UTC calendar quarter of its on-chain timestamp. amountUSD is upstream's " +
        "conversion at the historical BTC/USD rate of the transaction date — the implied " +
        "rate per transaction year tracks the price history, so a 2016 payment stays in " +
        "2016 dollars rather than being revalued at today's price. The export lists a " +
        "transaction once per receiving tracked address, so a transfer that fans out " +
        "across several tracked wallets contributes each received output; exact repeated " +
        "entries (about one percent of total USD) are summed as published rather than " +
        "second-guessed without chain data. Quarters between the first and last observed " +
        "payment always chart, at zero when empty. No full-year pace is projected for the " +
        "partial current year: crowdsourced reports arrive with a lag, which breaks the " +
        "uniform-flow assumption the projection math needs. Crowdsourced and verified " +
        "means lower bound — every claim on this page reads “at least this much.”",
    },

    // --------------------------------------- extortion.html · 2
    payments: {
      num: "02",
      kicker: "Payments",
      source: "Ransomwhere (CC0)",
      headline: "Fewer payments, bigger ransoms.",
      caption:
        "Bars count verified payments per year; the line follows the median payment in " +
        "day-of-transfer dollars, on a log scale climbing from pennies to six figures — " +
        "nearly seven orders of magnitude. The shape is the extortion economy's story so far: mass campaigns " +
        "squeezed hundreds of dollars out of thousands of victims, then operators moved " +
        "to organizations and the typical confirmed payment reached six figures while " +
        "the count collapsed. Read the recent bars with care — thinner crowdsourced " +
        "coverage and a changed business model both shrink them, and this dataset " +
        "cannot split the two effects.",
      legendPayments: "Verified payments",
      legendMedian: "Median payment (USD, log)",
      methodology:
        "A payment is one distinct on-chain transaction: the export lists a transaction " +
        "once per receiving tracked address, so transfers that fan out across several " +
        "tracked wallets are collapsed by transaction hash and their outputs summed " +
        "before anything is counted — on live data, roughly 22,000 ledger entries " +
        "collapse to about 19,000 payments. Yearly buckets use the transaction's " +
        "on-chain UTC timestamp; the median is over per-payment USD at the historical, " +
        "day-of-transfer rate. A year's median plots only with at least 10 payments — a " +
        "median of three payments is an anecdote — while the payment count always " +
        "plots. A year is marked * only when it is the partial generation year; the " +
        "record currently ends before that (last verified payment: Q3 2024), so the " +
        "final bar is simply where the reporting stops. No pace projection is drawn, " +
        "for the reporting-lag reason in the revenue methodology.",
    },

    // --------------------------------------- extortion.html · 3
    families: {
      num: "03",
      kicker: "Family concentration",
      source: "Ransomwhere (CC0)",
      headline: "The biggest bucket on the ledger has no name on it.",
      caption:
        "The families with the most confirmed revenue, ranked, with payment counts and " +
        "the years each was seen collecting. Two disclosures belong next to this board. " +
        "The single largest slice of verified revenue — about two thirds — carries no " +
        "family label at all: payments somebody proved, campaigns nobody attributed. " +
        "And a family's rank tracks how well its wallets were reported — coverage runs " +
        "deep for some campaigns and stops at a single wallet for others. That is why " +
        "this is a ranked board rather than a share-per-year chart: family coverage is " +
        "episodic, so yearly shares would mostly chart when volunteers filed their " +
        "reports.",
      note:
        "{unattributed_usd} — {unattributed_pct} of all confirmed revenue — is verified " +
        "but attributed to no family. It is disclosed here and never ranked on the board.",
      colFamily: "Family",
      colUsd: "confirmed USD",
      colPayments: "payments",
      colFirst: "first seen",
      colLast: "last seen",
      otherTemplate:
        "+ {families} more labeled families below the cut · {usd} confirmed · {payments} payments",
      methodology:
        "Family names are Ransomwhere's own labels, used as neutral identifiers. Per " +
        "family: confirmed revenue is the sum of transaction amountUSD across its " +
        "addresses, at historical day-of-transfer rates; payments are distinct " +
        "transaction hashes among those addresses; first and last seen are the years of " +
        "its earliest and latest verified transactions. The board ranks the top eight " +
        "labeled families by all-time confirmed USD; every labeled family below the cut " +
        "pools into the footer line. The export's “Unlabeled” bucket — verified payments " +
        "without an attribution — is excluded from the ranking and disclosed in the " +
        "panel note instead, because ranking it would present a reporting gap as the " +
        "leading brand. A share-per-year view was considered and rejected: wallets are " +
        "often reported long after a campaign ran, so yearly family shares would chart " +
        "reporting dates as much as anything the families did.",
    },

    // --------------------------------------------- attack.html · 1 · hero
    map: {
      num: "01",
      kicker: "The growing map",
      source: "MITRE ATT&CK® STIX bundles",
      headline: "Detections are graded against a moving target.",
      caption:
        "Active techniques and sub-techniques on the MITRE ATT&CK enterprise matrix, one " +
        "point per release, placed on real release dates. Any program that scores its " +
        "detection coverage against ATT&CK inherits this drift: a percentage earned against " +
        "last year's matrix quietly shrinks as the matrix grows. Watch the red line — " +
        "sub-techniques now outnumber the techniques they refine, so most of the growth " +
        "happens below the headline technique count.",
      statLabel: "Active techniques + sub-techniques, enterprise matrix",
      statLatest: "v{version} ({year})",
      statAgo: "v{version} ({year})",
      legendTechniques: "Techniques",
      legendSubtechniques: "Sub-techniques",
      methodology:
        "Each point is one release of the MITRE ATT&CK enterprise matrix, read from its " +
        "immutable STIX 2.1 bundle in the mitre-attack/attack-stix-data repository; its " +
        "x-position is the release date carried by that repository's index.json, so gaps " +
        "between points are real calendar gaps (major releases land about twice a year, "
        + "with point releases between). A " +
        "technique is a STIX attack-pattern object whose x_mitre_is_subtechnique flag is " +
        "false or absent; a sub-technique is the same object type with the flag true. Both " +
        "lines count active objects only: anything carrying revoked: true or " +
        "x_mitre_deprecated: true is excluded here and charted as churn below. Released " +
        "bundles never change, so each version's counts are computed once and cached; a " +
        "normal nightly run re-reads only the index. Lines step because a release's counts " +
        "hold until the next release.",
    },

    // --------------------------------------------- attack.html · 2
    churn: {
      num: "02",
      kicker: "Churn per release",
      source: "MITRE ATT&CK® STIX bundles",
      headline: "Each release redraws the edges of the map.",
      caption:
        "What every ATT&CK release did to the technique set — how many techniques and " +
        "sub-techniques it added, and how many it deprecated or revoked, diffed by STIX " +
        "object id against the release before it. Forty-odd releases in, this is the " +
        "changelog nobody reads, and it is the part detection engineering feels most: a " +
        "rule mapped to a retired technique doesn't break, it just quietly stops meaning " +
        "anything.",
      legendAdded: "Added",
      legendRetired: "Deprecated + revoked",
      methodology:
        "Consecutive enterprise releases are diffed by STIX object id across all " +
        "attack-pattern objects, techniques and sub-techniques together. “Added” counts " +
        "ids present in a release and absent from its predecessor. “Deprecated” counts ids " +
        "present in both releases whose x_mitre_deprecated flag flipped from false to " +
        "true; “revoked” counts the same flip on the STIX revoked flag. An object that " +
        "arrives already deprecated counts once, as an addition; an object retired in an " +
        "earlier release is never re-counted. The earliest indexed release (v1.0) has no " +
        "predecessor and shows no bars. The axis is a category axis of releases: the unit " +
        "of churn is a release, and gaps between releases vary from same-day point " +
        "releases to about half a year, so the equal spacing here is deliberate — the two " +
        "time-axis charts on this page carry the calendar.",
    },

    // --------------------------------------------- attack.html · 3
    catalog: {
      num: "03",
      kicker: "The catalog behind it",
      source: "MITRE ATT&CK® STIX bundles",
      headline: "Behind the matrix, the roster keeps filling in.",
      caption:
        "Active adversary groups (intrusion sets) and software — malware and tools, " +
        "counted together — per release, on the same release-date axis as the hero. This " +
        "is the evidence base the technique map stands on: techniques cite the " +
        "groups observed using them and the software that implements them, so the two catalogs " +
        "grow as attribution work accumulates, and entries leave only by deprecation or " +
        "revocation.",
      legendGroups: "Groups (intrusion sets)",
      legendSoftware: "Software (malware + tools)",
      methodology:
        "Groups are STIX intrusion-set objects; software is the union of malware and tool " +
        "objects, counted together. The same activity rule as the hero applies: objects " +
        "carrying revoked: true or x_mitre_deprecated: true are excluded. Campaigns, " +
        "tactics, mitigations, data sources, detection strategies, and relationship " +
        "records in the bundle are deliberately out of scope — this chart counts the named " +
        "adversaries and their tooling, the two catalogs a technique entry cites. Points " +
        "sit at index.json release dates and step between releases, like the hero; the " +
        "counts come from the same once-per-version cached stats.",
    },

    // --------------------------------------------- hygiene.html · 1 · hero
    validation: {
      num: "01",
      kicker: "The world line",
      source: "APNIC Labs DNSSEC measurement",
      headline: "Most of the internet still doesn't check its answers.",
      caption:
        "DNSSEC has been a finished standard since 2005: it lets a resolver verify that " +
        "the DNS answer it hands you is the one the domain owner signed, and switching " +
        "validation on is a resolver configuration choice, free of charge. The line is " +
        "APNIC's measured share of internet users whose resolvers actually perform that " +
        "check — climbing from under a tenth when the record starts in 2013 to roughly " +
        "four in ten today. At the pace of the last decade, universal validation is still " +
        "decades away.",
      statLabel: "Share of internet users behind validating resolvers",
      statLatest: "{latest_month}",
      statAgo: "{ago_month}",
      everyoneLabel: "everyone validates",
      methodology:
        "APNIC Labs measures DNSSEC validation by embedding test fetches in online " +
        "advertisements: each sampled user's resolver is asked for DNSSEC-signed names, " +
        "one of which carries a deliberately broken signature. A resolver that rejects " +
        "the broken name while fetching the valid one counts as validating; a user whose " +
        "queries land on a mix of validating and non-validating resolvers counts as " +
        "partially validating — shipped alongside the latest reading, deliberately kept out of the " +
        "headline line. The chart plots APNIC's world aggregate (code XA), 30-day " +
        "smoothed window, sampled by CyberMon to the last published day of each calendar " +
        "month; the full daily series is refetched from stats.labs.apnic.net every " +
        "night, so upstream corrections propagate. The stat compares the newest month " +
        "against the month ten years earlier (or the record's first month until the " +
        "record is ten years deep). The measurement caveat is APNIC's own: samples " +
        "arrive where the ad network delivers, so coverage is shaped by ad reach, and " +
        "APNIC weights per-economy sampling toward each economy's estimated internet " +
        "population. These are measured estimates over hundreds of millions of samples " +
        "a month — strong on trend, softer at the second decimal.",
    },

    // --------------------------------------------- hygiene.html · 2
    economies: {
      num: "02",
      kicker: "The giants compared",
      source: "APNIC Labs DNSSEC measurement",
      headline: "Where you live decides whether your DNS gets checked.",
      caption:
        "The same measured rate for a fixed set of ten: the economies with the most " +
        "internet users, by APNIC's own weighting. The gap is enormous — the top of this " +
        "list validates for roughly nine of every ten users, the bottom for almost " +
        "none, and some of the internet's oldest, richest infrastructures sit far below " +
        "half. The world line rides along for reference: it is user-weighted, so these " +
        "ten mostly decide where it goes.",
      worldLine: "World average",
      note:
        "Lines are quarterly samples of APNIC's 30-day windows, ranked by current rate " +
        "in the legend; the dashed line is the user-weighted world average.",
      methodology:
        "The set is fixed: the ten largest economies by APNIC's weighted sample count — " +
        "its estimate of each economy's internet-user population — as measured when this " +
        "module launched in July 2026: China, India, the United States, Brazil, " +
        "Indonesia, Japan, Mexico, Russia, the Philippines and Nigeria. Freezing " +
        "membership is deliberate; re-picking the list nightly would let membership " +
        "churn masquerade as adoption change. For each economy the pipeline pulls " +
        "APNIC's full daily series and samples the last published day of each " +
        "quarter-end month (30-day smoothed window), plus the newest available day; " +
        "legend order is current rate, descending. Per-economy caveat, per APNIC: " +
        "samples arrive where the measurement ads are delivered, and delivery volume " +
        "varies by economy — where it runs thin (as of this module's mid-2026 launch, " +
        "Russia yielded a small fraction of the samples of comparable economies) the " +
        "measured rate carries more noise.",
    },

    // --------------------------------------------- hygiene.html · 3
    spread: {
      num: "03",
      kicker: "The spread",
      source: "APNIC Labs DNSSEC measurement",
      headline: "Count economies, not users, and the picture flips.",
      caption:
        "Every economy APNIC measures with a meaningful sample, bucketed by its current " +
        "validation rate. Weighted this way — one economy, one vote — DNSSEC looks far " +
        "less bleak: the stat counts how many economies validate for at least half " +
        "their users. Hold it against the user-weighted hero line and the diagnosis " +
        "sharpens: the shortfall lives in a handful of enormous economies whose " +
        "incumbent resolver fleets never switched validation on.",
      statBig: "{n} of {total}",
      statLead: "measured economies validate for at least half their users",
      statNote: "economies with at least {min_seen} samples in the current 30-day window",
      tooltipBucket: "Validation rate {bucket}",
      tooltipUnit: "economies",
      yAxisLabel: "economies",
      methodology:
        "The distribution covers every economy on APNIC's DNSSEC world map with at " +
        "least 10,000 measurements in the current 30-day window — below that floor a " +
        "rate is an anecdote — bucketed by the share of sampled users behind validating " +
        "resolvers: under 10%, 10–25%, 25–50%, 50–75%, and 75% or higher (lower edges " +
        "inclusive). Each economy counts once regardless of size; that equal weighting " +
        "is the point, and the reason this chart can look healthier than the " +
        "user-weighted world line above. Values are parsed nightly from the world-map " +
        "table APNIC publishes (per-economy JSON exists, but pulling two hundred forty " +
        "series every night to rebuild one histogram would abuse the source; the table " +
        "is a single request). Same caveat as the rest of the page: rates are estimated " +
        "from ad-delivered samples, and thinly sampled economies are exactly the ones " +
        "the floor exists to keep out.",
    },
    // --------------------------------------------- guards.html · 1 · hero
    guards: {
      num: "01",
      kicker: "The guard share",
      source: "CISA KEV",
      headline: "The guards keep showing up on the exploited list.",
      caption:
        "Every entry in CISA's Known Exploited Vulnerabilities catalog, classified by " +
        "what the product is for. Bars show the share of each year's new listings that " +
        "are security products — VPN appliances, firewalls, endpoint protection, secure " +
        "gateways: the things bought to keep attackers out. More than one entry in nine " +
        "in the whole catalog is in a product sold to enforce security — and recent " +
        "years run well above that. The 2021–22 " +
        "seeding years chart like any other year: the classification rides on the entry " +
        "itself, so a back-catalog import answers the question as well as a fresh " +
        "listing does.",
      statLabel: "Security products' share of the whole exploited catalog",
      statNote: "{security} of {total} KEV entries · classifier v{version}, {rules} rules — the list is data, reviewable in the repo",
      methodology:
        "“Security product” here means: a product whose primary function is security " +
        "enforcement or secure access — firewalls and UTMs, VPN and secure-access " +
        "appliances, endpoint protection, email security gateways, identity and " +
        "privileged-access management, mobile device management, security operations " +
        "tooling, and dedicated secure file-transfer appliances from security vendors. " +
        "That line is a judgment, and drawing it is the methodological risk of this " +
        "whole page — so it is drawn once, in writing, as a curated and versioned " +
        "table (pipeline/security_products.py), never by string-matching product names " +
        "for the word “secure”. Mixed vendors get explicit product rules: Cisco counts " +
        "only its security estate (ASA, Firepower/FTD, AnyConnect, ISE — never IOS or " +
        "routers), Microsoft only Defender and Forefront TMG (never Exchange), Zyxel " +
        "only its firewalls, Juniper only ScreenOS. The harder calls are documented in " +
        "the module and applied consistently: MOVEit is file transfer, not security; " +
        "ADCs count only where the exploited deployment is a secure-access gateway (F5 " +
        "BIG-IP, Citrix NetScaler); desktop management, RMM and remote-support tools " +
        "are IT operations; mail servers are not counted just because email security " +
        "gateways are; backup is resilience; Zoho ManageEngine stays unclassified " +
        "because the catalog's product labels are too coarse to split honestly. Every " +
        "published number carries the classifier version that produced it, and the " +
        "table is reviewable data in this repo — if a call looks wrong, open an issue: " +
        "a one-line change reclassifies the whole history on the next nightly run. " +
        "Years with fewer than 10 entries never plot. The current year (marked *) is " +
        "partial and refills nightly.",
    },

    // --------------------------------------------- guards.html · 2
    recidivism: {
      num: "02",
      kicker: "Recidivism board",
      source: "CISA KEV",
      headline: "The same names keep coming back.",
      caption:
        "Every vendor with at least five entries in the catalog, ranked by how many " +
        "confirmed-exploited vulnerabilities CISA has listed across its products — with " +
        "first and last listing dates and the median gap between consecutive listings. " +
        "Rows where security products make up at least half the vendor's entries are " +
        "flagged. Read the gap column on the flagged rows: for the most-listed security " +
        "vendors, the pause between confirmed-exploited listings is measured in days " +
        "and weeks.",
      colVendor: "Vendor",
      colEntries: "KEV entries",
      colSecurity: "security",
      colFirst: "first listed",
      colLast: "last listed",
      colGap: "median gap",
      securityFlagLabel: "security products",
      windowTemplate:
        "whole catalog · min {min_vendor_entries} entries · flagged rows: at least " +
        "half the vendor's entries classify as security products",
      methodology:
        "For every vendor label in the catalog (whitespace-normalized but never " +
        "merged — Pulse Secure entries predate Ivanti's acquisition and keep that label, " +
        "because the catalog's attribution is the record), the board counts total " +
        "entries, security-classified entries (per the classifier described in the " +
        "hero's footnote), first and last dateAdded, and the median gap in days " +
        "between consecutive listings. A gap of 0 means CISA added several of the " +
        "vendor's CVEs on the same day, which bulk advisories regularly do. Vendors " +
        "with fewer than five entries stay off the board: one listing is an incident; " +
        "a cadence needs a history. The security flag marks rows where at least half " +
        "the entries classify as security products. Default sort: total entries, " +
        "descending. Click any column header to re-sort.",
    },

    // --------------------------------------------- guards.html · 3
    overlap: {
      num: "03",
      kicker: "Ransomware overlap",
      source: "CISA KEV",
      headline: "The ransomware flag clusters on the guards.",
      caption:
        "CISA marks each KEV entry known to have been used in ransomware campaigns. " +
        "Split the catalog with the same classifier as the rest of this page and the " +
        "flag is anything but evenly spread: entries on exploited security products " +
        "carry that flag roughly twice as often as the rest of the catalog. An edge " +
        "appliance that gates the network is one working exploit away from being the " +
        "whole intrusion — exactly the kind of foothold extortion operations shop for.",
      barSecurity: "Security products",
      barOther: "Rest of the catalog",
      methodology:
        "Both bars use the catalog's own knownRansomwareCampaignUse field (“Known” " +
        "versus anything else; a missing field never counts as Known — the KEV Latency " +
        "module applies the same rule) over the full catalog snapshot, seeding era " +
        "included. The split is the page's classifier: security products on one side, " +
        "every other entry on the other, so the two bars always cover the whole " +
        "catalog; each bar's entry counts ride in its tooltip. The chart answers one " +
        "narrow question — is the flag overrepresented on security products? It says " +
        "nothing about which campaigns, when, or how many victims: the flag is CISA's " +
        "current per-entry assessment, with no dates attached.",
    },

    // --------------------------------------------- epss.html · 1 · hero
    grade: {
      num: "01",
      kicker: "The grade",
      source: "EPSS (FIRST.org) · CISA KEV",
      headline: "The day before confirmation, the forecast was calm.",
      caption:
        "EPSS is the industry's de facto public exploitation forecast, and this site already " +
        "calls it the best public model — which is exactly why somebody should grade " +
        "it. For every vulnerability CISA added to its Known Exploited catalog, this " +
        "chart reads the EPSS score published the day before the listing — the model's " +
        "last daily forecast while the listing was still in the future — banded into " +
        "under 1%, 1–10%, and 10% or higher. EPSS predicts exploitation within 30 days, " +
        "and a KEV listing means exploitation was already observed, so on listing eve " +
        "the model should be at its most alarmed. Instead, in the catalog's recent years most " +
        "arrive having been scored below one percent the day before. One reading caveat " +
        "up front: the sharp 2022-to-2023 flip in the bars is a model change, not a " +
        "performance change — the v2-era model scored high across the board, every model " +
        "since scores low, and section 02 splits the eras so they never pool. The " +
        "whole-catalog comparison figure pools them anyway (it says so). Listings that " +
        "could not have a prior score are counted separately, never as misses.",
      statLabel: "Graded KEV additions scored under 1% on listing eve",
      statLatest: "{latest_year}",
      statAgo: "whole catalog",
      legendBelow: "under 1% the day before",
      legendMid: "1–10%",
      legendAbove: "10% or higher",
      // Filled by the renderer from catalog counts; the pending sentence is
      // appended only while the historical backfill is still incomplete.
      note:
        "{ungradeable} of {total} catalog entries had no day-before score to grade — " +
        "{before_pub} were listed before (or the day) their CVE record published; the " +
        "rest simply had no row in FIRST's corpus that day — and are counted " +
        "separately, never as misses.",
      pendingNote:
        "{pending} entries are still awaiting their historical day-before lookup; " +
        "every number on this page covers only what has been fetched so far.",
      methodology:
        "For every entry in CISA's Known Exploited Vulnerabilities catalog, the " +
        "pipeline asks FIRST's historical EPSS API for the entry's score on the day " +
        "before its KEV dateAdded, and each answer is fetched exactly once — " +
        "historical scores are immutable, and the published data file doubles as the " +
        "archive. Grading the day-before score is deliberately generous to the model: " +
        "EPSS estimates the probability of exploitation within the next 30 days, and a " +
        "KEV listing certifies exploitation was already observed (the median gap from " +
        "CVE publication to KEV listing is measured in weeks on this site's own KEV " +
        "Latency page), so listing eve is the moment the model has had every chance to " +
        "be alarmed — a sub-1% score there is the strongest possible form of miss, not " +
        "a timing technicality. The exception is fast listings: an entry added within " +
        "days of its CVE publishing gives a model that reads public signals little " +
        "runway, and such entries stay in the cohort — read the strongest-miss framing " +
        "with that in mind. Bands are shares of graded entries only. An entry " +
        "listed before, or the same day, its CVE record published cannot have a " +
        "day-before score and is reported separately; so are entries whose lookup is " +
        "still pending — partial coverage is disclosed, never blended. One fairness " +
        "caveat runs the other way: in the catalog's 2021–22 seeding era (the launch " +
        "batch plus back-catalog imports of years-old CVEs), the exploitation behind a " +
        "listing may predate it by years, so those bars answer “was the model alarmed " +
        "about old known-exploited CVEs” rather than “did it see a fresh one coming” — " +
        "and the seeding years actually grade better than the live era. The per-year " +
        "split exists so the eras never blend. A year plots only with at least 10 " +
        "graded entries. The current year (marked *) is partial and refills nightly.",
    },

    // --------------------------------------------- epss.html · 2
    distribution: {
      num: "02",
      kicker: "The distribution",
      source: "EPSS (FIRST.org) · CISA KEV",
      headline: "A histogram of hindsight.",
      caption:
        "The same graded cohort, spread across the log-ish probability buckets the " +
        "Score-vs-reality grid uses, and split by EPSS model version. The split is " +
        "load-bearing, not decoration: v1 through v5 are different models with " +
        "materially different score distributions, and pooling them into one histogram " +
        "would be the same landmine as mixing CVSS v2 with v3 scores. Read each model " +
        "on its own terms; what changes is where the mass sits — the v2-era model pushed " +
        "most of this cohort above 1%, while the v3 and v4 models placed the majority " +
        "below it (and the young v5 era, on a small early cohort, points the same way).",
      methodology:
        "Each graded entry contributes its day-before probability to one bucket: " +
        "under 0.1%, 0.1–1%, 1–10%, or 10% and higher (lower edges inclusive — the " +
        "same arithmetic as the Score-vs-reality grid on the CVE Ecosystem page). The " +
        "historical API does not return the model version, so it is derived from the " +
        "score date using the era table shipped in the data file — verified against " +
        "the version headers of FIRST's own daily CSV files: v1 through 2022-02-03, " +
        "v2 (v2022.01.01) through 2023-03-06, v3 (v2023.03.01) through 2025-03-16, " +
        "v4 (v2025.03.14) through 2026-06-14, v5 (v2026.06.15) since. Day-before " +
        "probabilities are stored at five decimals — this module's documented " +
        "exception to CyberMon's one-decimal rounding, because the difference between " +
        "0.04% and 0.4% is precisely what is being charted.",
    },

    // --------------------------------------------- epss.html · 3
    percentile: {
      num: "03",
      kicker: "The ranking view",
      source: "EPSS (FIRST.org) · CISA KEV",
      headline: "Where the exploited stood in line.",
      caption:
        "Raw probabilities are not comparable across model versions — each model " +
        "calibrates differently — but a percentile is: it says where a CVE ranked " +
        "among everything the model scored that same day. This view re-grades the " +
        "same cohort on that scale, and it is the fairest scale available to the " +
        "model. Even here, nearly three in ten of the graded cohort sat in the bottom " +
        "half of that day's ranking — confirmed-exploited vulnerabilities the model " +
        "typically placed behind more than a hundred thousand others on listing eve.",
      statBig: "{n} of {total}",
      statLead: "graded entries ranked in the model's bottom half on listing eve",
      statNote: "median day-before percentile: {median}",
      yAxisLabel: "share of graded entries",
      methodology:
        "Each graded entry contributes the percentile EPSS published alongside its " +
        "day-before score: the share of all CVEs scored that day with an equal or lower score. " +
        "FIRST recomputes percentiles daily against that day's whole corpus, which " +
        "makes them comparable across model versions in a way raw probabilities are " +
        "not — a v2 probability and a v4 probability mean different things, but " +
        "“bottom half of that day's ranking” means the same thing in every era. " +
        "Buckets are shares of graded entries that carry a percentile (the earliest " +
        "EPSS era published scores without percentiles for a stretch; such entries " +
        "grade in the probability charts but not here, and the counts ship in the " +
        "data file). The stat's median is the cohort's median day-before percentile.",
    },

    // --------------------------------------------- calendar.html · 1 · hero
    reservation: {
      num: "01",
      kicker: "Reservation aging",
      source: "cvelistV5 (MITRE)",
      headline: "One in five new CVEs arrives on an old ID.",
      caption:
        "Every CVE ID wears a year on its face — CVE-2025-12345 — and that year names " +
        "the moment the identifier was reserved, which can sit far ahead of anything " +
        "being published. The bands split each year's newly published records by the " +
        "age of their ID: minted the same year, the year before, or two-plus years " +
        "back. In the latest complete year, one in five records shipped on an " +
        "earlier-year ID — the vintage measures the age of the paperwork, not of the " +
        "bug.",
      statLabel: "Share of newly published CVEs carrying an earlier-year ID",
      statLatest: "{latest_year}",
      statAgo: "{ago_year}",
      legendSameYear: "Same-year ID",
      legendOneYear: "1-year-old ID",
      legendTwoPlus: "2+ years old",
      methodology:
        "For every published record in the cvelistV5 corpus (rejected records " +
        "excluded), the year prefix of its CVE ID is compared against its publication " +
        "year — the UTC year of datePublished. Same-year, one-year-old, and " +
        "two-plus-year-old IDs stack to 100%; the tooltip carries the counts. The ID " +
        "year records when the identifier was reserved: CNAs request blocks of IDs " +
        "and publish against them later, so an old ID typically means a reservation " +
        "that sat in a queue, a long coordinated disclosure, or a batch conversion. " +
        "The rare inverse — an ID minted after its publication year, a late-December " +
        "reservation published under January's clock — clamps to age zero, and the " +
        "clamp count ships in the data file (the real corpus currently contains " +
        "none). Records without a datePublished take their date from the ID and count " +
        "as same-year by construction. A year plots only with at least 500 published " +
        "records. The current year (marked *) is partial and refills nightly; the " +
        "headline compares complete years only, and the baseline year ships in the " +
        "data file rather than being derived.",
    },

    // --------------------------------------------- calendar.html · 2
    weekbeat: {
      num: "02",
      kicker: "The weekly beat",
      source: "cvelistV5 (MITRE)",
      headline: "Disclosure has a favorite weekday.",
      caption:
        "How each year's records spread across the week: the latest complete year " +
        "beside the year a decade before it. In the latest complete year, Tuesday leads with " +
        "roughly a quarter of all records, the weekend is close to silent, and ten " +
        "years ago the peak sat a day later, on Wednesday. The spike is a property " +
        "of publication workflows — advisories go out when release processes run, " +
        "and the biggest release processes run on Tuesday.",
      weekdayLabels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
      seriesYearLabel: "{year}",
      tooltipN: "{n} dated records in {year}",
      methodology:
        "Each published record with a day-precision datePublished contributes its " +
        "weekday; bars are the share of that year's dated records on each day, for " +
        "the latest complete year and the year a decade before it (both named in " +
        "the data file — the site never picks them; until the record is ten years " +
        "deep the earliest charted year stands in). Weekdays are judged in UTC, on " +
        "the date the record itself carries: a late-evening publication in a US " +
        "timezone lands on the next UTC day, so weekday mass can shift one day " +
        "forward relative to local release time — a Tuesday release in California " +
        "can read as Wednesday here. That skew direction is fixed and documented, " +
        "and it is not corrected, because the record carries no reliable local " +
        "timezone. Records without a publication timestamp are excluded from this " +
        "chart. A year enters the comparison only with at least 500 dated records.",
    },

    // --------------------------------------------- calendar.html · 3
    patchtuesday: {
      num: "03",
      kicker: "Patch Tuesday",
      source: "cvelistV5 (MITRE)",
      headline: "Twelve days carry triple their calendar share.",
      caption:
        "The second Tuesday of the month is Microsoft's release day, and a good part " +
        "of the industry schedules disclosure around it. Bars show the share of each " +
        "year's published records that land on those twelve days; the dashed line " +
        "marks what twelve days out of 365 would hold if publication ignored the " +
        "calendar — 3.3 percent. The latest complete year put roughly triple that " +
        "share on them, and the bar has cleared the line in every complete year " +
        "since 2014.",
      note:
        "The comparison, stated exactly: twelve specific UTC days per year against " +
        "a uniform-calendar baseline of 3.3% — a bar at 9.9% means those days held " +
        "three times their share of the calendar, and says nothing about how severe " +
        "or exploited the records were.",
      baselineLabel: "uniform calendar · {pct}",
      tooltipShare: "{pct} of the year's dated records",
      tooltipCount: "{on_pt} of {n} on patch Tuesdays",
      tooltipTopDay: "busiest single day: {date} ({n} records)",
      methodology:
        "A record counts as a patch-Tuesday publication when its UTC datePublished " +
        "falls on the second Tuesday of its month — defined precisely as the Tuesday " +
        "with day-of-month 8 through 14; every year has exactly twelve such days. " +
        "Bars are the share of each year's dated records on those days. The dashed " +
        "baseline is 3.3%: 12 of 365 days (12 of 366 in a leap year rounds to the " +
        "same figure), i.e. what those days would carry under a calendar-blind " +
        "uniform flow. The chart claims exactly that multiple and nothing more — " +
        "publication concentrating on release days says nothing about severity or " +
        "exploitation. The tooltip also names the year's single busiest publication " +
        "day for context; it is frequently a batch-conversion or mass-import day " +
        "rather than a patch Tuesday, and it is never ranked or editorialized. UTC " +
        "day boundaries as in the weekday chart. A year plots only with at least " +
        "500 dated records. The current year (marked *) is partial and refills " +
        "nightly.",
    },

    // --------------------------------------------- rescores.html · 1 · hero
    week: {
      num: "01",
      kicker: "Edits per week",
      source: "cvelistV5 (MITRE) · CyberMon's own nightly diffs",
      headline: "Published is not final.",
      caption:
        "A CVE record stays editable after it ships, and the severity score is no " +
        "exception: the assigning CNA can raise it, lower it, add one years later, or " +
        "withdraw it — on the live record, with no changelog attached. Every night " +
        "CyberMon re-reads the whole corpus and diffs each record's CNA-assigned score " +
        "against the night before. Bars above the line are scores revised upward, bars " +
        "below are revisions downward; backfilled first scores and CVSS version changes " +
        "ride along as separate muted counts, because bookkeeping and edits must never " +
        "blend. This record starts at first deploy and deepens nightly.",
      legendUp: "Score raised",
      legendDown: "Score lowered",
      legendFirst: "First score backfilled",
      legendShift: "CVSS version shift",
      legendRemoved: "Score removed",
      statLabel: "Events on the committed log",
      statSince: "since {first_date}",
      // {first_date} is filled from the data (the log's first observed
      // date); the empty variant renders while the log has no events yet.
      note:
        "No upstream publishes score-edit history — CyberMon has kept this record " +
        "since {first_date}.",
      noteEmpty:
        "No upstream publishes score-edit history — CyberMon's record starts with " +
        "tonight's corpus. Edits appear once there are two nights to compare.",
      emptyChart:
        "No diff nights on the log yet — the record starts now, and the first " +
        "comparable night fills the first bar.",
      methodology:
        "Every night the pipeline reduces each published CVE record to a score " +
        "fingerprint: the CNA-assigned base score of the newest CVSS version the record " +
        "carries, read by the same extraction the severity-inflation chart uses — the " +
        "two pages cannot disagree about what a record's score is. Tonight's " +
        "fingerprints are diffed against the previous night's, kept as cached state " +
        "alongside the corpus release tag (a re-run against the same release is " +
        "detected and skipped, so nothing double-counts). A changed score on the same " +
        "CVSS version is a rescore, raised or lowered. A record whose newest scored " +
        "version changed is a version shift, logged separately and never charted as up " +
        "or down: v2, v3 and v4 are different scales, and reading a v3-to-v4 move as a " +
        "raise would manufacture an edit out of a methodology change. A record gaining " +
        "its first in-record score is backfill-scoring, counted separately — filling a " +
        "blank is not editing a judgment; a score disappearing from a live record logs " +
        "as removed. Brand-new records produce no event at all: first assignment is the " +
        "inflation chart's subject. Events append to a committed CSV " +
        "(data/history/rescore_log.csv) that no upstream can replace, and the diffing " +
        "state is committed right beside it — the two can no longer diverge (the one " +
        "night they did, in July 2026, taught this module that lesson and left a " +
        "deduplicated scar on the log). If the state is ever lost it is rebuilt from " +
        "that night's corpus and the night logs zero events — at worst one night of " +
        "edits goes unrecorded, and that failure mode is stated here rather than " +
        "papered over. Bars group by ISO week of the observation date, UTC; the week " +
        "in progress keeps filling until it closes.",
    },

    // --------------------------------------------- rescores.html · 2
    magnitude: {
      num: "02",
      kicker: "Magnitude",
      source: "cvelistV5 (MITRE) · CyberMon's own nightly diffs",
      headline: "How far a score moves when it moves.",
      caption:
        "Each rescore's arithmetic: the new score minus the old, always on the same " +
        "CVSS version — an edit that changes version is a version shift and never lands " +
        "here. A half-point correction and a four-point rewrite are different events, " +
        "and this chart exists to keep them apart. Until the log holds enough rescores " +
        "to distribute honestly, the panel reports exactly how many it has instead of " +
        "plotting a histogram of anecdotes.",
      // Rendered instead of the chart while the log sits under the min-n
      // gate; both variants are filled from the data file, never hardcoded.
      placeholder:
        "{n} rescore events on the log since {first_date} — the distribution charts " +
        "once {min_n} have accumulated.",
      placeholderEmpty:
        "No rescore events on the log yet — the distribution charts once {min_n} " +
        "have accumulated.",
      medianLabel: "median delta {median}",
      tooltipCount: "{n} rescore events",
      xAxisLabel: "score delta (new − old)",
      yAxisLabel: "rescore events",
      methodology:
        "Delta is the new score minus the old per rescore event — same CVSS version by " +
        "construction, so every delta compares like with like; version shifts are " +
        "excluded from this chart entirely, because a difference across scoring scales " +
        "is not a measurement. Deltas land in fixed signed buckets (−4 and under, over −4 to −2, " +
        "under −2 to −0.1, +0.1 to under +2, +2 to under +4, +4 and over) at the " +
        "scores' own one-decimal precision; a delta of exactly zero cannot occur, since " +
        "an unchanged score is not an event. The distribution and its median stay " +
        "unplotted until the log holds at least 30 rescore events — a histogram of a " +
        "handful of edits would chart noise with a straight face. The gate and the " +
        "current count ship in the data file, and the placeholder shown before the gate " +
        "opens is rendered from them, not hardcoded.",
    },

    // --------------------------------------------- rescores.html · 3
    editors: {
      num: "03",
      kicker: "Who edits",
      source: "cvelistV5 (MITRE) · CyberMon's own nightly diffs",
      headline: "Every edit has an author.",
      caption:
        "The CNAs that assign scores are the ones who revise them, and the log records " +
        "which. The board counts rescore events per CNA — same version, new number — " +
        "split into raised and lowered. Expect it to start sparse: a board of " +
        "after-the-fact edits can only fill at the speed the ecosystem edits, and the " +
        "line above the board states exactly how much record it stands on.",
      boardNote: "{events} events on the log since {first_date}",
      boardNoteEmpty: "no events on the log yet — collection is live",
      windowTemplate:
        "whole record · {context} · min {min_events} rescore events per CNA",
      colCna: "CNA",
      colRescores: "rescores",
      colUp: "raised",
      colDown: "lowered",
      emptyBoard:
        "No CNA has enough logged rescores to rank yet — the board fills as the " +
        "record grows.",
      methodology:
        "For each CNA — the record's assigner on the night the edit was observed — the " +
        "board counts rescore events across the whole committed log, split by " +
        "direction. Version shifts, backfilled first scores and removals are excluded: " +
        "the board asks who changes their own numbers rather than who fills in paperwork. " +
        "CNAs with fewer than 3 logged rescores stay off the board — two edits are an " +
        "anecdote, not a habit. There is deliberately no time window yet: the record " +
        "is young, and windowing it would empty it; when the log is deep enough for a " +
        "rolling window, this note will change. Default sort: rescore count, " +
        "descending. Click any column header to re-sort.",
    },

    // --------------------------------------------- changelog.html · 1 · hero
    edits: {
      num: "01",
      kicker: "The edit stream",
      source: "CISA KEV · CyberMon's own nightly diffs",
      headline: "The exploited list gets edited after publication.",
      caption:
        "CISA's Known Exploited Vulnerabilities catalog is the closest thing " +
        "the industry has to an official list of what attackers actually use — " +
        "and it changes in place, with no published changelog. CyberMon diffs " +
        "every fresh catalog against the last observed one and keeps the " +
        "ledger. Bars count edits per month: remediation deadlines that moved, " +
        "ransomware flags that flipped, wording that was rewritten, and " +
        "entries that vanished outright. New listings are deliberately not " +
        "counted — a growing catalog is the system working; this chart counts " +
        "revisions to what was already published.",
      statLabel: "Edits to already-published entries, whole record",
      statNote: "edits across a catalog of {entries} entries · new listings excluded: {additions}",
      legendDueDate: "Due date moved",
      legendFlag: "Ransomware flag",
      legendText: "Text revised",
      legendRemoved: "Entry removed",
      // Filled by the renderer from the catalog block; the capture sentence
      // is appended only when the record carries Wayback-seeded events.
      note: "This record's first observation is {first_observed}.",
      waybackNote:
        "History before the nightly diffs is reconstructed from {captures} " +
        "Internet Archive captures of the feed — a backfilled edit is dated " +
        "to the first capture that shows it, and the true date lies " +
        "somewhere between that capture and the one before.",
      methodology:
        "Every run fingerprints each catalog entry: dueDate, " +
        "knownRansomwareCampaignUse, vendorProject, product, and " +
        "vulnerabilityName are kept verbatim; shortDescription, " +
        "requiredAction, and notes are kept as short stable hashes of the " +
        "whitespace-normalized text, so the log can say a text changed " +
        "without republishing it, and a pure whitespace reflow never counts. " +
        "The fresh catalog is diffed against the stored fingerprints; each " +
        "difference is one event in an append-only CSV " +
        "(data/history/kev_changelog.csv — like the NVD backlog history, an " +
        "original dataset this project accumulates, because CISA publishes " +
        "only the current snapshot). A missing ransomware flag reads as " +
        "“Unknown,” the same rule every KEV module on this site applies — so " +
        "the day CISA added that column to the feed did not log a fake edit " +
        "wave. Additions are logged but never charted as edits, and removals " +
        "are charted here and listed by name in the receipts board. Events " +
        "carry a granularity flag: “daily” events are dated to the nightly " +
        "run that first saw them (if the pipeline misses nights, changes pool " +
        "on the next run's date); “capture” events come from the one-time " +
        "Internet Archive backfill and are dated to the first capture showing " +
        "them — with weeks to months between captures, a capture-era month is " +
        "a lower-resolution bucket, and single-capture spikes can be one bulk " +
        "revision by CISA. The record's very first observation is a baseline: " +
        "it writes the fingerprints and logs nothing, because there is " +
        "nothing earlier to compare against.",
    },

    // --------------------------------------------- changelog.html · 2
    flagflip: {
      num: "02",
      kicker: "The ransomware flag",
      source: "CISA KEV · CyberMon's own nightly diffs",
      headline: "The ransomware flag arrives late.",
      caption:
        "Each KEV entry carries CISA's assessment of whether the " +
        "vulnerability is known to have been used in ransomware campaigns — " +
        "and that flag gets flipped on entries that have sat in the catalog " +
        "for months or years. Every KEV consumer who read the entry before " +
        "the flip saw “Unknown” where the catalog now says “Known.” The line " +
        "accumulates observed Unknown-to-Known flips; the stat is how long " +
        "after listing the flip typically lands.",
      statBig: "{n}",
      statLead: "entries flipped to “Known” after they were already listed",
      statNote:
        "median gap from listing to observed flip: {median} days — includes the 2023-12 " +
        "step where the flag column first appears in the captures",
      statNoteThin:
        "too few observed flips to state a typical gap yet — counts ship in " +
        "the data file either way",
      legendMonthly: "Flips observed that month",
      legendCumulative: "Cumulative flips",
      methodology:
        "A flip is a logged change of knownRansomwareCampaignUse to “Known” " +
        "on an entry already present in the previous observation. The gap is " +
        "measured from the entry's own dateAdded to the date the flip was " +
        "observed, so it is an upper bound at capture granularity: a flip " +
        "CISA made between two Internet Archive captures is dated to the " +
        "later one. One step in the curve is structural and worth naming: " +
        "CISA only added the ransomware column to the feed in October 2023, " +
        "so the first capture carrying it logs a flip for every entry that " +
        "arrived already flagged — for those, the gap measures how long the " +
        "entry sat in the catalog before the flag existed at all, and the " +
        "curve shows them as the step where the record's flag history " +
        "begins. The median is published only with at least 10 observed " +
        "flips; below that the count ships and the statistic stays null. " +
        "Flips back to “Unknown” are rarer, tracked, and disclosed in the " +
        "data file as reversals rather than netted against the total.",
    },

    // --------------------------------------------- changelog.html · 3
    receipts: {
      num: "03",
      kicker: "The receipts board",
      source: "CISA KEV · CyberMon's own nightly diffs",
      headline: "Some entries never stop changing.",
      caption:
        "The catalog entries with the most logged edits — every one a " +
        "revision CISA made to an already-published listing — and, below " +
        "them, every entry observed leaving the catalog. A removal is worth " +
        "naming: the exploited list is a federal remediation mandate, and an " +
        "entry that disappears from it takes its deadline along.",
      colCve: "CVE",
      colVendor: "Vendor",
      colProduct: "Product",
      colEdits: "edits",
      colLast: "last change",
      removalsTitle: "Removed from the catalog",
      removalRow: "{cve} — {vendor} {product} · listed {listed} · removed {removed}",
      removalRowUnlisted: "{cve} — {vendor} {product} · removed {removed}",
      noRemovals:
        "No removals observed in the record so far — when one happens, it " +
        "will be listed here by name.",
      methodology:
        "An entry's edit count is its logged field changes plus text " +
        "revisions across the whole record — additions and removals are not " +
        "edits and never inflate the count. The board shows the top dozen by " +
        "edit count (ties break by CVE id); “last change” is the date of the " +
        "entry's most recent logged edit. Removals come from the state's own " +
        "removal ledger: an entry present in one observation and absent from " +
        "the next is logged as removed and remembered — it stays on this " +
        "list even if it later returns (the return is logged as a new " +
        "addition). Capture-era dates carry the same granularity caveat as " +
        "the rest of the page: observed at the first capture that shows the " +
        "change, not necessarily the day CISA made it.",
    },

    // --------------------------------- naming.html · 1 · hero
    naming_board: {
      num: "01",
      kicker: "The most-renamed",
      source: "MITRE ATT&CK (enterprise)",
      headline: "One adversary, a roomful of names.",
      caption:
        "MITRE files each tracked threat group under a single name and records " +
        "the aliases every other vendor uses. The most-renamed answer to a dozen " +
        "or more names apiece — the same actor rebranded in each shop's house " +
        "style, so APT28 is also Fancy Bear, Forest Blizzard, Sofacy and " +
        "STRONTIUM. This board counts the names besides the canonical one. " +
        "ATT&CK's alias list is MITRE's own editorial call, not a full census of " +
        "the industry, and roughly four in ten tracked groups carry no second " +
        "name at all — the leaderboard belongs to the famous few.",
      statTemplate:
        "ATT&CK v{version} · the {shown} most-renamed of {with_aliases} groups " +
        "that answer to another name, out of {total} tracked",
      colActor: "Actor",
      colCount: "aliases",
      colAliases: "also tracked as",
      nodata: "Not enough data yet.",
      methodology:
        "Every threat-group entry in MITRE's current enterprise ATT&CK STIX " +
        "bundle carries an alias list: the first name is the group's canonical " +
        "label, the rest are the alternates other vendors publish. This board " +
        "counts the alternates — every alias that isn't the canonical name — for " +
        "each active group (neither revoked nor deprecated), ranked high to low " +
        "with ties broken by name; the page shows the top thirty and the full " +
        "ranking ships in the data file. It reads only the latest release, so it " +
        "is a snapshot of today's taxonomy, not a trend. One honest limit: the " +
        "alias list is MITRE's own curation, not an exhaustive record of every " +
        "vendor's naming, so read the counts as a floor.",
    },

    // --------------------------------- naming.html · 2
    naming_dist: {
      num: "02",
      kicker: "How many names",
      source: "MITRE ATT&CK (enterprise)",
      headline: "The names pile up on a famous few.",
      caption:
        "Each bar counts the active tracked groups carrying that many alternate " +
        "names. The distribution is lopsided: roughly four in ten groups carry " +
        "none at all — the taxonomy never renamed them — while a short tail of " +
        "headline actors answers to ten, twelve, fifteen. Aliasing isn't spread " +
        "across the threat landscape; it accretes on the groups vendors compete " +
        "to name.",
      xAxis: "alternate names per group",
      yAxis: "tracked groups",
      nodata: "Not enough data yet.",
      methodology:
        "The same active intrusion-sets as the board, bucketed by how many " +
        "alternate names each carries and gap-filled from zero so no count is " +
        "skipped. The zero bucket — groups the taxonomy tracks under a single " +
        "name — is drawn muted to set it apart from the renamed tail. A snapshot " +
        "of the current release, not a trend.",
    },

    // --------------------------------- top25.html · 1 · hero
    top25_ranks: {
      num: "01",
      kicker: "Official rank vs. reality",
      source: "CVE List V5 (MITRE) · CISA KEV · CWE Top 25 (MITRE)",
      headline: "The worst-bugs list and the wild rank the same bugs differently.",
      caption:
        "MITRE publishes a CWE Top 25 every year — the weakness classes it calls " +
        "the most dangerous. Set each one's official rank beside the rank it " +
        "actually earns from raw prevalence in the CVE corpus: how often that " +
        "class is the first-listed CWE on a published record. The two orders " +
        "pull apart, and several never crack the 25 most common weaknesses we " +
        "actually measure. One caveat kept in plain view: MITRE builds the list " +
        "partly from the same CVE and exploited-vulnerability data, so this is a " +
        "disagreement about ranking, not two independent worlds.",
      statTemplate:
        "MITRE CWE Top 25 ({year}) · measured prevalence {start}–{end} · " +
        "{in_top25} of {total} also rank in the measured top 25",
      colWeakness: "Weakness",
      colOfficial: "official",
      colMeasured: "measured",
      colPrevalence: "prevalence",
      colKev: "KEV hits",
      unranked: "outside",
      unrankedTitle: "not among the 25 most common weaknesses measured in the window",
      nodata: "Not enough data yet.",
      methodology:
        "The official column is MITRE's published CWE Top 25 for the newest " +
        "committed year — a static, hand-transcribed list from cwe.mitre.org/" +
        "top25, the module's only added source. The measured column ranks EVERY " +
        "weakness class by how often it is the first-listed CWE (CNA container " +
        "preferred, CISA-ADP as fallback) on a published CVE record over the " +
        "last five complete calendar years; an official pick can rank anywhere " +
        "in — or fall right out of — that ranking, shown as “outside.” " +
        "Prevalence is that class's share of all CWE-tagged published records in " +
        "the window. KEV hits count the class among CISA Known Exploited " +
        "Vulnerabilities entries that match a corpus record. One honest limit, " +
        "stated plainly: MITRE's own Top-25 formula is derived from NVD CVEs " +
        "joined to CISA KEV and re-scored, so it is not an independent oracle — " +
        "there is partial circularity with our KEV column. That is exactly why " +
        "the story is the DIVERGENCE between the published order and raw " +
        "prevalence, not the list itself. Recomputed nightly; the newest " +
        "committed official list wins. Sort any column.",
    },

    // --------------------------------- top25.html · 2
    top25_exploited: {
      num: "02",
      kicker: "What gets weaponized",
      source: "CVE List V5 (MITRE) · CISA KEV · CWE Top 25 (MITRE)",
      headline: "On the list is not the same as in the wild.",
      caption:
        "Take the same official Top 25 and ask a blunter question: which of " +
        "these classes actually show up in CISA's catalog of exploited " +
        "vulnerabilities? Each bar counts the KEV entries carrying that class as " +
        "their first-listed weakness; classes the exploited set never touches " +
        "fade to gray. Almost every one of the official Top 25 turns up in the " +
        "exploited set — so the list names the right hazards — but the volume " +
        "concentrates on a handful, and a few celebrated classes barely register.",
      statTemplate:
        "{in_kev} of {total} official classes appear in the exploited set · " +
        "together {coverage} of tagged KEV entries",
      xAxis: "exploited (KEV) entries",
      nodata: "Not enough data yet.",
      methodology:
        "Each bar is one of the official Top 25 classes, counting how many CISA " +
        "Known Exploited Vulnerabilities (KEV) entries carry that class as their " +
        "first-listed CWE (CNA container preferred, CISA-ADP as fallback) among " +
        "entries that match a record in the CVE corpus. Bars are sorted " +
        "most-exploited first; a class the exploited set never touches fades to " +
        "gray. “Coverage” is the share of all tagged KEV entries whose class " +
        "sits on the official list. The KEV catalog is small next to the full " +
        "corpus, and only entries matched to a corpus record carry a CWE here, " +
        "so read the counts as a floor. Same caveat as the board: MITRE builds " +
        "the Top 25 partly from KEV, so a class being both on the list and in " +
        "KEV is expected — the telling reads are the on-list classes with no KEV " +
        "entry, and the exploited classes the list ranks low. Recomputed nightly.",
    },

    // --------------------------------- adp.html · 1 · hero
    adp_handoff: {
      num: "01",
      kicker: "The handoff",
      source: "CVE List V5 (MITRE) — CISA-ADP containers",
      headline: "When the referee stopped scoring, a new hand picked up the pen.",
      caption:
        "Each month, the CVE records whose CISA-ADP (Vulnrichment) block was " +
        "last stamped then — the enrichment date, deliberately not the CVE's " +
        "birthday, because CISA back-fills legacy records by the thousand. The " +
        "curve climbs from Vulnrichment's 2024 launch, through the very months " +
        "NVD's own analysis pipeline had stalled. Red bars mark back-fill " +
        "sweeps: a month CISA spent stamping a bulk batch of old CVEs rather " +
        "than enriching fresh ones.",
      statLabel: "Share of the published CVE corpus now carrying a CISA-ADP enrichment",
      statNote: "{cisa} of {total} published records carry a CISA-ADP block",
      sweepTooltip: "Back-fill sweep",
      sweepNote:
        "Red bars are back-fill sweep months — at least half of that month's " +
        "enrichments landed on legacy CVEs (an ID reservation two or more " +
        "years older than the enrichment). That is the signature of a bulk " +
        "pass over old records, though old-vintage IDs freshly published and " +
        "triaged the same month count toward it too.",
      nvdContext:
        "For scale, NVD's own analysis backlog stands at about {backlog} CVEs " +
        "right now — the gap Vulnrichment fills.",
      nodata: "Not enough data yet.",
      methodology:
        "Every published CVE record is checked for a CISA-ADP container — " +
        "CISA's Vulnrichment program, matched by its provider shortName " +
        "“CISA-ADP” or the stable Vulnrichment orgId. Each such record " +
        "is bucketed by that container's own dateUpdated month — deliberately " +
        "NOT the CVE's datePublished: CISA back-fills legacy records (a 2019 " +
        "CVE's CISA-ADP block is stamped 2025), so a publication-date axis " +
        "would smear a false pre-2024 signal. A month is flagged as a back-fill " +
        "sweep (red) when it clears the volume floor and at least half its " +
        "enrichments land on legacy CVEs — an ID vintage two or more years " +
        "older than the enrichment year. The series starts at the first month " +
        "clearing the floor and runs gap-filled to the latest. On the missing " +
        "overlay: this chart deliberately does not draw NVD's 2024 analysis " +
        "collapse as a line, because CyberMon's own NVD backlog record only " +
        "begins at launch and there is no 2024 NVD flow to chart honestly. " +
        "NVD's documented slowdown is described here in prose, and the live " +
        "backlog figure shown for scale is read client-side from the current " +
        "nvd_decay.json — context, never a fabricated trend. Counts are of the " +
        "cvelistV5 corpus; the CVE List is the source of truth.",
    },

    // --------------------------------- adp.html · 2
    adp_adds: {
      num: "02",
      kicker: "What it adds",
      source: "CVE List V5 (MITRE) — CISA-ADP containers",
      headline: "Vulnrichment speaks in decisions, not just scores.",
      caption:
        "Of the records CISA enriched, the share carrying each machine-readable " +
        "addition. An SSVC decision — CISA's stakeholder-specific exploitation " +
        "call — rides on nearly every one; a CVSS score and a CWE weakness " +
        "class are selective patch-ins, added where the CNA left the field " +
        "blank. A record can carry all three, so the bars are independent and " +
        "never sum to a hundred.",
      labelSsvc: "SSVC decision",
      labelCvss: "CVSS score",
      labelCwe: "CWE class",
      yAxis: "share of CISA-ADP records",
      nodata: "Not enough data yet.",
      methodology:
        "For every published record carrying a CISA-ADP container, three checks " +
        "against that container: an SSVC decision (a metrics entry whose " +
        "“other” block has type “ssvc”), a CVSS base score " +
        "(any CVSS version in its metrics), and a CWE (any problemTypes cweId). " +
        "Each bar is the share of CISA-ADP records carrying that field; a record " +
        "can carry all three, so the bars are independent and do not sum to 100. " +
        "The denominator is every published record with a CISA-ADP block, " +
        "whether or not its container is dated.",
    },

    // --------------------------------- adp.html · 3
    adp_providers: {
      num: "03",
      kicker: "The sole enricher",
      source: "CVE List V5 (MITRE) — ADP containers",
      headline: "One agency does almost all of it.",
      caption:
        "Every organization that publishes as an Authorized Data Publisher " +
        "(ADP) — a second, non-CNA container bolted onto the CVE record — " +
        "ranked by how many records it actually enriches: where it added an " +
        "SSVC decision, a CVSS score, or a CWE, not just a reference tag. The " +
        "board is short and lopsided: CISA-ADP does the substantive work, " +
        "while the CVE Program's own root container rides on most records but " +
        "enriches none, so it doesn't appear. Ask “is anyone but CISA an " +
        "ADP?” and the record answers: effectively, no.",
      statTemplate: "{shown} ADP publishers · CISA-ADP on {pct} of the published corpus",
      colProvider: "Publisher",
      colRecords: "records",
      colShare: "% of corpus",
      nodata: "Not enough data yet.",
      methodology:
        "Each published record's ADP containers are read for their provider " +
        "shortName; a publisher scores a record only when its container added " +
        "substantive enrichment — an SSVC decision, a CVSS score, or a CWE, " +
        "not merely reference tags. Share is of all published records in the " +
        "cvelistV5 corpus. ADP is the CVE v5 mechanism for a third party to " +
        "enrich a record it did not assign; the CVE Program's own root " +
        "container rides on most records but adds only references, so it is " +
        "not counted here — in practice CISA-ADP is the only substantive " +
        "enricher, which is the whole point of the board.",
    },

    // --------------------------------- epssvol.html · 1 · hero
    epssvol_gap: {
      num: "01",
      kicker: "The gap",
      source: "EPSS (FIRST.org) · CyberMon's own nightly diffs",
      headline: "The number teams triage on moves overnight. The number that matters holds.",
      caption:
        "EPSS ships two figures per CVE: a probability of exploitation and " +
        "the percentile that ranks it against every other scored CVE. Triage " +
        "runs on the percentile — and it moves under almost every CVE from one " +
        "night to the next, not because the model changed its mind but because " +
        "the corpus grows by a few hundred CVEs a day and the whole population " +
        "re-ranks. The two lines are the share of CVEs whose percentile moved " +
        "and whose probability moved; the space between them is the whole " +
        "story. The exact figures are in the stat and the tooltip — read them " +
        "against each other.",
      // {first_date} is filled from the data (the log's first observed date);
      // the empty variant renders while the log has no diff-nights yet.
      note:
        "No upstream keeps a per-CVE EPSS change log — CyberMon has diffed the " +
        "feed nightly since {first_date}.",
      noteEmpty:
        "No upstream keeps a per-CVE EPSS change log — CyberMon's record " +
        "starts with tonight's feed. The gap appears once there are two nights " +
        "to compare.",
      // Rendered instead of the chart while the log sits under the min-days
      // gate; both variants are filled from the data file, never hardcoded.
      placeholder:
        "{days} of {min_days} diff-nights on record since {first_date} — the " +
        "gap charts once {min_days} nights have accumulated.",
      placeholderEmpty:
        "No diff-nights on the record yet — EPSS volatility begins at first " +
        "deploy, and the first comparable night draws the first point.",
      statLabel: "Share of compared CVEs whose EPSS percentile moved overnight",
      statVersus: "vs {prob} whose probability moved · {days} nights on record",
      legendPct: "Percentile moved",
      legendProb: "Probability moved",
      yAxisLabel: "share of compared CVEs",
      methodology:
        "Every night the pipeline fingerprints the EPSS feed already fetched " +
        "for the rest of the site — each CVE's raw probability and its " +
        "published percentile — and diffs it against the previous night's " +
        "fingerprint, kept as committed state beside the log (a re-run against " +
        "the same EPSS score_date is detected and skipped, so nothing " +
        "double-counts). Only CVEs present on both nights are compared: a CVE " +
        "new to tonight's feed has no prior to move from, and its arrival is " +
        "precisely what drives the reshuffle. “Moved” means the value changed " +
        "at the five-decimal precision EPSS publishes. The two lines are the " +
        "share of compared CVEs whose percentile moved and whose probability " +
        "moved; they diverge by design, because FIRST recomputes every " +
        "percentile nightly against that day's whole corpus while the raw " +
        "probability is the model's actual estimate — the percentile is a " +
        "moving denominator. When the feed's model_version changes, a new " +
        "model rescores the entire corpus overnight and everything moves for a " +
        "reason that has nothing to do with any one CVE; that night is logged " +
        "flagged and excluded from every trend here, the same quarantine " +
        "Silent Rescores applies to its seeding. This is a stability " +
        "measurement, not an accuracy one — the EPSS Report Card grades " +
        "whether the model was right; this asks how much it moves. Two honesty " +
        "notes: the record starts at first deploy, so it is thin by design and " +
        "deepens nightly; and the moat is soft — FIRST's dated daily snapshots " +
        "are publicly archived, so this is the only maintained per-CVE EPSS " +
        "change log, not the only one anyone could build.",
    },

    // --------------------------------- epssvol.html · 2
    epssvol_churn: {
      num: "02",
      kicker: "Material crossings",
      source: "EPSS (FIRST.org) · CyberMon's own nightly diffs",
      headline: "Most of the movement is bookkeeping. This is the part that isn't.",
      caption:
        "A percentile reshuffle changes a CVE's rank without changing what the " +
        "model believes; a probability that crosses a decision line does. " +
        "These bars count only the second kind — CVEs whose raw probability " +
        "crossed 0.1%, 1%, or 5% in a week, in either direction. Set against " +
        "the churn on the hero chart, material crossings are a rounding error, " +
        "and that is the point: the number teams gate on moves constantly, " +
        "while the number that should trigger action barely does.",
      note:
        "Thresholds are the probability lines triage policies actually gate on " +
        "(0.001 / 0.01 / 0.05); a crossing counts in either direction, and the " +
        "three counts are independent — one big jump can cross all three.",
      legendLo: "crossed 0.1%",
      legendMid: "crossed 1%",
      legendHi: "crossed 5%",
      yAxisLabel: "CVEs crossing a threshold",
      emptyChart:
        "No diff-nights on the log yet — material crossings appear once there " +
        "are two nights to compare.",
      methodology:
        "For each CVE compared on two consecutive EPSS snapshots (the " +
        "fingerprint and reset rules are in the hero methodology), the " +
        "pipeline checks whether its raw probability crossed any of three " +
        "fixed thresholds — 0.001, 0.01, 0.05 — meaning the “≥ threshold” side " +
        "flipped between the two nights, up or down. Bars group the per-night " +
        "counts by ISO week of the observation date (UTC); the week in " +
        "progress is starred and keeps filling until it closes, and empty " +
        "weeks between observed ones chart at zero so the axis never skips " +
        "time. The three series are counted independently, so a probability " +
        "that jumps from near zero to above 5% is counted under all three " +
        "lines. Reset nights (a model_version change) are excluded, as " +
        "everywhere on this page. The thresholds are the module's own, not " +
        "FIRST's — they stand in for the decision lines real triage policies " +
        "draw, and they are stated here so a reader can disagree with them.",
    },

    // --------------------------------- epssvol.html · 3
    epssvol_movers: {
      num: "03",
      kicker: "Biggest single-day moves",
      source: "EPSS (FIRST.org) · CyberMon's own nightly diffs",
      headline: "When the model does change its mind, this is how far.",
      caption:
        "The largest single-night jumps in raw EPSS probability on record — " +
        "the events the churn charts are the quiet background to. Each row is " +
        "one CVE on one night, ranked by the size of the move; the arrow and " +
        "the from→to column carry its direction. Expect the board to launch " +
        "sparse: a genuine probability swing is rare by construction, which is " +
        "exactly why the percentile-driven churn underneath it is so " +
        "misleading.",
      note:
        "The board keeps each night's single biggest move; a night with " +
        "several large moves contributes only its largest, so read it as a " +
        "floor on the day's volatility, not a full census.",
      windowTemplate: "{context} · {shown} shown · min move {min_delta}",
      boardNote: "{days} nights on record since {first_date}",
      boardNoteEmpty: "no diff-nights on the log yet — collection is live",
      colCve: "CVE",
      colDate: "moved",
      colShift: "probability",
      colDelta: "move",
      emptyBoard:
        "No single-day probability move has cleared the bar yet — the board " +
        "fills as the record grows.",
      methodology:
        "Each observed night contributes its single largest absolute change " +
        "in raw probability among the CVEs compared that night (the " +
        "fingerprint and reset rules are in the hero methodology). The board " +
        "ranks those nightly champions across the whole record by the " +
        "magnitude of the move — the sign is shown, never sorted on — and " +
        "keeps the biggest twenty above a minimum-move threshold (production " +
        "0.1; the placeholder and the threshold both ship in the data file). " +
        "Probabilities are shown as percentages at the feed's own precision. " +
        "Because only one mover is kept per night, a night with several large " +
        "independent swings is represented by its biggest alone; the board is " +
        "a lower bound on volatility, not a complete list. Reset nights are " +
        "excluded — a whole-corpus rescore is not one CVE moving.",
    },

    // --------------------------------- roster.html · 1 · hero
    roster_size: {
      num: "01",
      kicker: "Roster over time",
      source: "CVE.org organization roster · CyberMon nightly snapshots",
      headline: "The roster changes. Nobody keeps the history.",
      caption:
        "The CVE Program lists every organization allowed to assign a CVE today, " +
        "but publishes no history of the list: not when an assigner joined, not " +
        "when one left, not when its remit changed. CyberMon reads the roster " +
        "every night and keeps the diff. This line is the federation's headcount " +
        "over time — it begins as a single point tonight and deepens one snapshot " +
        "at a time, because the record can only start when the snapshots do.",
      yAxis: "organizations",
      statLabel: "Organizations on the roster",
      statSince: "tracked since {first_date}",
      statNet: "net {net} since {first_date}",
      // {first_date} is filled from the data (the record's first snapshot
      // date); the empty variant renders while there is only one snapshot.
      note:
        "No upstream publishes roster history — CyberMon has snapshotted the " +
        "roster since {first_date}, and the line deepens one night at a time.",
      noteEmpty:
        "No upstream publishes roster history — CyberMon's record starts with " +
        "tonight's snapshot. The curve begins to move once there are two nights " +
        "to compare.",
      emptyChart:
        "No snapshots on the record yet — the size series begins tonight.",
      methodology:
        "Every night the pipeline fetches the CVE Program's published " +
        "organization roster — the same CNAsList.json that powers cve.org's " +
        "List of Partners — and reduces it to one fingerprint per organization, " +
        "keyed by the shortName the assigner carries on CVE records. The count " +
        "of organizations is appended to a committed size history " +
        "(data/history/cna_roster_state.json), and the line is drawn from it. " +
        "The record starts at first deploy: the program publishes no " +
        "accreditation dates, so there is no earlier history to import, and the " +
        "series honestly begins as a single point rather than faking depth. A " +
        "broken fetch that returns a fraction of the roster is refused rather " +
        "than charted. Roster data is CVE Program data, the same source family " +
        "as the CVE List this site already aggregates; the program's terms " +
        "permit reuse of the published data.",
    },

    // --------------------------------- roster.html · 2
    roster_flux: {
      num: "02",
      kicker: "Onboardings & departures",
      source: "CVE.org organization roster · CyberMon nightly snapshots",
      headline: "Who joins, who leaves.",
      caption:
        "Each month's new assigners and departures, with scope changes to " +
        "existing organizations riding alongside. Because the program publishes " +
        "no accreditation date, an onboarding here means first seen in " +
        "CyberMon's snapshots — a floor that starts at first deploy, not a claim " +
        "about when an organization was actually accredited. Bars above the line " +
        "are organizations that appeared; below, ones that vanished; scope " +
        "changes are counted apart, never blended into either.",
      statOnboarded: "organizations joined · {departed} left the roster",
      legendOnboarded: "Joined (first observed)",
      legendDeparted: "Departed",
      legendScope: "Scope changed",
      note:
        "{events} roster changes recorded since {first_date}.",
      noteEmpty:
        "No roster changes recorded yet — a snapshot has to differ from the " +
        "night before, and the record starts now.",
      emptyChart:
        "No roster changes on the record yet — the first onboarding or " +
        "departure fills the first bar.",
      methodology:
        "Tonight's roster is diffed against the previous snapshot, keyed by " +
        "shortName. An organization present tonight but not last time is an " +
        "onboarding; present last time but gone now is a departure; present in " +
        "both with a changed scope statement is a scope change (compared by a " +
        "short stable hash of the text, so the event records that the scope " +
        "moved without republishing the prose). Events append to a committed, " +
        "append-only log (data/history/cna_roster.csv) — like the NVD backlog " +
        "history, an original dataset this project accumulates, because the " +
        "upstream keeps only today's roster. Bars group by calendar month of " +
        "the observation date, gap-filled so the axis never skips time. " +
        "Onboarding is first-observed, not accredited-on: with no published " +
        "accreditation dates, the log dates each organization to the night " +
        "CyberMon first saw it, and the very first run logs nothing because " +
        "there is no prior snapshot to diff.",
    },

    // --------------------------------- roster.html · 3
    roster_mix: {
      num: "03",
      kicker: "Today's composition",
      source: "CVE.org organization roster · CyberMon nightly snapshots",
      headline: "Mostly vendors, speaking for themselves.",
      caption:
        "Every organization on the roster tonight, tallied by the kind of " +
        "authority it claims — vendor, open-source project, researcher, CERT, " +
        "bug-bounty platform. Most CNAs are vendors scoped to their own " +
        "products; a shorter tail covers everyone else. Organizations can hold " +
        "more than one type, so the bars sum above the roster total. Above them " +
        "all sit two top-level roots, MITRE and CISA, that vouch for the rest.",
      statTemplate:
        "{total} organizations · {countries} countries · top-level roots " +
        "MITRE {mitre} / CISA {cisa}",
      xAxis: "organizations",
      nodata: "Not enough data yet.",
      methodology:
        "The composition is read straight from tonight's roster fetch, so " +
        "unlike the two charts above it is fully populated from day one. Each " +
        "organization's CNA.type list is tallied — an organization that lists " +
        "several types (a vendor that is also an open-source steward) counts " +
        "once in each, so the bars sum above the roster headcount by design. " +
        "The data file also carries the same roster split by top-level root " +
        "(MITRE or CISA), by reporting root, and by country, each a clean " +
        "partition that sums to the total, for anyone who wants to read the " +
        "federation a different way. A snapshot of today's roster, not a trend " +
        "— the trend is what the size and flux charts above are slowly " +
        "accumulating.",
    },
  },

  footer: {
    generatedTemplate: "Edition generated {generated_at}",
    sourcesTemplate:
      "Sources — cvelistV5 release {cvelist_release} ({cve_count} CVEs) · " +
      "EPSS {epss_version} scores of {epss_date} · CISA KEV {kev_version} ({kev_count} entries) · " +
      "NVD statuses fetched {nvd_fetched} · market terms fetched {market_fetched} · " +
      "HIBP breach catalog fetched {hibp_fetched} ({hibp_count} breaches) · " +
      "Ransomwhere {ransomwhere_addresses} addresses / {ransomwhere_txs} transactions " +
      "fetched {ransomwhere_fetched} · " +
      "ATT&CK enterprise v{attack_version} ({attack_versions} releases) · " +
      "APNIC DNSSEC series fetched {apnic_fetched} · " +
      "EPSS history: {epss_graded} KEV entries graded · " +
      "rescore log: {rescore_events} events on record · " +
      "KEV changelog: {kev_changelog_events} catalog events on record",
    metaError: "Edition metadata (data/meta.json) failed to load.",
    disclaimer:
      "CyberMon is an independent project. Not affiliated with, endorsed by, or speaking for " +
      "MITRE, NVD/NIST, CISA, FIRST, GDELT, Y Combinator/Algolia, arXiv, the Wikimedia " +
      "Foundation, the U.S. Securities and Exchange Commission, Have I Been Pwned, " +
      "Ransomwhere, APNIC, or the Internet Archive. Charts aggregate public data; no " +
      "individual CVE is news here, and no victim is identified or identifiable anywhere " +
      "on this site.",
    reuseNote:
      "Reuse is welcome: take any chart or number — screenshot, embed, quote — with a link " +
      "back to CyberMon as the source. This is a spare-time project rebuilt nightly by an " +
      "unattended pipeline and provided as-is, with no guarantee of correctness, completeness, " +
      "or availability; check a number against its primary source before you rely on it.",
    dataNote:
      "Data: CVE List V5 (MITRE), EPSS (FIRST.org), Known Exploited Vulnerabilities catalog (CISA), " +
      "NVD API 2.0 (NIST), GDELT 2.0 (news volume), Hacker News via Algolia Search API, " +
      "arXiv cs.CR metadata (thank you to arXiv for use of its open access interoperability), " +
      "Wikipedia pageview statistics via the Wikimedia REST API (CC0 aggregate data, " +
      "Wikimedia Foundation), SEC EDGAR full-text search (efts.sec.gov, public U.S. " +
      "Government data accessed per SEC fair-access guidelines), " +
      "breach catalog courtesy of Have I Been Pwned (haveibeenpwned.com), " +
      "Ransomwhere (crowdsourced ransomware payment tracker by Jack Cable, CC0), " +
      // The quoted sentence is MITRE's required copyright designation, verbatim
      // (attack.mitre.org → Resources → Terms of Use). Do not paraphrase it.
      "MITRE ATT&CK® (© 2026 The MITRE Corporation. This work is reproduced and distributed " +
      "with the permission of The MITRE Corporation.), " +
      "DNSSEC validation measurement data © APNIC Pty Ltd (APNIC Labs, stats.labs.apnic.net; " +
      "re-use with attribution permitted), " +
      "and KEV catalog history reconstructed from Internet Archive Wayback Machine captures.",
    repoLabel: "Pipeline, methodology & issues → github.com/Devko/CyberMon",
    // Module pages only (the Overview has no carousel). The PDF is built at
    // deploy time by tools/make_carousels.py and ships only inside the Pages
    // artifact, never in git.
    carouselTemplate: "This page as a LinkedIn carousel (PDF) → carousels/{id}.pdf",
  },

  // ------------------------------------------- carousel.html (print template)
  // Strings for the per-module slide decks (LinkedIn document-post PDFs).
  // Rendered by js/carousel.js, printed by tools/make_carousels.py.
  carousel: {
    edition: "Edition {generated_at}",
    slideFooter: "CyberMon · devko.github.io/CyberMon · data: {sources}",
    siteUrl: "devko.github.io/CyberMon",
    closingSources: "Data: {sources}",
    // Printed under a board the fit pass had to cut — a truncated table
    // must say so (the full ranking lives on the site).
    tableMore: "Top {shown} of {total} — the full board is on the site.",
    // Per-module primary upstreams, short enough for a slide footer. The
    // full attribution (editorial.footer.dataNote) stays on the site.
    sources: {
      cve: "CVE List V5 (MITRE) · EPSS (FIRST.org) · CISA KEV · NVD (NIST)",
      market: "GDELT 2.0 · Hacker News (Algolia) · arXiv cs.CR · Wikipedia pageviews · SEC EDGAR",
      kev: "CISA KEV catalog · CVE List V5 (MITRE)",
      concentration: "CVE List V5 (MITRE)",
      breaches: "Have I Been Pwned",
      extortion: "Ransomwhere (CC0)",
      attack: "MITRE ATT&CK®",
      hygiene: "APNIC Labs (stats.labs.apnic.net)",
      guards: "CISA KEV catalog",
      epss: "EPSS (FIRST.org) · CISA KEV",
      calendar: "CVE List V5 (MITRE)",
      rescores: "CVE List V5 (MITRE) · CyberMon nightly diffs",
      changelog: "CISA KEV catalog · Internet Archive Wayback Machine",
      naming: "MITRE ATT&CK®",
      top25: "CVE List V5 (MITRE) · CWE Top 25 (MITRE)",
      adp: "CVE List V5 (MITRE)",
      epssvol: "EPSS (FIRST.org) · CyberMon nightly diffs",
      roster: "CVE.org organization roster · CyberMon nightly snapshots",
    },
  },
};

// Tiny template helper: tpl("{a} vs {b}", {a: 1, b: 2}) -> "1 vs 2"
export function tpl(str, vars) {
  return str.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
}
