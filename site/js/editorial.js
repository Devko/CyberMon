// =============================================================================
// editorial.js — EVERY user-facing string on the site lives here.
// Rewrite the voice in this one file; nothing editorial is hardcoded elsewhere.
//
// Templates use {placeholders}; values are filled from site/data/*.json at
// render time so the copy never carries stale numbers.
// =============================================================================

const PIPELINE_URL = "https://github.com/Devko/CyberMon/blob/main/pipeline/";
const REPO_URL = "https://github.com/Devko/CyberMon";

export const editorial = {
  repoUrl: REPO_URL,
  pipelineUrl: PIPELINE_URL,

  masthead: {
    kicker: "Security-industry metrics · rebuilt nightly from open data",
    thesis: "CyberMon measures the security industry's public records and publishes the method behind every number.",
    sub: "Each chart states how it is computed and links to the pipeline code, which is open source and can be rerun.",
  },

  // Thematic nav groups, in display order. Each entry: a short label for the
  // nav row, and a one-line lede for the landing page's group header. The
  // LAST entry ("more") is the automatic catch-all: any nav entry with a
  // missing or unrecognized `group` id lands there, so a module merged
  // without a tag still ships navigable and a new group never needs code.
  navGroups: [
    {
      id: "machine",
      label: "CVE records",
      lede: "Who assigns CVE records, and how they are scored, enriched, tagged and changed after publication.",
    },
    {
      id: "exploitation",
      label: "Exploitation",
      lede: "CISA's list of exploited CVEs, EPSS exploitation forecasts and public exploit code.",
    },
    {
      id: "industry",
      label: "Industry",
      lede: "Buzzword attention, breach disclosure, SEC incident filings, ransom payments and DNSSEC validation.",
    },
    {
      id: "attackmap",
      label: "Threats",
      lede: "MITRE ATT&CK's techniques and group names, botnet C2 servers and malicious open-source packages.",
    },
    {
      id: "more",
      label: "More",
      lede: "Modules not yet assigned to a group.",
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
  //                  catalog and FIRST's EPSS feed (Security Products in KEV and
  //                  KEV Changelog are both KEV-derived).
  //   industry     — read from outside-world ledgers: GDELT/HN/arXiv (hype),
  //                  HIBP (breaches), Ransomwhere (ransoms), APNIC (hygiene).
  //   attackmap    — read from MITRE ATT&CK's STIX bundles (Threat Group Aliases is
  //                  ATT&CK alias data, not CVE data — it lives here).
  nav: [
    { id: "home", href: "index.html", label: "Overview" },
    { id: "cve", href: "cve.html", label: "CVE Ecosystem", group: "machine" },
    { id: "market", href: "market.html", label: "Buzzword Attention", group: "industry" },
    { id: "kev", href: "kev.html", label: "KEV Latency", group: "exploitation" },
    { id: "concentration", href: "concentration.html", label: "CNA Concentration", group: "machine" },
    { id: "breaches", href: "breaches.html", label: "Breach Catalog", group: "industry" },
    { id: "extortion", href: "extortion.html", label: "Ransom Payments", group: "industry" },
    { id: "attack", href: "attack.html", label: "ATT&CK Releases", group: "attackmap" },
    { id: "hygiene", href: "hygiene.html", label: "DNSSEC Validation", group: "industry" },
    { id: "guards", href: "guards.html", label: "Security Products in KEV", group: "exploitation" },
    { id: "epss", href: "epss.html", label: "EPSS Before KEV", group: "exploitation" },
    { id: "calendar", href: "calendar.html", label: "CVE Calendar", group: "machine" },
    { id: "changelog", href: "changelog.html", label: "KEV Changelog", group: "exploitation" },
    { id: "rescores", href: "rescores.html", label: "CVSS Score Changes", group: "machine" },
    { id: "naming", href: "naming.html", label: "Threat Group Aliases", group: "attackmap" },
    { id: "top25", href: "top25.html", label: "CWE Top 25", group: "machine" },
    { id: "adp", href: "adp.html", label: "Vulnrichment", group: "machine" },
    { id: "epssvol", href: "epssvol.html", label: "EPSS Volatility", group: "exploitation" },
    { id: "roster", href: "roster.html", label: "CNA Roster", group: "machine" },
    { id: "exploits", href: "exploits.html", label: "Time to PoC", group: "exploitation" },
    { id: "c2", href: "c2.html", label: "Botnet C2 Servers", group: "attackmap" },
    { id: "ai", href: "ai.html", label: "AI and Exploit Timing", group: "exploitation" },
    { id: "credits", href: "credits.html", label: "AI Credits", group: "machine" },
    { id: "tags", href: "tags.html", label: "Record Tags", group: "machine" },
    { id: "incidents", href: "incidents.html", label: "SEC Incident Filings", group: "industry" },
    { id: "advisories", href: "advisories.html", label: "Advisories Without a CVE", group: "machine" },
    { id: "malware", href: "malware.html", label: "Malicious Packages", group: "attackmap" },
  ],

  // ------------------------------------------------- index.html (landing)
  home: {
    kicker: "Overview",
    headline: "Pick a module.",
    caption:
      "CyberMon measures the security industry from public data: how vulnerabilities are " +
      "numbered, scored and catalogued, which ones are exploited, and the market attention, " +
      "breaches, incident filings and ransom payments around them. Each module below is a " +
      "separate page with its own nightly pipeline stage, data contracts and a " +
      "“how this is computed” note under every chart.",
    statusLive: "live",
    statusSoon: "coming soon",
    backlogNote:
      "Candidate modules are listed in the repository in docs/backlog.md.",
    // Instruments are NOT modules: no charts, no claims guards, no nav entry
    // (so the carousel and motion pipelines never see them). They render as
    // their own block under the module directory.
    instruments: {
      label: "Instruments",
      lede: "Tools for looking up individual records in the data the modules summarize.",
      status: "instrument",
      items: [
        {
          id: "field",
          href: "field.html",
          num: "3D",
          label: "The Field",
          headline: "Every published CVE is placed as one point in a 3D view.",
          blurb:
            "Published records from the cvelistV5 corpus in a WebGL view. Arrange them by " +
            "publication date, score and EPSS; by days from publication to the first public " +
            "exploit and to the KEV listing; by CVSS and EPSS bucket; or by assigner, vendor, " +
            "weakness or NVD status. Hover to read a record; a link keeps the arrangement and " +
            "filters. Rebuilt nightly from the same corpus pass as the charts.",
        },
        {
          id: "observatory",
          href: "observatory.html",
          num: "Δ",
          label: "Mutation Observatory",
          headline: "The Observatory puts CyberMon's CVE-level change logs on one timeline.",
          blurb:
            "CNA score changes (mostly first scores on existing records), KEV additions, " +
            "edits and removals, and each night's largest EPSS probability change, with " +
            "quarantined nights left out. Events are dated by the night CyberMon observed " +
            "them; EPSS events by FIRST's score date. Select a date range, look up one CVE, " +
            "or download the events as CSV.",
        },
      ],
    },
    modules: [
      {
        id: "cve",
        href: "cve.html",
        num: "01",
        label: "CVE Ecosystem",
        headline: "Close to half of scored CVEs are rated High or Critical each year.",
        blurb:
          "Ten charts on CVE scores and records: severity by CVSS version over time, CVEs " +
          "per year by severity, CVSS against EPSS and KEV, NVD's backlog and daily " +
          "throughput, scores by CNA, publication volume, missing fields, the most common " +
          "weakness classes, and CVSS 4.0 adoption. Rebuilt every night.",
        live: true,
      },
      {
        id: "market",
        href: "market.html",
        num: "02",
        label: "Buzzword Attention",
        headline: "Attention to each security buzzword is tracked monthly in five public sources.",
        blurb:
          "News coverage (GDELT), Hacker News discussion, arXiv papers, Wikipedia pageviews " +
          "and SEC EDGAR filings, each term indexed to its own peak in a rolling five-year " +
          "window, with the largest year-over-year changes and a comparison of research " +
          "and news attention. Rebuilt nightly.",
        live: true,
      },
      {
        id: "kev",
        href: "kev.html",
        num: "03",
        label: "KEV Latency",
        headline: "Most KEV entries were listed a week or more after their CVE was published.",
        blurb:
          "Days from CVE publication to listing in CISA's Known Exploited Vulnerabilities " +
          "catalog, the same gap in buckets, the remediation deadlines CISA sets, and the " +
          "share of listings flagged for known ransomware use. Entries from the catalog's " +
          "2021–22 seeding period are shown apart from later years.",
        live: true,
      },
      {
        id: "concentration",
        href: "concentration.html",
        num: "04",
        label: "CNA Concentration",
        headline: "Hundreds of CNAs assign CVEs; since 2021 the five largest have issued about half.",
        blurb:
          "The number of active CNAs each year, the share of each year's CVEs from the five " +
          "and ten largest, new CNAs per year, and the CNAs that later reject the largest " +
          "share of their own published records. Rebuilt nightly from the same corpus as " +
          "CVE Ecosystem.",
        live: true,
      },
      {
        id: "breaches",
        href: "breaches.html",
        num: "05",
        label: "Breach Catalog",
        headline: "Breaches typically reach Have I Been Pwned months after their recorded breach date.",
        blurb:
          "The Have I Been Pwned breach catalog: days from the recorded breach date to " +
          "HIBP's listing, breaches and exposed accounts per year, and the data classes " +
          "exposed most often. Entries from HIBP's launch import are kept out of the trend.",
        live: true,
      },
      {
        id: "extortion",
        href: "extortion.html",
        num: "06",
        label: "Ransom Payments",
        headline: "Crowdsourced, blockchain-verified ransomware payments total more than a billion dollars.",
        blurb:
          "Payments from the Ransomwhere dataset, which counts only payments to reported " +
          "and verified addresses: revenue per quarter in dollars at the day of transfer, " +
          "payment counts and median sizes, and revenue by ransomware family. Every total " +
          "is a lower bound. Rebuilt nightly.",
        live: true,
      },
      {
        id: "attack",
        href: "attack.html",
        num: "07",
        label: "ATT&CK Releases",
        headline: "Active ATT&CK techniques and sub-techniques have increased every year since 2018.",
        blurb:
          "Active techniques and sub-techniques in each MITRE ATT&CK enterprise release, " +
          "what each release added, deprecated or revoked, and the number of groups and " +
          "software entries. Parsed nightly from MITRE's STIX bundles.",
        live: true,
      },
      {
        id: "hygiene",
        href: "hygiene.html",
        num: "08",
        label: "DNSSEC Validation",
        headline: "Fewer than half of internet users sit behind DNSSEC-validating resolvers.",
        blurb:
          "DNSSEC validation as measured by APNIC Labs: the world share of users since " +
          "2013, the ten economies with the most internet users, and the distribution " +
          "across all measured economies. Rebuilt nightly.",
        live: true,
      },
      {
        id: "guards",
        href: "guards.html",
        num: "09",
        label: "Security Products in KEV",
        headline: "More than one KEV entry in nine is a security product.",
        blurb:
          "Every CISA KEV entry classified by a curated, versioned list of security " +
          "vendors and products: the security-product share of each year's listings, the " +
          "vendors listed most often, and how often those entries carry the ransomware flag " +
          "compared with the rest of the catalog. Rebuilt nightly.",
        live: true,
      },
      {
        id: "epss",
        href: "epss.html",
        num: "10",
        label: "EPSS Before KEV",
        headline: "Roughly half or more of recent KEV additions had an EPSS score under 1% the day before listing.",
        blurb:
          "For CVEs in CISA's KEV catalog, the EPSS score published the day before each " +
          "listing: probability bands per listing year, the distribution by EPSS model " +
          "version, and the percentile ranks. It describes what the forecast said and does " +
          "not measure its accuracy.",
        live: true,
      },
      {
        id: "calendar",
        href: "calendar.html",
        num: "11",
        label: "CVE Calendar",
        headline: "Since 2022, more CVEs have been published on Tuesday than on any other day.",
        blurb:
          "How old a CVE's ID is when its record is published, publication by weekday, " +
          "and the share of each year's CVEs published on the twelve Patch Tuesdays. Read " +
          "from the corpus every night.",
        live: true,
      },
      {
        id: "changelog",
        href: "changelog.html",
        num: "12",
        label: "KEV Changelog",
        headline: "CISA changes KEV entries after listing them, including due dates and ransomware flags.",
        blurb:
          "Each night CyberMon compares the Known Exploited Vulnerabilities catalog with " +
          "the last copy it saw and logs changed due dates, changed ransomware flags, " +
          "rewritten descriptions and notes, and removed entries. Changes before July 2026 " +
          "come from Internet Archive captures of the feed.",
        live: true,
      },
      {
        id: "rescores",
        href: "rescores.html",
        num: "13",
        label: "CVSS Score Changes",
        headline: "CNAs change CVSS scores on published CVE records, mostly by adding a missing score.",
        blurb:
          "Each night CyberMon compares every CVE's CNA-assigned score with the previous " +
          "night's and logs the changes: scores raised or lowered, CVSS version changes, " +
          "removed scores, and scores added to records that had none, often in batches. " +
          "The cvelistV5 git history holds the raw edits; this log has run since July 2026.",
        live: true,
      },
      {
        id: "naming",
        href: "naming.html",
        num: "14",
        label: "Threat Group Aliases",
        headline: "ATT&CK's most-renamed threat groups carry more than a dozen other names each.",
        blurb:
          "MITRE ATT&CK files each threat group under one name and lists other names it " +
          "is known by: the groups with the most aliases, and the distribution of alias " +
          "counts across the active groups. Read nightly from the current enterprise STIX " +
          "bundle.",
        live: true,
      },
      {
        id: "top25",
        href: "top25.html",
        num: "15",
        label: "CWE Top 25",
        headline: "Most of MITRE's CWE Top 25 also rank among the 25 most frequent weaknesses in CVEs.",
        blurb:
          "MITRE's annual CWE Top 25 beside how often each weakness is the first-listed " +
          "CWE in CVE records and in CISA's KEV catalog: the official rank against the " +
          "measured rank, and which of the 25 appear in KEV. Rebuilt nightly.",
        live: true,
      },
      {
        id: "adp",
        href: "adp.html",
        num: "16",
        label: "Vulnrichment",
        headline: "CISA's Vulnrichment program has added data to about half of all published CVEs.",
        blurb:
          "NVD's analysis backlog grew through 2024, the year CISA launched Vulnrichment. " +
          "Its CISA-ADP container adds SSVC decision points to nearly every record it covers, " +
          "and a CVSS score or a CWE id to about a fifth each. Monthly counts by the " +
          "container's own update date, what it adds, and the ADP publishers ranked by " +
          "records enriched. Read nightly from the CVE List.",
        live: true,
      },
      {
        id: "epssvol",
        href: "epssvol.html",
        num: "17",
        label: "EPSS Volatility",
        headline: "EPSS percentiles change for almost every CVE each night; probabilities change for very few.",
        blurb:
          "CyberMon compares each night's EPSS feed with the previous night's. The " +
          "percentile is a rank against all scored CVEs, a set that grows every day, so it " +
          "changes for almost every CVE; the probability changes for very few. Also weekly " +
          "counts of probabilities crossing 0.1%, 1% and 5%, and the largest single-night " +
          "changes. FIRST publishes daily scores but no change log; CyberMon has kept this " +
          "one since July 2026.",
        live: true,
      },
      {
        id: "roster",
        href: "roster.html",
        num: "18",
        label: "CNA Roster",
        headline: "The CVE Program publishes no join dates, so CyberMon logs roster changes nightly.",
        blurb:
          "The CVE Program publishes its current list of partner organizations, and the " +
          "roster file's git history holds the raw edits. CyberMon snapshots the list " +
          "every night and logs organizations joining, leaving, renamed or changing scope, " +
          "with the current roster by type, root and country. The log starts in July 2026.",
        live: true,
      },
      {
        id: "exploits",
        href: "exploits.html",
        num: "19",
        label: "Time to PoC",
        headline: "Since 2021 the median public exploit has appeared a week or more after the CVE.",
        blurb:
          "Days from CVE publication to the first public exploit code dated by Exploit-DB " +
          "(negative when the exploit came first), how often public exploit code was out " +
          "before CISA added the CVE to KEV, and the share of each severity bucket with " +
          "public exploit code, with Nuclei detection templates counted separately. Rebuilt " +
          "nightly from the trackers' published indexes.",
        live: true,
      },
      {
        id: "c2",
        href: "c2.html",
        num: "20",
        label: "Botnet C2 Servers",
        headline: "Feodo Tracker's botnet C2 blocklist is counted by malware family every night.",
        blurb:
          "abuse.ch's Feodo Tracker publishes only its current blocklist of botnet " +
          "command-and-control servers. CyberMon records the count by malware family each " +
          "night and shows the current list by family, country and network, and how long " +
          "ago the tracker first saw each server. Unchanged counts cannot show whether the " +
          "servers are unchanged or the tracker has stopped updating.",
        live: true,
      },
      {
        id: "ai",
        href: "ai.html",
        num: "21",
        label: "AI and Exploit Timing",
        headline: "No judged exploit-timing measure has sped up since ChatGPT's release.",
        blurb:
          "A dated timeline of AI releases, reports and incidents over CyberMon's " +
          "exploit-timing series (days from CVE publication to public exploit code), with " +
          "each series tested for a change at three candidate start dates for an “AI era”. " +
          "At the ChatGPT date none of the judged measures sped up; the later dates do not " +
          "yet have enough complete years to judge. Also AI-security attention against the " +
          "same series.",
        live: true,
      },
      {
        id: "credits",
        href: "credits.html",
        num: "22",
        label: "AI Credits",
        headline: "AI labs and vendors announce vulnerabilities in the thousands; hundreds of CVE records credit them.",
        blurb:
          "CVE records that credit an AI lab's model or an AI-security vendor, matched " +
          "against a curated registry that keeps labs and vendors separate. The credited " +
          "records are broken down by severity, weakness class and target, joined to EPSS, " +
          "the public exploit and detection corpora and CISA KEV, and set beside each " +
          "finder's own announced numbers with unit and source.",
        live: true,
      },
      {
        id: "tags",
        href: "tags.html",
        num: "23",
        label: "Record Tags",
        headline: "More CVEs are tagged as issued for products the vendor no longer supports.",
        blurb:
          "CNAs can tag a CVE record “unsupported-when-assigned” or “disputed”. Per " +
          "publication year, the first tag keeps climbing and the second has not kept pace " +
          "with the corpus. Also which CNAs set the tags (few do) and how tagged records " +
          "are scored compared with the same CNAs' other records. A tag records what the " +
          "CNA stated; CyberMon does not check it.",
        live: true,
      },
      {
        id: "incidents",
        href: "incidents.html",
        num: "24",
        label: "SEC Incident Filings",
        headline: "US public companies have filed dozens of material-incident 8-Ks since December 2023.",
        blurb:
          "Since 18 December 2023 a US public company must disclose a material " +
          "cybersecurity incident on Form 8-K under Item 1.05. The module counts those " +
          "filings on EDGAR by month and quarter, the amendments that follow and the days " +
          "to the first one, and Item 8.01 filings that describe a cybersecurity incident, " +
          "with links to the latest filings. Re-read from SEC EDGAR full-text search every " +
          "night.",
        live: true,
      },
      {
        id: "advisories",
        href: "advisories.html",
        num: "25",
        label: "Advisories Without a CVE",
        headline: "Most GitHub-reviewed advisories carry a CVE id; a quarter of Rust's do not.",
        blurb:
          "GitHub-reviewed security advisories for open-source packages, split by whether " +
          "they carry a CVE id: per publication year, per ecosystem, and by GitHub's " +
          "severity rating. Advisories without a CVE id do not appear in CVE-based feeds. " +
          "Rebuilt nightly from OSV's ecosystem exports.",
        live: true,
      },
      {
        id: "malware",
        href: "malware.html",
        num: "26",
        label: "Malicious Packages",
        headline: "Six in ten reports in the OpenSSF malicious-packages feed were published in one month.",
        blurb:
          "Reports in the OpenSSF malicious-packages feed per registry per month, each " +
          "registry's share of each year's reports, and how many reports were later " +
          "withdrawn. These count reports of malicious packages, not installs or victims. " +
          "Rebuilt nightly from OSV's ecosystem exports.",
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
    body: "Couldn't fetch {file}. Sections that read other files still work; reload to retry.",
    // Chart-library variant: the JSON loaded, ECharts (CDN) did not.
    libraryTitle: "The chart library did not load.",
    libraryBody:
      "The charts need ECharts from cdn.jsdelivr.net, which this browser could not " +
      "load. The numbers are in {file}.",
  },

  methodologyLabel: "How this is computed",
  navFoldLabel: "All modules",
  tocLabel: "On this page",
  chartSourcePrefix: "Data: ",
  chartSourceLinkText: "all sources & licenses ↓",
  methodologySourcePrefix: "Source of truth: ",
  // Pipeline module that builds each section's numbers (section id -> file
  // under pipeline/); a section missing here falls back to metrics.py.
  sourceFiles: {
    inflation: "metrics.py",
    flood: "metrics.py",
    reality: "metrics.py",
    decay: "metrics.py",
    cna: "metrics.py",
    volume: "metrics.py",
    hype: "market_metrics.py",
    risers: "market_metrics.py",
    divergence: "market_metrics.py",
    throughput: "nvd_throughput.py",
    quality: "quality_metrics.py",
    cwe: "quality_metrics.py",
    latency: "kev_metrics.py",
    buckets: "kev_metrics.py",
    remediation: "kev_metrics.py",
    ransomware: "kev_metrics.py",
    concentration: "concentration_metrics.py",
    entrants: "concentration_metrics.py",
    rejection: "concentration_metrics.py",
    disclosure: "breach_metrics.py",
    exposure: "breach_metrics.py",
    leaks: "breach_metrics.py",
    revenue: "extortion_metrics.py",
    payments: "extortion_metrics.py",
    families: "extortion_metrics.py",
    map: "attack_metrics.py",
    churn: "attack_metrics.py",
    catalog: "attack_metrics.py",
    validation: "hygiene_metrics.py",
    economies: "hygiene_metrics.py",
    spread: "hygiene_metrics.py",
    guards: "guards_metrics.py",
    recidivism: "guards_metrics.py",
    overlap: "guards_metrics.py",
    grade: "epss_report_metrics.py",
    distribution: "epss_report_metrics.py",
    percentile: "epss_report_metrics.py",
    reservation: "calendar_metrics.py",
    weekbeat: "calendar_metrics.py",
    patchtuesday: "calendar_metrics.py",
    week: "rescore_tracker.py",
    magnitude: "rescore_tracker.py",
    editors: "rescore_tracker.py",
    edits: "kev_changelog.py",
    flagflip: "kev_changelog.py",
    flaglag: "kev_changelog.py",
    obs_stream: "observatory.py",
    obs_trail: "observatory.py",
    obs_window: "observatory.py",
    receipts: "kev_changelog.py",
    naming_board: "naming_metrics.py",
    naming_dist: "naming_metrics.py",
    top25_ranks: "top25_metrics.py",
    top25_exploited: "top25_metrics.py",
    adp_handoff: "adp_metrics.py",
    adp_adds: "adp_metrics.py",
    adp_providers: "adp_metrics.py",
    epssvol_gap: "epss_volatility.py",
    epssvol_churn: "epss_volatility.py",
    epssvol_movers: "epss_volatility.py",
    roster_size: "cna_roster.py",
    roster_flux: "cna_roster.py",
    roster_mix: "cna_roster.py",
    poc_gap: "poc_metrics.py",
    poc_preempt: "poc_metrics.py",
    poc_coverage: "poc_metrics.py",
    c2_weather: "botnet_metrics.py",
    c2_today: "botnet_metrics.py",
    c2_age: "botnet_metrics.py",
    ai_clock: "ai_metrics.py",
    ai_banked: "ai_metrics.py",
    ai_attention: "ai_metrics.py",
    credits_funnel: "ai_credits_metrics.py",
    credits_profile: "ai_credits_metrics.py",
    credits_lanes: "ai_credits_metrics.py",
    credits_board: "ai_credits_metrics.py",
    credits_weakness: "ai_credits_metrics.py",
    credits_targets: "ai_credits_metrics.py",
    credits_coverage: "ai_credits_metrics.py",
    incidents_clock: "sec_incidents_metrics.py",
    incidents_amend: "sec_incidents_metrics.py",
    incidents_receipts: "sec_incidents_metrics.py",
    gap_years: "osv_metrics.py",
    gap_ecosystems: "osv_metrics.py",
    gap_severity: "osv_metrics.py",
    mal_months: "osv_metrics.py",
    mal_share: "osv_metrics.py",
    mal_withdrawn: "osv_metrics.py",
    cvss4: "cvss_v4_metrics.py",
    tags_trend: "tags_metrics.py",
    tags_board: "tags_metrics.py",
    tags_severity: "tags_metrics.py",
  },

  // Display names for OSV ecosystem ids (advisories.html, malware.html).
  // The id stays the data key; the bracket names the language where the
  // registry name does not.
  osvEcosystems: {
    npm: "npm",
    PyPI: "PyPI",
    Maven: "Maven (Java)",
    Packagist: "Packagist (PHP)",
    Go: "Go",
    "crates.io": "crates.io (Rust)",
    NuGet: "NuGet (.NET)",
    RubyGems: "RubyGems",
    Hex: "Hex (Erlang/Elixir)",
    SwiftURL: "Swift",
    "GitHub Actions": "GitHub Actions",
    Pub: "Pub (Dart)",
    VSCode: "VS Code extensions",
    other: "Other",
  },

  // Shared by every chart that draws a full-year pace projection for the
  // partial current year (volume curve, 9.8 flood, new entrants). The
  // pipeline emits the projection only for flow metrics — see
  // docs/data-contracts.md, "Pace projections".
  projection: {
    note:
      "Dashed or hollow marks show the partial year extended to twelve " +
      "months at its pace so far. This is arithmetic, not a forecast.",
    tooltipProjected: "{name} · full year at this pace ≈ {n}",
    tooltipElapsed: "{pct} of the year elapsed",
    floodLabel: "≈ {n} at this pace",
    floodTooltipName: "All severities",
  },

  // Shared by the additive charts that can drop the Linux kernel CNA
  // (volume curve, 9.8 flood, CNA concentration). The pipeline ships a
  // without_linux variant with its own pace projection — see
  // docs/data-contracts.md, "Linux-kernel variants".
  linuxToggle: {
    labels: ["All CNAs", "Without Linux kernel"],
    note:
      "This view removes the records of the Linux kernel CNA (assigner " +
      "“Linux”) from every year. Charts without this toggle include them.",
  },

  sections: {
    // ------------------------------------------- market.html · 1 · hero
    hype: {
      num: "01",
      kicker: "Attention curves",
      source: "GDELT 2.0 · Hacker News via Algolia · arXiv cs.CR · Wikipedia pageviews · SEC EDGAR full-text search",
      headline: "Each term is scaled to its own busiest month of the last five years.",
      caption:
        "Monthly counts for one term at a time from five sources: news articles (GDELT), " +
        "Hacker News stories and comments, arXiv cs.CR preprints, Wikipedia pageviews and " +
        "SEC EDGAR filings. Each source's series is indexed to its own five-year peak " +
        "(peak = 100), so a source with a few papers a month and one with thousands of " +
        "articles can share one axis. Pick a term from the list or click a card.",
      selectLabel: "Term",
      termCountNote: "{n} terms tracked; the list is in pipeline/market_terms.py",
      sparklineNote:
        "Click a card to load that term above. Each sparkline shows the GDELT index only; " +
        "a term with no GDELT data yet shows a label instead of a line.",
      methodology:
        "For each tracked term the pipeline pulls a monthly count over a rolling five-year " +
        "window from five sources: GDELT 2.0 (news article volume); Hacker News (Algolia " +
        "search API, stories and comments); arXiv (cs.CR preprint count); Wikipedia " +
        "(monthly pageviews of one curated on-topic article per term, summed over the " +
        "article's earlier titles when it was moved, bot traffic excluded); and SEC EDGAR " +
        "full-text search (filings matching the term as a quoted phrase, with acronyms " +
        "spelled out to avoid matches on unrelated financial terms). The term-to-article " +
        "mapping is in pipeline/market_terms.py, and a term with no on-topic article has " +
        "no Wikipedia series. Each series is indexed to its own highest month in the " +
        "window (peak = 100). The index is recomputed nightly, so a new peak lowers every " +
        "earlier point proportionally. The tooltip shows the raw count for every point. " +
        "Series are not shown as a share of the tracked term list, because adding or " +
        "retiring a term would then change every other term's history. When a source's " +
        "fetch fails or is rate-limited (GDELT rate-limits heavily), the previous night's " +
        "counts stand. A month that closed while a term's fetch was failing stays blank " +
        "until a later nightly run fills it, and a source with no successful fetch for " +
        "more than three days keeps its curve but posts no year-over-year change or " +
        "divergence. A GDELT, Hacker News, arXiv or EDGAR line that starts partway " +
        "through the window marks a gap in collection. A Wikipedia line starts with the " +
        "first month the Pageviews API reports for its article's titles. The month in " +
        "progress is collected but is not charted, ranked or averaged until it closes, " +
        "because a partial month would show as a drop at the end of every curve.",
    },

    // ------------------------------------------- market.html · 2
    risers: {
      num: "02",
      kicker: "Risers & fallers",
      source: "GDELT 2.0 · Hacker News via Algolia · arXiv cs.CR · Wikipedia pageviews · SEC EDGAR full-text search",
      headline: "Agentic AI has the steepest year-over-year rise in news and in research papers.",
      caption:
        "Year-over-year change in each term's count, one row per term and source: " +
        "articles, posts, papers, pageviews or filings in the twelve calendar months " +
        "ending with the latest complete month, against the twelve months before them. " +
        "Every row covers the same twenty-four months. Sources are kept in separate rows " +
        "because a term can rise in one source while it falls in another.",
      statRiserLabel: "Largest rise",
      statFallerLabel: "Largest fall",
      statTemplate: "{label} · {source}",
      colTerm: "Term",
      colSource: "Source",
      colChange: "YoY change",
      colVolume: "Last 12 months",
      eligibilityNote:
        "A row needs all of the last twenty-four calendar months collected and a minimum " +
        "volume. A term whose fetch for a source is incomplete (new, mid-backfill, waiting " +
        "out an upstream rate limit, or missing a month inside the window) is left off " +
        "until the fetch completes.",
      methodology:
        "For each term and source, the pipeline sums raw monthly counts over the twelve " +
        "calendar months ending with the latest complete month (the month in progress is " +
        "excluded) and over the twelve months before those. YoY change is the percentage " +
        "difference between the two sums. Both windows are fixed calendar spans anchored " +
        "at that month for every term and source. A pair missing any month inside them " +
        "posts no figure, because a missing month is unknown, not zero, and the window " +
        "does not slide back past a gap to find twenty-four months that exist (until " +
        "2026-09-20 it did, which could compare mismatched periods under one label). A " +
        "pair is also excluded when its prior-year sum is zero, when both windows together " +
        "hold fewer than thirty raw hits (too few for a meaningful percentage), or when " +
        "its source has had no successful fetch for more than three days. Any column can " +
        "be sorted; the default order is largest rise first.",
    },

    // ------------------------------------------- market.html · 3
    divergence: {
      num: "03",
      kicker: "Research vs. media divergence",
      source: "GDELT 2.0 · arXiv cs.CR",
      headline: "Each term is placed by how near research and news are to their own peaks.",
      caption:
        "Each term's position is its recent arXiv cs.CR index (vertical) against its " +
        "recent GDELT news index (horizontal), each measured against that source's own " +
        "five-year peak. Above the diagonal, research is closer to its peak than news " +
        "coverage is; below it, news coverage is closer to its peak than research is. " +
        "Terms near the diagonal sit at similar levels in both.",
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
        "{plotted} of {total} tracked terms have enough data in both sources to plot. " +
        "The others have fewer than ten hits in one source across the three anchor months " +
        "(usually arXiv papers), or are missing an anchor month while a fetch catches up.",
      methodology:
        "Each axis is the term's own attention index (see the attention-curves " +
        "methodology), averaged over the same three calendar months in both sources: the " +
        "three ending with the latest complete month, with the month in progress " +
        "excluded. GDELT is the x-axis and arXiv the y-axis. A term missing any of those " +
        "months in either source is omitted; it is not averaged over whichever months " +
        "each source happens to have. Of the five collected sources, the chart uses only " +
        "GDELT and arXiv, the clearest pairing of news and research: Wikipedia pageviews " +
        "mix both audiences, SEC filings track investor language, and Hacker News sits " +
        "between them. A term's divergence score is the y value minus the x value, in " +
        "index points. Scores beyond ±10 are labelled “research leads” or “media leads”, " +
        "and scores inside that band “aligned”; the band is wide because both indices " +
        "vary from month to month. Terms with fewer than ten raw hits in either source " +
        "across the three months are also omitted, because two or three papers against a " +
        "small peak can produce an index of 100. When GDELT or arXiv has had no " +
        "successful fetch for more than three days, no term is plotted.",
    },

    // -------------------------------------------------------------- 1 · hero
    inflation: {
      num: "01",
      kicker: "CVSS scores by year",
      source: "cvelistV5 (MITRE) — CNA-assigned scores",
      headline: "About half of scored CVEs are rated High or Critical.",
      caption:
        "Median CVSS base score of newly published CVEs, by year and by scoring version. " +
        "v3 scores run higher than v2 scores, so a separate line per version keeps a " +
        "change of version from looking like a change in severity. The blended line " +
        "starts in the first year in which CNA-assigned scores cover at least 20% of " +
        "published records (see the methodology); the per-version lines start earlier, " +
        "on much thinner coverage. In each complete year since 2020 the median sits " +
        "close to 7.0, the lower edge of High, and four to five in ten scored CVEs are " +
        "rated 7.0 or higher, with no sustained rise.",
      statLabel: "Share of scored CVEs rated High or Critical (base score ≥ 7.0)",
      statLatest: "{latest_year}",
      statAgo: "{ago_year}",
      methodology:
        "For every CVE in the cvelistV5 corpus, the CNA-assigned base score, split by " +
        "CVSS version (v2, v3.x, v4). Each line is the median score of CVEs published " +
        "that year; shaded bands span the 25th to 75th percentile (IQR). A record scored " +
        "under several versions appears in each version's series but only once in the " +
        "blended line, at its newest version's score. “% High or Critical” is the share " +
        "of scored CVEs that year with a base score of 7.0 or more; unscored CVEs are " +
        "excluded. Vertical markers are CVSS spec releases that fall inside the charted " +
        "years. Filters: a point is plotted only if that year has at least 100 scored " +
        "CVEs in that series; per-version points cannot predate the version's spec " +
        "release, because CNAs add scores to old records; and the blended line also " +
        "requires scores on at least 20% of the CVEs published that year, because a " +
        "year with 1% coverage shows which records were scored later, not what was " +
        "published. The headline stat compares the latest complete year with the year " +
        "ten years earlier, or with the earliest year that passes these filters until " +
        "the record goes back that far. The current year is plotted (labeled partial, " +
        "refilled nightly) but is not used in the headline stat, because a partial year " +
        "is not comparable with a complete one.",
    },

    // ------------------------------------------------------------------- 2
    flood: {
      num: "02",
      kicker: "Severity by year",
      source: "cvelistV5 (MITRE)",
      headline: "Close to four thousand CVEs a year were rated Critical in 2024 and 2025.",
      caption:
        "Published CVEs per year, grouped by the CVSS base score in the CVE record " +
        "itself. The Critical count for 2026 passed four thousand with months of the " +
        "year still to go, and since 2024 more than nine in ten published records carry " +
        "a score. Records left of the vertical marker mostly carry none: in those years " +
        "NVD kept severity in its own database, which this chart does not read, so the " +
        "wide gray band reflects the record format of the time, not the vulnerabilities. " +
        "The current year is partial.",
      eraMarker: "← scored in NVD, not in the record",
      toggleAbsolute: "Absolute",
      toggleShare: "Share of year",
      linuxNote:
        "Since 2024 nearly every record with no score anywhere in it is a " +
        "kernel record; without the kernel, the gray “no score” band is close " +
        "to zero.",
      methodology:
        "CVEs are grouped by base score, using the highest CVSS version in each record: " +
        "Critical ≥ 9.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.0–3.9. “No score in record” " +
        "counts CVEs published that year with no base score anywhere in the CVE record, " +
        "in either the CNA container or an ADP container. The vertical marker is " +
        "computed: it sits at the first year in which at least 10% of published records " +
        "carry a score in the record. Before about 2018, CNAs rarely put scores in the " +
        "record; NVD assigned CVSS scores in its own database, which this chart does not " +
        "ingest. In-record scoring covered fewer than one in ten of 2017's records and " +
        "covers more than nine in ten today (section 08 tracks the missing-score share). " +
        "When NVD's enrichment slowed sharply in 2024, CISA's Vulnrichment program began " +
        "adding scores through its ADP container; the Vulnrichment module measures what " +
        "CISA adds and how much of it CNAs later cover with their own scores. " +
        "The share view scales each year to 100%. The current year (marked *) is " +
        "partial and refills nightly. In the absolute view, a dashed marker at the " +
        "current-year edge extends the partial year's total (all published records, " +
        "unscored included) to twelve months: the count so far divided by the fraction " +
        "of the UTC calendar year elapsed at generation time. It appears only once 12.5% " +
        "of the year has elapsed (about mid-February), assumes publication is uniform " +
        "through the year, and ignores seasonality and late-year backfill. The severity " +
        "mix is not projected, and the share view has no marker because shares are " +
        "already normalized to their year.",
    },

    // ------------------------------------------------------------------- 3
    reality: {
      num: "03",
      kicker: "Severity vs. exploitation",
      source: "cvelistV5 (MITRE) · EPSS (FIRST.org) · CISA KEV",
      headline: "More than six in ten Critical-rated CVEs carry less than a 1% probability of exploitation.",
      caption:
        "Each scored CVE with a current EPSS score, placed on a grid by its CVSS severity " +
        "and by EPSS's estimated probability of exploitation in the next 30 days. CVSS " +
        "rates technical severity; EPSS estimates likelihood. The two are related: the " +
        "share with a probability of 10% or more rises about twentyfold from Low to " +
        "Critical. CISA's Known Exploited Vulnerabilities (KEV) catalog also includes " +
        "entries rated below High.",
      statCriticalTemplate: "{pct} of Critical-rated CVEs have an EPSS probability below 1%",
      statCriticalNote: "across {n} Critical CVEs with a current EPSS score",
      statKevTemplate: "{pct} of CISA KEV entries are rated below High",
      statKevNote: "{below_high} of {total} scored KEV entries have a base score under 7.0",
      kevBarTitle: "KEV entries by CVSS bucket",
      methodology:
        "The grid covers scored CVEs that have a current EPSS score; each cell counts the " +
        "CVEs in one CVSS bucket and one EPSS probability bucket. Cell color uses a " +
        "log-like scale so that sparse cells stay visible. The first stat is the share of " +
        "CVEs rated 9.0 or higher whose EPSS probability is below 1%. The KEV stat is the " +
        "share of CISA KEV catalog entries whose CVSS base score is below 7.0. The score is " +
        "the newest CVSS version anywhere in the record, the CNA container before ADP " +
        "containers. v2, v3 and v4 scores share one axis here, although v3 scores run " +
        "higher than v2 (section 01 separates them). For KEV entries published before " +
        "CNAs scored in the record, the score is usually CISA's own ADP score, so the KEV " +
        "stat largely uses CISA's numbers. EPSS estimates the probability of exploitation " +
        "in the next 30 days; it is a model's prediction, not a record of exploitation.",
    },

    // ------------------------------------------------------------------- 4
    decay: {
      num: "04",
      kicker: "NVD backlog",
      source: "NVD API 2.0 (NIST) · CyberMon's own nightly snapshots",
      headline: "Tens of thousands of CVEs carry NVD's “Deferred” status.",
      caption:
        "NVD adds analysis, CVSS scores and product data to CVE records. The bars count " +
        "every CVE by its NVD status on a logarithmic axis; the three red bars at the " +
        "bottom are the live queue (Received, Awaiting Analysis, Undergoing Analysis). " +
        "“Deferred” is NVD's label for CVEs it has set aside with no analysis scheduled. " +
        "The solid line tracks the size of the live queue, one snapshot per night; the " +
        "dashed line is its Awaiting Analysis part.",
      note:
        "NVD publishes no backlog history. CyberMon has recorded a nightly snapshot " +
        "since {first_date}.",
      barsTitle: "All CVEs by NVD status (log scale; queue statuses in red)",
      lineTitle: "Backlog total (solid) and Awaiting Analysis (dashed), nightly snapshots",
      methodology:
        "Statuses come from NVD's vulnStatus field at fetch time (the full corpus, synced " +
        "incrementally from the API and re-read in full from NVD's yearly feeds about " +
        "once a week). “Backlog total” = Received + Awaiting Analysis + Undergoing " +
        "Analysis; “Deferred” is NVD's label for CVEs it has decided not to enrich. The " +
        "bar axis is logarithmic because the Modified count is more than an order of " +
        "magnitude larger than the live queue, which would not be visible on a linear " +
        "axis. NVD publishes no historical series, so CyberMon appends one row per " +
        "nightly run to its own committed CSV (data/history/nvd_backlog.csv; the last run " +
        "per date wins). The history starts when this record did. A night without a " +
        "successful run has no row, and the chart's date axis skips it.",
    },

    // ------------------------------------------------------------------- 5
    throughput: {
      num: "05",
      kicker: "NVD throughput",
      source: "NVD API 2.0 (NIST) · CyberMon's own nightly snapshots",
      headline: "CyberMon counts the CVEs entering and leaving NVD's analysis queue each night.",
      caption:
        "Section 04 counts the queue; this section counts the changes. Each night " +
        "CyberMon compares every CVE's NVD status with the previous night's snapshot. " +
        "The differences are that day's movements: new CVEs received, and CVEs leaving " +
        "the analysis queue as Analyzed or as Deferred. The same comparisons also time " +
        "the queue: how many days a CVE waits, as far as the snapshots can see, before it " +
        "is analyzed. NVD itself publishes only the totals.",
      note:
        "NVD publishes no transition history. CyberMon's record of these movements " +
        "starts {first_date}. Waits are measured between CyberMon's nightly snapshots, " +
        "so every duration is a lower bound.",
      lineTitle: "CVEs changing status, one point per nightly comparison",
      seriesAnalyzed: "Analyzed (left the queue)",
      seriesDeferred: "Deferred (left the queue)",
      seriesReceived: "Newly received",
      statMedianLabel: "median observed wait in the analysis queue",
      statMedianBig: "{days} days",
      statMedianNote:
        "across {n} timed exits from the queue. Each wait is a lower bound, counted " +
        "from the first snapshot that showed the CVE awaiting analysis. The record is " +
        "young and cannot yet contain waits longer than its own age, so this median is " +
        "likely to rise as the record grows.",
      statCountLabel: "timed queue exits collected so far",
      statCountNote:
        "the median is published once {min_known} exits have been timed; with fewer, " +
        "one unusual week would dominate it",
      resweepFlag: "full re-read day: NVD's feed files lag by about a day, so the catch-up appears in the next night's row",
      afterResweepFlag: "night after a full re-read: may include changes that earlier incremental syncs missed",
      methodology:
        "Each nightly run syncs NVD's per-CVE vulnStatus (incremental API pulls, plus a " +
        "full re-read of NVD's yearly feeds about once a week) and compares the new " +
        "snapshot with the previous one. A status change between snapshots is a " +
        "transition. The chart draws three counts per comparison: CVEs entering " +
        "“Received,” CVEs leaving the live queue for “Analyzed,” and CVEs leaving it for " +
        "“Deferred.” Entries into “Awaiting Analysis” are counted in the data file but " +
        "not drawn. The live queue includes “Received”; before 23 September 2026 the " +
        "Analyzed line counted exits from Awaiting Analysis and Undergoing Analysis " +
        "only, so a Received record analyzed between two snapshots was missed there. " +
        "Only exits seen awaiting analysis are timed. NVD publishes no status-change " +
        "timestamps, so each status is dated to the day CyberMon first saw it. A queue " +
        "wait is the span between the snapshot that first showed the CVE in the queue " +
        "and the snapshot that first showed it analyzed; it is a lower bound set by the " +
        "nightly cadence, and it cannot see changes that happen between two snapshots. " +
        "Statuses recorded before this tracker started have no entry date; their " +
        "transitions count in the flow but are not timed, and no date is filled in for " +
        "them. The median is not published until {min_known} exits have been timed, " +
        "because a median of fewer is unreliable. A full re-read can repair missed sync " +
        "windows and put several days of transitions on one date: the night after the " +
        "re-read, because the re-read itself uses feed files that lag by about a day. " +
        "That row is ringed on the chart and flagged in the tooltip. After a night with " +
        "no run, the next comparison covers more than one day. One row per run date is " +
        "appended to a committed CSV (data/history/nvd_throughput.csv; a second run on " +
        "the same date adds its counts to that date's row). Like the backlog record in " +
        "section 04, it cannot be rebuilt from any other source: the history starts " +
        "when CyberMon started keeping it.",
    },

    // ------------------------------------------------------------------- 6
    cna: {
      num: "06",
      kicker: "Scores by CNA",
      source: "cvelistV5 (MITRE) — CNA-assigned scores",
      headline: "The highest-rating CNAs score three or four in ten of their CVEs 9.0 or higher.",
      caption:
        "CVE Numbering Authorities (CNAs) can score the CVEs they publish. This board " +
        "uses those scores, not NVD's, and ranks each CNA by the share it rates 9.0 or " +
        "higher. Some of the largest CNAs, with a hundred times as many scored CVEs, rate " +
        "fewer than one in ten that high. The board does not show why: CNAs cover " +
        "different products, and some score in CVSS 4.0 while others use 3.x.",
      colCna: "CNA",
      colN: "scored CVEs",
      colAvg: "avg CVSS",
      colMedian: "median",
      colGeq9: "% ≥ 9.0",
      colGeq7: "% ≥ 7.0",
      windowTemplate: "CNA-assigned scores · last {window_years} calendar years, the current one included · min {min_cves} scored CVEs",
      methodology:
        "For each CNA (the record's assigner in cvelistV5), the base scores that CNA " +
        "assigned itself over a rolling {window_years}-year window. Each record counts " +
        "once, at the newest CVSS version its CNA scored (v4.0 where given, else v3.x, " +
        "else v2), so a CNA that scores in v4.0 is measured on v4.0 scores. CNAs with " +
        "fewer than {min_cves} scored CVEs in the window are excluded so that small " +
        "samples cannot top the table. Default sort: share of scores ≥ 9.0, descending. " +
        "Click any column header to re-sort.",
    },

    // ------------------------------------------------------------------- 7
    volume: {
      num: "07",
      kicker: "CVE volume",
      source: "cvelistV5 (MITRE)",
      headline: "More CVEs were published in each year since 2017 than in the year before.",
      caption:
        "Published CVE records per year, with rejected records alongside. Rejections " +
        "fell from a fifth of all records in 2017 to under two percent in 2023, then " +
        "rose again in 2024 and 2025. The current year is partial: its point at the " +
        "right edge is the count so far, and the short dashed line extends it to twelve " +
        "months at its pace so far.",
      toggleLinear: "Linear",
      toggleLog: "Log scale",
      linuxNote:
        "The kernel's records start in 2024, and most of the rise in rejections " +
        "in 2024 and 2025 comes from them. The dashed pace line follows the toggle.",
      methodology:
        "Counts come from the cvelistV5 corpus. “Published” counts CVE records by " +
        "original publication year; “rejected” counts records in state REJECTED, also by " +
        "original publication year. REJECTED records that were never published " +
        "(withdrawn reservations, which have no datePublished) are excluded, not counted " +
        "under the year in their ID; most rejections of recent-year IDs are of this " +
        "kind. The log-scale toggle changes only the axis. The current year is labeled " +
        "partial and refills nightly; it is not comparable with a complete year. The " +
        "dashed segment and hollow marker extend the partial year to twelve months: the " +
        "count so far divided by the fraction of the UTC calendar year elapsed at " +
        "generation time. The projection appears only once 12.5% of the year has " +
        "elapsed (about mid-February; before that the divisor is too small for a stable " +
        "estimate), assumes publication is uniform through the year, and ignores " +
        "seasonality and late-year backfill. The solid line shows the actual partial " +
        "count.",
    },

    // ------------------------------------------------------------------- 8
    quality: {
      num: "08",
      kicker: "Record completeness",
      source: "cvelistV5 (MITRE)",
      headline: "About one in ten new CVE records still lacks a weakness class (CWE).",
      caption:
        "For each year's published CVE records, the share missing each of three " +
        "machine-readable fields: a weakness class (CWE), a CVSS base score, and " +
        "structured affected-version data. Tools that read CVE records use these fields; " +
        "when a record lacks one, each user of the record has to find it elsewhere. " +
        "Before about 2018 all three were usually kept in NVD's database, not in the " +
        "record (see the methodology). Since 2024, almost all records missing a score " +
        "come from the Linux kernel CNA; the kernel toggle on the severity-by-year chart " +
        "(section 02) shows this.",
      legendCwe: "No CWE",
      legendCvss: "No CVSS score",
      legendAffected: "No usable version data",
      methodology:
        "For every published record in the cvelistV5 corpus (rejected records excluded), " +
        "three checks against the record itself, in both CNA and ADP containers. A CWE " +
        "counts as present if any problemTypes description carries a cweId. A CVSS score " +
        "counts if any metrics container carries a base score of any CVSS version. " +
        "Affected-version data counts if any affected[] entry has either a versions[] " +
        "item with a concrete version string (placeholders such as “n/a” and " +
        "“unspecified” do not count) or a defaultStatus of “affected” or “unaffected” " +
        "(“unknown” does not count). Each line is that year's missing count over its " +
        "published total; the tooltip gives the counts. A year is plotted only if it has " +
        "at least 500 published records. Before about 2018, weakness classes, scores and " +
        "affected-product data (as CPE configurations) were kept in NVD's own database, " +
        "which this chart does not ingest. The early plateau therefore reflects where the " +
        "data was stored, and the decline since reflects these fields moving into the " +
        "record itself (section 02 shows the same shift for scores). The current year " +
        "(marked *) is partial and refills nightly.",
    },

    // ------------------------------------------------------------------- 9
    cwe: {
      num: "09",
      kicker: "Weakness classes",
      source: "cvelistV5 (MITRE)",
      headline: "Cross-site scripting is the most common weakness class of the last ten complete years.",
      caption:
        "The eight most common weakness classes of the last ten complete years, each " +
        "shown as its share of that year's CWE-tagged records, with all other classes " +
        "pooled as “Other.” The eight are chosen from the whole period's totals, so no " +
        "class can drop off this chart; what changes is each class's share. Most move " +
        "by a few points over the period and cross-site scripting by more than a dozen; " +
        "missing authorization rises from almost nothing, while improper input " +
        "validation and out-of-bounds reads decline.",
      // rendered as a panel-note by cve.js (same slot the decay chart uses)
      note:
        "Shares are of CWE-tagged records only; each year's tooltip gives the share " +
        "of that year's records that carry a CWE.",
      otherLabel: "Other",
      methodology:
        "Each CWE-tagged published record contributes its first-listed CWE id (the CNA " +
        "container first, ADP containers as fallback), one class per record, so a " +
        "year's shares sum to roughly 100 after rounding. The top 8 are ranked by total " +
        "tagged volume across the last ten complete calendar years; the partial current " +
        "year is excluded from both the window and the ranking, because a partial year " +
        "would skew the ranking. Shares are of CWE-tagged records only, and coverage " +
        "varies widely by year; each year's tooltip gives its tagged count and its share " +
        "of all published records. A year is plotted only if it has at least 500 tagged " +
        "records. Class names come from a small built-in map in the pipeline; ids the " +
        "map does not know are shown as bare CWE numbers.",
    },

    // ------------------------------------------------------------------ 10
    cvss4: {
      num: "10",
      kicker: "CVSS 4.0 adoption",
      source: "cvelistV5 (MITRE) — CNA-assigned scores",
      // Static fallback (screen readers, the TOC, a failed fetch); the
      // renderer replaces it with headlineTemplate filled from the data.
      headline: "Most new CVE records do not carry a CVSS 4.0 score from their CNA.",
      headlineTemplate: "CNAs put a CVSS 4.0 score on {pct} of this year's new CVE records.",
      caption:
        "Each month's newly published CVE records, split by the CVSS versions their " +
        "CNA scored: v4.0 only, v3.x and v4.0 together, v3.x only, or neither. " +
        "In {latest_year}, {latest_pct} of new records carried a v4.0 score; in " +
        "{current_year} so far, {current_pct} ({v4_current} of {published_current}), " +
        "from {v4_cnas} CNAs. Since CVSS 4.0 was published in late 2023, three CNAs " +
        "account for most v4.0 scores, and most records with a v4.0 score also carry " +
        "a v3.x score.",
      toggleMonthly: "Monthly",
      toggleYearly: "Yearly",
      classLabels: {
        v4_only: "v4.0 only",
        both: "v3.x and v4.0",
        v3_only: "v3.x only",
        neither: "Neither",
      },
      note:
        "Scores in ADP containers are not counted here. {neither_adp} of " +
        "{current_year}'s {neither} “neither” records carry a CVSS score added " +
        "by an ADP, mostly CISA's v3.1; the severity-by-year chart (section 02) " +
        "counts those.",
      adoptersTitle: "Largest v4.0 adopters since {since}",
      adoptersContext:
        "{adopters} CNAs have scored at least one record in v4.0. The {shown} " +
        "largest, listed here, account for {top_share} of all v4.0-scored records.",
      colCna: "CNA",
      colV4: "v4.0 records",
      colShare: "Share of its records",
      colOnly: "v4.0 only",
      compareTitle: "v4.0 minus v3.x, same record, same CNA",
      compareStat:
        "{n} records scored in both · same severity band {same} · v4.0 a band " +
        "higher {higher} · a band lower {lower} · median difference {median}",
      compareAxis: "v4.0 − v3.x base score",
      compareTooltip: "{n} records with a difference of {range}",
      nodata: "Not enough data yet.",
      methodology:
        "For every published record in the cvelistV5 corpus, the CVSS versions its CNA " +
        "container scores: a v4.0 base score, a v3.x base score (3.0 and 3.1 count " +
        "alike), both, or neither. A record scored only in v2 counts as “neither”. " +
        "Scores in ADP containers are not counted, because this section measures what " +
        "the CNA of record scored; the note under the chart gives how many “neither” " +
        "records an ADP scored. Months are publication months from {since}, the month " +
        "CVSS 4.0 was published; years start in 2023. Shares are of all records " +
        "published in the month or year; the current month and year (marked *) are " +
        "partial. The adopters board covers records published since {since} and lists " +
        "the fifteen CNAs with the most v4.0-scored records (each with at least " +
        "{min_v4}). Both of its share columns divide by all of the CNA's records in that " +
        "window: one counts v4.0-scored records, the other v4.0-only records. The " +
        "histogram takes every record whose CNA gave both a v4.0 and a v3.x base score " +
        "(the highest 3.x minor version when several are present) and groups v4.0 minus " +
        "v3.x in half-point bins; the two end bins collect everything beyond. Severity " +
        "bands are the site's usual ones (Critical ≥ 9.0, High 7.0–8.9, Medium 4.0–6.9, " +
        "Low below 4.0). The two versions measure different things, so a difference " +
        "between them is not an error in either score.",
    },

    // --------------------------------------------- kev.html · 1 · hero
    latency: {
      num: "01",
      kicker: "Listing latency",
      source: "CISA KEV · cvelistV5 (MITRE)",
      headline: "The median KEV listing comes weeks after the CVE record is published.",
      caption:
        "Days from a CVE record's publication to the day CISA added the CVE to its " +
        "Known Exploited Vulnerabilities catalog: median and interquartile range for " +
        "each year of listing. Listings from the 2021–22 seeding era are left out (see " +
        "the callout below the chart). The catalog opened with a backlog of years-old " +
        "CVEs and kept importing older entries through 2022, and those latencies would " +
        "dominate the chart. Among later listings the typical wait has {middle_verb}, " +
        "from a median of {baseline_median} days for {baseline_year} listings to " +
        "{latest_median} for {latest_year}, and the share listed more than a year " +
        "after publication has {tail_verb}.",
      // Appended by kev_latency.js when the generation year has at least
      // 10 matched listings. Latency is fixed on the listing day, so a
      // partial year is not right-censored — only thin.
      captionCurrent:
        " Listings so far in {current_year} have a median of {current_median} days.",
      // The caption's verbs are chosen from the data by kev_latency.js, so
      // a reversed trend rewrites the sentence instead of contradicting it.
      // The caption uses the first word of each pair ("the typical wait has
      // …", "the share … has …"); the second is a plain adjective kept for
      // the renderer's {middle_word} / {tail_word}.
      captionWords: {
        middle: { up: ["lengthened", "longer"], down: ["shortened", "shorter"],
                  flat: ["barely changed", "unchanged"] },
        tail: { up: ["edged up", "larger"], down: ["edged down", "smaller"],
                flat: ["held steady", "unchanged"] },
      },
      statLabel: "Median days from CVE publication to KEV listing",
      statLatest: "{latest_year}",
      statAgo: "{ago_year}",
      backfillNote:
        "{n} entries were added in the catalog's seeding era, from the November 2021 " +
        "launch through 2022 (dateAdded before {date_added_before}). Their median " +
        "nominal latency is {median_days} days. That figure reflects the import of " +
        "older CVEs, not the speed of listing, and is excluded from the chart above.",
      methodology:
        "For every entry in CISA's Known Exploited Vulnerabilities catalog that matches a CVE " +
        "record in the cvelistV5 corpus, latency is the KEV dateAdded minus the CVE record's " +
        "datePublished, in days. The trend starts with 2023 listings. The catalog launched in " +
        "November 2021 with a backlog of years-old CVEs and kept bulk-importing older entries " +
        "through 2022. The data shows the change: the seeding era's " +
        "pooled median 'latency', in the callout, runs near two and a half years, against " +
        "{baseline_median} days for {baseline_year} additions. A seeding-era latency " +
        "therefore measures the age of the backlog, so those entries are reported in the " +
        "callout and not plotted. Negative latencies are kept as negative: a KEV listing can " +
        "come before the publication of its own CVE record, and flooring those values at " +
        "zero would hide those listings. A year plots only if it has at least 10 matched " +
        "entries. KEV entries with no matching CVE record in the corpus have no publication " +
        "date; they are counted separately in the data file.",
    },

    // --------------------------------------------- kev.html · 2
    buckets: {
      num: "02",
      kicker: "Latency distribution",
      source: "CISA KEV · cvelistV5 (MITRE)",
      headline: "Nearly four in ten KEV listings come within a week, one in seven after three years.",
      caption:
        "The same matched listings as the trend above, grouped by latency: before the " +
        "CVE record was published, within a week, a month, a quarter or a year, after " +
        "one to three years, and after more than three years. The red bar counts " +
        "listings that came before the CVE record was published.",
      methodology:
        "Every matched entry in the trend cohort (added 2023 or later; the 2021–22 seeding " +
        "era is left out for the reason given above) falls in one bucket by its latency: " +
        "before publish (latency below zero), 0–7d, 8–30d, 31–90d, 91–365d, 1–3y, 3y+. " +
        "Lower edges are inclusive: a listing on day 8 is in 8–30d. Percentages are shares " +
        "of the matched cohort, not of the full catalog; an entry with no matching CVE " +
        "record has no publication date and therefore no latency.",
    },

    // --------------------------------------------- kev.html · 3
    remediation: {
      num: "03",
      kicker: "Remediation deadlines",
      source: "CISA KEV",
      headline: "Median remediation deadlines fell from six months in 2021 to three weeks or less.",
      caption:
        "How long federal agencies get to fix each KEV entry: the time from the day " +
        "CISA lists a vulnerability to the remediation deadline it sets, median and " +
        "interquartile range per year of listing. The seeding era is included here, " +
        "unlike in the latency chart, because the deadline is set on the listing day " +
        "for back-catalog entries too. The 2021 launch cohort got deadlines measured " +
        "in months; the {latest_year} listings carried a median of {latest_median} days" +
        "{current_clause}.",
      // Filled by kev_remediation.js from the data; the clause is empty when
      // the generation year has no listings yet.
      captionCurrentClause: ", and the {current_year} listings so far have a median of {current_median} days",
      methodology:
        "Remediation span is the KEV dueDate minus dateAdded, in days, for every catalog " +
        "entry carrying both fields and matched to a published CVE record (the same join " +
        "as the latency chart), 2021 launch cohort included. The launch batch is left out " +
        "of the latency trend because its nominal latency measures backlog age; its " +
        "remediation spans are policy decisions made on the listing date, so they are " +
        "charted here. Lines are the median span of entries added each year; shaded bands " +
        "span the 25th–75th percentile. For context, BOD 22-01 set six months for CVEs " +
        "with IDs assigned before 2021 and two weeks for all others, and entries added " +
        "since typically carry two to three weeks. The chart shows the deadlines CISA " +
        "assigned, which need not match the directive's defaults.",
    },

    // --------------------------------------------- kev.html · 4
    ransomware: {
      num: "04",
      kicker: "Ransomware share",
      source: "CISA KEV",
      headline: "CISA flags about one KEV entry in five as used in ransomware campaigns.",
      caption:
        "Each KEV entry records whether CISA knows the vulnerability to have been used " +
        "in ransomware campaigns. Bars show the share of each year's new listings " +
        "flagged “Known”; the year's counts are in the tooltip. The 2021–22 seeding " +
        "years are included, as in the remediation chart, because the flag is a " +
        "property of the entry and applies to back-catalog imports and new listings " +
        "alike. The newest bars are lower bounds: CISA often sets the flag after " +
        "listing, frequently more than a year later (the KEV Changelog page measures " +
        "that lag), so recent years rise as flags are added.",
      methodology:
        "Every entry in CISA's Known Exploited Vulnerabilities catalog carries " +
        "knownRansomwareCampaignUse (“Known” or “Unknown”); entries missing the field " +
        "count as “Unknown.” For each calendar year of dateAdded the chart reports " +
        "entries added, entries flagged “Known,” and the share. The catalog is read as " +
        "a current snapshot, so each entry shows CISA's present assessment whichever " +
        "year it was listed; that is why the seeding era is charted here while the " +
        "latency trend leaves it out. The same snapshot rule right-censors recent " +
        "years: a listing flagged “Known” next year counts as “Unknown” today, so the " +
        "latest bars are lower bounds, and a dip there is not yet evidence of a " +
        "decline. No CVE-record join is involved. A year plots only with at least 10 " +
        "entries. The current year (marked *) is partial and refills nightly.",
    },

    // --------------------------------- concentration.html · 1 · hero
    concentration: {
      num: "01",
      kicker: "Volume concentration",
      source: "cvelistV5 (MITRE)",
      headline: "There are more CNAs than ever, and five of them published most of 2025's CVEs.",
      caption:
        "Three lines from one corpus: the number of CVE Numbering Authorities (CNAs) " +
        "that published at least one record each year, and the share of that year's " +
        "records from the top 5 and top 10 of them. In the decade to 2023 the top-5 " +
        "share mostly fell as the program added CNAs. Since 2023 it has risen: the " +
        "roster grew seventeen-fold between 2015 and 2025, yet in 2025 five CNAs " +
        "still shipped a majority of the year's records, their share climbing for a " +
        "second straight year. Each CNA, vendor or not, writes the records it " +
        "assigns, including any severity score.",
      statLabel: "Share of published CVEs from the year's top 5 CNAs",
      statLatest: "{latest_year}",
      statAgo: "{ago_year}",
      linuxNote:
        "Without the kernel the top-5 share still climbs after 2023, and the " +
        "shares are recomputed over the remaining CNAs.",
      methodology:
        "Each CVE record's assigner (the CNA of record in cvelistV5) is counted by " +
        "original publication year. A CNA is active in a year if it published or " +
        "rejected at least one record that year. Top-5 and top-10 share are the " +
        "fractions of that year's published records from its five or ten largest " +
        "assigners. The top five are recomputed every year, so the names change even " +
        "when the share does not. The pipeline also computes a Herfindahl–Hirschman " +
        "Index (HHI) per year: the sum of squared shares, on the 0–10,000 scale " +
        "antitrust regulators use, {hhi_latest} for the latest complete year. The HHI " +
        "covers every assigner, not only the largest, and the two measures can move " +
        "in opposite directions: between 2023 and 2024 the top-5 share rose while the " +
        "index fell. The data file carries both for every year; the chart draws the " +
        "shares and this note quotes the index. Years with no published records " +
        "appear at zero, so the axis has no gaps. The current year is partial and " +
        "refills nightly.",
    },

    // --------------------------------- concentration.html · 2
    entrants: {
      num: "02",
      kicker: "New entrants",
      source: "cvelistV5 (MITRE)",
      headline: "Each year from 2023 to 2025 added more new CNAs than any year before 2023.",
      caption:
        "Bars count CNAs that published their first CVE record that year; the line is " +
        "the number of active CNAs. Every complete year since 2023 has brought in more " +
        "new CNAs than any year before 2023. Over the same years the chart above shows " +
        "the top-5 share rising in 2024 and 2025: the newcomers raised the CNA count, " +
        "and the five largest CNAs still gained share.",
      methodology:
        "A newcomer in year Y is a CNA whose earliest record in the corpus (published " +
        "or rejected) falls in Y. This is its first appearance in the data; the corpus " +
        "carries no accreditation dates. The active-CNA line counts CNAs with at least " +
        "one published or rejected record that year, the same definition as the " +
        "concentration chart. Because first appearance is computed against the full " +
        "corpus, the first charted year counts every CNA active that year as new by " +
        "construction. The current year is partial and refills nightly. The hollow " +
        "extension above the current-year bar paces the newcomer count to twelve " +
        "months: newcomers so far divided by the fraction of the UTC calendar year " +
        "elapsed at generation time, shown only once 12.5% of the year has elapsed " +
        "(roughly mid-February). First appearances are events, so they can be paced, " +
        "but only under the strong assumption that newcomers arrive evenly through " +
        "the year, ignoring seasonality and late-year backfill. The active-CNA line " +
        "is not projected, because a headcount has no pace.",
    },

    // --------------------------------- concentration.html · 3
    rejection: {
      num: "03",
      kicker: "Rejection board",
      source: "cvelistV5 (MITRE)",
      headline: "Rejection rates differ by more than tenfold between CNAs.",
      caption:
        "Each CNA's records from the last {window_years} years, split into published " +
        "and rejected. A rejected record here is one that shipped and was later marked " +
        "REJECTED, for example as a duplicate, a withdrawn assignment or a dispute " +
        "settled against it. A high rate is not necessarily bad practice: rejection is " +
        "how errors in published records get corrected, and a CNA that rejects nothing " +
        "may not be re-checking its records.",
      colCna: "CNA",
      colTotal: "CVEs (pub+rej)",
      colRejected: "rejected",
      colRate: "rejection rate",
      windowTemplate:
        "CVE record states by assigner · last {window_years} calendar years, the current one included · min {min_total} records (published + rejected)",
      methodology:
        "For each assigner in cvelistV5, records dated in the last {window_years} " +
        "years are counted by state, PUBLISHED or REJECTED. Rejection rate is rejected " +
        "over (published + rejected). CNAs with fewer than {min_total} records in the " +
        "window are excluded, because a rate over a few records (two rejections out " +
        "of two, say) is an anecdote. Reserved IDs that were rejected without ever " +
        "being published carry no publication date and are excluded from every " +
        "rejection count on this site: the board counts records that shipped and were " +
        "then withdrawn, not reservations that went unused. Default sort: rejection " +
        "rate, descending. Click any column header to re-sort.",
    },
    // ------------------------------------------------ breaches.html · 1 · hero
    disclosure: {
      num: "01",
      kicker: "Breach to catalog",
      source: "Have I Been Pwned breach catalog",
      headline: "Breaches typically reach HIBP's catalog months after they happen.",
      caption:
        "For each breach in the Have I Been Pwned (HIBP) catalog, the days between the " +
        "date the breach happened and the day HIBP added it, shown as the median and " +
        "interquartile range for each year of cataloging. Breaches loaded around the " +
        "catalog's December 2013 launch are reported in the note below and kept out of " +
        "the trend. Since 2014 the typical gap is measured in months, and roughly a third " +
        "of entries take more than a year to reach the catalog. This differs from the " +
        "dwell-time figures vendors report from their own customers' incidents: it runs " +
        "from the breach to a public catalog that anyone can query.",
      statLabel: "Median days from breach to public catalog",
      statWhole: "since {trend_start}",
      statLatest: "{latest_year}",
      importNote:
        "{n} breaches entered the catalog around its December 2013 launch (added before " +
        "{added_before}), with a median nominal lag of {median_days} days. That figure " +
        "reflects the initial import of breaches that were already public, so it is kept " +
        "out of the trend above.",
      methodology:
        "Lag is a breach's AddedDate minus its BreachDate, in days, for each cohort breach " +
        "in the HIBP catalog (the cohort rules are in the volume chart's methodology). " +
        "BreachDate is HIBP's best estimate of when the incident happened. HIBP's " +
        "documentation says it is not always accurate, and some entries carry only month " +
        "precision, so individual lags are noisy; the medians absorb most of that noise. " +
        "The line is the median lag of the breaches cataloged each year, and the shaded " +
        "band spans the 25th to 75th percentile. The trend starts in 2014. HIBP launched " +
        "on 2013-12-04 by importing breaches that were already public: six of its seven " +
        "opening-import entries predate the service itself, and the seven carry a median " +
        "nominal lag of well over a year. In 2014, the first full calendar year of live " +
        "cataloging, the median lag was 5 days. Older breaches have entered the catalog " +
        "in every year since and stay in the trend, because a breach reaching the catalog " +
        "years late is what the chart measures; only the launch import is set aside. A " +
        "lag can be negative (a breach cataloged before its stated breach date). Negative " +
        "lags are kept, as in the KEV latency chart, because they point to date-quality " +
        "problems in the source record. A year plots only with at least 10 cohort " +
        "breaches. The current year (marked *) is partial and updates nightly.",
    },

    // ------------------------------------------------ breaches.html · 2
    exposure: {
      num: "02",
      kicker: "Volume",
      source: "Have I Been Pwned breach catalog",
      headline: "Every year since 2014, HIBP loaded tens of millions of breached accounts or more.",
      caption:
        "Bars count the breaches cataloged each year; the line counts the accounts in " +
        "them, on a log axis because one large breach can outweigh a typical year's " +
        "total. Both are lower bounds: the catalog holds only breaches whose data became " +
        "public and was loaded into HIBP. The current year is partial and updates nightly.",
      catalogNote:
        "Cohort: {cohort} of {total} cataloged breaches. Excluded: {fabricated} " +
        "fabricated, {spam_list} spam lists, {malware} malware corpora, {stealer_log} " +
        "stealer-log batches. The last two hold real stolen data but no single breached " +
        "organization, which is the unit this ledger counts.",
      legendBreaches: "Breaches cataloged",
      legendRecords: "Accounts exposed",
      methodology:
        "Counts come from the full HIBP breach catalog, grouped by the calendar year of " +
        "AddedDate. The cohort excludes, in this order of precedence: fabricated entries " +
        "(IsFabricated, breaches HIBP judges to be fabricated), spam lists (IsSpamList, " +
        "address collections with no breached organization), malware corpora (IsMalware) " +
        "and stealer logs (IsStealerLog). The last two are real credential theft, " +
        "collected device by device from malware victims. They have no single breached " +
        "organization, and their nominal breach date describes when the corpus was " +
        "compiled, which would distort the lag chart above. Each excluded entry counts " +
        "under its first matching reason, so the exclusions plus the cohort always add up " +
        "to the catalog total; the note under the chart lists them. Accounts per year is " +
        "the sum of PwnCount, HIBP's count of the accounts it loaded from each breach. A " +
        "person appears once for each breach they are in, so the sum counts exposures, " +
        "not people. The December 2013 launch additions are charted here like any other " +
        "year; only the lag chart sets them aside. In the bars, a dashed hollow extension " +
        "projects the partial current year's breach count to twelve months: the count so " +
        "far divided by the fraction of the UTC calendar year elapsed at generation time. " +
        "It is shown only once 12.5% of the year has passed (about mid-February) and " +
        "assumes that cataloging runs at an even rate through the year, which is a strong " +
        "assumption. The accounts line is not projected: one large breach can carry more " +
        "accounts than the rest of its year combined, so a projection would turn a single " +
        "upload into a forecast.",
    },

    // ------------------------------------------------ breaches.html · 3
    leaks: {
      num: "03",
      kicker: "Data classes",
      source: "Have I Been Pwned breach catalog",
      headline: "Nearly every cataloged breach includes email addresses; a falling share includes passwords.",
      caption:
        "The six data classes listed most often across the cataloged breaches, each shown " +
        "as the share of that year's breaches that contain it. A breach can list many " +
        "classes, so the shares are independent and do not add up to 100%. Email " +
        "addresses appear in nearly every breach each year. Passwords appeared in nine " +
        "of ten breaches cataloged in 2014, about four in ten by 2025, and a lower share " +
        "every year since 2019. The other classes move up and down, some by more than 20 " +
        "points from one year to the next.",
      methodology:
        "The class list is rebuilt from the data every night: all data classes in the " +
        "cohort are ranked by the number of breaches listing them, and the top six are " +
        "charted. The catalog distinguishes well over a hundred classes, most of them " +
        "rare. Each line is the share of that year's cohort breaches, grouped by " +
        "AddedDate year, whose DataClasses field lists the class, counting each class at " +
        "most once per breach. The launch import is not set apart here, but 2013's seven " +
        "breaches fall below the plotting floor. Because a breach can list many classes, " +
        "the shares are independent: there is no “other” bucket and no 100% stack. The " +
        "ranking can change as the catalog grows, and a change in rank changes which " +
        "lines appear, by design. A year plots only with at least 10 cohort breaches. The " +
        "current year (marked *) is partial and updates nightly.",
    },

    // --------------------------------------- extortion.html · 1 · hero
    revenue: {
      num: "01",
      kicker: "Confirmed revenue",
      source: "Ransomwhere (CC0)",
      headline: "Verified ransom payments on the Ransomwhere ledger total over a billion dollars.",
      caption:
        "Bitcoin payments to reported ransomware addresses, summed by the quarter in which " +
        "they were sent and valued at that day's exchange rate. The data comes from " +
        "Ransomwhere: crowdsourced reports of extortion addresses, each reviewed before it " +
        "is included, with the payments read from the blockchain. A payment appears only " +
        "after someone reported the receiving wallet, so every bar is a lower bound on " +
        "ransom revenue, not an estimate of the market. Reporting has stalled: the " +
        "ledger's last verified payment landed in Q3 2024, and the chart ends there. The " +
        "data cannot show whether ransom payments declined after that or only the " +
        "reporting did.",
      statLabel: "Confirmed ransom revenue on the Ransomwhere ledger, all time",
      statNote: "a lower bound: {payments} verified payments; {addresses} addresses tracked",
      methodology:
        "Ransomwhere's CC0 export lists tracked extortion addresses, each with its " +
        "verified inbound transactions. The pipeline adds each transaction's amountUSD to " +
        "the UTC calendar quarter of its on-chain timestamp. amountUSD is Ransomwhere's " +
        "conversion at the BTC/USD rate of the transaction date. The implied rate for " +
        "each year follows the price history, so a 2016 payment is counted in 2016 " +
        "dollars and is not revalued at today's price. The export lists a transaction " +
        "once per receiving tracked address, so a transfer split across several tracked " +
        "wallets contributes each output it sent to them. Exact repeated entries (about " +
        "one percent of total USD) are summed as published, since they cannot be checked " +
        "without chain data. Every quarter between the first and last observed payment is " +
        "charted, at zero when empty. No full-year projection is drawn for a partial " +
        "current year, because reports arrive late and a projection assumes an even flow " +
        "through the year. Because the data is crowdsourced and verified, every total on " +
        "this page is a lower bound.",
    },

    // --------------------------------------- extortion.html · 2
    payments: {
      num: "02",
      kicker: "Payments",
      source: "Ransomwhere (CC0)",
      headline: "The ledger's payments became far fewer and far larger after 2021.",
      caption:
        "Bars count verified payments per year; the line is the median payment in " +
        "dollars at the rate of the transfer day, on a log scale. The medians for 2013 to " +
        "2015 (under three dollars) are not ransom amounts: most transfers to the tracked " +
        "wallets in those years were under ten dollars. From 2016 to 2022 the median grew " +
        "some 250-fold. From 2016 through 2021 the ledger holds hundreds to thousands of " +
        "payments a year, with medians between about $90 and $3,500; from 2022 it holds " +
        "fewer than 150 a year, with medians around $100,000 or higher. Thinner crowdsourced " +
        "coverage and changes in how ransomware operates could both lower the recent " +
        "counts, and this dataset cannot separate the two.",
      legendPayments: "Verified payments",
      legendMedian: "Median payment (USD, log)",
      methodology:
        "A payment is one distinct on-chain transaction. The export lists a transaction " +
        "once per receiving tracked address, so transfers split across several tracked " +
        "wallets are merged by transaction hash, with their outputs summed, before " +
        "anything is counted; on current data about 22,000 ledger entries become about " +
        "19,000 payments. Years follow the transaction's on-chain UTC timestamp, and the " +
        "median is taken over per-payment USD at the rate of the transfer day. A year's " +
        "median is plotted only when the year has at least 10 payments, since a median " +
        "of three payments says little; the payment count is always plotted. A year is " +
        "marked * only when it is the partial generation year. The record currently ends " +
        "earlier (last verified payment: Q3 2024), so the final bar is where the " +
        "reporting stops. No projection is drawn, for the reporting-lag reason given in " +
        "the revenue methodology.",
    },

    // --------------------------------------- extortion.html · 3
    families: {
      num: "03",
      kicker: "Family concentration",
      source: "Ransomwhere (CC0)",
      headline: "About two thirds of verified ransom revenue carries no family label.",
      caption:
        "The eight labeled families with the most confirmed revenue, with their payment " +
        "counts and the years each family's reported wallets first and last received " +
        "money. Two limits apply. The revenue with no family label, about two thirds of " +
        "the total, is larger than any family's and is reported in the note below the " +
        "board. A family's rank also depends on how many of its wallets were reported: " +
        "some families have many reported wallets, others one. Because reports for a " +
        "family arrive in bursts, the board ranks all-time totals; yearly shares would " +
        "mostly track when volunteers filed reports.",
      note:
        "{unattributed_usd} ({unattributed_pct} of all confirmed revenue) is verified but " +
        "has no family label. It is reported here and left off the board.",
      colFamily: "Family",
      colUsd: "confirmed USD",
      colPayments: "payments",
      colFirst: "first seen",
      colLast: "last seen",
      otherTemplate:
        "+ {families} more labeled families not shown · {usd} confirmed · {payments} payments",
      methodology:
        "Family names are Ransomwhere's own labels, used as identifiers without further " +
        "judgment. For each family, confirmed revenue is the sum of transaction amountUSD " +
        "across its addresses at the rate of the transfer day; payments are the distinct " +
        "transaction hashes among those addresses; first and last seen are the years of " +
        "its earliest and latest verified transactions. The board ranks the top eight " +
        "labeled families by all-time confirmed USD, and every other labeled family is " +
        "pooled into the line below the board. The export's “Unlabeled” bucket (verified " +
        "payments with no attribution) is left out of the ranking and reported in the " +
        "note instead; ranked, a gap in attribution would appear as the leading family. " +
        "A share-per-year chart was considered and rejected: wallets are often reported " +
        "long after a campaign ran, so yearly family shares would partly chart reporting " +
        "dates.",
    },

    // --------------------------------------------- attack.html · 1 · hero
    map: {
      num: "01",
      kicker: "Techniques per release",
      source: "MITRE ATT&CK® STIX bundles",
      headline: "The ATT&CK enterprise matrix has grown every year since 2018.",
      caption:
        "Active techniques and sub-techniques on the MITRE ATT&CK enterprise matrix, one " +
        "point per release, placed on the release dates MITRE's STIX index records. A " +
        "detection-coverage percentage measured against an earlier matrix falls when the " +
        "matrix grows, unless the new entries are covered too. Sub-techniques now " +
        "outnumber the techniques they refine (the red line is sub-techniques), and " +
        "most of the growth since 2018 has been in sub-techniques.",
      statLabel: "Active techniques + sub-techniques, enterprise matrix",
      statLatest: "v{version} ({year})",
      statAgo: "v{version} ({year})",
      legendTechniques: "Techniques",
      legendSubtechniques: "Sub-techniques",
      methodology:
        "Each point is one release of the MITRE ATT&CK enterprise matrix, read from its " +
        "STIX 2.1 bundle in the mitre-attack/attack-stix-data repository. Its x-position " +
        "is the release date in that repository's index.json, so gaps between points are " +
        "calendar gaps (major releases come about twice a year, with point releases " +
        "between). One date is early: the index dates v7.0, the release that introduced " +
        "sub-techniques, 2020-03-31, the date of their beta, while MITRE's versions page " +
        "dates the release July 2020, so that step is drawn about three months early. A " +
        "technique is a STIX attack-pattern object whose x_mitre_is_subtechnique flag is " +
        "false or absent; a sub-technique is the same object type with the flag true. Both " +
        "lines count active objects only: objects with revoked: true or " +
        "x_mitre_deprecated: true are excluded here and counted as churn below. A released " +
        "bundle does not change, so each version's counts are computed once and cached; a " +
        "normal nightly run reads only the index. The lines step because a release's " +
        "counts hold until the next release.",
    },

    // --------------------------------------------- attack.html · 2
    churn: {
      num: "02",
      kicker: "Churn per release",
      source: "MITRE ATT&CK® STIX bundles",
      headline: "Nearly all ATT&CK technique additions and retirements come in major releases.",
      caption:
        "For each ATT&CK release, how many techniques and sub-techniques it added and how " +
        "many it deprecated or revoked, compared by STIX object id with the release before " +
        "it. Across its forty-odd releases, the largest change was v7.0, which introduced " +
        "sub-techniques: it added 302 and revoked or deprecated 140. A detection rule " +
        "mapped to a technique that is later retired still runs, but its ATT&CK mapping " +
        "then points to a deprecated or revoked entry.",
      legendAdded: "Added",
      legendRetired: "Deprecated + revoked",
      methodology:
        "Consecutive enterprise releases are compared by STIX object id across all " +
        "attack-pattern objects (techniques and sub-techniques together). “Added” counts " +
        "ids present in a release and absent from its predecessor. “Deprecated” counts ids " +
        "present in both releases whose x_mitre_deprecated flag changed from false to " +
        "true; “revoked” counts the same change in the STIX revoked flag. Each retirement " +
        "counts once: an object that changes both flags in one release counts as revoked, " +
        "an object that arrives already deprecated counts only as an addition, and an " +
        "object retired in an earlier release is not counted again. The earliest indexed " +
        "release (v1.0) has no predecessor and is not drawn. The x-axis spaces releases " +
        "evenly because the unit here is a release; gaps between releases range from zero " +
        "days (two point releases on one day) to about half a year, and the two time-axis " +
        "charts on this page show the calendar.",
    },

    // --------------------------------------------- attack.html · 3
    catalog: {
      num: "03",
      kicker: "Groups and software",
      source: "MITRE ATT&CK® STIX bundles",
      headline: "ATT&CK's catalogs of groups and software have grown since 2018.",
      caption:
        "Active adversary groups (intrusion sets) and software (malware and tools, " +
        "counted together) per release, on the same release-date axis as the first chart. " +
        "Technique entries cite the groups observed using them and the software that " +
        "implements them. An entry leaves these counts when MITRE deprecates or revokes it.",
      legendGroups: "Groups (intrusion sets)",
      legendSoftware: "Software (malware + tools)",
      methodology:
        "Groups are STIX intrusion-set objects; software is malware and tool objects, " +
        "counted together. The same activity rule as the first chart applies: objects " +
        "with revoked: true or x_mitre_deprecated: true are excluded. Campaigns, tactics, " +
        "mitigations, data sources, detection strategies and relationship records in the " +
        "bundle are out of scope; this chart counts the named groups and their software, " +
        "the two catalogs a technique entry cites. Points sit at index.json release dates " +
        "and step between releases, as in the first chart; the counts come from the same " +
        "cached per-version stats.",
    },

    // --------------------------------------------- hygiene.html · 1 · hero
    validation: {
      num: "01",
      kicker: "World rate",
      source: "APNIC Labs DNSSEC measurement",
      headline: "About four in ten internet users are behind resolvers that validate DNSSEC.",
      caption:
        "DNSSEC lets a resolver verify that a DNS answer is the one the domain owner " +
        "signed. The standard has been complete since 2005, and turning validation on is " +
        "a resolver configuration setting, free of charge. The line is APNIC's measured " +
        "share of internet users whose resolvers perform that check, climbing from under " +
        "a tenth when the record starts in 2013 to roughly four in ten today. At the " +
        "average rate of the last ten years, reaching every user would take decades more.",
      statLabel: "Share of internet users behind validating resolvers",
      statLatest: "{latest_month}",
      statAgo: "{ago_month}",
      everyoneLabel: "everyone validates",
      methodology:
        "APNIC Labs measures DNSSEC validation with test fetches embedded in online " +
        "advertisements. Each sampled user's resolver is asked for DNSSEC-signed names, " +
        "one of which carries an intentionally broken signature. A resolver that rejects " +
        "the broken name and fetches the valid one counts as validating. A user whose " +
        "queries reach a mix of validating and non-validating resolvers counts as " +
        "partially validating; that rate is included in the data file with the latest " +
        "reading and is kept out of the line. The chart plots APNIC's world aggregate " +
        "(code XA), 30-day smoothed window, sampled by CyberMon to the last published day " +
        "of each calendar month. The full daily series is refetched from " +
        "stats.labs.apnic.net every night, so upstream corrections carry through. The " +
        "stat compares the newest month with the month ten years earlier (or with the " +
        "record's first month until the record is ten years long). APNIC states the " +
        "measurement's limits: samples arrive where the ad network delivers, so coverage " +
        "follows ad reach, and APNIC weights each economy's results by its estimated " +
        "internet population. The figures are estimates from hundreds of millions of " +
        "samples a month, reliable for the trend and less so in the decimals.",
    },

    // --------------------------------------------- hygiene.html · 2
    economies: {
      num: "02",
      kicker: "Ten largest economies",
      source: "APNIC Labs DNSSEC measurement",
      headline: "In the ten largest economies, validation ranges from nine in ten users to almost none.",
      caption:
        "The same measured rate for a fixed set of ten: the economies with the most " +
        "internet users, by APNIC's own weighting. The highest validates for roughly nine " +
        "of every ten users and the lowest for almost none; Japan and the United States " +
        "are both below half. The dashed world line is weighted by users, and these ten " +
        "economies carry more than half of that weight.",
      worldLine: "World average",
      note:
        "Lines are quarterly samples of APNIC's 30-day windows. The legend is ordered by " +
        "current rate; the dashed line is the user-weighted world average.",
      methodology:
        "The set is fixed: the ten largest economies by APNIC's weighted sample count, " +
        "which is its estimate of each economy's internet-user population, as measured " +
        "when this module launched in July 2026. They are China, India, the United " +
        "States, Brazil, Indonesia, Japan, Mexico, Russia, the Philippines and Nigeria. " +
        "Membership is frozen by design, because re-picking the list nightly would mix " +
        "changes in membership with changes in adoption. For each economy the pipeline " +
        "pulls APNIC's full daily series and samples the last published day of each " +
        "quarter-end month (30-day smoothed window), plus the newest available day. The " +
        "legend is ordered by current rate, highest first. APNIC notes that samples " +
        "arrive where the measurement ads are delivered and that delivery volume varies " +
        "by economy. Where it is thin, the measured rate is noisier; at this module's " +
        "launch in mid-2026, Russia yielded a small fraction of the samples of " +
        "comparable economies.",
    },

    // --------------------------------------------- hygiene.html · 3
    spread: {
      num: "03",
      kicker: "Distribution by economy",
      source: "APNIC Labs DNSSEC measurement",
      headline: "In most measured economies, at least half of users have validating resolvers.",
      caption:
        "Each economy APNIC measures with at least 10,000 samples, grouped by its current " +
        "validation rate and counted once regardless of size. Counted this way the result " +
        "is better than the user-weighted world line: the stat counts the economies where " +
        "at least half of users are behind validating resolvers. The difference comes " +
        "from a few very populous economies with low rates, such as China at nearly zero.",
      statBig: "{n} of {total}",
      statLead: "measured economies where at least half of users are behind validating resolvers",
      statNote: "economies with at least {min_seen} samples in the current 30-day window",
      tooltipBucket: "Validation rate {bucket}",
      tooltipUnit: "economies",
      yAxisLabel: "economies",
      methodology:
        "The distribution covers every economy on APNIC's DNSSEC world map with at least " +
        "10,000 measurements in the current 30-day window; below that floor a rate is too " +
        "uncertain to use. Economies are grouped by the share of sampled users behind " +
        "validating resolvers: under 10%, 10–25%, 25–50%, 50–75%, and 75% or higher " +
        "(lower edges inclusive). Each economy counts once regardless of size, which is " +
        "why this chart can look better than the user-weighted world line above. Values " +
        "are parsed nightly from the world-map table APNIC publishes. APNIC also " +
        "publishes a JSON series per economy, but fetching about two hundred forty of " +
        "them every night to build one histogram would put needless load on the source; " +
        "the table is a single request. As on the rest of the page, the rates are " +
        "estimates from ad-delivered samples, and the sample floor keeps out the most " +
        "thinly sampled economies.",
    },
    // --------------------------------------------- guards.html · 1 · hero
    guards: {
      num: "01",
      kicker: "Security-product share",
      source: "CISA KEV",
      headline: "More than one KEV entry in nine is in a security product.",
      caption:
        "Every entry in CISA's Known Exploited Vulnerabilities catalog, classified by " +
        "what the product is for. Bars show the share of each year's new listings that " +
        "are security products: VPN appliances, firewalls, endpoint protection, secure " +
        "gateways and similar products sold to enforce security. The stat gives the " +
        "catalog-wide share, and recent years run well above that. The 2021–22 " +
        "seeding years are charted like other years, because the classification depends " +
        "only on the product and applies to back-catalog imports and new listings alike.",
      statLabel: "Security products' share of the KEV catalog",
      statNote: "{security} of {total} KEV entries · classifier v{version}, {rules} rules, published in the repo",
      methodology:
        "“Security product” here means a product whose primary function is security " +
        "enforcement or secure access: firewalls and UTMs, VPN and secure-access " +
        "appliances, endpoint protection, email security gateways, identity and " +
        "privileged-access management, mobile device management, security operations " +
        "tooling, and dedicated secure file-transfer appliances from security vendors. " +
        "Where that line falls is a judgment and the main methodological risk of this " +
        "page, so it is written down once as a curated, versioned table " +
        "(pipeline/security_products.py) and not inferred by matching product names " +
        "against the word “secure”. Mixed vendors get explicit product rules: Cisco " +
        "counts only its security products (ASA, Firepower/FTD, AnyConnect, ISE; not IOS " +
        "or routers), Microsoft only Defender and Forefront TMG (not Exchange), Zyxel " +
        "only its firewalls, Juniper only ScreenOS. The harder calls are documented in " +
        "the module and applied consistently: MOVEit is file transfer, not security; " +
        "ADCs count only where the exploited deployment is a secure-access gateway (F5 " +
        "BIG-IP, Citrix NetScaler); desktop management, RMM and remote-support tools " +
        "are IT operations; mail servers do not count, although email security gateways " +
        "do; backup is resilience; Zoho ManageEngine stays unclassified because the " +
        "catalog's product labels are too coarse to split. The data file records the " +
        "classifier version behind its numbers. If a call looks wrong, open an issue: " +
        "a one-line change to the table reclassifies the full history on the next " +
        "nightly run. Years with fewer than 10 entries do not plot. The current year " +
        "(marked *) is partial and refills nightly.",
    },

    // --------------------------------------------- guards.html · 2
    recidivism: {
      num: "02",
      kicker: "Repeat vendors",
      source: "CISA KEV",
      headline: "For the most-listed security vendors, the median gap between KEV listings is days to weeks.",
      caption:
        "Every vendor with at least five entries in the catalog, ranked by how many of " +
        "its vulnerabilities CISA has listed, with first and last listing dates and the " +
        "median gap in days between consecutive listings. Rows where security products " +
        "make up at least half the vendor's entries are flagged; among the most-listed " +
        "of those, the median gap is days to weeks.",
      colVendor: "Vendor",
      colEntries: "KEV entries",
      colSecurity: "security",
      colFirst: "first listed",
      colLast: "last listed",
      colGap: "median gap",
      securityFlagLabel: "security products",
      windowTemplate:
        "full catalog · min {min_vendor_entries} entries · flagged: at least half " +
        "the vendor's entries are security products",
      methodology:
        "Vendor labels are the catalog's own, whitespace-normalized and not merged. " +
        "CISA has since relabelled most Pulse Secure entries as Ivanti, so they count " +
        "on Ivanti's row, while the one still labelled Pulse Secure is counted " +
        "separately. For each label the board counts total entries, security-classified " +
        "entries (per the classifier described in section 01's methodology), first and " +
        "last dateAdded, and the median gap in days between consecutive listings. A gap " +
        "of 0 means CISA added two or more of the vendor's CVEs on the same day. Vendors " +
        "with fewer than five entries are left off, because a median gap needs several " +
        "listings. The security flag marks rows where at least half the entries " +
        "classify as security products. Default sort: total entries, descending. Click " +
        "any column header to re-sort.",
    },

    // --------------------------------------------- guards.html · 3
    overlap: {
      num: "03",
      kicker: "Ransomware overlap",
      source: "CISA KEV",
      headline: "KEV entries in security products carry the ransomware flag about twice as often.",
      caption:
        "CISA flags each KEV entry whose vulnerability is known to have been used in " +
        "ransomware campaigns. Split by the classifier used on the rest of this page, " +
        "entries on exploited security products carry that flag roughly twice as often " +
        "as the rest of the catalog.",
      barSecurity: "Security products",
      barOther: "Rest of the catalog",
      methodology:
        "Both bars use the catalog's knownRansomwareCampaignUse field (“Known” against " +
        "anything else; a missing field counts as not Known, the same rule as on the " +
        "KEV Latency page) over the full catalog snapshot, seeding era included. The " +
        "split is this page's classifier: security products in one bar, all other " +
        "entries in the other, so together the two bars cover the catalog; each bar's " +
        "entry counts are in its tooltip. The chart measures only whether the flag is " +
        "more common on security products. It says nothing about which campaigns, when, " +
        "or how many victims: the flag is CISA's current per-entry assessment and " +
        "carries no date.",
    },

    // --------------------------------------------- epss.html · 1 · hero
    grade: {
      num: "01",
      kicker: "Day-before scores",
      source: "EPSS (FIRST.org) · CISA KEV",
      headline: "Roughly half or more of recent KEV additions scored under 1% the day before listing.",
      caption:
        "For each vulnerability added to CISA's KEV catalog, the chart shows its EPSS " +
        "score on the day before listing, in three bands. This describes scores before " +
        "catalog inclusion; it does not measure forecast accuracy. EPSS estimates the " +
        "probability of exploitation within the next 30 days, and KEV dateAdded is not " +
        "the date exploitation occurred. A low probability does not rule out an event, " +
        "and this selected cohort cannot establish calibration or overall model " +
        "performance. The 2022-to-2023 shift coincides with a model change (v2 to v3, " +
        "March 2023) and the catalog's seeding cutoff, which cannot be separated here. " +
        "Model versions are split in section 02; entries without a prior score are " +
        "counted separately.",
      statLabel: "Scored KEV additions under 1% the day before listing",
      statLatest: "{latest_year}",
      statAgo: "full catalog, all model eras pooled",
      legendBelow: "under 1% the day before",
      legendMid: "1–10%",
      legendAbove: "10% or higher",
      // Filled by the renderer from catalog counts; the pending sentence is
      // appended only while the historical backfill is still incomplete.
      note:
        "{ungradeable} of {total} catalog entries have no day-before score and are " +
        "counted separately, outside the bands: {before_pub} were listed on or before " +
        "the day their CVE record was published, and the rest had no row in FIRST's " +
        "data for that day.",
      pendingNote:
        "{pending} entries are still awaiting their historical day-before lookup; the " +
        "numbers on this page cover only the lookups fetched so far.",
      methodology:
        "For each current CISA KEV entry, the pipeline retrieves FIRST's historical " +
        "EPSS score for the day before dateAdded. Bands are shares of entries with an " +
        "available score; entries listed on or before publication, unavailable scores " +
        "and pending lookups are reported separately. A year needs at least 10 scored " +
        "entries; the current year is partial. KEV inclusion confirms known " +
        "exploitation but supplies no event date for testing the next-30-day forecast, " +
        "so this is a retrospective catalog cohort and not a calibration test or a " +
        "false-negative rate. That kind of evaluation needs dated outcomes, a defined " +
        "forecast window, comparison records and explicit observation coverage. " +
        "Seeding-era entries may concern exploitation years before listing. Model " +
        "versions are separated because their probability distributions differ. The " +
        "published file keeps the historical lookups.",
    },

    // --------------------------------------------- epss.html · 2
    distribution: {
      num: "02",
      kicker: "Scores by model version",
      source: "EPSS (FIRST.org) · CISA KEV",
      headline: "EPSS v2 scored most of these entries above 1%; v3 and v4 scored most below.",
      caption:
        "The same scored entries, in the four probability buckets of the " +
        "Score-vs-reality grid, split by EPSS model version. Versions v1 through v5 " +
        "are different models with materially different score distributions, so one " +
        "pooled histogram would mix incomparable scores, as mixing CVSS v2 and v3 " +
        "scores would. Under the v2 model most of these entries scored above 1%; under " +
        "v3 and v4 the majority scored below it, and the v5 era, on a small early " +
        "cohort, shows the same pattern so far.",
      methodology:
        "Each scored entry contributes its day-before probability to one bucket: " +
        "under 0.1%, 0.1–1%, 1–10%, or 10% and higher (lower edges inclusive, the same " +
        "arithmetic as the Score-vs-reality grid on the CVE Ecosystem page). The " +
        "historical API does not return the model version, so it is derived from the " +
        "score date using the era table in the data file, checked against the version " +
        "headers of FIRST's daily CSV files: v1 through 2022-02-03, " +
        "v2 (v2022.01.01) through 2023-03-06, v3 (v2023.03.01) through 2025-03-16, " +
        "v4 (v2025.03.14) through 2026-06-14, v5 (v2026.06.15) since. Day-before " +
        "probabilities are stored at five decimals, an exception to CyberMon's " +
        "one-decimal rounding, because the difference between 0.04% and 0.4% is what " +
        "this chart separates.",
    },

    // --------------------------------------------- epss.html · 3
    percentile: {
      num: "03",
      kicker: "Day-before percentile",
      source: "EPSS (FIRST.org) · CISA KEV",
      headline: "About three in ten scored KEV additions ranked in EPSS's bottom half the day before.",
      caption:
        "Raw probabilities are not comparable across model versions, because each model " +
        "is calibrated differently. A percentile is comparable: it gives the share of " +
        "all CVEs scored that same day with an equal or lower score. This view shows the " +
        "same scored entries on that scale. About three in ten sat in the bottom half of " +
        "the day's ranking; for a typical entry in that half, more than a hundred " +
        "thousand CVEs ranked above it on the day before listing.",
      statBig: "{n} of {total}",
      statLead: "scored entries ranked in EPSS's bottom half the day before listing",
      statNote: "median day-before percentile: {median}",
      yAxisLabel: "share of scored entries",
      methodology:
        "Each scored entry contributes the percentile EPSS published with its " +
        "day-before score: the share of all CVEs scored that day with an equal or lower " +
        "score. FIRST recomputes percentiles daily against that day's full set of scored " +
        "CVEs, so they can be compared across model versions where raw probabilities " +
        "cannot: a v2 probability and a v4 probability mean different things, but the " +
        "bottom half of a day's ranking means the same in every era. Buckets are shares " +
        "of scored entries that carry a percentile. The earliest EPSS era published " +
        "scores without percentiles for a period; such entries appear in the probability " +
        "charts but not here, and their count is in the data file. The stat's median is " +
        "the median day-before percentile of these entries.",
    },

    // --------------------------------------------- calendar.html · 1 · hero
    reservation: {
      num: "01",
      kicker: "ID age",
      source: "cvelistV5 (MITRE)",
      headline: "One in five CVEs published in 2025 carried an earlier year's ID.",
      caption:
        "Every CVE ID contains a year (CVE-2025-12345). Under CVE rules that year can " +
        "be the year the ID was reserved or the year the flaw was made public, and " +
        "either can be years before the record is published. The bands split each " +
        "year's newly published records by the age of their ID: same year, one year " +
        "earlier, or two or more years earlier. In 2025, one in five records shipped " +
        "on an earlier-year ID, and 2026 is running lower. The age of an ID is not " +
        "the age of the flaw it describes.",
      statLabel: "Share of newly published CVEs carrying an earlier-year ID",
      statLatest: "{latest_year}",
      statAgo: "{ago_year}",
      legendSameYear: "Same-year ID",
      legendOneYear: "1-year-old ID",
      legendTwoPlus: "2+ years old",
      methodology:
        "For every published record in the cvelistV5 corpus (rejected records " +
        "excluded), the year in its CVE ID is compared with its publication year, the " +
        "UTC year of datePublished. Same-year, one-year-old and two-or-more-year-old " +
        "IDs stack to 100%; the tooltip carries the counts. The ID year is not a " +
        "reservation timestamp. CNAs request blocks of IDs and publish against them " +
        "later, and a CNA may also give an ID the year its flaw was made public; the " +
        "Linux kernel CNA does this at scale for years-old fixes. An old ID can " +
        "therefore mean a queued reservation, a long coordinated disclosure, a batch " +
        "conversion, or a new record for an old, already public flaw. The rare " +
        "inverse, a next-year ID published in late December, is counted as age zero; " +
        "the number of such records ships in the data file (the real corpus " +
        "currently contains none). Records without a datePublished take their year " +
        "from the ID and count as same-year by construction. A year plots only with " +
        "at least 500 published records. The current year (marked *) is partial and " +
        "refills nightly. The headline compares complete years only, and the " +
        "baseline year is set in the data file, not derived by the page.",
    },

    // --------------------------------------------- calendar.html · 2
    weekbeat: {
      num: "02",
      kicker: "Weekday pattern",
      source: "cvelistV5 (MITRE)",
      headline: "In 2025, Tuesday carried about a quarter of all CVE publications.",
      caption:
        "The share of each year's records published on each weekday, for the latest " +
        "complete year and the year a decade before it. In the latest complete year, " +
        "Tuesday leads with roughly a quarter of all records, while Saturday and " +
        "Sunday carry few; a decade earlier the peak sat later in the week.",
      weekdayLabels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
      seriesYearLabel: "{year}",
      tooltipN: "{n} dated records in {year}",
      methodology:
        "Each published record with a day-precision datePublished contributes its " +
        "weekday. Bars are the share of that year's dated records on each day, for " +
        "the latest complete year and the year a decade before it. Both years are " +
        "set in the data file, not chosen by the page; until the record is ten years " +
        "deep, the earliest charted year is used instead. Weekdays are judged in UTC, " +
        "on the date the record carries. A late-evening publication in a US timezone " +
        "falls on the next UTC day, so a Tuesday release in California can count as " +
        "Wednesday here; a publisher east of UTC can shift the other way. The shift " +
        "is not corrected, because the record carries no reliable local timezone. " +
        "Records without a publication timestamp are excluded from this chart. A " +
        "year enters the comparison only with at least 500 dated records.",
    },

    // --------------------------------------------- calendar.html · 3
    patchtuesday: {
      num: "03",
      kicker: "Patch Tuesday",
      source: "cvelistV5 (MITRE)",
      headline: "In 2025, Patch Tuesdays carried nearly three times their calendar share of CVEs.",
      caption:
        "Microsoft releases security updates on the second Tuesday of each month, and " +
        "several other vendors, Adobe and SAP among them, publish on the same day. " +
        "Bars show the share of each year's published records that land on those " +
        "twelve days. The dashed line is what twelve days out of 365 would hold if " +
        "publication ignored the calendar: 3.3 percent. The latest complete year put " +
        "two to three times that share on them, and the bar has cleared the line in " +
        "every complete year since 2014. Tuesday has also been the busiest weekday in " +
        "recent years, so a dotted step line shows what the same twelve days would " +
        "carry as ordinary Tuesdays in the same year. The gap between the bar and " +
        "that line is the excess on release days beyond the general Tuesday effect; " +
        "it is a residual and does not isolate a cause. Every year since 2019 the bar " +
        "has cleared what its own ordinary Tuesdays would carry.",
      note:
        "The comparison: twelve UTC days per year against two baselines, a uniform " +
        "calendar (3.3%) and the year's own ordinary Tuesdays scaled to twelve days. " +
        "A bar at three times the 3.3% line means those days held three times their " +
        "calendar share; a bar at twice its dotted line means twice what the same " +
        "twelve days would carry as ordinary Tuesdays. Neither ratio says anything " +
        "about how severe or exploited the records were.",
      baselineLabel: "uniform calendar · {pct}",
      tuesdayBaselineSeries: "as ordinary Tuesdays",
      tooltipShare: "{pct} of the year's dated records",
      tooltipCount: "{on_pt} of {n} on Patch Tuesdays",
      tooltipTuesday: "as ordinary Tuesdays they would carry {pct}",
      tooltipTopDay: "busiest single day: {date} ({n} records)",
      methodology:
        "A record counts as a Patch Tuesday publication when its UTC datePublished " +
        "falls on the second Tuesday of its month, which is the Tuesday with " +
        "day-of-month 8 through 14; every year has exactly twelve such days. Bars are " +
        "the share of each year's dated records on those days. The dashed baseline " +
        "is 3.3%: 12 of 365 days (12 of 366 in a leap year rounds to the same " +
        "figure), the share those days would carry if publication were spread evenly " +
        "over the calendar. The dotted baseline is the ordinary-Tuesday share. Within " +
        "the year's observation window (first to last dated record), the records on " +
        "the other Tuesdays are averaged per Tuesday, multiplied by the window's " +
        "count of Patch Tuesdays and divided by the year's dated records. Tuesdays " +
        "are counted from the actual dates, not assumed to be 52, and the baseline " +
        "is left empty, not set to zero, when the window holds no other Tuesday. The " +
        "chart claims those two ratios only: the excess over the Tuesday line is not " +
        "attributed to a cause, and publication clustering on release days says " +
        "nothing about severity or exploitation. The tooltip also names the year's " +
        "busiest single publication day for context. That day is often a batch " +
        "conversion or mass import rather than a Patch Tuesday, and it is not ranked " +
        "or commented on. UTC day boundaries as in the weekday chart. A year plots " +
        "only with at least 500 dated records. The current year (marked *) is " +
        "partial and refills nightly.",
    },

    // --------------------------------------------- rescores.html · 1 · hero
    week: {
      num: "01",
      kicker: "Edits per week",
      source: "cvelistV5 (MITRE) · CyberMon's own nightly diffs",
      headline: "CNAs change severity scores on CVE records after publication.",
      caption:
        "A CVE record can be edited after it is published, including its severity " +
        "score: the assigning CNA can raise it, lower it, add one years later or " +
        "remove it, and the record keeps no changelog of its own. Each night " +
        "CyberMon reads the corpus and compares every record's CNA-assigned score " +
        "with the previous night's. In the lower panel, bars above the line are " +
        "scores raised and bars below are scores lowered. The upper panel counts " +
        "first scores added to existing records, CVSS version changes and removed " +
        "scores separately, because none of them is a new value for an existing " +
        "score on the same CVSS version. The log starts at first deploy and grows " +
        "nightly.",
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
        "The CVE record carries no history of score edits; the cvelistV5 git " +
        "repository does. CyberMon has compared the CNA-assigned score night by " +
        "night since {first_date}.",
      noteEmpty:
        "The CVE record carries no history of score edits; the cvelistV5 git " +
        "repository does. CyberMon's comparison starts with tonight's corpus, and " +
        "edits appear once there are two nights to compare.",
      emptyChart:
        "No compared nights on the log yet. The first night that can be compared " +
        "with a previous one fills the first bar.",
      methodology:
        "Each night the pipeline reduces every published CVE record to a score " +
        "fingerprint: the CNA-assigned base score of the newest CVSS version the " +
        "record carries, read by the same extraction the severity-inflation chart " +
        "uses, so the two pages agree on a record's score. Tonight's fingerprints are " +
        "compared with the previous night's, which are stored in the repository " +
        "together with the corpus release tag. A re-run against the same release is " +
        "detected and skipped, so no night is counted twice. A changed score on the " +
        "same CVSS version is a rescore, raised or lowered. A change in the record's " +
        "newest scored version is a version shift. Shifts are logged separately and " +
        "not charted as raised or lowered, because v2, v3 and v4 are different " +
        "scales and a move between them is a change of method, not an edit. The " +
        "version is the exact one the record names, so a 3.0-to-3.1 re-issue is also " +
        "a version shift. (Until 2026-09-20 the fingerprint stored only the version " +
        "family, so older rows read v3 and v4. On the first night with exact labels, " +
        "a family-only label was treated as the same version as an exact label in " +
        "that family, so that night did not log a version shift for every scored " +
        "record.) A record " +
        "gaining its first CNA-assigned score is counted separately as a backfill, " +
        "since it fills a blank field; a score disappearing from a live record is " +
        "logged as removed. Brand-new records produce no event; their first scores " +
        "are the subject of the severity-inflation chart. cvelistV5 is a public git " +
        "repository whose commits record the edits; this log adds a normalized " +
        "nightly diff of the CNA-assigned score that can be read without replaying " +
        "commits. Events are appended to a CSV in the repository " +
        "(data/history/rescore_log.csv), and the comparison state is stored beside " +
        "it, so the two cannot diverge. They diverged once, in July 2026, while the " +
        "state was cached outside the repository, and the duplicated events were " +
        "removed from the log. If the state is lost, it is rebuilt from that night's " +
        "corpus and that night logs zero events, so at most one night of edits goes " +
        "unrecorded. Bars group by ISO week of the observation date (UTC); the " +
        "current week keeps filling until it closes.",
    },

    // --------------------------------------------- rescores.html · 2
    magnitude: {
      num: "02",
      kicker: "Magnitude",
      source: "cvelistV5 (MITRE) · CyberMon's own nightly diffs",
      headline: "Most rescores lower the score, and most move it by less than two points.",
      caption:
        "Each rescore's change: the new score minus the old, always on the same CVSS " +
        "version; an edit that changes version, 3.0 to 3.1 included, is a version " +
        "shift and never lands here. The buckets separate small corrections of under " +
        "two points from changes of four points or more. Below 30 rescores the panel " +
        "shows the count instead of a histogram.",
      // Rendered instead of the chart while the log sits under the min-n
      // gate; both variants are filled from the data file, never hardcoded.
      placeholder:
        "{n} rescore events on the log since {first_date}; the distribution is " +
        "charted once {min_n} have accumulated.",
      placeholderEmpty:
        "No rescore events on the log yet; the distribution is charted once {min_n} " +
        "have accumulated.",
      medianLabel: "median delta {median}",
      tooltipCount: "{n} rescore events",
      xAxisLabel: "score delta (new − old)",
      yAxisLabel: "rescore events",
      methodology:
        "Delta is the new score minus the old for each rescore event. Both scores " +
        "are on the same exact CVSS version, not only the same family, so every " +
        "delta compares like with like. Version shifts, including 3.0-to-3.1 " +
        "re-issues, are excluded from this chart, because a difference between two " +
        "scoring scales is not a measurement. Deltas fall into fixed signed buckets " +
        "(−4 and under, over −4 to −2, over −2 to −0.1, +0.1 to under +2, +2 to under " +
        "+4, +4 and over) at the scores' one-decimal precision. A delta of zero " +
        "cannot occur, since an unchanged score is not an event. The distribution " +
        "and its median are not plotted until the log holds at least 30 rescore " +
        "events, because a histogram of a few edits would mostly show noise. The " +
        "threshold and the current count ship in the data file, and the text shown " +
        "before the threshold is reached is built from them.",
    },

    // --------------------------------------------- rescores.html · 3
    editors: {
      num: "03",
      kicker: "Rescores by CNA",
      source: "cvelistV5 (MITRE) · CyberMon's own nightly diffs",
      headline: "A handful of CNAs made most of the rescores logged since July 2026.",
      caption:
        "Each rescore is filed under the CNA named as assigner on the record the night " +
        "the edit was seen. That CNA is responsible for the score; it is usually, but " +
        "not provably, the party that made the change. The board counts rescore " +
        "events per CNA (same version, new score), split into raised and lowered. The " +
        "log began in July 2026, so the board is still short; the line above it gives " +
        "the number of rescores it is built on and the size of the whole log.",
      boardNote: "{rescores} rescore events among {events} logged since {first_date}",
      boardNoteEmpty: "no events on the log yet; collection is running",
      windowTemplate:
        "whole log · {context} · min {min_events} rescore events per CNA",
      colCna: "CNA",
      colRescores: "rescores",
      colUp: "raised",
      colDown: "lowered",
      emptyBoard:
        "No CNA has enough logged rescores to rank yet; the board fills as the log " +
        "grows.",
      methodology:
        "For each CNA (the record's assigner on the night the edit was observed), the " +
        "board counts rescore events across the whole log, split by direction. " +
        "Version shifts, backfilled first scores and removals are excluded, because " +
        "the board counts new values for existing scores. CNAs with fewer than 3 " +
        "logged rescores are left off the board; two edits are too few to show a " +
        "pattern. There is no time window yet: the log is young, and a window would " +
        "empty the board. When the log is long enough for a rolling window, this note " +
        "will change. Default sort: rescore count, descending. Click any column " +
        "header to re-sort.",
    },

    // --------------------------------------------- changelog.html · 1 · hero
    edits: {
      num: "01",
      kicker: "Catalog edits",
      source: "CISA KEV · CyberMon's own nightly diffs",
      headline: "CISA edits KEV entries in place after they are published.",
      caption:
        "CISA edits entries in its Known Exploited Vulnerabilities catalog in place. " +
        "The catalog page and feed carry no changelog; CISA's kev-data repository " +
        "keeps the files' commit history. CyberMon diffs each fresh catalog against " +
        "the last observed one, keeps every difference, and records the edits as a " +
        "per-field ledger. Bars count edits per month: remediation deadlines moved, " +
        "ransomware flags flipped, text revised, and entries removed. New listings are " +
        "deliberately not counted; the chart counts changes to entries already " +
        "published.",
      statLabel: "Edits to already-published entries since the record began",
      statNote: "edits across a catalog of {entries} entries · new listings excluded: {additions}",
      legendDueDate: "Due date moved",
      legendFlag: "Ransomware flag",
      legendText: "Text revised",
      legendRemoved: "Entry removed",
      // Filled by the renderer from the catalog block; the capture sentence
      // is appended only when the record carries Wayback-seeded events.
      note: "The record's first observation is {first_observed}.",
      waybackNote:
        "History before the nightly diffs is reconstructed from {captures} " +
        "Internet Archive captures of the feed. A backfilled edit is dated to the " +
        "first capture that shows it; the true date lies between that capture and " +
        "the one before.",
      methodology:
        "Every run fingerprints each catalog entry. dueDate, " +
        "knownRansomwareCampaignUse, vendorProject, product and vulnerabilityName " +
        "are kept verbatim; shortDescription, requiredAction and notes are kept as " +
        "short stable hashes of the whitespace-normalized text, so the log can record " +
        "that a text changed without republishing it, and a whitespace-only change " +
        "does not count. The fresh catalog is diffed against the stored fingerprints, " +
        "and each difference is one event in an append-only CSV " +
        "(data/history/kev_changelog.csv). Like the NVD backlog history, it is a " +
        "dataset this project accumulates: the catalog feeds carry only the current " +
        "snapshot, and CISA's kev-data git repository keeps whole-file commits, not " +
        "per-field events. A missing ransomware flag reads as “Unknown,” the same " +
        "rule as on the KEV Latency and Security Products in KEV pages. The first capture carrying that " +
        "column therefore logged a flip for each entry already flagged as Known; " +
        "section 02 names that step month and keeps it out of its statistics, while " +
        "the edit total above includes it. Additions are logged but not charted as " +
        "edits; removals are charted here and listed by name in section 04. Events " +
        "carry a granularity flag. “Daily” events are dated to the nightly run that " +
        "first saw them (if the pipeline misses nights, changes pool on the next " +
        "run's date). “Capture” events come from the one-time Internet Archive " +
        "backfill and are dated to the first capture showing them; with weeks to " +
        "months between captures, a capture-era month is a lower-resolution bucket, " +
        "and a single-capture spike can be one bulk revision by CISA. The record's " +
        "first observation is a baseline: it writes the fingerprints and logs " +
        "nothing, since there is nothing earlier to compare against.",
    },

    // --------------------------------------------- changelog.html · 2
    flagflip: {
      num: "02",
      kicker: "Ransomware-flag flips",
      source: "CISA KEV · CyberMon's own nightly diffs",
      headline: "CISA often adds the ransomware flag months or years after listing.",
      caption:
        "Each KEV entry carries CISA's assessment of whether the vulnerability is " +
        "known to have been used in ransomware campaigns. CISA changes that flag from " +
        "“Unknown” to “Known” on entries that have been in the catalog for months or " +
        "years, so anyone who read an entry before the change saw “Unknown” (or, " +
        "before October 2023, no flag). Bars count the flips observed each month and " +
        "the line accumulates them; the stat counts flips after listing, and its note " +
        "gives the median time from listing to the observed flip.",
      statBig: "{n}",
      statLead: "entries flipped to “Known” after they were already listed",
      // With a capture-seeded record the step month is set apart from the
      // headline count: statNote/statNotePooled name it; statNoteNoStep is
      // for a record built from nightly diffs alone (no step to name).
      statNote:
        "not counting the {step_flips} flips logged together in {step_month}, the month the " +
        "flag column first appears in the captures; those record the new column, not " +
        "reassessments. Median gap from listing to observed flip: {post_median} days " +
        "({median} days including the step)",
      statNotePooled:
        "not counting the {step_flips} flips logged together in {step_month}, the month the " +
        "flag column first appears in the captures. Median gap from listing to observed " +
        "flip: {median} days, step included",
      statNoteNoStep: "median gap from listing to observed flip: {median} days",
      statNoteThin:
        "too few observed flips for a median yet; the counts are in the data file",
      legendMonthly: "Flips observed that month",
      legendCumulative: "Cumulative flips",
      methodology:
        "A flip is a logged change of knownRansomwareCampaignUse to “Known” on an " +
        "entry already present in the previous observation. The gap runs from the " +
        "entry's dateAdded to the date the flip was observed, so it is an upper bound: " +
        "a flip CISA made between two Internet Archive captures is dated to the later " +
        "capture. One step in the curve comes from the feed format. CISA added the " +
        "ransomware column to the feed in October 2023, so the first capture carrying " +
        "it logs a flip for each entry already flagged at that point. For those " +
        "entries the gap mostly measures how long the entry sat in the catalog before " +
        "the column existed, and the curve shows them as the step where the record's " +
        "flag history begins. The median is published only with at least 10 observed " +
        "flips; below that, only the count is published. Flips back to “Unknown” are " +
        "tracked (none so far) and reported in the data file as reversals, separately " +
        "from the total.",
    },

    // --------------------------------------------- changelog.html · 3
    flaglag: {
      num: "03",
      kicker: "Time to the flag",
      source: "CISA KEV · CyberMon's own nightly diffs · Internet Archive captures",
      headline: "Most ransomware-flag flips come more than three months after listing.",
      caption:
        "For each entry flipped from “Unknown” to “Known” ransomware use, the days from " +
        "the entry's dateAdded to the first observation of the flip. The distribution " +
        "view shows the spread; the listing-year view shows the median and middle half " +
        "for the entries listed in each year. Flips dated from Internet Archive " +
        "captures are upper bounds: the flip happened at or before the capture that " +
        "first shows it.",
      statBig: "{median} days",
      statLead: "median from listing to the observed flip",
      statLeadThin: "too few flips to state a median yet",
      statNote:
        "{n} flips · middle half {p25}–{p75} days · {n_daily} observed by the nightly " +
        "diff, {n_capture} from captures (upper bounds)",
      statNoteStep: "the {step_flips} flips logged together in {step_month} are left out",
      wentBack: "{went_back} of these flips later went back to “Unknown”",
      wentBackNone: "none of these flips has gone back to “Unknown”",
      note:
        "Each date is the first observation of the flip, not the day CISA made it. " +
        "Recent listing years have had less time to be flipped, so their medians are " +
        "capped by their age.",
      noBlock: "This edition predates the flag-lag data; the next nightly build adds it.",
      toggleLabels: ["Distribution", "By listing year"],
      legendDaily: "Nightly diff (to the day)",
      legendCapture: "Capture (upper bound)",
      legendIqr: "Middle half (p25–p75)",
      legendMedian: "Median",
      axisDays: "days from dateAdded to observed flip",
      axisDaysShort: "days",
      axisYear: "listing year (flips)",
      yearTip: "Listed {year} · {n} flips",
      yearThin: "fewer than 10 flips — no median published",
      bucketLabels: {
        "0-30d": "≤30 d", "31-90d": "31–90 d", "91-180d": "91–180 d",
        "181-365d": "181–365 d", "1-2y": "1–2 y", "2-4y": "2–4 y", "4y+": ">4 y",
      },
      methodology:
        "The cohort is every logged change of knownRansomwareCampaignUse from " +
        "“Unknown” to “Known” on an entry already in the catalog, minus the flips in " +
        "the step month named in section 02 (the first capture carrying the flag " +
        "column, when each entry already flagged flipped at once). The lag is the " +
        "flip's observation date minus the entry's dateAdded, in days. Each flip is " +
        "dated to its first observation, so each lag is an upper bound. “Daily” flips " +
        "were seen by the nightly diff and are accurate to the day; “capture” flips " +
        "come from the Internet Archive backfill and can trail the real change by " +
        "weeks to months. For entries listed before CISA added the column in October " +
        "2023, the lag includes time before the flag existed. The listing-year view " +
        "groups flips by the year of dateAdded; its median and quartiles are " +
        "published only with at least 10 flips in the year, and a recent year can " +
        "only show lags as long as its entries are old. A flip that later went back " +
        "to “Unknown” stays in the cohort and is counted separately.",
    },

    // --------------------------------------------- changelog.html · 4
    receipts: {
      num: "04",
      kicker: "Most-edited entries",
      source: "CISA KEV · CyberMon's own nightly diffs",
      headline: "Some KEV entries have been edited eight or more times after listing.",
      caption:
        "The twelve entries with the most logged edits to an already-published " +
        "listing (the one-time ransomware-flag step of December 2023 included) and, " +
        "below them, every entry observed leaving the catalog. Removals are named " +
        "because KEV entries carry federal remediation deadlines under BOD 22-01, " +
        "and a removed entry's deadline goes with it.",
      colCve: "CVE",
      colVendor: "Vendor",
      colProduct: "Product",
      colEdits: "edits",
      colLast: "last change",
      removalsTitle: "Removed from the catalog",
      removalRow: "{cve} — {vendor} {product} · listed {listed} · removed {removed}",
      removalRowUnlisted: "{cve} — {vendor} {product} · removed {removed}",
      noRemovals:
        "No removals observed in the record so far; any removal will be listed here " +
        "by name.",
      methodology:
        "An entry's edit count is its logged field changes and text revisions over " +
        "the full record; additions and removals are not counted as edits. The board " +
        "shows the top dozen by edit count (ties break by CVE id, compared as text); " +
        "“last change” is the date of the entry's most recent logged edit. Removals " +
        "come from the state's removal ledger: an entry present in one observation " +
        "and absent from the next is logged as removed and kept on this list even if " +
        "it later returns (the return is logged as a new addition). Capture-era dates " +
        "carry the same caveat as the rest of the page: they are the first capture " +
        "that shows the change, which can be later than the day CISA made it.",
    },

    // --------------------------------- naming.html · 1 · hero
    naming_board: {
      num: "01",
      kicker: "Most aliases",
      source: "MITRE ATT&CK (enterprise)",
      headline: "The most-renamed ATT&CK groups carry a dozen or more alternate names each.",
      caption:
        "MITRE ATT&CK files each tracked threat group under one name and records " +
        "aliases used by other vendors: APT28 is also listed as Fancy Bear, Forest " +
        "Blizzard, Sofacy and STRONTIUM. The most-renamed groups carry a dozen " +
        "or more names apiece. MITRE notes that an associated name may describe an " +
        "overlapping activity cluster rather than the same group. This table counts " +
        "the names besides the canonical one. The alias list is MITRE's selection and " +
        "does not record every vendor's naming. Roughly four in ten tracked groups " +
        "carry no second name in ATT&CK, which says nothing about what other vendors " +
        "call them.",
      statTemplate:
        "ATT&CK v{version} · the {shown} groups with the most aliases, of " +
        "{with_aliases} that have any, out of {total} tracked",
      colActor: "Group",
      colCount: "aliases",
      colAliases: "also tracked as",
      nodata: "Not enough data yet.",
      methodology:
        "Threat-group (intrusion-set) entries in MITRE's current enterprise ATT&CK " +
        "STIX bundle carry an alias list whose first entry is the group's canonical " +
        "name; the other entries are alternate names. The table counts the alternate " +
        "names (every alias that differs from the canonical name) for each active " +
        "group, meaning neither revoked nor deprecated. Groups are ranked from most " +
        "to fewest, with ties broken by name. The page shows the top thirty, extended " +
        "so that the cut does not split a tie; the full ranking is in the data file. " +
        "Only the latest release is read, so this is a snapshot of the current " +
        "release and does not show change over time. Limit: the alias list is MITRE's " +
        "curation, not a complete record of vendor naming, so the counts are a lower " +
        "bound.",
    },

    // --------------------------------- naming.html · 2
    naming_dist: {
      num: "02",
      kicker: "Alias counts",
      source: "MITRE ATT&CK (enterprise)",
      headline: "Most ATT&CK groups have three or fewer alternate names.",
      caption:
        "Each bar counts the active tracked groups with that many alternate names. " +
        "Roughly four in ten groups have none (ATT&CK lists no other name for them), " +
        "while a short tail of groups has ten or more, up to fifteen.",
      xAxis: "alternate names per group",
      yAxis: "tracked groups",
      nodata: "Not enough data yet.",
      methodology:
        "The same active intrusion sets as the table above, grouped by how many " +
        "alternate names each has. Every count from zero to the maximum is shown, " +
        "including empty ones. The zero bucket (groups ATT&CK lists under a single " +
        "name) is drawn muted. This is a snapshot of the current release and does " +
        "not show change over time.",
    },

    // --------------------------------- top25.html · 1 · hero
    top25_ranks: {
      num: "01",
      kicker: "Official rank vs. measured rank",
      source: "CVE List V5 (MITRE) · CISA KEV · CWE Top 25 (MITRE)",
      headline: "The CWE Top 25 order differs from weakness frequency in CVE records.",
      caption:
        "MITRE publishes the CWE Top 25 annually, ranking the weakness classes it " +
        "considers most dangerous. The table sets each class's official rank beside " +
        "its measured rank: how often the class is the first-listed CWE on a " +
        "published CVE record. The two orders differ, and a few official picks fall " +
        "outside the 25 most common weaknesses in the measured window. The two ranks " +
        "measure different things. MITRE weights each class's NVD frequency by the " +
        "average CVSS severity of its CVEs over one year; the measured rank counts " +
        "frequency alone over five years. The comparison shows where the definitions " +
        "disagree and is not a correction of MITRE's list.",
      statTemplate:
        "MITRE CWE Top 25 ({year}) · measured prevalence {start}–{end} · " +
        "{in_top25} of {total} also rank in the measured top 25",
      colWeakness: "Weakness",
      colOfficial: "official",
      colMeasured: "measured",
      colPrevalence: "prevalence",
      colKev: "KEV hits",
      unranked: "outside",
      unrankedTitle: "never the first-listed CWE on a published record in the window",
      nodata: "Not enough data yet.",
      methodology:
        "The official column is MITRE's published CWE Top 25 for the newest " +
        "committed year: a static list transcribed by hand from cwe.mitre.org/" +
        "top25, the module's only added source. The measured column ranks every " +
        "weakness class that appears as the first-listed CWE (CNA container " +
        "preferred, CISA-ADP as fallback) on a published CVE record over the " +
        "last five complete calendar years, by how often it appears. An official " +
        "pick can land anywhere in that ranking; a class that is never the " +
        "first-listed CWE in the window is shown as “outside.” " +
        "Prevalence is the class's share of all CWE-tagged published records in " +
        "the window. KEV hits count the class among CISA Known Exploited " +
        "Vulnerabilities entries that match a corpus record. Limit: MITRE's " +
        "published methodology scores each CWE by combining its normalized " +
        "frequency among NVD CVEs in a one-year window (June 1, 2024 through " +
        "June 1, 2025 for the 2025 list) with the average CVSS v3 base severity of " +
        "those CVEs, after a mapping review that considers multiple CWE mappings " +
        "per record; KEV counts are shown beside MITRE's list but are not an input " +
        "to its score. The measured rank uses a different measure on a different " +
        "population (first-listed-CWE frequency alone, over five calendar years of " +
        "cvelistV5), so differences between the two orders reflect different " +
        "definitions and do not correct MITRE's list. Recomputed nightly; the " +
        "newest committed official list is used. Click a column header to sort.",
    },

    // --------------------------------- top25.html · 2
    top25_exploited: {
      num: "02",
      kicker: "Official classes in KEV",
      source: "CVE List V5 (MITRE) · CISA KEV · CWE Top 25 (MITRE)",
      headline: "Almost every CWE Top 25 class appears in KEV, in very uneven numbers.",
      caption:
        "The same official Top 25, counted against CISA's Known Exploited " +
        "Vulnerabilities (KEV) catalog. Each bar is the number of KEV entries whose " +
        "first-listed weakness is that class; classes with no KEV entry are drawn in " +
        "gray. Almost every one of the official Top 25 turns up in the exploited set, " +
        "but the counts are uneven, from over a hundred entries for some classes to " +
        "one or none for others.",
      statTemplate:
        "{in_kev} of {total} official classes appear in the exploited set · " +
        "together {coverage} of tagged KEV entries",
      xAxis: "exploited (KEV) entries",
      nodata: "Not enough data yet.",
      methodology:
        "Each bar is one of the official Top 25 classes: the number of CISA Known " +
        "Exploited Vulnerabilities (KEV) entries whose first-listed CWE (CNA " +
        "container preferred, CISA-ADP as fallback) is that class, among entries " +
        "that match a record in the CVE corpus. Bars are sorted by count, highest " +
        "first; a class with no KEV entry is drawn in gray. The combined share above " +
        "the chart is the share of all tagged KEV entries whose class is on the " +
        "official list. KEV is small next to the full corpus, and only entries " +
        "matched to a corpus record carry a CWE here, so the counts are a lower " +
        "bound. KEV is not an input to MITRE's score (see the table above). The " +
        "two sources differ most on listed classes with no KEV entry and on " +
        "heavily exploited classes the list ranks low. Recomputed nightly.",
    },

    // --------------------------------- adp.html · 1 · hero
    adp_handoff: {
      num: "01",
      kicker: "Enrichment by month",
      source: "CVE List V5 (MITRE) — CISA-ADP containers",
      headline: "Since mid-2024, CISA has enriched about half of all published CVE records.",
      caption:
        "Each bar counts the CVE records whose CISA-ADP (Vulnrichment) block was " +
        "last updated that month. The date is the block's dateUpdated, a " +
        "last-modified date: a record updated again moves to the later month, so " +
        "early months are lower bounds. The chart does not use the CVE's " +
        "publication date, because CISA adds blocks to older records in batches of " +
        "thousands. The series starts at Vulnrichment's 2024 launch, in the months " +
        "when NVD's own analysis had slowed sharply. Red bars mark back-fill months, " +
        "when at least half of the month's enrichments went to old CVEs.",
      statLabel: "Share of published CVE records carrying a CISA-ADP block",
      statNote: "{cisa} of {total} published records carry a CISA-ADP block",
      partialMonth: "month in progress",
      sweepTooltip: "Back-fill month",
      sweepNote:
        "Red bars are back-fill months: at least half of that month's enrichments " +
        "went to legacy CVEs, whose ID year is two or more years before the " +
        "enrichment year. This is consistent with a bulk pass over old records, but " +
        "a newly published record with an old ID, enriched the same month, also " +
        "counts as legacy.",
      nvdContext:
        "For comparison, NVD's analysis backlog stands at {backlog} CVEs in " +
        "tonight's edition.",
      nodata: "Not enough data yet.",
      methodology:
        "Every published CVE record is checked for a CISA-ADP container, the block " +
        "CISA's Vulnrichment program adds, matched by its provider shortName " +
        "“CISA-ADP” or by the Vulnrichment orgId. Each such record is placed in the " +
        "month of that container's own dateUpdated, not the CVE's datePublished: " +
        "CISA adds blocks to older records (a 2019 CVE's CISA-ADP block can be " +
        "dated 2025), so a publication-date axis would show CISA activity before " +
        "2024 that did not happen then. A month is flagged as a back-fill month " +
        "(red) when it has at least 50 enrichments and at least half of them went to " +
        "legacy CVEs, whose ID year is two or more years before the enrichment year. " +
        "The series starts at the first month with at least 50 enrichments and " +
        "continues without gaps to the latest month. The chart does not draw NVD's " +
        "2024 analysis slowdown as a line: CyberMon's own NVD backlog record begins " +
        "at launch, so there is no 2024 NVD series to chart. The slowdown is " +
        "described in prose, and the backlog figure shown for comparison is read in " +
        "the browser from the current nvd_decay.json; it is context, not a trend. " +
        "Counts are of the cvelistV5 corpus, which is the source of truth for the " +
        "CVE List.",
    },

    // --------------------------------- adp.html · 2
    adp_adds: {
      num: "02",
      kicker: "Fields added",
      source: "CVE List V5 (MITRE) — CISA-ADP containers",
      headline: "Nearly every CISA-ADP block carries SSVC decision points.",
      caption:
        "Of the records CISA enriched, the share carrying each machine-readable " +
        "addition. SSVC decision points, CISA's assessment of exploitation, " +
        "automatability and technical impact, appear on nearly every one. A CVSS " +
        "score and a CWE weakness class appear on far fewer, added mostly where the " +
        "CNA left the field blank. A record can carry all three, so the bars are " +
        "independent and do not sum to 100.",
      labelSsvc: "SSVC decision points",
      labelCvss: "CVSS score",
      labelCwe: "CWE class",
      yAxis: "share of CISA-ADP records",
      nodata: "Not enough data yet.",
      methodology:
        "For every published record carrying a CISA-ADP container, three checks are " +
        "made against that container: SSVC decision points (a metrics entry whose " +
        "“other” block has type “ssvc”), a CVSS base score (any CVSS version in its " +
        "metrics) and a CWE (any problemTypes cweId). Each bar is the share of " +
        "CISA-ADP records carrying that field. A record can carry all three, so the " +
        "bars are independent and do not sum to 100. The denominator is every " +
        "published record with a CISA-ADP block, whether or not its container is " +
        "dated.",
    },

    // --------------------------------- adp.html · 3
    adp_providers: {
      num: "03",
      kicker: "ADP publishers",
      source: "CVE List V5 (MITRE) — ADP containers",
      headline: "CISA adds almost all of the substantive ADP enrichment on CVE records.",
      caption:
        "An Authorized Data Publisher (ADP) adds its own container to a CVE record, " +
        "separate from the assigning CNA's. The board ranks ADP publishers by the " +
        "records where they added SSVC decision points, a CVSS score or a CWE; " +
        "references alone do not count. CISA-ADP leads by a wide margin. Other " +
        "publishers that clear the bar, currently supplier ADPs that add data about " +
        "products they ship, do so on far fewer records. The CVE Program's own ADP " +
        "container (the “CVE Program Container”) adds only references, so it does " +
        "not appear.",
      statTemplate: "{shown} ADP publishers with substantive enrichment · CISA-ADP on {pct} of the published corpus",
      colProvider: "Publisher",
      colRecords: "records",
      colShare: "% of corpus",
      nodata: "Not enough data yet.",
      methodology:
        "Each published record's ADP containers are read for their provider " +
        "shortName. A publisher is credited with a record only when its container " +
        "added SSVC decision points, a CVSS score or a CWE; references alone do not " +
        "count. Share is of all published records in the cvelistV5 corpus. ADP is " +
        "the CVE v5 mechanism for an organization other than the assigning CNA to " +
        "add data to a record. The CVE Program's own ADP container is on most " +
        "records but adds only references, so it is not counted. CISA-ADP accounts " +
        "for nearly all substantive enrichment; the other publishers that clear the " +
        "bar are currently supplier ADPs, each on a small fraction of the records " +
        "CISA-ADP covers.",
    },

    // --------------------------------- epssvol.html · 1 · hero
    epssvol_gap: {
      num: "01",
      kicker: "Percentile vs probability",
      source: "EPSS (FIRST.org) · CyberMon's own nightly diffs",
      headline: "EPSS percentiles move for nearly all CVEs each night; probabilities for about 1%.",
      caption:
        "EPSS publishes two figures per CVE: a probability of exploitation and a " +
        "percentile that ranks it against all other scored CVEs. The percentile " +
        "changes for almost every CVE from one night to the next, the probability for " +
        "far fewer. For a CVE whose probability is unchanged, a percentile change comes " +
        "from the rest of the ranking: the scored set grows by a few hundred CVEs a " +
        "day, and other CVEs' scores move. The two lines are the nightly shares of " +
        "compared CVEs whose percentile and whose probability changed; exact figures " +
        "are in the stat and the tooltips.",
      // {first_date} is filled from the data (the log's first observed date);
      // the empty variant renders while the log has no diff-nights yet.
      note:
        "FIRST publishes daily snapshots but no per-CVE change log; CyberMon has " +
        "diffed the feed nightly since {first_date}.",
      noteEmpty:
        "FIRST publishes daily snapshots but no per-CVE change log; CyberMon's record " +
        "starts with tonight's feed. The chart appears once there are two nights to " +
        "compare.",
      // Appended to the note when the catalog names quarantined nights.
      noteQuarantined:
        " {n} of {days} nights are excluded from all charts on this page " +
        "({reasons}); the data file lists each with its reason.",
      // Rendered instead of the chart while the log sits under the min-days
      // gate; both variants are filled from the data file, never hardcoded.
      placeholder:
        "{days} of {min_days} diff-nights on record since {first_date}; the chart " +
        "appears once {min_days} nights have accumulated.",
      placeholderEmpty:
        "No diff-nights on record yet. The record begins at first deploy, and the " +
        "first comparable night draws the first point.",
      statLabel: "Share of compared CVEs whose EPSS percentile moved overnight",
      statVersus: "vs {prob} whose probability moved · {days} clean nights on record",
      legendPct: "Percentile moved",
      legendProb: "Probability moved",
      yAxisLabel: "share of compared CVEs",
      methodology:
        "Every night the pipeline fingerprints the EPSS feed already fetched for the " +
        "rest of the site (each CVE's raw probability and published percentile) and " +
        "diffs it against the previous night's fingerprint, which is kept in the " +
        "pipeline's cache; losing the cache costs one night's diff, never a log row. " +
        "A re-run against the same EPSS score_date is detected and skipped, so " +
        "nothing is counted twice. Only CVEs present on both nights are compared: a " +
        "CVE new to tonight's feed has no prior value, and new arrivals are part of " +
        "what shifts the percentiles. “Moved” means the value changed at the " +
        "five-decimal precision EPSS publishes. The two lines are the shares of " +
        "compared CVEs whose percentile moved and whose probability moved. They " +
        "diverge because FIRST recomputes every percentile nightly against that day's " +
        "full set of scored CVEs, while the raw probability is the model's estimate " +
        "for that CVE alone. When the feed's model_version changes, a new model " +
        "rescores the corpus overnight and nearly every value moves for reasons " +
        "unrelated to any one CVE; that night is logged, flagged and excluded from " +
        "all trends here, as the CVSS Score Changes page does with its seeding. Two more kinds of " +
        "night are excluded by rules applied to the log itself, so the result is " +
        "reproducible: a night whose diff pools more than one snapshot because the " +
        "runs between it and the previous row failed, and an anomalous night, on which " +
        "the share of probabilities that moved is more than five times the clean-night " +
        "median (and above five percent) with no model change. The second rule covers " +
        "corpus-wide jumps like those first seen in August 2026, when about one CVE " +
        "in eight moved and then moved back. Every excluded night is listed with its " +
        "reason in the data file's catalog block. This measures stability, not " +
        "accuracy; the EPSS Before KEV page shows where scores stood the day before a KEV " +
        "listing without judging whether the model was right. Limits: the record " +
        "starts at first deploy, so it is short and grows nightly; and FIRST's dated " +
        "daily snapshots are publicly archived, so this is the only maintained " +
        "per-CVE EPSS change log but not the only one that could be built.",
    },

    // --------------------------------- epssvol.html · 2
    epssvol_churn: {
      num: "02",
      kicker: "Threshold crossings",
      source: "EPSS (FIRST.org) · CyberMon's own nightly diffs",
      headline: "Crossings of the 0.1%, 1% and 5% probability lines are rare next to percentile moves.",
      caption:
        "A percentile change moves a CVE's rank without changing the model's " +
        "probability for it. These bars count the other kind of change: CVEs whose " +
        "raw probability crossed 0.1%, 1% or 5%, in either direction, summed per " +
        "week. Next to the percentile changes in section 01 these crossings are rare, " +
        "fewer than one for every hundred percentile changes over the clean nights. " +
        "Nights on which a large share of the corpus moved and then moved back are " +
        "excluded from these bars and listed in the data file.",
      note:
        "Thresholds: 0.001 / 0.01 / 0.05, chosen by CyberMon. A crossing counts in " +
        "either direction, and the three counts are independent: one large jump can " +
        "cross all three.",
      legendLo: "crossed 0.1%",
      legendMid: "crossed 1%",
      legendHi: "crossed 5%",
      yAxisLabel: "CVEs crossing a threshold",
      emptyChart:
        "No diff-nights on the log yet; crossings appear once there are two nights " +
        "to compare.",
      methodology:
        "For each CVE compared on two consecutive EPSS snapshots (the fingerprint and " +
        "exclusion rules are in section 01's methodology), the pipeline checks whether " +
        "its raw probability crossed any of three fixed thresholds, 0.001, 0.01 and " +
        "0.05, meaning the “≥ threshold” side changed between the two nights, up or " +
        "down. Bars sum the per-night counts by ISO week of the observation date " +
        "(UTC); the week in progress is starred and fills until it closes, and empty " +
        "weeks between observed ones chart at zero so the axis does not skip time. " +
        "The three series are counted independently, so a probability that jumps from " +
        "near zero to above 5% counts under all three. Reset nights, pooled nights " +
        "and corpus-wide jumps are excluded, as everywhere on this page. The " +
        "thresholds are CyberMon's, not FIRST's; they are stated here so a reader can " +
        "apply different ones.",
    },

    // --------------------------------- epssvol.html · 3
    epssvol_movers: {
      num: "03",
      kicker: "Biggest single-night moves",
      source: "EPSS (FIRST.org) · CyberMon's own nightly diffs",
      headline: "The twenty largest single-night EPSS probability moves each exceed 25 percentage points.",
      caption:
        "The largest single-night changes in raw EPSS probability on record. Each row " +
        "is one CVE on one night, ranked by the size of the change; the arrow and the " +
        "from→to column give its direction. On most clean nights some CVE's " +
        "probability moves by ten percentage points or more, but it is one CVE among the " +
        "hundreds of thousands compared.",
      note:
        "The board keeps each night's single largest move. A night with several " +
        "large moves contributes only its largest, so the board understates " +
        "volatility on those nights.",
      windowTemplate: "{context} · {shown} shown · min move {min_delta}",
      boardNote: "{days} clean nights since {first_date}",
      boardNoteEmpty: "no diff-nights on the log yet; collection has started",
      colCve: "CVE",
      colDate: "moved",
      colShift: "probability",
      colDelta: "move",
      emptyBoard:
        "No single-night probability move has reached the minimum yet; the board " +
        "fills as the record grows.",
      methodology:
        "Each clean night contributes its largest absolute change in raw probability " +
        "among the CVEs compared that night (fingerprint rules are in section 01's " +
        "methodology). The board ranks these nightly maxima across the record by the " +
        "size of the move; the sign is shown but not used for ranking. It keeps the " +
        "largest twenty at or above a minimum move (production threshold 0.1, i.e. 10 " +
        "percentage points; the threshold ships in the data file). Probabilities are " +
        "shown as percentages to three decimals and moves in percentage points. " +
        "Because only one move is kept per night, a night with several large " +
        "independent changes is represented by its largest alone, so the board is a " +
        "lower bound on volatility, not a complete list. Excluded nights (model " +
        "resets, pooled nights and corpus-wide jumps, by the rules in section 01's " +
        "methodology) do not contribute: a corpus-wide move is not one CVE moving.",
    },

    // --------------------------------- roster.html · 1 · hero
    roster_size: {
      num: "01",
      kicker: "Roster over time",
      source: "CVE.org organization roster · CyberMon nightly snapshots",
      headline: "The CVE Program roster has grown since tracking began in July 2026.",
      caption:
        "The CVE Program lists every organization on its roster, the assigning CNAs " +
        "plus the roots, ADPs and secretariat, but publishes no accreditation dates: " +
        "none for when an organization joined, left or changed scope. The roster " +
        "file is kept in a public git repository whose commits record each edit. " +
        "CyberMon reads the roster every night and keeps a dated log of the " +
        "differences. The line shows the number of organizations on the roster over " +
        "time, starting from the first tracked night.",
      yAxis: "organizations",
      statLabel: "Organizations on the roster",
      statSince: "tracked since {first_date}",
      statNet: "net {net} since {first_date}",
      // {first_date} is filled from the data (the record's first snapshot
      // date); the empty variant renders while there is only one snapshot.
      note:
        "The roster file carries no accreditation dates. CyberMon has taken a " +
        "nightly snapshot since {first_date}, and the line gains one point per " +
        "snapshot.",
      noteEmpty:
        "The roster file carries no accreditation dates. CyberMon's record starts " +
        "with tonight's snapshot; the line begins to move once there are two nights " +
        "to compare.",
      emptyChart:
        "No snapshots on the record yet; the size series begins tonight.",
      methodology:
        "Each night the pipeline fetches the CVE Program's published organization " +
        "roster, the same CNAsList.json that feeds the List of Partners on cve.org, " +
        "and reduces it to one fingerprint per organization, keyed by the shortName " +
        "the organization uses on CVE records. The count of organizations is " +
        "appended to a size history stored in the repository " +
        "(data/history/cna_roster_state.json), and the line is drawn from it. The " +
        "record starts at first deploy. The program publishes no accreditation " +
        "dates, and the roster file's git history (CVEProject/cve-website) could in " +
        "principle be replayed for earlier snapshots, but this log has not imported " +
        "it, so the series begins with CyberMon's first snapshot. A fetch that " +
        "returns less than half of the previous roster is treated as broken and " +
        "refused, not charted. Roster data is CVE Program data, the same source " +
        "family as the CVE List this site already uses; the program's terms permit " +
        "reuse of the published data.",
    },

    // --------------------------------- roster.html · 2
    roster_flux: {
      num: "02",
      kicker: "Onboardings & departures",
      source: "CVE.org organization roster · CyberMon nightly snapshots",
      headline: "Since July 2026, more organizations have joined the CVE roster than left it.",
      caption:
        "Organizations added to and removed from the roster each month, with scope " +
        "changes and renames shown as separate bars. The program publishes no " +
        "accreditation dates, so an onboarding here is the night an organization " +
        "first appeared in CyberMon's snapshots, which start at first deploy; it is " +
        "not the date the organization was accredited. Bars above the line are " +
        "organizations that appeared, bars below are organizations that left. Scope " +
        "changes and renames are counted separately from both, and a shortName that " +
        "changes while the organization stays is counted as one rename.",
      statOnboarded: "organizations joined · {departed} left the roster",
      legendOnboarded: "Joined (first observed)",
      legendDeparted: "Departed",
      legendScope: "Scope changed",
      legendRenamed: "Renamed (same organization, new shortName)",
      note:
        "{events} roster changes recorded since {first_date}.",
      noteEmpty:
        "No roster changes recorded yet. A change is logged when a snapshot differs " +
        "from the previous night's.",
      emptyChart:
        "No roster changes on the record yet; the first onboarding or departure " +
        "fills the first bar.",
      methodology:
        "Tonight's roster is compared with the previous snapshot, keyed by " +
        "shortName. An organization present tonight but not in the previous snapshot " +
        "is an onboarding; one present before but missing now is a departure; one " +
        "present in both with a changed scope statement is a scope change. Scope " +
        "text is compared by a short stable hash, so the log records that the scope " +
        "changed without storing the text. A departed and an onboarded shortName are " +
        "logged as one rename when they share a cnaID that is unique on both nights " +
        "and also agree on name, on scope, or on country and type. A cnaID that the " +
        "roster gives to several organizations identifies none of them and is never " +
        "used to pair. Snapshots stored before 20 September 2026 carry no cnaID, so " +
        "the diff could not recognise a rename before then. The one such pair on the " +
        "record, August's TQtC → Qt (The Qt Company renamed Qt Group under the same, " +
        "unique cnaID CNA-2025-0016 in the roster file's history), was reconciled by " +
        "hand into one rename plus its scope change. Events are appended to a log in " +
        "the repository (data/history/cna_roster.csv); apart from that " +
        "reconciliation, rows are only ever added. Like the NVD backlog history, it " +
        "is a dataset this project accumulates: the roster file's git history holds " +
        "the raw edits, and this log holds the events. Bars group by calendar month " +
        "of the observation date, with empty months shown at zero. Because no " +
        "accreditation dates are published, the log dates each organization to the " +
        "night CyberMon first saw it, and the first run logged nothing because there " +
        "was no earlier snapshot to compare.",
    },

    // --------------------------------- roster.html · 3
    roster_mix: {
      num: "03",
      kicker: "Today's composition",
      source: "CVE.org organization roster · CyberMon nightly snapshots",
      headline: "Most organizations on the CVE roster are vendors.",
      caption:
        "Every organization on tonight's roster, counted by the organization types " +
        "it lists: vendor, open source, researcher, hosted service, CERT, bug bounty " +
        "provider and others. Most are vendors. An organization can list more than " +
        "one type, so the bars sum to more than the roster total. The total counts " +
        "every organization listed, including the roots, ADPs and secretariat, so " +
        "the count of organizations with an assigning role beside it is smaller. " +
        "Two top-level roots, MITRE and CISA, oversee the rest.",
      statTemplate:
        "{total} organizations listed, {assigning} with an assigning role · " +
        "{countries} countries · top-level roots MITRE {mitre} / CISA {cisa}",
      xAxis: "organizations",
      nodata: "Not enough data yet.",
      methodology:
        "The composition is read from tonight's roster fetch, so unlike the two " +
        "charts above it is complete from the first night. Each organization's " +
        "CNA.type list is tallied: an organization that lists several types (a " +
        "vendor that also maintains open-source projects) counts once in each, so " +
        "the bars sum to more than the roster headcount. The data file also splits " +
        "the roster by program role (CNA, CNA-LR, Root, Top-Level Root, ADP, " +
        "Secretariat; also counted once per role held), with the number of " +
        "organizations holding an assigning role, CNA or CNA-LR, reported beside " +
        "the headcount. It also splits the roster by top-level root (MITRE or " +
        "CISA), by reporting root and by country; each of these is a partition that " +
        "sums to the total. This chart shows tonight's roster only; the size and " +
        "change charts above show how it moves over time.",
    },

    // --------------------------------- exploits.html · 1 · hero
    poc_gap: {
      num: "01",
      kicker: "Days to first public exploit",
      source: "Exploit-DB (OffSec) · cvelistV5 (MITRE)",
      headline: "Since 2021, the first public exploit has typically come weeks after the CVE record.",
      caption:
        "For every CVE with dated public exploit code: the days from the CVE record's " +
        "publication to the first public exploit, as a median and interquartile range " +
        "per publication year. In the program's first years the median was deeply " +
        "negative: early CVE records catalogued exploits that already existed. " +
        "From the mid-2000s through 2020 the median sat within a month of zero, and in " +
        "most of those years it was negative: among CVEs that got public exploit code, " +
        "the code usually existed by the time the record was published. Values below " +
        "zero are exploits published with the advisory, or years before a CVE ID was " +
        "assigned. Since 2021 the median has been positive, weeks after publication, on " +
        "cohorts a fraction of their earlier size. Those cohorts hold one to three " +
        "hundred CVEs each, and the youngest are still being indexed by the archive, so " +
        "the AI and Exploit Timing page marks them provisional. The 2024 cohort, with a median of " +
        "months, is a single outlier year, not a trend.",
      statLabel: "Median days from CVE publication to first public exploit code",
      statLatest: "{latest_year}",
      statAgo: "{ago_year}",
      note:
        "{dated} CVEs carry a dated public exploit in Exploit-DB; " +
        "{matched} matched a CVE record in the corpus and are charted, and {unmatched} " +
        "matched no record.",
      methodology:
        "Only Exploit-DB dates the exploit itself, so only Exploit-DB dates this chart: " +
        "its date_published field records when the exploit was published (which can be " +
        "earlier than its addition to the archive), and the earliest entry per CVE is " +
        "used. Metasploit's module metadata carries a disclosure_date, which is the " +
        "module author's record of when the vulnerability was disclosed, not when the " +
        "module shipped; the merge date would need the repository's git history, which " +
        "this pipeline does not clone. A Metasploit exploit module therefore counts as " +
        "public exploit code for its CVE but never dates it, and a CVE with only a " +
        "Metasploit module is absent from this chart. Until 2026-09-20 the Metasploit " +
        "disclosure date stood in for a code date here; it no longer does, and the " +
        "series was rebuilt. Nuclei templates are detection checks, not exploits, and " +
        "carry no date: they count only toward a separate detection line in the " +
        "coverage chart below. The gap is the Exploit-DB date minus the CVE record's " +
        "datePublished, in days, grouped by the CVE's publication year; a year plots " +
        "only with at least 10 matched CVEs. Negative gaps are kept, as on the KEV " +
        "Latency page: exploit code published before the CVE record (an advisory " +
        "shipped with its exploit, or an old exploit assigned a CVE years later) is a " +
        "real event, and flooring it at zero would hide the cases where the code came " +
        "first. Placeholder dates are treated as absent. The current year (marked *) " +
        "is partial. Limits: this counts public exploit code that one archive dates, a " +
        "lower bound that misses private exploits and code published elsewhere. The " +
        "cohort is self-selected: only a few percent of records ever get a tracked " +
        "public exploit, so the chart describes the CVEs that attracted one, and recent " +
        "years are also right-censored (a young CVE has had less time to attract code). " +
        "The source has also shrunk: the dated cohort per year is now well under a " +
        "fifth of its late-2000s size, so a trend here is also a trend in what " +
        "Exploit-DB indexes.",
    },

    // --------------------------------- exploits.html · 2
    poc_preempt: {
      num: "02",
      kicker: "Exploit code before KEV listing",
      source: "CISA KEV · Exploit-DB (OffSec)",
      headline: "Since 2023, public code preceded just over half of KEV listings with a dated exploit.",
      caption:
        "CISA's Known Exploited Vulnerabilities (KEV) catalog lists vulnerabilities " +
        "the U.S. government has confirmed are exploited in the wild. For KEV entries " +
        "whose CVE has a dated public exploit, each bar is the share whose exploit code " +
        "was public before the day CISA listed the entry. The 2021–22 seeding years are " +
        "drawn muted: the catalog's launch imported years-old CVEs, and their exploit " +
        "code, where dated, almost always came first. From 2023 on, just over half of " +
        "the listings with a dated PoC had the code published before the listing day.",
      note:
        "Since {cutoff_year}: for {trend_pct} of the {trend_n} KEV listings with a " +
        "dated public PoC, the code was published before the listing day.",
      methodology:
        "Each KEV entry is joined to the first public exploit date used in the chart " +
        "above (Exploit-DB's date_published; Metasploit dates the disclosure, not the " +
        "module, and Nuclei is undated, so neither is used here). An entry counts as " +
        "preempted when that date is strictly earlier than the catalog's dateAdded; a " +
        "PoC published on the listing day does not count. The denominator is entries " +
        "with a dated PoC, roughly a quarter of the catalog. An entry with no tracked " +
        "public exploit gives no information on which came first, so it is excluded. " +
        "The 2021–22 seeding era (entries added before 2023-01-01, the same cutoff the " +
        "KEV Latency module uses) is kept out of the headline figure because the launch " +
        "backfill imported years-old CVEs whose exploits are as old as the CVEs; those " +
        "years are drawn muted. A year plots only with at least 10 matched entries. The " +
        "KEV data is the same feed the rest of the site uses. The exploit side has the " +
        "limits of the chart above: tracked public code only, so the share is a lower " +
        "bound on how often exploit code was public before the listing.",
    },

    // --------------------------------- exploits.html · 3
    poc_coverage: {
      num: "03",
      kicker: "Exploit code by severity",
      source: "Exploit-DB (OffSec) · Metasploit (Rapid7) · Nuclei templates (ProjectDiscovery) · cvelistV5 (MITRE)",
      headline: "Public exploit code is most common on CVEs rated critical.",
      caption:
        "For CVE records published in the latest complete year, the share in each " +
        "CVSS severity bucket that has tracked public exploit code: an Exploit-DB entry " +
        "or a Metasploit exploit module. Nuclei detection templates appear in the " +
        "tooltip as a separate count, since a detection check is not an exploit. " +
        "Coverage is low in every bucket: the overwhelming majority of records have no " +
        "tracked public exploit code. It rises with severity, and critical-rated records " +
        "have public exploit code at more than ten times the rate of medium-rated " +
        "records. Score vs. Reality, on the CVE Ecosystem page, sets the same severity " +
        "buckets against EPSS forecasts of exploitation; this chart counts exploit code " +
        "already published.",
      note:
        "Records published in {window_year}, the latest complete year. A young record " +
        "has had limited time to attract code and coverage can only grow, so each bar " +
        "is a lower bound.",
      methodology:
        "For the latest complete calendar year, every published CVE record is bucketed " +
        "by the same effective score the Score-vs-Reality grid uses (the newest-version " +
        "base score anywhere in the record; records without one count as unscored). A " +
        "record is marked covered when tracked public exploit code references its id: " +
        "an Exploit-DB entry, with or without a usable date, or a Metasploit module " +
        "whose type is exploit. Auxiliary scanners and post modules reference CVEs " +
        "without being exploits for them and do not count. Nuclei CVE templates are " +
        "detection checks; they are counted separately, shown in the tooltip, and not " +
        "included in the bar. Severity buckets with fewer than 10 records are withheld. " +
        "Coverage is a share of that year's published records, so the chart reflects " +
        "the corpus's own composition; records without a base score rarely have " +
        "tracked exploit code either. The window is one complete recent year, stated " +
        "on the chart, chosen to show the current rate instead of decades of " +
        "accumulation; the cost is the right-censoring described in the note above.",
    },

    // --------------------------------- c2.html · 1 (hero)
    c2_weather: {
      num: "01",
      kicker: "C2 servers over time",
      source: "abuse.ch Feodo Tracker · CyberMon nightly snapshots",
      headline: "CyberMon counts the servers on Feodo Tracker's botnet C2 blocklist every night.",
      caption:
        "Each night CyberMon counts the botnet command-and-control (C2) servers " +
        "on abuse.ch's Feodo Tracker blocklist and stores the counts; the " +
        "tracker publishes only the current list. The tracker's FAQ attributes " +
        "its empty datasets to law-enforcement takedowns, naming Emotet in 2021 " +
        "and Operation Endgame in 2024, so a count in the single digits can " +
        "follow a takedown. It can also mean the tracker has stopped updating: " +
        "a snapshot records what the feed says, not whether the feed is current, " +
        "and the two look the same on this chart. Servers the tracker newly " +
        "lists appear here as a rise in the count.",
      yAxis: "C2 servers",
      statLabel: "C2 servers the tracker marks online",
      statWhen: "of {listed} listed · snapshots since {first_date}",
      noReading: "no reading: the nightly run missed this date",
      legendListed: "All listed",
      // {first_date} fills from the record's actual start; the empty
      // variant renders while there is only one snapshot on file.
      note:
        "Feodo Tracker publishes only the current list; CyberMon has recorded " +
        "it nightly since {first_date}.",
      // Renders instead of `note` once the last {nights} snapshots are
      // identical (at least a week of them): the counts alone cannot say
      // whether the servers are unchanged or the feed has stalled.
      noteFlat:
        "Feodo Tracker publishes only the current list; CyberMon has recorded " +
        "it nightly since {first_date}. The last {nights} snapshots, since " +
        "{since}, all show the same counts: {listed} listed, {online} online. " +
        "Identical counts can mean no change in the servers or a tracker that " +
        "has stopped updating; the counts cannot tell which.",
      noteEmpty:
        "Feodo Tracker publishes only the current list; CyberMon's record " +
        "starts with tonight's snapshot and adds one each night.",
      methodology:
        "Each night the pipeline fetches Feodo Tracker's public botnet C2 " +
        "blocklist (ipblocklist.json) and reduces it to per-family counts: " +
        "listed (on tonight's blocklist) and online (the tracker's status for a " +
        "server that answered like a botnet C2 on its last probe). The pipeline " +
        "does not read the tracker's last-online dates, so an online status can " +
        "be old. The counts are appended to a committed history file " +
        "(data/history/botnet_c2.csv), a dataset this project accumulates, like " +
        "the NVD backlog record, because the tracker publishes only the current " +
        "list. The chart stacks the online count by malware family; the dashed " +
        "line is the total listed. The pipeline has no minimum-count check: a " +
        "drop to zero, as after a takedown, is recorded as data, while a " +
        "malformed or unreachable feed stops the run and records nothing. " +
        "abuse.ch publishes Feodo Tracker data under CC0. The record starts at " +
        "the module's first deploy.",
    },

    // --------------------------------- c2.html · 2
    c2_today: {
      num: "02",
      kicker: "Tonight's blocklist",
      source: "abuse.ch Feodo Tracker · CyberMon nightly snapshots",
      headline: "Tonight's blocklist holds a handful of C2 servers.",
      caption:
        "Every server on tonight's blocklist, counted by malware family. The " +
        "accent segment is the servers the tracker marks online (they answered " +
        "as a C2 on the tracker's last probe); the rest are listed but offline. " +
        "Below, the same servers counted by hosting country and by network. The " +
        "module publishes counts only, never the blocklist itself, so no address " +
        "appears here; the raw list is available from the tracker's feed.",
      statTemplate: "{listed} C2s listed · {online} online · {families} malware families",
      legendOnline: "Online (answered as C2)",
      legendDark: "Listed, offline",
      countriesLabel: "By hosting country",
      asnsLabel: "By network (AS name)",
      xAxis: "C2 servers",
      nodata:
        "The blocklist is empty tonight, as the tracker reports it.",
      methodology:
        "The composition comes from tonight's snapshot alone, so it was complete " +
        "from the first night. Each listed server counts once toward its malware " +
        "family, its hosting country and its network (tallied by autonomous-system " +
        "number and labelled with the AS name the tracker publishes). Online means " +
        "the server responded like a botnet C2 on the tracker's last probe; the " +
        "tracker states that it adds an address only after it returns a valid C2 " +
        "response. Countries and networks are shown as text counts. Per-server " +
        "details (addresses, ports, hostnames) stay in the pipeline, and the output " +
        "contract rejects them.",
    },

    // --------------------------------- c2.html · 3
    c2_age: {
      num: "03",
      kicker: "Age on the tracker",
      source: "abuse.ch Feodo Tracker · CyberMon nightly snapshots",
      headline: "Each listed C2 server is aged from the day Feodo Tracker first saw it.",
      caption:
        "For every server on tonight's blocklist, the days since Feodo Tracker " +
        "first saw it. This is its age on the tracker; it does not show that the " +
        "server was listed throughout or that it still responds. The youngest " +
        "buckets hold servers first seen recently; the oldest hold servers first " +
        "seen long ago that are still listed. The median changes when entries are " +
        "added or removed; while the list is unchanged it rises by one day each " +
        "night. Tonight's value is shown above the chart.",
      statLabel: "Median age of tonight's listed C2s",
      statValue: "{median} days",
      statWhen: "oldest {oldest} days",
      yAxis: "C2 servers",
      nodata: "The blocklist is empty tonight, so there are no ages to show.",
      methodology:
        "Age is the number of whole days between a server's first_seen " +
        "stamp on Feodo Tracker and tonight's snapshot date, grouped into fixed " +
        "buckets from under 30 days to over 2 years. The median and the oldest " +
        "are computed over every listed server, online or offline, since an " +
        "offline server that remains listed is still on the tracker's record. " +
        "Like the composition chart, this uses tonight's snapshot only and needs " +
        "no accumulated history.",
    },

    // --------------------------------- ai.html · 1 · hero
    ai_clock: {
      num: "01",
      kicker: "Exploit clock and AI timeline",
      source: "Exploit-DB (OffSec) · cvelistV5 (MITRE) · CyberMon AI timeline",
      headline: "The median time from CVE to public exploit code has not shortened since ChatGPT.",
      seeAlso: {
        text: "Which CVE records credit AI labs and vendors:",
        href: "credits.html",
        label: "AI Credits →",
      },
      caption:
        "The red line is the exploitation clock from the Time to PoC module: for " +
        "each CVE whose first public exploit code Exploit-DB dates, the median " +
        "number of days from the CVE record's publication to that exploit, by " +
        "publication year. The dots along the top are the AI timeline: model " +
        "releases, threat-intelligence reports that looked for offensive uplift, " +
        "defensive milestones and the first documented cases of AI used in real " +
        "operations. Every dot is dated, categorised and linked below the chart. " +
        "The shaded band starts at the AI-era date chosen in the menu. The raw " +
        "median made most of its move toward zero by 2013, a decade before the " +
        "ChatGPT band opens, and inside the band it moves later if it moves at " +
        "all. The pale line counts only exploits dated within 90 days either side " +
        "of publication, and only cohorts at least 90 days old, so every year is " +
        "measured over the same window and the current year can be included. " +
        "Every settled year since 2005 has sat inside a three-week band around " +
        "zero. Up on the vertical axis means the exploit arrived later, so the " +
        "rise into the current year is a longer wait. Years the exploit trackers " +
        "are still indexing are drawn hollow: they lack exploits that will be " +
        "indexed later, so they read slow, and no verdict on this page uses them. " +
        "Where the two lines differ, the raw line includes exploits outside the " +
        "pale line's 90-day window: on the left, old exploits that received CVE " +
        "ids years later; on the right, exploit code published months after the " +
        "CVE. Neither difference shows faster exploitation. Right of the marked " +
        "edge there is no complete year of data. The 2026 milestones, which " +
        "include models and programmes aimed at finding vulnerabilities, sit " +
        "beyond what this page can test.",
      selectLabel: "AI era begins",
      evidenceEdge: "last complete year: {year}",
      rawLabel: "As recorded (all gaps)",
      lflLabel: "Like-for-like (±90d window)",
      axisSlower: "↑ exploit\n  arrives\n  later",
      axisFaster: "↓ exploit\n  arrives\n  sooner",
      provisionalFrom: "provisional →",
      statLabel: "Speed metrics that accelerated in the AI era",
      statOf: "of {judged} judged metric-era tests",
      statUplift: "vendor threat reports that looked for offensive uplift and reported none",
      bandLabel: "AI era · from {label}",
      tipMonth: "{date} · month precision",
      railTitle: "AI timeline with dates and sources",
      railSourceLabel: "source",
      note:
        "The clock covers {first_year}–{last_year}: {n} matched CVEs over the " +
        "complete years, shown against {milestones} dated AI milestones.",
      methodology:
        "The clock series is copied from the Time to PoC module " +
        "(time_to_poc.json) without recomputation: the same median, matched " +
        "cohort and caveats, so the two pages agree. The current year is left " +
        "out of this series instead of being marked partial, because this " +
        "module tests where a series changes direction and a half-finished year " +
        "at the right-hand edge can look like such a change. The AI timeline is " +
        "a small hand-maintained table (pipeline/ai_timeline_data.py). Each row " +
        "has a source URL and a date precision; rows without a single " +
        "unambiguous date are marked month-precision and plotted at mid-month, " +
        "and the tooltip says so. Rows are categorised as capability releases, " +
        "no-uplift findings, offensive-use reports, defensive milestones and lab " +
        "research. An event gets a row if it is security-relevant, which " +
        "includes improvements in finding vulnerabilities as well as in " +
        "exploiting them; a frontier model release with no security claim " +
        "attached does not qualify. The no-uplift rows are central: two of " +
        "the largest vendor threat-intelligence teams looked specifically for " +
        "offensive capability uplift in 2024 and early 2025 and reported finding " +
        "none, so a 2018–2023 trend cannot be attributed to a 2025 capability. " +
        "The vertical axis is logarithmic in both directions and linear within a " +
        "month of zero, because the series runs from about -770 days to a few " +
        "months. On a linear axis the 1999 cohort would set the scale, and " +
        "everything from 2004 on would be squeezed into a fifth of the chart's " +
        "height, most of it a flat line. The transform changes no number, and " +
        "the tooltips give the real values in days. Widely cited vendor figures " +
        "that point the other way, Mandiant's 63-to-5-day time-to-exploit series " +
        "and the DBIR's edge-device share, are not plotted: they come from " +
        "private incident corpora and cannot be reproduced from this pipeline. " +
        "They are recorded with attribution in the repository " +
        "(pipeline/ai_timeline_data.EXTERNAL_CONTEXT) and are never drawn on an " +
        "axis here. The module inherits three limits from the clock and does not " +
        "fix them. First, the clock measures public exploit code dated by one " +
        "archive over a self-selected cohort, so it is a lower bound, not a " +
        "census. Second, recent years are right-censored: a CVE enters the cohort " +
        "only once it has a public exploit, so a 2024 record whose exploit " +
        "appears in 2027 is missing, and recent cohorts lose their slowest " +
        "cases. That bias makes recent years look faster, which favours this " +
        "page's conclusion: censoring would produce an apparent acceleration, " +
        "and none appears. Third, collection has thinned: the dated cohort per " +
        "year is well under a fifth of its late-2000s size, so a slowing verdict " +
        "is also consistent with the trackers indexing less.",
    },

    // --------------------------------- ai.html · 2
    ai_banked: {
      num: "02",
      kicker: "Inflection test",
      source: "Exploit-DB (OffSec) · cvelistV5 (MITRE)",
      headline: "No judged speed metric moved toward faster exploitation after the cutoff.",
      caption:
        "This chart puts the comparison in chart 01 into numbers. The top bar is " +
        "the like-for-like clock, the one measure here that is not biased by " +
        "recent cohorts having had less time to attract exploit code, and it " +
        "comes first because it is the strongest evidence. The three bars below " +
        "it read the full matched cohort in three ways. For each metric the test " +
        "takes three levels: the start of the record, the five years before the " +
        "cutoff, and the settled years since. It then asks what share of the " +
        "metric's total movement the AI era accounts for, and in which " +
        "direction. Bars to the right mean the era moved that metric toward " +
        "faster exploitation; only those would support the claim that AI sped " +
        "exploitation up, and they are drawn in the accent colour. Bars to the " +
        "left mean it moved toward slower exploitation. Changing the cutoff at " +
        "the top of the page redraws the bars.",
      axisLabel: "share of the metric's total movement, since the cutoff (→ faster)",
      primaryTag: "strongest evidence: fixed 90-day window",
      tableCaption: "Levels behind each bar, {era} cutoff ({date}):",
      tipEarly: "start of record:",
      tipPre: "5 years to {cut_year}:",
      tipPost: "since the cutoff:",
      tipBanked: "movement before the cutoff: {pct}% of the total",
      tipInsufficient:
        "Withheld: only {years} complete, settled year(s) after the cutoff year; the test needs two.",
      rowLevels: "{early} → {pre} → {post}   ({share})",
      rowInsufficient: "withheld: {years} complete, settled year(s) after the cutoff year",
      verdicts: {
        accelerated: "accelerated",
        decelerated: "slowed",
        no_inflection: "no inflection",
        insufficient: "withheld",
      },
      allWithheld: "Withheld: {years} complete, settled year(s) from {post_start_year} on.",
      note:
        "{accelerated} of {judged} judged metrics accelerated in the AI era" +
        "{withheld}. The start and pre-cutoff levels are {window}-year means; " +
        "the post level averages every settled year since the cutoff. A shift " +
        "under {threshold}% of a metric's total movement counts as no " +
        "inflection.",
      // {withheld} in `note`: filled only when some metrics are withheld.
      noteWithheldClause: " ({total} tested; the others are withheld for lack of settled years)",
      noteWithheld:
        "All {total} metrics are withheld at this cutoff: the record has fewer " +
        "than two complete, settled years from {post_start_year} on (the year " +
        "containing the cutoff counts for neither side, and a year the trackers " +
        "are still indexing does not count). The test runs once two such years " +
        "exist.",
      methodology:
        "There are four metrics, and the first differs from the other three. The " +
        "like-for-like clock counts only exploits dated within 90 days either " +
        "side of publication, and only cohorts at least 90 days old, so every " +
        "year, including the current partial one, has had the same window in " +
        "which exploit code could appear. The lower bound of the window matters " +
        "as much as the upper one: a gap of -4,452 days is an old exploit " +
        "receiving a CVE id, a cataloguing event and not a fast exploit, and " +
        "such gaps pull a one-sided median arbitrarily far negative. The clock " +
        "is not a rate over all published CVEs. That rate falls from about 45% " +
        "to under 1% across the record, almost entirely because annual CVE " +
        "volume grew from roughly 5,700 to 40,000, which is a change in coverage " +
        "that the coverage chart shows. One bias remains: the exploit trackers " +
        "add entries for older disclosures over time, so the newest cohort is " +
        "still missing exploits that will be added later and reads slightly " +
        "slow. A cohort still being indexed is therefore drawn hollow and never " +
        "counts toward a verdict. The other three metrics are read from the same " +
        "matched cohort and share one denominator: the median gap in days from " +
        "publication to first public exploit, the share of the cohort whose " +
        "public code arrived no later than a week after publication, and the " +
        "share whose exploit code predates the CVE record. The second metric's " +
        "underlying field is “gap at most 7 days”, which includes every negative " +
        "gap, so a PoC published a year before its CVE counts. That is why the " +
        "early years read above 95%: the catalogue was recording exploits that " +
        "already existed. These three are not independent tests. They are three " +
        "summary statistics of one distribution over one cohort, and the third " +
        "is a strict subset of the second (every negative gap is also under " +
        "seven days). A median can stay put while a tail moves, so three views " +
        "are useful, but counting them as separate evidence counts the same data " +
        "three times. The same applies to the ChatGPT and GPT-4 cutoffs, which " +
        "share most of their years. KEV latency is left out: its series is " +
        "quarantined to begin in 2023, which leaves two of the three cutoffs " +
        "with no pre-cutoff years to compare against, and a metric whose history " +
        "starts inside the era under test cannot test that era. Each metric gets " +
        "three levels, means of complete years instead of single-year " +
        "endpoints: the first five years of the record, the five years ending " +
        "at the cutoff, and every settled year since. Single years are not used " +
        "because the 1999 cohort is about a hundred CVEs at a median two years " +
        "negative, and a ratio anchored on it would depend on one small, unusual " +
        "year. A cutoff's pre window ends with the last year that ends before " +
        "its date, and its post window starts with the first year that begins " +
        "after it, so the year containing the cutoff (2022 for ChatGPT) is " +
        "charted but counts for neither side. A shift smaller than 10% of the " +
        "metric's total travelled distance is reported as no inflection, and an " +
        "era with fewer than 2 complete, settled years behind it (years the " +
        "trackers are still indexing do not count) is not judged; its verdict " +
        "appears once the record has those years. The direction sign is " +
        "computed in the pipeline, not in the chart code: a falling gap and a " +
        "rising within-a-week share both mean faster, and keeping that rule in " +
        "one place avoids sign errors in the charts.",
    },

    // --------------------------------- ai.html · 3
    ai_attention: {
      num: "03",
      kicker: "Attention and the clock",
      source: "GDELT 2.0 · Hacker News (Algolia) · arXiv cs.CR · Wikipedia pageviews · SEC EDGAR · Exploit-DB",
      headline: "Attention to AI security multiplied while the exploit clock stayed within a narrow band.",
      caption:
        "The solid lines show attention to AI security: the five attention lanes " +
        "of the Buzzword Attention module, averaged per term, with each lane " +
        "indexed to its own peak. The dashed line is the like-for-like exploit " +
        "clock (the pale line in chart 01, settled years only) over the same " +
        "window, held flat across each year because it is measured annually. " +
        "Over the window attention multiplied, while the clock's annual median " +
        "stayed inside a band of days. Had the time to exploitation shortened " +
        "as attention rose, the dashed line would fall; it does not.",
      clockLabel: "Exploitation clock (median gap)",
      axisAttention: "attention index",
      axisClock: "median gap",
      unavailable:
        "The attention lanes are missing from this edition because the Security " +
        "Market data did not load. The two sections above are unaffected.",
      note:
        "{label} ran from an index of {index_first} in {month_first} to " +
        "{index_last} in {month_last}. Over the same window the clock's annual " +
        "median stayed between {clock_min}d and {clock_max}d ({year_first}–{year_last}).",
      methodology:
        "The attention lanes come from the Buzzword Attention module " +
        "(market_hype.json): the curated terms “AI Security” and “Agentic AI”, " +
        "selected from that module's reviewable watchlist. Each term's monthly " +
        "value is the mean of its per-source indexes over the sources that have " +
        "a value that month. The Buzzword Attention module already indexes each " +
        "lane to its own peak, so this is a mean of comparable 0-100 series, and " +
        "a term whose Wikipedia lane starts late is not penalised for the gap. " +
        "The number of sources behind each point is in the payload. The clock is " +
        "chart 01's like-for-like series (exploits within 90 days either side of " +
        "publication, settled cohorts only, so a year still being indexed cannot " +
        "move it), drawn as a step: interpolating an annual median across twelve " +
        "months would draw monthly values that were never measured. The two " +
        "series share no unit and no sampling rate, so they have separate axes, " +
        "and the chart claims no correlation between them. The clock's axis " +
        "always spans at least plus or minus 90 days instead of being fitted to " +
        "the data. Over this window the clock varies by a few days, and an axis " +
        "fitted to that range would stretch it to the full chart height and make " +
        "it look like a large change. Ninety days, about a quarter, is an " +
        "editorial choice, and the axis widens if the data ever exceeds it. The " +
        "window is the market module's 60 months, so it starts roughly a year " +
        "before ChatGPT: enough months before the release to show a step change, " +
        "too few for the long-run comparison, which charts 01 and 02 make.",
    },

    // --------------------------------- credits.html · 1 · hero
    // House rule for this page's copy (2026-09-20, after an external review):
    // the data is about ATTRIBUTION. Write "credited", never "found"; state
    // what was measured, not why it happened; a number about this registry's
    // matches is not a number about the world. No metaphors.
    credits_funnel: {
      num: "01",
      kicker: "Announced and credited",
      source: "CVE List V5 (MITRE) · CISA KEV · Exploit-DB · Metasploit · Nuclei · finders' own announcements",
      headline: "AI finders announce thousands of vulnerabilities, and CVE records credit each kind with hundreds.",
      seeAlso: {
        text: "Exploitation speed before and after the AI era:",
        href: "ai.html",
        label: "AI and Exploit Timing →",
      },
      caption:
        "Labs and vendors report their results in their own units: " +
        "vulnerabilities found, reports submitted, advisories published. This " +
        "page counts a narrower set: published CVE records whose credits name " +
        "the lab's model or the vendor. The two sets differ, and neither " +
        "verifies the other. An announced finding may still be undisclosed, may " +
        "be in private code that never receives a CVE, or may be published " +
        "without a credit. An LLM lab is counted only when a credit for finding " +
        "or reporting the bug names its model. A vendor is counted whenever such " +
        "a credit names it, which is weaker evidence: about four in ten vendor " +
        "credits name the company only through a person there or in a thank-you " +
        "line. The two columns are never added together. Each finder's announced " +
        "numbers are listed with their unit and source, and only an announced " +
        "CVE count is drawn as a bar beside the credited count. The measured " +
        "rows below them are rebuilt nightly.",
      kindLabels: { llm: "LLM labs", vendor: "AI-security vendors" },
      kindRules: {
        llm: "counted when a finding credit names the model",
        vendor:
          "counted when a finding credit names the vendor · {system_pct} of " +
          "these records credit the vendor or its tool as the finder",
      },
      statTemplate:
        "{llm} CVEs credit an LLM lab's model · {vendor} credit an AI-security " +
        "vendor · {kev} of them are on CISA KEV",
      claimsLabel: "What they announce",
      measuredLabel: "What the CVE record shows",
      claimCredited: "{n} CVEs credited here to date",
      claimLive: "running counter, read {date}",
      claimUnitNote: "different unit",
      compareAnnounced: "announced",
      compareCredited: "credited here",
      stageSeverity: "Severity",
      claimsNone: "No first-party number on file for this column's finders.",
      claimMoreTemplate: "+{n} more on the site",
      stageCredited: "Credited CVEs",
      stageSerious: "High or critical",
      stagePoc: "Exploit corpus",
      stageKev: "On CISA KEV",
      severityLabels: {
        critical: "Critical", high: "High", medium: "Medium", low: "Low",
        unscored: "Unscored",
      },
      baselineTemplate:
        "Baseline, every CVE carrying any credit since {from}: {serious_pct} " +
        "high or critical, {poc_pct} in an exploit corpus, {kev_pct} on KEV " +
        "({kev} of {credited}).",
      kevNote:
        "KEV lists exploitation that CISA has confirmed and catalogued. A CVE " +
        "that is not on it has not been shown to be unexploited, and these " +
        "cohorts are young (last row of chart 02). KEV-listed here: {cves}.",
      kevNoteNone:
        "KEV lists exploitation that CISA has confirmed and catalogued. A CVE " +
        "that is not on it has not been shown to be unexploited, and these " +
        "cohorts are young (last row of chart 02).",
      ledgerNote:
        "Every matched record, with its finder, evidence tier and credit role:",
      ledgerLinkText: "ai_credits_ledger.json",
      nodata: "Not enough data yet.",
      methodology:
        "A published CVE record can carry a credits field. Each credit is " +
        "matched against a hand-curated registry of AI finders in the pipeline " +
        "(ai_credits_data.py). The registry is narrow because a loose match " +
        "catches Capgemini, a researcher named Ai and every .ai domain, and it " +
        "matches only names it lists: the first version missed Google's " +
        "OSS-Fuzz-Gen. A match gets one of three tiers. “System” means the " +
        "credit names an AI system such as Claude, Codex or Big Sleep, or, for " +
        "some vendors, the vendor's own name standing alone as the finder. " +
        "“Org” means it names only the organisation, usually as a person's " +
        "employer. “Fix” means the name appears only under a credit role that " +
        "is not about finding the bug (remediation developer, reviewer or " +
        "verifier, coordinator, sponsor); fix matches are never counted. LLM " +
        "labs count at the system tier only; vendors count at system or org. A " +
        "match does not show how a bug was found; it records what the CVE " +
        "record says. Severity is the base score of the newest CVSS version in " +
        "the record, taken from the CNA where the CNA scored that version and " +
        "from CISA's enrichment otherwise. “In an exploit corpus” means " +
        "Exploit-DB, a Metasploit module or a Nuclei template references the " +
        "CVE. Nuclei templates are detection checks and only sometimes exploits, " +
        "and exploit code published anywhere else is not seen. Each measured " +
        "row is a share of the credited CVEs; the rows are not nested. Announced " +
        "figures are not measured here. Each is the finder's own published " +
        "figure, recorded with its wording, date and source, and it is drawn as " +
        "a hatched “announced” bar beside the credited count only when its unit " +
        "is CVEs assigned; an announcement in any other unit gets no bar. " +
        "“Credited here to date” is this page's all-time count for that finder. " +
        "The announcement has its own cut-off date and its own list of CVEs, so " +
        "the pair is not a verification rate. Credit text is never republished " +
        "because it carries personal names and addresses; the ledger linked " +
        "above holds CVE ids, tiers and roles. Disclosure: the registry and this " +
        "copy were drafted with Claude, an Anthropic model, and an outside " +
        "review corrected an error that had inflated Anthropic's count. The " +
        "registry, the counting rule and every quoted claim are in the " +
        "repository.",
    },

    // --------------------------------- credits.html · 2
    credits_profile: {
      num: "02",
      kicker: "Side by side",
      source: "CVE List V5 (MITRE) · EPSS (FIRST.org) · CISA KEV · Exploit-DB · Metasploit · Nuclei",
      headline: "Lab-credited CVEs have higher CVSS scores and similar EPSS, exploit and KEV figures.",
      caption:
        "Nine measurements for three populations: CVEs crediting an LLM lab's " +
        "model, CVEs crediting an AI-security vendor, and all CVEs that carry a " +
        "credit. The baseline is drawn into each bar as a tick. Lab-credited " +
        "records have a higher median CVSS score and a much larger share of " +
        "memory-safety weaknesses. On median EPSS percentile, listing in an " +
        "exploit corpus and KEV membership, each AI column is within a handful " +
        "of records of what the baseline rate would give a population its size. " +
        "The comparison is descriptive and is not adjusted for publication age, " +
        "target mix or crediting practice. The last row shows why age matters: " +
        "the lab-credited cohort is much younger than the baseline, and exploit " +
        "listings and KEV entries accumulate over time. The baseline is all " +
        "credited CVEs; it is not a human-only control group.",
      columns: {
        llm: "LLM labs",
        vendor: "AI-security vendors",
        baseline: "All credited CVEs",
      },
      nTemplate: "{n} CVEs",
      rows: {
        median_cvss: "Median CVSS score",
        serious: "High or critical",
        memory_pct: "Memory-safety weakness",
        top_cwe: "Most common weakness",
        median_epss_pctile: "Median EPSS percentile",
        poc_pct: "In an exploit corpus",
        kev_pct: "On CISA KEV",
        cna_scored_pct: "Scored by its own CNA",
        recent_pct: "Published in the last 90 days",
      },
      cweNames: {
        "CWE-20": "input validation",
        "CWE-22": "path traversal",
        "CWE-78": "command injection",
        "CWE-79": "cross-site scripting",
        "CWE-89": "SQL injection",
        "CWE-121": "stack overflow",
        "CWE-122": "heap overflow",
        "CWE-125": "out-of-bounds read",
        "CWE-352": "CSRF",
        "CWE-416": "use-after-free",
        "CWE-476": "NULL dereference",
        "CWE-787": "out-of-bounds write",
        "CWE-862": "missing authorization",
        "CWE-918": "SSRF",
      },
      tickNote:
        "The light tick in each bar is the baseline's value on that row. Rows " +
        "with small shares are scaled to their own largest value, so compare a " +
        "bar with its tick, not with the row above.",
      nodata: "Not enough data yet.",
      methodology:
        "All three columns cover the same calendar window, from the first month " +
        "either kind is credited to this edition, but not the same follow-up " +
        "time: a record published last month has had one month in which to be " +
        "listed anywhere. The baseline is every published CVE whose record " +
        "carries a credit, the AI-credited ones included; they are under two " +
        "percent of it, and it may contain AI-assisted work whose credits do not " +
        "say so. Median CVSS uses each record's newest base score. CVSS is " +
        "assigned by the CNA or by CISA, so a higher median describes recorded " +
        "severity. EPSS is FIRST's estimate of exploitation probability; the row " +
        "is the median of its published percentile, and all three medians are " +
        "well under 50. “In an exploit corpus” covers Exploit-DB, Metasploit and " +
        "Nuclei only. “Scored by its own CNA” is the share whose CVSS score came " +
        "from the assigning CNA and not from CISA's enrichment; it is low where " +
        "a CNA such as Mozilla's publishes no scores. The AI columns are small: " +
        "one CVE moves the labs' exploit-corpus row by about half a point. A " +
        "stronger comparison would measure outcomes a fixed number of days after " +
        "publication and match on product and CNA; this page does not do that.",
    },

    // --------------------------------- credits.html · 3
    credits_lanes: {
      num: "03",
      kicker: "Month by month",
      source: "CVE List V5 (MITRE)",
      headline: "The registry matches one credit before 2025.",
      caption:
        "CVEs whose finding credits name a registry entity, by publication " +
        "month. The earliest match is an OpenSSL CVE from October 2024 credited " +
        "to Google's OSS-Fuzz-Gen. That describes this registry: a credit naming " +
        "a system the registry does not list is not counted, and the first " +
        "version of this page missed that record and said there was none before " +
        "2025. Lab credits then arrive in single-month clusters with empty " +
        "months between them, and appear in every month from February 2026. " +
        "Vendor credits begin in March 2025. The toggle switches between the two " +
        "kinds, which are never stacked together. The last bar is a partial " +
        "month.",
      toggleLabels: ["LLM labs", "AI-security vendors"],
      laneLabels: {
        anthropic: "Anthropic (Claude)",
        openai: "OpenAI (Codex / GPT)",
        google: "Google (Big Sleep, OSS-Fuzz-Gen)",
        other_llm: "Other model makers",
        vendor: "AI-security vendors",
      },
      yAxis: "credited CVEs",
      nodata: "Not enough data yet.",
      methodology:
        "One bar per publication month, from the first month any finder of that " +
        "kind is matched through the current, partial month. Empty months are " +
        "kept. A CVE crediting two labs adds to both lanes, so a stacked bar " +
        "can be slightly taller than the month's distinct-CVE total, which the " +
        "tooltip reports. Months are publication dates, not discovery dates.",
    },

    // --------------------------------- credits.html · 4
    credits_board: {
      num: "04",
      kicker: "Who is credited",
      source: "CVE List V5 (MITRE) · CISA KEV",
      headline: "In each column one or two finders hold most of the credits, with very different severity mixes.",
      caption:
        "Every registry entity matched in at least one record, ranked by the " +
        "CVEs that count under its kind's rule. ZAST.AI's credits are almost " +
        "all medium-severity records published through one CNA. Anthropic's row " +
        "has the most criticals. “Names the AI” is how many of a row's records " +
        "name the system itself; for several vendors that is a minority or none, " +
        "because their credits name a person or only the company. “Not counted” " +
        "is what the rule leaves out: for a lab, records that name the " +
        "organisation but no model, and for any row, records that credit it " +
        "only for the fix. OpenAI is named on several times more records than " +
        "its models are, mostly as a person's employer or as a collaborator.",
      colFinder: "Finder",
      colCounted: "credited CVEs",
      colSeverity: "severity mix",
      colSerious: "high + critical",
      colSystem: "names the AI",
      colNotCounted: "not counted",
      colKev: "KEV",
      colSince: "first named",
      colCnas: "credited most by",
      kindShort: { llm: "lab", vendor: "vendor" },
      uncountedNamed: "{n} name the organisation only",
      uncountedFix: "{n} credit it for the fix only",
      nodata: "Not enough data yet.",
      methodology:
        "One row per registry finder that appears in at least one published " +
        "record. “Credited CVEs” applies the kind's counting rule; the severity " +
        "strip, the high-plus-critical share and the KEV column describe those " +
        "CVEs. “Names the AI” counts records at the system tier. “Not counted” " +
        "is the remainder; hover over a cell for its make-up. “Credited most by” " +
        "lists the CNAs whose records carry the credited CVEs (a finder with " +
        "none shows “—”). The CNA writes the credit line, so a vendor that is " +
        "its own CNA writes its own.",
    },

    // --------------------------------- credits.html · 5
    credits_weakness: {
      num: "05",
      kicker: "Weakness classes",
      source: "CVE List V5 (MITRE)",
      headline: "Memory safety leads the lab-credited CVEs, while injection leads the baseline.",
      caption:
        "Each CVE's first-listed weakness, grouped into six families. In the " +
        "baseline, injection (cross-site scripting, SQL injection, command " +
        "injection) is the largest family, at more than a third. Among " +
        "lab-credited CVEs memory safety is the largest, at several times the " +
        "baseline share; crypto and certificate weaknesses are also several " +
        "times the baseline share, and injection is small. The vendor-credited " +
        "population falls between the two on both memory safety and injection. " +
        "The record does not say what was examined. The lab-credited records " +
        "concentrate in a few projects (chart 06), and Anthropic has said its " +
        "early work searched for memory-corruption bugs because they are easier " +
        "to validate.",
      seriesLabels: {
        llm: "LLM labs",
        vendor: "AI-security vendors",
        baseline: "All credited CVEs",
      },
      xAxis: "share of that population's CVEs",
      nodata: "Not enough data yet.",
      methodology:
        "A record's first-listed CWE (the CNA's, else CISA's) is placed in one " +
        "of six families by exact id. The family lists are committed in the " +
        "pipeline (ai_credits_data.py) and are flat lists, not MITRE's view " +
        "hierarchy. Anything unlisted is “Other CWE”, and a record with no CWE " +
        "is its own row. Bars are shares of each population, because the " +
        "populations differ in size by two orders of magnitude; the tooltip " +
        "carries the counts. The Anthropic statement is from its February 2026 " +
        "post on LLM-discovered zero-days, which is also the source of one of " +
        "the claims in chart 01.",
    },

    // --------------------------------- credits.html · 6
    credits_targets: {
      num: "06",
      kicker: "Affected products",
      source: "CVE List V5 (MITRE)",
      headline: "Five products account for about half of the lab-credited CVEs.",
      caption:
        "The affected product each record lists first, ranked per kind. The " +
        "lab-credited records are concentrated: a browser, a Java crypto library " +
        "and an operating system lead the list. The record does not say how " +
        "those targets were chosen. The vendor-credited list is less " +
        "concentrated, with its top five holding about a quarter. Its first row " +
        "is Red Hat Enterprise Linux, which Red Hat, as CNA, lists first in its " +
        "records, including records for flaws in upstream packages.",
      shareTemplate:
        "top {top_n} hold {share} of the {named} CVEs naming a product · " +
        "{distinct} products in all",
      nodata: "Not enough data yet.",
      methodology:
        "The first entry of each record's affected list, vendor and product " +
        "joined, placeholders such as n/a dropped, a vendor the product name " +
        "already starts with removed, and spellings folded case-insensitively. " +
        "It is the CNA's description, not the finder's: a distribution CNA " +
        "lists its distribution even when the flaw is in an upstream library, " +
        "so one upstream bug can appear under several product names. Shares " +
        "are of the CVEs that name any product. The top five rows are drawn in " +
        "the kind's colour; ten are listed.",
    },

    // --------------------------------- credits.html · 7
    credits_coverage: {
      num: "07",
      kicker: "Credit coverage",
      source: "CVE List V5 (MITRE)",
      headline: "Fewer than half of published CVEs carry any credit.",
      caption:
        "The share of published CVEs whose record carries a credit of any kind. " +
        "It has risen from almost none in 2018 to more than four in ten. Because " +
        "coverage is incomplete, the counts on this page leave out AI-assisted " +
        "work that was published without a credit the registry recognises. The " +
        "percentages, medians and rankings can also be biased, in either direction, " +
        "if the uncredited records differ from the credited ones. Part of any " +
        "rise in AI credits can come from this general rise in crediting.",
      yAxis: "% of published CVEs with a credit",
      tooltipTemplate: "{with_credits} of {published} published CVEs carry a credit",
      nodata: "Not enough data yet.",
      methodology:
        "For each publication year, the published records with a non-empty " +
        "credits list over all published records. Rejected records and records " +
        "without a publication date are left out of both counts. The current " +
        "year is partial, but the figure is a share, so it is comparable as it " +
        "stands. Credits are written by the CNA, not the finder, and practice " +
        "differs: some CNAs credit every reporter, some credit no one, and a " +
        "few write their own product into the line.",
    },

    // --------------------------------- incidents.html · 1 (hero)
    // Every count on this page is filled from data/sec_incidents.json. Until
    // the first nightly EDGAR read lands, the edition is status "empty" and
    // each section shows `nodata` — no zeros are drawn for counts nobody made.
    incidents_clock: {
      num: "01",
      kicker: "Filings per month",
      source: "SEC EDGAR full-text search (Forms 8-K, 8-K/A)",
      headline: "Companies file one or two Item 1.05 incident disclosures in a typical month.",
      caption:
        "Since 18 December 2023 (15 June 2024 for smaller reporting " +
        "companies), a US public company that decides a cybersecurity " +
        "incident is material must disclose it on Form 8-K under Item 1.05 " +
        "within four business days of that decision. The bars count those " +
        "filings per month by the date the 8-K reached EDGAR. The date of " +
        "the incident appears only in a filing's text, and not every filing " +
        "gives one. " +
        "Amendments (8-K/A) are a separate series. The third series is " +
        "Item 8.01 filings that describe a cybersecurity incident: the " +
        "voluntary item that SEC staff guidance of May 2024 suggested for " +
        "incidents a company has not, or not yet, judged material.",
      statLabel: "Item 1.05 incident disclosures on EDGAR (original 8-Ks)",
      statWhen:
        "from {companies} companies since {start} · {amendments} amendments · " +
        "{voluntary} Item 8.01 incident filings · latest Item 1.05 filed {latest}",
      legendOriginals: "Item 1.05 · original 8-K",
      legendAmendments: "Item 1.05 · amendment (8-K/A)",
      legendVoluntary: "Item 8.01 · incident (voluntary)",
      toggleMonthly: "Monthly",
      toggleQuarterly: "Quarterly",
      guidanceMark: "SEC staff 8.01 guidance",
      partialTooltip: "partial period",
      yAxis: "Filings",
      note:
        "Hollow bars mark partial periods: December 2023, because the rule " +
        "took effect on 18 December 2023, and the current month.",
      nodata:
        "No edition yet. The nightly pipeline reads EDGAR's full-text " +
        "search; until its first read, nothing has been counted, so nothing " +
        "is drawn as zero.",
      // {q105}/{forms105}/... fill from the edition's own `definitions` —
      // the query IS the measurement, so the page prints the one it ran.
      methodology:
        "Two queries against SEC EDGAR full-text search (efts.sec.gov), " +
        "re-run every night over the window since 18 December 2023, one " +
        "calendar month at a time. Item 1.05: the phrase {q105} in form {forms105} filings. " +
        "EDGAR applies that form filter to the root form, so the results " +
        "include the 8-K/A amendments. The phrase only finds candidates, " +
        "since a filing can mention Item 1.05 without being filed under it. " +
        "A filing counts when EDGAR's own item list for it contains Item " +
        "{item105}; form 8-K is an original disclosure, 8-K/A an amendment. " +
        "Item 8.01: the phrase {q801} in form {forms801} originals. A filing " +
        "counts when its item list contains Item {item801} and not Item " +
        "1.05, and when the phrase appears in the 8-K itself. A match only " +
        "in an attached exhibit does not count, because risk language in " +
        "press releases would otherwise add routine announcements. " +
        "Full-text search returns one hit per document, so filings are " +
        "de-duplicated by accession number, and companies are counted once " +
        "per primary filer (CIK). Months are calendar months of the filing " +
        "date EDGAR records; the first month counts from the rule's " +
        "effective date. Where a response lacks a filing's item list, the " +
        "phrase match decides, and the edition records how many filings " +
        "rested on that fallback. If EDGAR cannot be read, the previous " +
        "edition is carried forward and marked as such in the footer.",
    },

    // --------------------------------- incidents.html · 2
    incidents_amend: {
      num: "02",
      kicker: "Amendments",
      source: "SEC EDGAR full-text search (Forms 8-K, 8-K/A)",
      headline: "About a third of Item 1.05 disclosures have been amended, most within 90 days.",
      caption:
        "Item 1.05 lets a company file before it knows an incident's full " +
        "scope or impact; it must then amend the 8-K once it does. Each " +
        "Item 1.05 amendment is matched to the same company's most recent " +
        "Item 1.05 original filed on or before it. The bars count the days " +
        "from each original to its first amendment.",
      statLabel: "Median days from an Item 1.05 filing to its first amendment",
      statValue: "{median} days",
      statWhen: "{amended} of {originals} disclosures amended so far · longest {max} days",
      unmatched:
        "Amendments left out of the lag because the filer has no Item 1.05 " +
        "original in the window: {unmatched}.",
      xAxis: "Days from original to first amendment",
      yAxis: "Disclosures",
      note:
        "Recent disclosures have had little time to be amended, so the " +
        "share amended and the median both understate what the record will " +
        "show later.",
      noAmend: "No Item 1.05 filing in this edition has been amended yet.",
      nodata:
        "No edition yet. Until the nightly pipeline's first read of EDGAR's " +
        "full-text search, there is no lag to measure.",
      methodology:
        "Amendments are Item 1.05 filings on form 8-K/A. Each is matched to " +
        "the latest Item 1.05 original (form 8-K) from the same primary " +
        "filer CIK filed on or before the amendment's date, so a company " +
        "with two incidents has each amendment attached to the nearer one. " +
        "The lag is the number of calendar days between the two filing " +
        "dates, taken from each original's first amendment only. Later " +
        "amendments to the same original count as filings in the chart " +
        "above but not again here. An amendment whose filer has no earlier " +
        "Item 1.05 original since 18 December 2023 is counted as unmatched " +
        "and left out. The lag runs between filing dates; nothing on this " +
        "page measures the time from an incident to its disclosure.",
    },

    // --------------------------------- incidents.html · 3
    incidents_receipts: {
      num: "03",
      kicker: "Latest filings",
      source: "SEC EDGAR (sec.gov/Archives)",
      headline: "Each recent Item 1.05 filing below links to its record on EDGAR.",
      caption:
        "The most recent Item 1.05 filings, originals and amendments, each " +
        "linked to its filing index on EDGAR; the filing date is the link. " +
        "These are the companies' own public disclosures, listed under the " +
        "filer's name as EDGAR records it. Where a company gives the date " +
        "of the incident, it is in the filing's text.",
      colDate: "Filed",
      colForm: "Form",
      colCompany: "Filer",
      colLag: "Days after original",
      // The filing date is the link; this names it for screen readers.
      linkLabel: "(filing index on EDGAR)",
      nodata:
        "No edition yet. The first nightly read of EDGAR fills this table " +
        "with the latest Item 1.05 filings and their links.",
      noRows: "No Item 1.05 filing in this edition's window.",
      methodology:
        "Up to the 25 newest Item 1.05 filings in the window, newest first " +
        "(ties by accession number). The filer is the first company named on " +
        "the filing, with the ticker shown in EDGAR's display name. The link " +
        "is built from the filer's CIK and the accession number " +
        "(sec.gov/Archives/edgar/data/<CIK>/<accession>/<accession>-index.htm). " +
        "For an amendment, “days after original” is the lag to the " +
        "original it was matched to, as in the chart above.",
    },

    // --------------------------------- advisories.html · 1 (hero)
    gap_years: {
      num: "01",
      kicker: "Advisories without a CVE",
      source: "GitHub Advisory Database (CC-BY 4.0) via OSV.dev",
      headline: "About one GitHub-reviewed advisory in twelve carries no CVE id.",
      // {placeholders} fill from data/advisory_gap.json at render time.
      caption:
        "GitHub-reviewed security advisories for open-source packages, by " +
        "the year GitHub published them, split by whether the advisory " +
        "carries a CVE id. {without_pct} of the {advisories} live " +
        "advisories carry none. Those {without} advisories would not appear " +
        "in a vulnerability program that tracks only CVE ids. Some are " +
        "notices of malicious packages, not vulnerabilities; most of those " +
        "are npm packages GitHub listed in 2020. The year is GitHub's " +
        "publication date, so an older vulnerability that GitHub reviewed " +
        "later counts in the year of the review. Pick an ecosystem to see " +
        "its split.",
      statLabel: "of GitHub-reviewed advisories carry no CVE id",
      statWhen: "{without} of {advisories} advisories · withdrawn ones excluded",
      selectLabel: "Ecosystem",
      allLabel: "All ecosystems",
      toggleCount: "Counts",
      toggleShare: "No-CVE share",
      legendWith: "With a CVE",
      legendWithout: "No CVE",
      legendYoung: "No CVE, published in the last {days} days",
      legendShare: "Share without a CVE",
      tooltipShare: "{pct} without a CVE",
      nodata:
        "No edition yet. The nightly pipeline fills this page from OSV's exports.",
      note:
        "* {year} is partial. The palest segment is provisional, because an " +
        "advisory can gain a CVE after publication. Of the {lag_n} " +
        "advisories whose CVE has an NVD publication date, the CVE reached " +
        "NVD more than 90 days after the advisory for {later_90}, and more " +
        "than a year after for {later_365}.",
      methodology:
        "The pipeline reads OSV.dev's per-ecosystem exports (all.zip for " +
        "each of the twelve GitHub advisory ecosystems) and keeps the records " +
        "whose id starts GHSA-. OSV mirrors only GitHub-reviewed advisories; " +
        "the pipeline checks the reviewed flag on every record and found " +
        "{not_reviewed} live records without it in this edition. Withdrawn " +
        "advisories ({withdrawn}) are left out. An advisory that affects " +
        "packages in several ecosystems appears in several exports and is " +
        "counted once here ({multi} advisories span more than one " +
        "ecosystem). An advisory counts as having a CVE when OSV lists a " +
        "CVE id among its aliases. OSV also adds links from the CVE side (a " +
        "CVE record that names the advisory), so its alias list can be " +
        "longer than GitHub's own, and the no-CVE count here is the lower of " +
        "the two. Years are GitHub's publication dates. Advisories published " +
        "in the {days} days before the edition are drawn as provisional, " +
        "because a CVE can be added later. The lag figures in the note use " +
        "the NVD publication date GitHub records for the aliased CVE.",
    },

    // --------------------------------- advisories.html · 2
    gap_ecosystems: {
      num: "02",
      kicker: "By ecosystem",
      source: "GitHub Advisory Database (CC-BY 4.0) via OSV.dev",
      headline: "About one Rust advisory in four has no CVE id; almost every Maven advisory has one.",
      caption:
        "The share of each ecosystem's reviewed advisories that carry no CVE " +
        "id, across all publication years. An advisory that affects " +
        "packages in several ecosystems counts in each of them. The count " +
        "behind each share is on the bar label or in its tooltip.",
      xAxis: "% of the ecosystem's advisories without a CVE",
      barLabel: "{pct} · {without} of {total}",
      tooltip: "{without} of {total} advisories without a CVE ({young} published in the last {days} days)",
      smallNote: "Fewer than {min_n} advisories, not ranked: {list}.",
      nodata:
        "No edition yet. The nightly pipeline fills this page from OSV's exports.",
      methodology:
        "Per ecosystem, the live reviewed advisories that list a package in " +
        "that ecosystem, split by whether OSV lists a CVE alias. The " +
        "ecosystem names are OSV's: crates.io is Rust, Packagist is PHP, Hex " +
        "is Erlang and Elixir, and Swift packages are listed by their source " +
        "URL. Shares cover all publication years. An ecosystem with fewer " +
        "than {min_n} advisories gets no share, because a percentage over so " +
        "few advisories moves with each one.",
    },

    // --------------------------------- advisories.html · 3
    gap_severity: {
      num: "03",
      kicker: "Severity",
      source: "GitHub Advisory Database (CC-BY 4.0) via OSV.dev",
      headline: "No-CVE advisories are rated Critical or Low more often; many Criticals are malware notices.",
      caption:
        "GitHub's own severity rating, as a share of the advisories with a " +
        "CVE and of those without. {crit_without} of the no-CVE advisories " +
        "are rated Critical, against {crit_with} of those with a CVE. More " +
        "of them are rated Low as well. Hundreds of the no-CVE Critical " +
        "advisories are notices of malicious packages, most of them npm " +
        "packages GitHub listed in 2020. Without those notices, the no-CVE " +
        "advisories are rated Critical less often than the ones with a CVE.",
      rowWith: "With a CVE",
      rowWithout: "Without a CVE",
      levels: {
        CRITICAL: "Critical",
        HIGH: "High",
        MODERATE: "Moderate",
        LOW: "Low",
        UNRATED: "No rating",
      },
      tooltip: "{level}: {n} advisories · {pct} of the row",
      nodata:
        "No edition yet. The nightly pipeline fills this page from OSV's exports.",
      methodology:
        "The severity is the rating GitHub gives the advisory (Critical, " +
        "High, Moderate, Low), read from the record's database_specific " +
        "block. It is not a CVSS score computed here and not NVD's rating of " +
        "the aliased CVE. Each row sums to 100% of its advisories: all live " +
        "reviewed advisories with a CVE alias in one row, all without in " +
        "the other, across all publication years. The export does not flag " +
        "malicious-package notices; the caption's count of them comes from " +
        "GitHub's advisory API, checked on 23 September 2026.",
    },

    // --------------------------------- malware.html · 1 (hero)
    mal_months: {
      num: "01",
      kicker: "Reports per month",
      source: "OpenSSF malicious-packages (Apache-2.0) via OSV.dev",
      headline: "Six in ten of the feed's reports were published in a single month.",
      caption:
        "Each bar is one month of reports in the OpenSSF malicious-packages " +
        "feed: one report per malicious package, dated when the report was " +
        "published to the feed. {peak_month} holds {peak_reports} reports, " +
        "{peak_share} of all reports on file, and {peak_top_n} of them name " +
        "one contributor, {peak_top_source}. In a typical month of the last " +
        "two years the feed published {median} reports (the median month). " +
        "These are counts of reports, not of installs or victims.",
      statLabel: "malicious-package reports on file",
      statWhen: "published since {first_month} · {this_year} so far in {year}",
      toggleStacked: "Stacked",
      toggleLog: "By registry, log scale",
      yAxis: "reports",
      yAxisLog: "reports (log scale)",
      burstsLabel: "Largest months",
      burstTemplate: "{month}: {n} ({share} of all; {src_n} from {src})",
      burstTemplateNone: "{month}: {n} ({share} of all; {src_n} credit no contributor)",
      nodata:
        "No edition yet. The nightly pipeline fills this page from OSV's exports.",
      note:
        "* {month} is partial. The log view draws npm, PyPI, RubyGems, " +
        "NuGet and Other as separate lines, so the smaller registries remain " +
        "readable next to npm.",
      methodology:
        "The pipeline reads OSV.dev's per-ecosystem exports and keeps the " +
        "records whose id starts MAL-: the OpenSSF malicious-packages feed, " +
        "which OSV republishes. Each report counts once, in the month of its " +
        "published date, which is when the report entered the feed. That is " +
        "not the date the package appeared on the registry or the date it " +
        "was removed. Withdrawn reports stay in the counts; the next section " +
        "counts them separately. The contributor named for a month is the " +
        "source the feed credits most often in that month's reports; a " +
        "report can credit several sources, or none. Registries beyond the " +
        "four largest are folded into Other.",
    },

    // --------------------------------- malware.html · 2
    mal_share: {
      num: "02",
      kicker: "By registry",
      source: "OpenSSF malicious-packages (Apache-2.0) via OSV.dev",
      headline: "npm accounts for almost every report on file, but PyPI had most of 2023's.",
      caption:
        "Each year's reports, split by registry. npm holds {npm_share} of " +
        "all reports on file, but the split varies by year: in 2023 PyPI " +
        "carried most of the year's reports, and RubyGems holds " +
        "{ruby_share} of this year's so far.",
      yAxis: "% of the year's reports",
      tooltip: "{name}: {n} reports · {pct}",
      nodata:
        "No edition yet. The nightly pipeline fills this page from OSV's exports.",
      methodology:
        "Per publication year, each registry's reports over all the year's " +
        "reports. The registry is the one the report names. OSV files a VS " +
        "Code extension under VSCode whether it was published to the " +
        "Microsoft marketplace or to Open VSX, and this page does the same. " +
        "The current year is partial, but its shares are comparable with " +
        "full years; one large month can still shift them.",
    },

    // --------------------------------- malware.html · 3
    mal_withdrawn: {
      num: "03",
      kicker: "Withdrawn",
      source: "OpenSSF malicious-packages (Apache-2.0) via OSV.dev",
      headline: "Almost no report in the feed has been withdrawn.",
      caption:
        "{withdrawn} of {reports} reports ({pct}) carry a withdrawal " +
        "date, meaning the feed retracted the report after publishing it. " +
        "A withdrawn report stays in the export, so it is counted here by " +
        "the year the report was first published.",
      yAxis: "withdrawn reports",
      byEcosystem: "By registry",
      ecoTemplate: "{name} {n} of {reports}",
      tooltip: "{year}: {n} of {total} reports withdrawn",
      nodata:
        "No edition yet. The nightly pipeline fills this page from OSV's exports.",
      methodology:
        "A report counts as withdrawn when its record carries a withdrawn " +
        "timestamp. Bars are grouped by the year the report was published, " +
        "not the year it was withdrawn. The record has no field for a " +
        "reason, so this page gives none.",
    },

    // --------------------------------------------- tags.html · 1 · hero
    tags_trend: {
      num: "01",
      kicker: "Unsupported when assigned",
      source: "CVE List V5 (MITRE)",
      headline: "More CVEs are tagged as issued for products the vendor no longer supports.",
      caption:
        "The CVE record format lets the CNA attach tags to a record. " +
        "“unsupported-when-assigned” means the product was already out of " +
        "vendor support when the CVE ID was assigned: {first} records " +
        "carried it in {first_year}, {latest} in {latest_year}, and " +
        "{current} so far in {current_year}. “disputed” means some party " +
        "disputes that the record describes a vulnerability. It appeared on " +
        "between {dmin} and {dmax} records a year from {dfrom} to {dto}, " +
        "while yearly publications more than doubled, so its share of each " +
        "year's records fell. “exclusively-hosted-service” marks a cloud " +
        "service with nothing for a customer to install. A tag records what " +
        "the CNA noted and is not checked here. An untagged record does not " +
        "mean the product is supported or the record undisputed: most CNAs " +
        "never set these tags.",
      statLabel: "Records tagged “unsupported-when-assigned”",
      statLatest: "{latest_year}",
      statFirst: "{first_year}",
      statCurrent: "{current} in {current_year} so far",
      toggleCount: "Records",
      toggleShare: "Share of year",
      tagLabels: {
        "unsupported-when-assigned": "unsupported-when-assigned",
        disputed: "disputed",
        "exclusively-hosted-service": "exclusively-hosted-service",
      },
      tooltipShare: "{pct} of {published} published",
      contextNote:
        "Not charted: tags a CNA defines for itself (prefixed x_), {private} " +
        "distinct ones so far. Most used: {top}. ADP containers carry only " +
        "{adp}.",
      nodata: "No tagged records in the corpus yet. The nightly pipeline fills this chart.",
      methodology:
        "For every published record in the cvelistV5 corpus, the tags array of the " +
        "CNA container, counted once per record per tag and filed under the record's " +
        "publication year (rejected records excluded). The three tags charted are the " +
        "ones the CVE record schema defines; tags prefixed x_ are private to the CNA " +
        "that sets them and are listed only in the note. The record carries no date " +
        "for when a tag was added, so a record tagged years after publication counts " +
        "under its publication year, and the chart cannot show when tagging happened. " +
        "Shares are tagged records over all records published that year. The first " +
        "year shown is the first year any of the three tags appears. The current year " +
        "(marked *) is partial and refills nightly; its share is comparable with full " +
        "years, its count is not.",
    },

    // --------------------------------------------- tags.html · 2
    tags_board: {
      num: "02",
      kicker: "Who tags",
      source: "CVE List V5 (MITRE)",
      headline: "Most active CNAs set neither tag in the last five years.",
      caption:
        "Tagged records from {from} to {to}, by the CNA that set the tag. " +
        "{u_cnas} of the {active} CNAs that published a record in those years " +
        "set “unsupported-when-assigned” at least once, and the top three " +
        "account for {u_top3} of the tags. “disputed” is set mostly " +
        "by one CNA: {d_top} set {d_top1} of them. The counts describe each " +
        "CNA's tagging practice, not its products.",
      windowTemplate:
        "{from}–{to} · up to twelve CNAs, each with at least {min_n} tagged records · {cnas} CNAs set the tag at least once",
      colCna: "CNA",
      colN: "Tagged records",
      colShare: "Share of the tag",
      colRate: "Share of its records",
      nodata: "No CNA has set this tag often enough to list.",
      methodology:
        "Records published in the last {window_years} publication years (the current, " +
        "partial year included), by the assigner of record. The twelve CNAs with the " +
        "most tagged records in the window are listed, each with at least {min_n}; " +
        "the rest still count toward the number of CNAs that set the tag. “Share of " +
        "the tag” is the CNA's tagged records over all records carrying that tag in " +
        "the window; “share of its records” is the CNA's tagged records over every " +
        "record it published in the window. The active-CNA count is every assigner " +
        "with at least one published record in the window.",
    },

    // --------------------------------------------- tags.html · 3
    tags_severity: {
      num: "03",
      kicker: "Tagged against baseline",
      source: "CVE List V5 (MITRE)",
      headline: "Records tagged unsupported are rated Critical more often than their CNAs' other records.",
      caption:
        "The severity of tagged records from {from} to {to} against two baselines: " +
        "every other record from the CNAs that set the tag, and every record " +
        "published in those years. Records tagged “unsupported-when-assigned” " +
        "are rated Critical {u_crit} of the time, against {u_same} for the same " +
        "CNAs' other records and {all_crit} across all records. The tagged row and " +
        "the row of its CNAs' other records draw on the same CNAs, so each CNA's " +
        "scoring habits appear in both. The comparison does not show why the " +
        "tagged records score higher.",
      rowLabels: {
        tagged: "{tag}",
        same_cnas_untagged: "its CNAs' other records",
        all: "all records",
      },
      severityLabels: {
        critical: "Critical",
        high: "High",
        medium: "Medium",
        low: "Low",
        unscored: "No score in record",
      },
      tooltipRow: "{n} records",
      nodata: "Not enough tagged records yet.",
      methodology:
        "Records published in the last {window_years} publication years (the current, " +
        "partial year included). Each record is bucketed by the base score in the " +
        "record itself: the newest CVSS version present, with the CNA's score first " +
        "and an ADP score as the fallback within that version. This is the rule the " +
        "CVE Ecosystem page uses for severity by year. The buckets are Critical " +
        "(≥ 9.0), High (7.0–8.9), Medium (4.0–6.9), Low (below 4.0), and no score. " +
        "“Its CNAs' other records” pools every record from any CNA that set the tag at " +
        "least once in the window, minus the tagged ones. The two rows weight each " +
        "CNA differently: a CNA that tags heavily makes up more of the tagged row " +
        "than of the baseline. Bars are shares of each row's records; the " +
        "tooltip carries the counts.",
    },
  },

  footer: {
    generatedTemplate: "Edition generated {generated_at}",
    sourcesTemplate:
      "Sources: cvelistV5 release {cvelist_release} ({cve_count} CVEs) · " +
      "EPSS {epss_version} scores of {epss_date} · CISA KEV {kev_version} ({kev_count} entries) · " +
      "NVD statuses fetched {nvd_fetched} · market terms fetched {market_fetched} · " +
      "HIBP breach catalog fetched {hibp_fetched} ({hibp_count} breaches) · " +
      "Ransomwhere {ransomwhere_addresses} addresses / {ransomwhere_txs} ledger entries " +
      "fetched {ransomwhere_fetched} · " +
      "ATT&CK enterprise v{attack_version} ({attack_versions} releases) · " +
      "APNIC DNSSEC series fetched {apnic_fetched} · " +
      "EPSS history: {epss_graded} KEV entries with a score from the day before listing · " +
      "rescore log: {rescore_events} events · " +
      "KEV changelog: {kev_changelog_events} catalog events · " +
      "Exploit-DB index ({exploitdb_entries} entries) · " +
      "Metasploit metadata ({metasploit_modules} modules) · " +
      "Nuclei CVE templates ({nuclei_cves}) · " +
      "Feodo Tracker: {feodo_listed} C2s listed ({feodo_online} online) " +
      "fetched {feodo_fetched} · " +
      "SEC EDGAR 8-K incident filings: {sec_incidents} · " +
      "OSV exports: {osv_ghsa} reviewed advisories, {osv_mal} malicious-package " +
      "reports fetched {osv_fetched}",
    // {sec_incidents} fill: counts once fetched; the pending line before the
    // first nightly EDGAR read (meta.sources.sec_incidents.status "empty").
    secFetched: "{filings_105} Item 1.05 / {filings_801} Item 8.01 fetched {fetched}",
    secPending: "pending the first nightly read",
    metaError: "Edition metadata (data/meta.json) failed to load.",
    disclaimer:
      "CyberMon is an independent project, not affiliated with, endorsed by or speaking for " +
      "MITRE, NVD/NIST, CISA, FIRST, GDELT, Y Combinator/Algolia, arXiv, the Wikimedia " +
      "Foundation, the U.S. Securities and Exchange Commission, Have I Been Pwned, " +
      "Ransomwhere, APNIC, OffSec, Rapid7, ProjectDiscovery, abuse.ch, GitHub, the OpenSSF, " +
      "Google (OSV.dev) or the Internet Archive. Charts aggregate public data. The site " +
      "does not report individual CVEs as news and does not identify victims, with one " +
      "exception: the SEC Incident Filings page lists public companies' own SEC filings under the " +
      "filer's name as EDGAR records it. No attacker infrastructure is republished; C2 " +
      "servers appear only as aggregate counts, never as addresses.",
    reuseNote:
      "Charts and numbers may be reused (screenshots, embeds, quotes) with a link to " +
      "CyberMon as the source. CyberMon is a spare-time project, rebuilt nightly by an " +
      "unattended pipeline and provided as is, with no guarantee of correctness, " +
      "completeness or availability. Check a number against its primary source before " +
      "relying on it.",
    dataNote:
      // The CVE Terms of Use grant reuse provided MITRE's copyright designation is
      // reproduced; CVE® and CWE™ are MITRE trademarks. Do not paraphrase.
      "Data: CVE List V5 and the CNA roster from CVE.org (Copyright © 1999–2026 The MITRE " +
      "Corporation; CVE® is a registered trademark of The MITRE Corporation; reproduced under " +
      "the CVE Terms of Use), the CWE Top 25 (cwe.mitre.org; CWE™ is a trademark of The MITRE " +
      "Corporation), EPSS (FIRST.org), Known Exploited Vulnerabilities catalog (CISA), " +
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
      "the Exploit Database index (OffSec, exploit-db.com), " +
      "Metasploit Framework module metadata (Rapid7, BSD-3-Clause), " +
      "the Nuclei templates CVE index (ProjectDiscovery, MIT), " +
      "botnet C2 blocklist by abuse.ch's Feodo Tracker (feodotracker.abuse.ch, CC0; " +
      "attribution appreciated), " +
      "the GitHub Advisory Database (GitHub, CC-BY 4.0) and the OpenSSF malicious-packages " +
      "feed (Apache-2.0), both read from the OSV.dev ecosystem exports, " +
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
  // Copy for the animated social clips (site/motion.html, rendered by
  // tools/make_motion.py). Same rule as everywhere else: no user-facing string
  // lives in a scene file, so pipeline/tests/test_claims_motion.py can audit
  // every claim here against the committed data.
  //
  // Headlines deliberately carry NO span figure. A clip's window grows every
  // night, so "four years of…" would quietly go stale; where a span or a count
  // belongs on the sheet it is rendered from the data as a {placeholder}.
  motion: {
    wordmark: "CYBERMON",
    // Module page id -> scene id, for the footer link common.js renders.
    // Only pages whose data a scene actually animates appear here; a module
    // without a clip simply gets no link. Without this the clips ship inside
    // the Pages artifact with nothing on the site pointing at them — built,
    // deployed and undiscoverable.
    byModule: {
      cve: "severity-flood",
      market: "hype-race",
      concentration: "cna-concentration",
    },
    linkTemplate: "This module as an animated clip (MP4) → motion/{scene}.mp4",
    scenes: {
      "hype-race": {
        kicker: "News mentions",
        headline: "Ransomware once led news mentions of the tracked terms; it no longer does.",
        source: "GDELT 2.0 news mentions",
        meta:
          "trailing 12 months, by month. All {terms} tracked terms shown; raw " +
          "article counts, not the site's per-term index.",
      },
      "severity-flood": {
        kicker: "CVEs by severity",
        headline: "CVEs rated Critical went from a handful a year to thousands.",
        source: "CVE List V5 (MITRE)",
        // The era caveat is not optional garnish: without it the growing stack
        // reads as "vulnerabilities got worse" when what changed is where the
        // score is written down.
        // The clip ends holding on a year that is only part-written, so its
        // stack drops off a cliff. Left unexplained, that closing frame reads as
        // "publishing collapsed" — the most likely misread of the whole scene,
        // and the one a shared clip carries furthest. Hence the asterisk, which
        // this line defines on screen.
        meta:
          "published CVEs per year, by the score in the CVE record. Before {era}, " +
          "severity scores were kept in NVD's database, which this chart does not read; " +
          "the gray band counts records with no score in the record. {gen}* is still " +
          "filling in.",
        eraMarker: "scored in NVD, not in the record",
      },
      "cna-concentration": {
        kicker: "CNA concentration",
        headline: "Hundreds of CNAs now assign CVEs; the five largest still issue about half.",
        source: "CVE List V5 (MITRE)",
        meta:
          "share of each year's CVEs issued by the five largest CNAs, and the number of " +
          "CNAs that published or rejected a record that year. {gen}* is still filling in.",
        shareLabel: "Top-5 share",
        countLabel: "Active CNAs",
      },
    },
  },

  carousel: {
    edition: "Edition {generated_at}",
    slideFooter: "CyberMon · devko.github.io/CyberMon · data: {sources}",
    siteUrl: "devko.github.io/CyberMon",
    closingSources: "Data: {sources}",
    // Printed under a board the fit pass had to cut — a truncated table
    // must say so (the full ranking lives on the site).
    tableMore: "Top {shown} of {total}; the full table is on the site.",
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
      top25: "CVE List V5 (MITRE) · CWE Top 25 (MITRE) · CISA KEV",
      adp: "CVE List V5 (MITRE)",
      epssvol: "EPSS (FIRST.org) · CyberMon nightly diffs",
      roster: "CVE.org organization roster · CyberMon nightly snapshots",
      exploits: "Exploit-DB (OffSec) · Metasploit (Rapid7) · Nuclei (ProjectDiscovery) · cvelistV5 (MITRE) · CISA KEV",
      c2: "abuse.ch Feodo Tracker (CC0) · CyberMon nightly snapshots",
      ai: "Exploit-DB (OffSec) · cvelistV5 (MITRE) · CyberMon AI timeline · GDELT · Hacker News · arXiv · Wikipedia · SEC EDGAR",
      credits: "CVE List V5 (MITRE) · EPSS (FIRST.org) · CISA KEV · Exploit-DB · Metasploit · Nuclei · finders' own announcements",
      incidents: "SEC EDGAR full-text search (Forms 8-K, 8-K/A)",
      advisories: "GitHub Advisory Database (CC-BY 4.0) via OSV.dev",
      malware: "OpenSSF malicious-packages via OSV.dev",
      tags: "CVE List V5 (MITRE)",
    },
  },
};

// Tiny template helper: tpl("{a} vs {b}", {a: 1, b: 2}) -> "1 vs 2"
export function tpl(str, vars) {
  return str.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
}
