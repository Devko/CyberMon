// =============================================================================
// editorial.js — the text that the module pages, their charts, the carousel
// slides and the animated clips show to a reader.
//
// What lives here:
//   - page and section copy: kickers, headlines, captions, stats, notes,
//     methodology, toggle and column labels, the nav and the footer;
//   - `ui`: strings every page shares (the empty-state line, "vs", "n/a",
//     the "On this page" list, the nav's instrument links, the hover title
//     of CVE links);
//   - `sections.<id>.labels`: each chart's short text: series and axis
//     names, tooltip and hover phrases, and fallback words that a template
//     fills in. Series names double as the keys ECharts matches legends and
//     tooltips on, so the chart code reads them from here and compares
//     against the same value;
//   - `sections.<id>.nodata`: a section's own empty-state line; a chart
//     whose section has none shows `ui.nodata`;
//   - the carousel and motion-clip copy (`carousel`, `motion`).
//
// What stays in code, by design:
//   - internal series ids (names starting with "_", never shown);
//   - bare unit tokens: an axis name or count suffix that is only a unit
//     ("days", "share", "payments", "CNAs", the "d" after a day count, "pp");
//   - number and date formatting: signs and symbols (± ≤ ≥ ▲ ▼ → * #), the
//     k/M/B suffixes, "n=", "—" and "?" for a missing value, and month
//     abbreviations;
//   - proper names of sources and statuses: GDELT, Hacker News, arXiv,
//     Wikipedia, SEC EDGAR, the NVD status names, and the CYBERMON wordmark
//     in the masthead and on the carousel slides;
//   - developer error and console messages, and code comments;
//   - the HTML shells (site/*.html): <title>, meta tags and <noscript> text;
//   - the two instruments, the Field (field.js) and the Mutation Observatory
//     (observatory.js), which keep their own copy in their own files.
//
// Templates use {placeholders}; values are filled from site/data/*.json at
// render time so the copy never carries stale numbers. tpl() below fills
// them.
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
      lede:
        "CISA's Known Exploited Vulnerabilities (KEV) catalog, Exploit Prediction Scoring " +
        "System (EPSS) forecasts and public exploit code.",
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
    { id: "ai", href: "ai.html", label: "AI and PoC Timing", group: "exploitation" },
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
    caption: "Each module below is a separate page with its own nightly pipeline stage.",
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
          headline: "Every published CVE as one point in a 3D view.",
          blurb:
            "Arrange the cvelistV5 corpus by publication date, score and EPSS, by days to " +
            "the first public exploit and to the KEV listing, on a CVSS × EPSS grid, or by " +
            "assigner, vendor, weakness or NVD status. Filter it, look up a CVE, or list " +
            "the shown records as a table; the page address keeps the view. Rebuilt " +
            "nightly with the charts.",
        },
        {
          id: "observatory",
          href: "observatory.html",
          num: "Δ",
          label: "Mutation Observatory",
          headline: "The Observatory puts CyberMon's CVE-level change logs on one timeline.",
          blurb:
            "CNA score changes (mostly first scores on existing records), KEV additions, " +
            "edits and removals, and each night's largest EPSS probability change. Events " +
            "are dated by the night CyberMon observed them, EPSS events by FIRST's score " +
            "date. Select a date range, look up one CVE, or download the events as CSV.",
        },
      ],
    },
    modules: [
      {
        id: "cve",
        href: "cve.html",
        num: "01",
        label: "CVE Ecosystem",
        headline: "Between four and six in ten scored CVEs have been rated High or Critical each year since 2020.",
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
        headline: "Most tracked buzzwords had their busiest month of news coverage more than two years ago.",
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
          "The number of active CNAs (CVE Numbering Authorities) each year, the share of " +
          "each year's CVEs from the five and ten largest, new CNAs per year, and the CNAs " +
          "that later reject the largest share of their own published records. Rebuilt " +
          "nightly from the same corpus as CVE Ecosystem.",
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
        headline: "Ransomware payments recorded by Ransomwhere total more than a billion dollars.",
        blurb:
          "Ransomwhere, a crowdsourced tracker, counts only payments to addresses that " +
          "were reported to it and verified, so every total is a lower bound. Revenue per " +
          "quarter in dollars at the day of transfer, payment counts and median sizes, and " +
          "revenue by ransomware family. Rebuilt nightly.",
        live: true,
      },
      {
        id: "attack",
        href: "attack.html",
        num: "07",
        label: "ATT&CK Releases",
        headline: "Active ATT&CK techniques and sub-techniques have more than tripled since v1.0 in 2018.",
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
        headline: "About four in ten internet users sit behind resolvers that fully validate DNSSEC.",
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
        headline: "More than one in nine KEV entries is in a security product.",
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
        headline: "More than half of scored KEV additions since 2023 had an EPSS score under 1% the day before listing.",
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
        headline: "The ATT&CK groups with the most aliases carry more than a dozen other names each.",
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
        headline: "CISA's Vulnrichment program has added data to more than half of all published CVEs.",
        blurb:
          "CISA writes Vulnrichment data into CVE records through an Authorized Data " +
          "Publisher (ADP) container, CISA-ADP. The container adds SSVC decision points to " +
          "nearly every record it covers, and a CVSS score or a CWE id to about a fifth " +
          "each. Monthly counts by the container's own update date, what it adds, and the " +
          "ADP publishers ranked by records enriched. Read nightly from the CVE List.",
        live: true,
      },
      {
        id: "epssvol",
        href: "epssvol.html",
        num: "17",
        label: "EPSS Volatility",
        headline: "On an average night, EPSS percentiles change for nearly all CVEs and probabilities for about 1%.",
        blurb:
          "CyberMon compares each night's EPSS feed with the previous night's: the share " +
          "of CVEs whose percentile and whose probability changed, weekly counts of " +
          "probabilities crossing 0.1%, 1% and 5%, and the largest single-night changes. " +
          "The percentile is a rank against all scored CVEs, a set that grows every day. " +
          "FIRST publishes daily scores but no change log; this one starts in July 2026.",
        live: true,
      },
      {
        id: "roster",
        href: "roster.html",
        num: "18",
        label: "CNA Roster",
        headline: "Organizations joining the CVE roster have outnumbered those leaving since July 2026.",
        blurb:
          "The CVE Program publishes its current list of partner organizations without " +
          "join dates; the roster file's git history holds the raw edits. CyberMon " +
          "snapshots the list every night and logs organizations joining, leaving, renamed " +
          "or changing scope, with the current roster by type, root and country.",
        live: true,
      },
      {
        id: "exploits",
        href: "exploits.html",
        num: "19",
        label: "Time to PoC",
        headline: "Since 2022 the median public exploit has appeared two weeks or more after the CVE.",
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
        headline: "Feodo Tracker's botnet C2 blocklist holds a handful of servers.",
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
        label: "AI and PoC Timing",
        headline: "Public exploit code in Exploit-DB has not appeared sooner since ChatGPT's release.",
        blurb:
          "Days from CVE publication to the first exploit code Exploit-DB dates, set " +
          "against a dated timeline of AI releases, reports and incidents. Each series is " +
          "tested for a change at three candidate start dates for an “AI era”. At the " +
          "ChatGPT date none of the judged measures moved earlier; each later date is " +
          "judged once two complete, settled years follow it. This is public exploit code, " +
          "not attacks in the wild. Also AI-security attention against the same series.",
        live: true,
      },
      {
        id: "credits",
        href: "credits.html",
        num: "22",
        label: "AI Credits",
        headline: "The largest single AI finder announcement counts more vulnerabilities than CVE records credit to all AI labs and vendors combined.",
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
          "publication year, the count of records with the first tag has risen in every " +
          "complete year since 2022; the second has not kept pace with the corpus. Also " +
          "which CNAs set the tags (few do) and how tagged records are scored compared " +
          "with the same CNAs' other records. A tag records what the CNA stated; " +
          "CyberMon does not check it.",
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
        headline: "Most GitHub-reviewed advisories carry a CVE id; Rust's lack one more often than those of any other large registry.",
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
        headline: "More than half of the reports in the OpenSSF malicious-packages feed were published in a single month.",
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

  // Strings shared by every page and chart rather than owned by one section.
  ui: {
    // The empty state of any chart or stat whose section has no `nodata`
    // line of its own.
    nodata: "Not enough data yet.",
    // The jump list over a module page's sections (common.js renderToc).
    onThisPage: "On this page",
    // Hover title on every CVE id linked into the Field (dom.js withCveLinks).
    openInField: "Open this record in the Field",
    // Between the latest and the baseline figure of a hero stat.
    vs: "vs",
    // Filled into a {placeholder} whose value is missing.
    na: "n/a",
    // The instruments' nav links and their row label on phones; the
    // landing page's instrument cards use home.instruments instead.
    navField: "The Field →",
    navObservatory: "Observatory →",
    navInstruments: "Instruments",
    // aria-label of the masthead wordmark, which links home on module pages.
    homeLink: "CyberMon overview",
  },

  methodologyLabel: "How this is computed",
  navFoldLabel: "All modules",
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
    cna_profile: "cna_profile_metrics.py",
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
      "Dashed or hollow marks extend the partial year to twelve months at " +
      "its pace so far. They are not a forecast.",
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
      headline: "Most tracked buzzwords had their busiest month of news coverage more than two years ago.",
      caption:
        "Monthly counts for one term at a time from five sources: news articles (GDELT), " +
        "Hacker News stories and comments, arXiv cs.CR (cryptography and security) " +
        "preprints, Wikipedia pageviews and SEC EDGAR filings. Each source's series is " +
        "indexed to its own five-year peak (peak = 100), so a source with a few papers a " +
        "month and one with thousands of articles can share one axis. Pick a term from " +
        "the list.",
      selectLabel: "Term",
      termCountNote: "{n} terms tracked; the list is in pipeline/market_terms.py",
      sparklineNote:
        "Click a card to load that term above. Each sparkline shows the GDELT index only; " +
        "a term with no GDELT data yet shows a label instead of a line.",
      methodology:
        "For each tracked term the pipeline pulls a monthly count over a rolling five-year " +
        "window from five sources. GDELT 2.0 counts news articles. Hacker News (Algolia " +
        "search API) counts stories and comments. The arXiv count is cs.CR preprints. " +
        "Wikipedia counts monthly pageviews of one curated on-topic article per term, " +
        "summed over the article's earlier titles when it was moved, bot traffic " +
        "excluded. SEC EDGAR full-text search counts filings matching the term as a " +
        "quoted phrase, with acronyms spelled out to avoid matches on unrelated financial " +
        "terms. The term-to-article " +
        "mapping is in pipeline/market_terms.py, and a term with no on-topic article has " +
        "no Wikipedia series. The index is recomputed nightly, so a new peak lowers every " +
        "earlier point proportionally. The tooltip shows the raw count for every point. " +
        "When a source's fetch fails or is rate-limited (GDELT rate-limits heavily), the " +
        "previous night's counts stand. A month that closed while a term's fetch was " +
        "failing stays blank until a later nightly run fills it. A source with no " +
        "successful fetch for more than three days keeps its curve but posts no " +
        "year-over-year change or divergence. A GDELT, Hacker News, arXiv or EDGAR " +
        "line that starts partway through the window marks a gap in collection. A " +
        "Wikipedia line starts with the " +
        "first month the Pageviews API reports for its article's titles. The month in " +
        "progress is collected but is not charted, ranked or averaged until it closes, " +
        "because a partial month would show as a drop at the end of every curve.",
      labels: {
        sparklineEmpty: "no media data yet",
      },
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
        "A term and source missing any of the twenty-four months, or below the minimum " +
        "volume, have no row until the fetch completes.",
      methodology:
        "For each term and source, the pipeline sums raw monthly counts over the twelve " +
        "calendar months ending with the latest complete month (the month in progress is " +
        "excluded) and over the twelve months before those. YoY change is the percentage " +
        "difference between the two sums. A pair missing any month inside either window " +
        "posts no figure, because a missing month is unknown, not zero; the window does " +
        "not slide back past a gap. A pair is also excluded when its prior-year sum is " +
        "zero, when both windows together hold fewer than thirty raw hits, or when its " +
        "source has had no successful fetch for more than three days. Any column can be " +
        "sorted; the default order is largest rise first.",
      labels: {
        barClipped: "bar clipped at ±{cap}%",
      },
    },

    // ------------------------------------------- market.html · 3
    divergence: {
      num: "03",
      kicker: "Research vs. media divergence",
      source: "GDELT 2.0 · arXiv cs.CR",
      headline: "More terms sit above the diagonal, with research nearer its five-year peak than news coverage, than below it.",
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
        "three ending with the latest complete month. GDELT is the x-axis and arXiv the " +
        "y-axis; the other three sources are not used here. A term missing any of those " +
        "months in either source is omitted; it is not averaged over whichever months " +
        "each source happens to have. A term's divergence score is the y value minus " +
        "the x value, in index points. Scores beyond ±10 are labelled “research leads” " +
        "or “media leads”, " +
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
        "Median CVSS (Common Vulnerability Scoring System) base score of newly " +
        "published CVEs, as scored by the CVE Numbering Authority (CNA) that " +
        "published each record, by year and by scoring version. " +
        "Each CVSS version computes the base score with its own formula, so a separate " +
        "line per version keeps a change of version from looking like a change in " +
        "severity. The blended line starts in the first year in which CNA-assigned " +
        "scores cover at least 20% of published records; the v3 " +
        "line starts earlier, on much thinner coverage. From 2020 to 2025 the yearly " +
        "median stayed close to 7.0, the lower edge of High, and between 40% and 52% of " +
        "scored CVEs were rated 7.0 or higher each year, with no sustained rise.",
      statLabel: "Share of scored CVEs rated High or Critical (base score ≥ 7.0)",
      statLatest: "{latest_year}",
      statAgo: "{ago_year}",
      methodology:
        "For every CVE in the cvelistV5 corpus, the CNA-assigned base score, split by " +
        "CVSS version (v2, v3.x, v4). Each line is the median score of CVEs published " +
        "that year; shaded bands span the 25th to 75th percentile. A record scored " +
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
      labels: {
        versionMedian: "CVSS {v} median",
        blended: "Blended median",
        yAxis: "CVSS base score",
      },
    },

    // ------------------------------------------------------------------- 2
    flood: {
      num: "02",
      kicker: "Severity by year",
      source: "cvelistV5 (MITRE)",
      headline: "Close to four thousand CVEs a year were rated Critical in 2024 and 2025.",
      caption:
        "Published CVEs per year, grouped by the CVSS base score in the CVE record " +
        "itself. The 2026 Critical count passed double the 2025 count with months " +
        "of the year still to go, and since 2024 more than nine in ten published " +
        "records carry a score. Records left of the vertical marker mostly carry " +
        "none. For those years NIST's National Vulnerability Database (NVD) kept " +
        "scores in its own database, which this chart does not read, so the gray " +
        "band reflects the record format of the time, not the vulnerabilities.",
      eraMarker: "← scored in NVD, not in the record",
      toggleAbsolute: "Absolute",
      toggleShare: "Share of year",
      linuxNote:
        "Since 2024 most records with no score anywhere in them are kernel " +
        "records; without the kernel, the gray “no score” band is close to " +
        "zero.",
      methodology:
        "CVEs are grouped by base score, using the highest CVSS version in each record: " +
        "Critical ≥ 9.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.0–3.9. “No score in record” " +
        "counts CVEs published that year with no base score anywhere in the CVE record, " +
        "in either the CNA container or an ADP container (data added by an Authorized " +
        "Data Publisher, a program partner such as CISA). The vertical marker sits at " +
        "the first year in which at least 10% of published records carry a score in " +
        "the record. Scores held only in NVD's database are not counted. Since 2024, " +
        "CISA's Vulnrichment program has added scores to records through its ADP " +
        "container, and those count here. " +
        "The share view scales each year to 100%. The current year (marked *) is " +
        "partial and refills nightly. In the absolute view, a dashed marker at the " +
        "current-year edge extends the partial year's total (all published records, " +
        "unscored included) to twelve months: the count so far divided by the fraction " +
        "of the UTC calendar year elapsed at generation time. It appears only once 12.5% " +
        "of the year has elapsed (about mid-February), assumes publication is uniform " +
        "through the year, and ignores seasonality and late-year backfill. The severity " +
        "mix is not projected, and the share view has no marker.",
      labels: {
        unscored: "No score in record",
        low: "Low",
        medium: "Medium",
        high: "High",
        critical: "Critical (≥9.0)",
      },
    },

    // ------------------------------------------------------------------- 3
    reality: {
      num: "03",
      kicker: "Severity vs. exploitation",
      source: "cvelistV5 (MITRE) · EPSS (FIRST.org) · CISA KEV",
      headline: "More than six in ten Critical-rated CVEs carry less than a 1% probability of exploitation.",
      caption:
        "Each scored CVE with a current EPSS score, placed on a grid by its CVSS severity " +
        "and its EPSS score. EPSS, FIRST's Exploit Prediction Scoring System, estimates " +
        "the probability of exploitation in the next 30 days; CVSS rates technical " +
        "severity. The share with a probability of 10% or more rises about twentyfold " +
        "from Low to Critical. The bars count the entries of CISA's Known Exploited " +
        "Vulnerabilities (KEV) catalog in the same CVSS buckets.",
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
        "containers. v2, v3 and v4 scores share one axis here, although each version " +
        "computes the score with its own formula (section 01 separates them). For KEV " +
        "entries published before CNAs scored in the record, the score is usually " +
        "CISA's own ADP score, so the KEV stat largely uses CISA's numbers. EPSS is a " +
        "model's prediction, not a record of exploitation.",
      labels: {
        xAxis: "EPSS: predicted probability of exploitation →",
        yAxis: "CVSS →",
        tipCell: "CVSS {cvss} × EPSS {epss}",
        tipCves: "{n} CVEs",
        tipKevBucket: "CVSS {bucket}",
        tipKev: "{n} KEV entries",
      },
    },

    // ------------------------------------------------------------------- 4
    decay: {
      num: "04",
      kicker: "NVD backlog",
      source: "NVD API 2.0 (NIST) · CyberMon nightly snapshots",
      headline: "Tens of thousands of CVEs carry NVD's “Deferred” status.",
      caption:
        "NVD adds analysis, CVSS scores and product data to CVE records. The bars count " +
        "every CVE by its NVD status on a logarithmic axis; the three red bars are " +
        "the live queue (Received, Awaiting Analysis, Undergoing Analysis). " +
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
        "Analysis. The bar axis is logarithmic so that the smaller queue statuses stay " +
        "visible beside the Modified count. Each nightly run appends one row to a " +
        "committed CSV (data/history/nvd_backlog.csv); a second run on the same date " +
        "replaces that date's row. A night without a successful run has no row, and " +
        "the chart's date axis skips it.",
      labels: {
        backlog: "Backlog total",
        awaiting: "Awaiting analysis",
        tipCves: "{n} CVEs",
        firstDateFallback: "today",
      },
    },

    // ------------------------------------------------------------------- 5
    throughput: {
      num: "05",
      kicker: "NVD throughput",
      source: "NVD API 2.0 (NIST) · CyberMon nightly snapshots",
      headline: "Since July 2026, NVD has deferred close to half of the CVEs leaving its analysis queue.",
      caption:
        "Each night CyberMon compares every CVE's NVD status with the previous " +
        "night's snapshot. The lines count three kinds of change: CVEs newly " +
        "received, and CVEs leaving the analysis queue as Analyzed or as Deferred. " +
        "The same comparisons time how long a CVE waits in the queue before it is " +
        "analyzed.",
      note:
        "NVD publishes no transition history. CyberMon's record starts on " +
        "{first_date}.",
      lineTitle: "CVEs changing status, one point per nightly comparison",
      seriesAnalyzed: "Analyzed (left the queue)",
      seriesDeferred: "Deferred (left the queue)",
      seriesReceived: "Newly received",
      statMedianLabel: "median observed wait in the analysis queue",
      statMedianBig: "{days} days",
      statMedianNote:
        "across {n} timed exits from the queue. Each wait is a lower bound, counted " +
        "from the first nightly snapshot that showed the CVE awaiting analysis. The " +
        "record cannot yet contain waits longer than its own age, so the median can " +
        "rise as the record grows.",
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
        "The headline's share is Deferred exits over Analyzed plus Deferred exits, " +
        "summed over the whole record. NVD publishes no status-change timestamps, so " +
        "each status is dated to the night CyberMon first saw it. A queue wait runs " +
        "from the snapshot that first showed the CVE awaiting analysis (or undergoing " +
        "it) to the snapshot that first showed it analyzed; time spent as “Received” " +
        "is not counted, and a CVE analyzed straight from “Received” is not timed. " +
        "CVEs already in a status when the tracker started have no entry date; their " +
        "transitions count in the flow but are not timed. The median is not published " +
        "until {min_known} exits have been timed, because a median of fewer is " +
        "unreliable. A full re-read can catch transitions that incremental syncs " +
        "missed. The feed files lag by about a day, so that catch-up lands in the row " +
        "for the night after the re-read, which is ringed on the chart and flagged in " +
        "the tooltip. After a night with no run, the next comparison covers more than " +
        "one day. Each run date gets one row in a committed CSV " +
        "(data/history/nvd_throughput.csv); a second run on the same date adds its " +
        "counts to that date's row.",
      labels: {
        firstDateFallback: "today",
      },
    },

    // ------------------------------------------------------------------- 6
    cna: {
      num: "06",
      kicker: "Scores by CNA",
      source: "cvelistV5 (MITRE) — CNA-assigned scores",
      headline: "The highest-rating CNAs score more than a third of their CVEs 9.0 or higher.",
      caption:
        "CNAs can score the CVEs they publish. This board " +
        "uses those scores, not NVD's, and ranks each CNA by the share it rates 9.0 or " +
        "higher. Some of the largest CNAs, with thousands of scored CVEs each, rate " +
        "fewer than one in ten that high. CNAs cover different products, and some " +
        "score in CVSS 4.0 while others use 3.x, so the board does not show why their " +
        "shares differ.",
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
        "fell from a fifth of all records in 2017 to under one percent in 2023, and " +
        "the share was higher in 2024 and 2025.",
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
        "under the year in their ID. The current year is labeled partial and refills " +
        "nightly. The " +
        "dashed segment and hollow marker extend the partial year to twelve months: the " +
        "count so far divided by the fraction of the UTC calendar year elapsed at " +
        "generation time. The projection appears only once 12.5% of the year has " +
        "elapsed (about mid-February; before that the divisor is too small for a stable " +
        "estimate), assumes publication is uniform through the year, and ignores " +
        "seasonality and late-year backfill. The solid line shows the actual partial " +
        "count.",
      labels: {
        published: "Published",
        rejected: "Rejected",
      },
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
        "structured affected-version data. Before about 2018 all three were usually " +
        "kept in NVD's database, not in the record, so the early plateau shows where " +
        "the data was stored. Since 2024, most records missing a score come from the " +
        "Linux kernel CNA; the kernel toggle on the severity-by-year chart (section 02) " +
        "shows this.",
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
        "at least 500 published records. Data held only in NVD's database is not " +
        "counted. The current year (marked *) is partial and refills nightly.",
      labels: {
        tipRecords: "{n} records",
      },
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
        "pooled as “Other.” The eight are chosen from the whole period's totals, so " +
        "the same eight appear in every year. From 2017 " +
        "to 2025, cross-site scripting rose from about 9% to about 18% of tagged " +
        "records and SQL injection from about 1% to about 9%. Missing authorization " +
        "rose from almost nothing to about 5%, improper input validation and " +
        "out-of-bounds reads fell below 2%, and the other three classes moved by about " +
        "two points or less.",
      // rendered as a panel-note by cve.js (same slot the decay chart uses)
      note:
        "The share of each year's records that carry a CWE varies widely; each " +
        "year's tooltip gives it, with the tagged count.",
      otherLabel: "Other",
      methodology:
        "Each CWE-tagged published record contributes its first-listed CWE id (the CNA " +
        "container first, ADP containers as fallback), one class per record, so a " +
        "year's shares sum to roughly 100 after rounding. The top 8 are ranked by total " +
        "tagged volume across the last ten complete calendar years; the partial current " +
        "year is excluded from both the window and the ranking. A year is plotted only " +
        "if it has at least 500 tagged " +
        "records. Class names come from a small built-in map in the pipeline; ids the " +
        "map does not know are shown as bare CWE numbers.",
      labels: {
        tipTagged: "{n} tagged ({pct} of {published} published)",
      },
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
        "Months are publication months from {since}, the month " +
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
      labels: {
        tipPublished: "{n} published",
        binRange: "{lo} to {hi}",
      },
    },

    // --------------------------------------------- kev.html · 1 · hero
    latency: {
      num: "01",
      kicker: "Listing latency",
      source: "CISA KEV · cvelistV5 (MITRE)",
      headline: "The median KEV listing comes weeks after the CVE record is published.",
      caption:
        "Days from a CVE record's publication to the day CISA added the CVE to its " +
        "Known Exploited Vulnerabilities (KEV) catalog: median and interquartile range " +
        "(IQR, the middle half) for each year of listing since 2023. Listings from the " +
        "2021–22 seeding era are summarized below the chart. The typical wait has " +
        "{middle_verb}, from a median of {baseline_median} days for {baseline_year} " +
        "listings to {latest_median} for {latest_year}, and the share listed more than " +
        "a year after publication has {tail_verb}.",
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
        "launch through 2022 (dateAdded before {date_added_before}), when CISA was " +
        "importing a backlog of older CVEs. Their median latency is {median_days} days. " +
        "That figure measures the age of the backlog, not the speed of listing, so these " +
        "entries are not plotted.",
      methodology:
        "For every KEV entry that matches a CVE record in the cvelistV5 corpus, latency is " +
        "the KEV dateAdded minus the CVE record's datePublished, in days. The trend starts " +
        "with 2023 listings because the seeding era's pooled median latency runs near two " +
        "and a half years, against {baseline_median} days for {baseline_year} additions. " +
        "Negative latencies are kept: a KEV listing can come before its CVE record is " +
        "published, and flooring those values at zero would hide those listings. A year " +
        "plots only if it has at least 10 matched entries. KEV entries with no matching CVE " +
        "record in the corpus have no publication date; they are counted separately in the " +
        "data file.",
      labels: {
        median: "Median latency",
        tipSpread: "median {median} · IQR {p25}–{p75}",
        tipCount: "{n} matched entries · {before} before publish · {over} over a year",
      },
    },

    // --------------------------------------------- kev.html · 2
    buckets: {
      num: "02",
      kicker: "Latency distribution",
      source: "CISA KEV · cvelistV5 (MITRE)",
      headline: "Since 2023, nearly four in ten KEV listings come within a week of CVE publication, one in seven after three years.",
      caption:
        "The listings in the trend above, grouped by days from CVE publication to KEV " +
        "listing. The red bar counts listings made before the CVE record was published.",
      methodology:
        "Every matched entry added in 2023 or later falls in one bucket by its latency: " +
        "before publish (latency below zero), 0–7d, 8–30d, 31–90d, 91–365d, 1–3y, 3y+. " +
        "Lower edges are inclusive: a listing on day 8 is in 8–30d. Percentages are shares " +
        "of these entries, not of the full catalog.",
      labels: {
        buckets: {
          before_publish: "before publish",
          "0-7d": "0–7d",
          "8-30d": "8–30d",
          "31-90d": "31–90d",
          "91-365d": "91–365d",
          "1-3y": "1–3y",
          "3y+": "3y+",
        },
        tipCount: "{n} entries",
      },
    },

    // --------------------------------------------- kev.html · 3
    remediation: {
      num: "03",
      kicker: "Remediation deadlines",
      source: "CISA KEV",
      headline: "Median remediation deadlines fell from six months in 2021 to three weeks in 2022–2025 and two weeks or less in 2026.",
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
        "as the latency chart), 2021 launch cohort included. Lines are the median span of " +
        "entries added each year; shaded bands span the 25th–75th percentile. Binding " +
        "Operational Directive (BOD) 22-01, which requires federal agencies to meet " +
        "these deadlines, set six months for CVEs with IDs assigned before 2021 and two " +
        "weeks for all others. The chart shows the deadlines CISA assigned, which need " +
        "not match those defaults.",
      labels: {
        median: "Median deadline span",
        tipSpread: "median {median} · IQR {p25}–{p75}",
        tipCount: "{n} entries listed",
      },
    },

    // --------------------------------------------- kev.html · 4
    ransomware: {
      num: "04",
      kicker: "Ransomware share",
      source: "CISA KEV",
      headline: "CISA flags about one KEV entry in five as used in ransomware campaigns.",
      caption:
        "Each KEV entry records whether CISA knows the vulnerability to have been used " +
        "in ransomware campaigns. Bars show the share of each year's listings flagged " +
        "“Known”; the year's counts are in the tooltip. The 2021–22 seeding years are " +
        "included because the flag describes the entry, whenever it was listed. The " +
        "newest bars are lower bounds: CISA sets some flags after listing, often more " +
        "than a year later (the KEV Changelog page measures that lag), so recent years " +
        "rise as flags are added.",
      methodology:
        "Every KEV entry carries knownRansomwareCampaignUse (“Known” or “Unknown”); " +
        "entries missing the field count as “Unknown.” For each calendar year of " +
        "dateAdded the chart reports entries added, entries flagged “Known,” and the " +
        "share. The catalog is read as a current snapshot, so each entry shows CISA's " +
        "present assessment, and an entry flagged next year counts as “Unknown” today. " +
        "No CVE-record join is involved. A year plots only with at least 10 entries. " +
        "The current year (marked *) is partial and refills nightly.",
      labels: {
        tipShare: "flagged for ransomware use",
        tipCount: "{n} of {total} entries added",
      },
    },

    // --------------------------------- concentration.html · 1 · hero
    concentration: {
      num: "01",
      kicker: "Volume concentration",
      source: "cvelistV5 (MITRE)",
      headline: "There are more CNAs than ever, and five of them published most of 2025's CVEs.",
      caption:
        "The number of active CVE Numbering Authorities (CNAs) each year, and the " +
        "share of that year's published records from the top 5 and top 10 of them. " +
        "In the decade to 2023 the top-5 share mostly fell as the program added " +
        "CNAs; from 2023 to 2025 it rose. The number of active CNAs grew " +
        "seventeen-fold between 2015 and 2025.",
      statLabel: "Share of published CVEs from the year's top 5 CNAs",
      statLatest: "{latest_year}",
      statAgo: "{ago_year}",
      linuxNote:
        "Without the kernel the top-5 share also rose from 2023 to 2025, and the " +
        "shares are recomputed over the remaining CNAs.",
      methodology:
        "Each CVE record's assigner (the CNA of record in cvelistV5) is counted by " +
        "original publication year. A CNA is active in a year if it published or " +
        "rejected at least one record that year. Top-5 and top-10 share are the " +
        "fractions of that year's published records from its five or ten largest " +
        "assigners, chosen afresh each year. The Herfindahl–Hirschman Index (HHI), " +
        "the sum of squared shares on the 0–10,000 scale antitrust regulators use, " +
        "was {hhi_latest} for the latest complete year; the data file carries it for " +
        "every year, and the chart does not draw it. The HHI covers every assigner, " +
        "not only the largest, so the two measures can move in opposite directions: " +
        "between 2023 and 2024 the top-5 share rose while the index fell. The current " +
        "year is partial and refills nightly.",
      labels: {
        top5: "Top-5 share",
        top10: "Top-10 share",
        active: "Active CNAs",
      },
    },

    // --------------------------------- concentration.html · 2
    entrants: {
      num: "02",
      kicker: "New entrants",
      source: "cvelistV5 (MITRE)",
      headline: "Each year from 2023 to 2025 added more new CNAs than any year before 2023.",
      caption:
        "Bars count CNAs that published their first CVE record that year; the line is " +
        "the number of active CNAs.",
      methodology:
        "A newcomer in year Y is a CNA whose earliest record in the corpus (published " +
        "or rejected) falls in Y. This is its first appearance in the data; the corpus " +
        "carries no accreditation dates. The active-CNA line counts CNAs with at least " +
        "one published or rejected record that year, the same definition as the " +
        "concentration chart. The current year is partial and refills nightly. The " +
        "hollow extension above the current-year bar paces the newcomer count to " +
        "twelve months: newcomers so far divided by the fraction of the UTC calendar " +
        "year elapsed at generation time, shown only once 12.5% of the year has " +
        "elapsed (roughly mid-February). It assumes newcomers arrive evenly through " +
        "the year and ignores seasonality and late-year backfill. The active-CNA line " +
        "is not projected.",
      labels: {
        firstYear: "First-year CNAs",
        active: "Active CNAs",
      },
    },

    // --------------------------------- concentration.html · 3
    rejection: {
      num: "03",
      kicker: "Rejection board",
      source: "cvelistV5 (MITRE)",
      headline: "Rejection rates differ by more than tenfold between CNAs.",
      caption:
        "Each CNA's records from the last {window_years} years, split into published " +
        "and rejected. A rejected record here is one that was published and later " +
        "marked REJECTED, for example as a duplicate, a withdrawn assignment or a " +
        "dispute settled against it. Rejection is how errors in published records are " +
        "corrected, so a high rate is not by itself a sign of poor practice.",
      colCna: "CNA",
      colTotal: "CVEs (pub+rej)",
      colRejected: "rejected",
      colRate: "rejection rate",
      windowTemplate:
        "CVE record states by assigner · last {window_years} calendar years, the current one included · min {min_total} records (published + rejected)",
      methodology:
        "For each assigner in cvelistV5, records whose original publication year falls " +
        "in the last {window_years} calendar years are counted by state, PUBLISHED or " +
        "REJECTED. Rejection rate is rejected over (published + rejected). CNAs with " +
        "fewer than {min_total} records in the window are excluded, so that a CNA with " +
        "two rejections out of two records cannot top the board. Reserved IDs that " +
        "were rejected without ever being published have no publication date and are " +
        "not counted. Default sort: rejection rate, descending. Click any column " +
        "header to re-sort.",
    },

    // --------------------------------- concentration.html · 4
    cna_profile: {
      num: "04",
      kicker: "CNA profile",
      source: "cvelistV5 (MITRE) · CISA KEV · Exploit-DB (OffSec) · Metasploit (Rapid7) · CyberMon nightly diffs",
      headline:
        "Among CNAs with at least 100 records in five years, some name a weakness " +
        "type (CWE) on fewer than one record in twenty and others on every record.",
      caption:
        "Pick a CNA to set its records published {from}–{to} against every CNA that " +
        "published at least {min_published} records in those years. The top panel " +
        "compares the CNA's CVSS (Common Vulnerability Scoring System) base scores " +
        "with all CNAs' records. In each strip below, every listed CNA is a tick and " +
        "the dashed line is the median CNA; rank 1 is the highest value. CWE is the " +
        "Common Weakness Enumeration. KEV is CISA's Known Exploited Vulnerabilities " +
        "catalog.",
      windowTemplate:
        "Published {from}–{to} · {n} of the {all} CNAs that published in those years had at least {min_published} records",
      nodata: "No CNA published enough records in the window yet.",
      methodology:
        "Records count by original publication year over the last {years} complete " +
        "calendar years, {from}–{to}. A CNA is listed when it published at least " +
        "{min_published} records in that window. CWE, CVSS score and affected-version " +
        "data count only when the CNA's own container carries them; data that CISA or " +
        "another Authorized Data Publisher (ADP) added later is left out. " +
        "Affected-version data counts when an affected entry names a concrete version " +
        "or a definite default status. The score panel uses the CNA-assigned base " +
        "score of each record's newest CVSS version, in whole-point bands. A median " +
        "score is ranked only for CNAs with at least {min_scored} scored records. " +
        "Rejection rate is records later marked REJECTED over published plus " +
        "rejected. Score changes count same-version changes to a CNA-assigned score " +
        "on the nightly rescore log, which began on {log_from}. They cover any of the " +
        "CNA's records, and the count is not scaled by its size. The KEV share counts " +
        "records in CISA's catalog. The exploit share counts records with an " +
        "Exploit-DB entry or a Metasploit exploit module. Tied CNAs share the best " +
        "rank. Recent records have had less time to be exploited, listed or " +
        "rejected. Differences between CNAs mostly follow the products they cover " +
        "and how they run their programs; they are not a measure of intent.",
      labels: {
        searchLabel: "Find a CNA",
        searchPlaceholder: "part of a name",
        selectLabel: "CNA",
        option: "{cna} ({n} records)",
        matches: "{n} of {total} CNAs match",
        noMatch: "No CNA matches; the current one stays selected",
        head: "{cna}: {published} records published {from}–{to}, plus {rejected} published and later rejected.",
        legendMedian: "median CNA",
        legendPeers: "other listed CNAs",
        legendAll: "all CNAs' records (score panel)",
        metrics: {
          score_median: "CVSS base scores the CNA assigned: share of its scored records in each band",
          cwe_pct: "Records with a CWE",
          scored_pct: "Records with a CVSS score",
          affected_pct: "Records with usable affected-version data",
          rejected_pct: "Rejection rate",
          rescores: "Score changes logged since {log_from}",
          kev_pct: "Records in KEV",
          exploit_pct: "Records with public exploit code",
        },
        readout: "{value} · median CNA {median} · {rank}",
        readoutScore: "median score {value} · median CNA {median} · {rank}",
        rank: "rank {rank} of {n}",
        rankTied: "rank {rank} of {n}, tied",
        rankLong: "rank {rank} of {n} CNAs, where 1 is the highest",
        rankLongTied: "rank {rank} of {n} CNAs, where 1 is the highest, tied with {others} other CNAs",
        rankLongTiedOne: "rank {rank} of {n} CNAs, where 1 is the highest, tied with one other CNA",
        unranked: "not ranked",
        alt: "{title}. {cna}: {value}. Median CNA: {median}. {cna} is {rank}.",
        altHist: "{title}. {cna}'s median score: {value}. Median CNA: {median}. {cna} is {rank}. The median of all CNAs' scored records is {all}.",
        altAll: "The median of all CNAs' scored records is {median}.",
        scoreNone: "{cna} put a CVSS score on none of its records.",
        scoreFew: "{cna} scored {scored} records, fewer than the {min_scored} a median needs.",
        hover: "{cna}: {value}",
        histHover: "{band}: {cna} {own} · all CNAs {all}",
        tableSummary: "Score bands as a table",
        colBand: "band",
        colAll: "all CNAs",
      },
    },
    // ------------------------------------------------ breaches.html · 1 · hero
    disclosure: {
      num: "01",
      kicker: "Breach to catalog",
      source: "Have I Been Pwned breach catalog",
      headline: "Since 2014, the median breach has reached HIBP's catalog months after it happened.",
      caption:
        "For each breach in the Have I Been Pwned (HIBP) catalog, the days between the " +
        "date the breach happened and the day HIBP added it, shown as the median and " +
        "interquartile range for each year of cataloging. " +
        "Breaches loaded at the catalog's December 2013 launch are kept out of the trend. " +
        "Roughly a third of entries take more than a year to reach the catalog. The " +
        "median for a single year has ranged from under a week, in 2014, to more than a " +
        "year, in 2017 and 2023. This is the time to a public catalog, not the dwell " +
        "time vendors report from their customers' incidents.",
      statLabel: "Median days from breach to public catalog",
      statWhole: "since {trend_start}",
      statLatest: "{latest_year}",
      importNote:
        "{n} breaches entered the catalog at its December 2013 launch (added before " +
        "{added_before}), with a median nominal lag of {median_days} days. They were " +
        "already public when HIBP imported them, so they are kept out of the trend above.",
      methodology:
        "Lag is a breach's AddedDate minus its BreachDate, in days, for each cohort breach " +
        "in the HIBP catalog (the cohort rules are in the volume chart's methodology). " +
        "BreachDate is HIBP's best estimate of when the incident happened. HIBP's " +
        "documentation says it is not always accurate, and some entries carry only month " +
        "precision, so individual lags are noisy. The line is the median lag of the " +
        "breaches cataloged each year, and the shaded band spans the 25th to 75th " +
        "percentile. The trend starts in 2014. HIBP launched on 2013-12-04 by importing " +
        "breaches that were already public, and six of its seven opening-import entries " +
        "predate the service itself. Older breaches have entered the catalog in every " +
        "year since and stay in the trend; only the launch import is set aside. Negative " +
        "lags (a breach cataloged before its stated breach date) would point to date " +
        "errors in the source record and are kept. A year plots only with at least 10 " +
        "cohort breaches. The current year (marked *) is partial and updates nightly.",
      labels: {
        median: "Median lag",
        tipSpread: "median {median} · IQR {p25}–{p75}",
        tipCount: "{n} breaches · {over} over a year",
        tipNegative: "{pct} before stated breach date",
      },
    },

    // ------------------------------------------------ breaches.html · 2
    exposure: {
      num: "02",
      kicker: "Volume",
      source: "Have I Been Pwned breach catalog",
      headline: "In every complete year since 2014, HIBP loaded tens of millions of breached accounts or more.",
      caption:
        "Bars count the breaches cataloged each year; the line counts the accounts in " +
        "them, on a log axis because one large breach can outweigh a typical year's " +
        "total. Both are lower bounds: the catalog holds only breaches whose data became " +
        "public and was loaded into HIBP. The current year is partial and updates nightly.",
      catalogNote:
        "Cohort: {cohort} of {total} cataloged breaches. Excluded: {fabricated} " +
        "fabricated, {spam_list} spam lists, {malware} malware corpora, {stealer_log} " +
        "stealer-log batches.",
      legendBreaches: "Breaches cataloged",
      legendRecords: "Accounts exposed",
      methodology:
        "Counts come from the full HIBP breach catalog, grouped by the calendar year of " +
        "AddedDate. The cohort excludes, in this order of precedence: fabricated entries " +
        "(IsFabricated), spam lists (IsSpamList, address collections with no breached " +
        "organization), malware corpora (IsMalware) and stealer logs (IsStealerLog). The " +
        "last two hold real credentials stolen from infected devices but no single " +
        "breached organization, and their nominal breach date is when the corpus was " +
        "compiled, which would distort the lag chart. Each excluded entry counts under " +
        "its first matching reason, so the exclusions plus the cohort add up to the " +
        "catalog total. Accounts per year is the sum of PwnCount, HIBP's count of the " +
        "accounts it loaded from each breach. A person appears once for each breach they " +
        "are in, so the sum counts exposures, not people. The December 2013 launch " +
        "additions are charted here like any other year. In the bars, a dashed hollow " +
        "extension projects the partial current year's breach count to twelve months: " +
        "the count so far divided by the fraction of the UTC calendar year elapsed at " +
        "generation time. It is shown only once 12.5% of the year has passed (about " +
        "mid-February) and assumes that cataloging runs at an even rate through the " +
        "year. The accounts line is not projected, because one large breach can carry " +
        "more accounts than the rest of its year combined.",
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
        "addresses appear in at least 95% of the breaches in each complete year since " +
        "2015. Passwords appeared in nine of ten breaches cataloged in 2014, about four " +
        "in ten in 2025, and a lower share in each complete year since 2019. The other " +
        "classes move up and down, some by more than 20 points from one year to the next.",
      methodology:
        "The class list is rebuilt from the data every night: all data classes in the " +
        "cohort are ranked by the number of breaches listing them, and the top six are " +
        "charted. When the ranking changes, the charted lines change with it. Each line " +
        "is the share of that year's cohort breaches, grouped by AddedDate year, whose " +
        "DataClasses field lists the class, counting each class at most once per breach. " +
        "A year plots only with at least 10 cohort breaches, so 2013's seven " +
        "launch-import breaches are not drawn. The current year (marked *) is partial " +
        "and updates nightly.",
      labels: {
        tipBreaches: "{n} breaches",
      },
    },

    // --------------------------------------- extortion.html · 1 · hero
    revenue: {
      num: "01",
      kicker: "Confirmed revenue",
      source: "Ransomwhere (CC0)",
      headline: "Verified ransom payments on the Ransomwhere ledger total over a billion dollars.",
      caption:
        "Bitcoin payments to reported ransomware addresses, summed by the quarter in which " +
        "they were sent and valued at that day's exchange rate. Ransomwhere collects " +
        "crowdsourced reports of extortion addresses, reviews each one before including " +
        "it, and reads the payments from the blockchain. A payment appears only after " +
        "someone reported the receiving wallet, so every bar is a lower bound on ransom " +
        "revenue. The ledger's last verified payment landed in Q3 2024, and the chart " +
        "ends there. The data cannot show whether ransom payments declined after that or " +
        "only the reporting did.",
      statLabel: "Confirmed ransom revenue on the Ransomwhere ledger, all time",
      statNote: "a lower bound: {payments} verified payments; {addresses} addresses tracked",
      methodology:
        "Ransomwhere's CC0 export lists tracked extortion addresses, each with its " +
        "verified inbound transactions. The pipeline adds each transaction's amountUSD to " +
        "the UTC calendar quarter of its on-chain timestamp. amountUSD is Ransomwhere's " +
        "conversion at the BTC/USD rate of the transaction date, so a 2016 payment is " +
        "counted in 2016 dollars. The export lists a transaction once per receiving " +
        "tracked address, so a transfer split across several tracked wallets contributes " +
        "each output it sent to them. Exact repeated entries (about one percent of total " +
        "USD) are summed as published, since they cannot be checked without chain data. " +
        "Every quarter between the first and last observed payment is charted, at zero " +
        "when empty. No full-year projection is drawn for a partial current year, " +
        "because reports arrive late.",
      labels: {
        tipRevenue: "confirmed ransom revenue",
        tipBasis: "dollars at day-of-transfer rates · lower bound",
      },
    },

    // --------------------------------------- extortion.html · 2
    payments: {
      num: "02",
      kicker: "Payments",
      source: "Ransomwhere (CC0)",
      headline: "After 2021 the ledger holds fewer than half as many payments a year as in 2016–2021, at medians more than ten times higher.",
      caption:
        "Bars count verified payments per year; the line is the median payment in " +
        "dollars at the rate of the transfer day, on a log scale. The medians for 2013 to " +
        "2015 (under three dollars) are not ransom amounts: most transfers to the tracked " +
        "wallets in those years were under ten dollars. From 2016 through 2021 the " +
        "ledger holds hundreds to thousands of " +
        "payments a year, with medians between about $90 and $3,500. It holds about 150 " +
        "payments for 2022 and about 20 for each of 2023 and 2024, with medians around " +
        "$100,000 or higher. Thinner crowdsourced " +
        "coverage and changes in how ransomware operates could both lower the recent " +
        "counts, and this dataset cannot separate the two.",
      legendPayments: "Verified payments",
      legendMedian: "Median payment (USD, log)",
      methodology:
        "A payment is one distinct on-chain transaction. The export lists a transaction " +
        "once per receiving tracked address, so transfers split across several tracked " +
        "wallets are merged by transaction hash, with their outputs summed, before " +
        "anything is counted. On current data about 22,000 ledger entries become about " +
        "19,000 payments. Years follow the transaction's on-chain UTC timestamp, and the " +
        "median is taken over per-payment USD at the rate of the transfer day. A year's " +
        "median is plotted only when the year has at least 10 payments; the payment " +
        "count is always plotted. A year is marked * only when it is the partial " +
        "generation year.",
      labels: {
        yAxisMedian: "median USD (log)",
        tipPayments: "{n} verified payments · {usd} total",
        tipMedian: "median payment",
        tipNoMedian: "median not shown (fewer than {n} payments)",
      },
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
        "money. A family's rank depends on how many of its wallets were reported: some " +
        "families have many reported wallets, others one. Revenue with no family label " +
        "is left off the board and given in the note below it.",
      note:
        "{unattributed_usd} ({unattributed_pct} of all confirmed revenue) is verified but " +
        "has no family label, more than any one family's total.",
      colFamily: "Family",
      colUsd: "confirmed USD",
      colPayments: "payments",
      colFirst: "first seen",
      colLast: "last seen",
      otherTemplate:
        "+ {families} more labeled families not shown · {usd} confirmed · {payments} payments",
      methodology:
        "Family names are Ransomwhere's own labels. For each family, confirmed revenue is " +
        "the sum of transaction amountUSD across its addresses at the rate of the " +
        "transfer day. Payments are the distinct transaction hashes among those " +
        "addresses, and first and last seen are the years of its earliest and latest " +
        "verified transactions. The board ranks the top eight labeled families by " +
        "all-time confirmed USD, and every other labeled family is pooled into the line " +
        "below the board. The export's “Unlabeled” bucket (verified payments with no " +
        "attribution) is left out of the ranking. The board ranks all-time totals " +
        "because wallets are often reported long after a campaign ran, so yearly family " +
        "shares would partly chart reporting dates.",
    },

    // --------------------------------------------- attack.html · 1 · hero
    map: {
      num: "01",
      kicker: "Techniques per release",
      source: "MITRE ATT&CK® STIX bundles",
      headline: "ATT&CK's enterprise matrix has more than three times the techniques and sub-techniques of v1.0 in 2018.",
      caption:
        "Active techniques and sub-techniques on the MITRE ATT&CK enterprise matrix, one " +
        "point per release, placed on the release dates in MITRE's release index. " +
        "Sub-techniques now outnumber the techniques they refine, and most of the growth " +
        "since 2018 has been in sub-techniques.",
      statLabel: "Active techniques + sub-techniques, enterprise matrix",
      statLatest: "v{version} ({year})",
      statAgo: "v{version} ({year})",
      legendTechniques: "Techniques",
      legendSubtechniques: "Sub-techniques",
      methodology:
        "Each point is one release of the MITRE ATT&CK enterprise matrix, read from its " +
        "STIX 2.1 bundle (a JSON format for threat data) in the " +
        "mitre-attack/attack-stix-data repository. Its x-position is the release date in " +
        "that repository's index.json, so gaps between points are calendar gaps (major " +
        "releases come about twice a year, with point releases between). One date is " +
        "early. The index gives v7.0, the release that introduced sub-techniques, the " +
        "date of their beta, 2020-03-31. MITRE's versions page dates the release July " +
        "2020, so that step is drawn about three months early. A technique is a STIX " +
        "attack-pattern object whose x_mitre_is_subtechnique flag is false or absent; a " +
        "sub-technique is the same object type with the flag true. Both lines count " +
        "active objects only: objects with revoked: true or x_mitre_deprecated: true are " +
        "excluded here and counted as churn below. The lines step because a release's " +
        "counts hold until the next release.",
      labels: {
        yAxis: "active entries",
      },
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
        "sub-techniques: it added 302 and revoked or deprecated 140.",
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
        "evenly, one slot per release. Gaps between releases range from zero days (two " +
        "point releases on one day) to about half a year; the other two charts on this " +
        "page use a calendar axis.",
      labels: {
        yAxis: "techniques + sub-techniques",
        tipRetired: "({deprecated} deprecated · {revoked} revoked)",
      },
    },

    // --------------------------------------------- attack.html · 3
    catalog: {
      num: "03",
      kicker: "Groups and software",
      source: "MITRE ATT&CK® STIX bundles",
      headline: "ATT&CK lists about three times as many groups and more than four times as many software entries as v1.0 in 2018.",
      caption:
        "Active adversary groups (intrusion sets) and software (malware and tools, " +
        "counted together) per release, on the same release-date axis as the first chart. " +
        "Technique entries cite the groups observed using them and the software that " +
        "implements them.",
      legendGroups: "Groups (intrusion sets)",
      legendSoftware: "Software (malware + tools)",
      methodology:
        "Groups are STIX intrusion-set objects; software is malware and tool objects. " +
        "The same activity rule as the first chart applies: objects with revoked: true " +
        "or x_mitre_deprecated: true are excluded. Campaigns, tactics, mitigations, data " +
        "sources, detection strategies and relationship records in the bundle are not " +
        "counted. Points sit at index.json release dates and step between releases, as " +
        "in the first chart.",
      labels: {
        yAxis: "active entries",
      },
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
        "a resolver configuration setting. The line is APNIC's measured share of " +
        "internet users whose resolvers perform that check; it was under a tenth when " +
        "the record started in 2013. At the average rate of the last ten years, " +
        "reaching every user would take more than twenty years.",
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
        "(code XA), 30-day smoothed window, sampled at the last published day of each " +
        "calendar month. The full daily series is refetched from stats.labs.apnic.net " +
        "every night, so upstream corrections carry through. The stat compares the " +
        "newest month with the month ten years earlier. APNIC states the measurement's " +
        "limits: samples arrive where the ad network delivers, so coverage follows ad " +
        "reach, and APNIC weights each economy's results by its estimated internet " +
        "population. The figures are estimates from hundreds of millions of samples a " +
        "month.",
      labels: {
        validating: "Validating",
        tipShare: "of users behind validating resolvers",
      },
    },

    // --------------------------------------------- hygiene.html · 2
    economies: {
      num: "02",
      kicker: "Ten largest economies",
      source: "APNIC Labs DNSSEC measurement",
      headline: "In the ten largest economies, validation ranges from nine in ten users to almost none.",
      caption:
        "The same measured rate for a fixed set of ten: the economies with the most " +
        "internet users, by APNIC's own weighting. Japan and the United States are both " +
        "below half. The dashed line is APNIC's world rate, which weights each economy " +
        "by its estimated number of internet users.",
      worldLine: "World average",
      note:
        "Lines are quarterly samples of APNIC's 30-day windows. The legend is ordered by " +
        "current rate, highest first.",
      methodology:
        "The set is the ten largest economies by APNIC's weighted sample count (its " +
        "estimate of each economy's internet-user population) when this module launched " +
        "in July 2026: China, India, the United States, Brazil, Indonesia, Japan, " +
        "Mexico, Russia, the Philippines and Nigeria. The list is not re-picked, because " +
        "a changing list would mix changes in membership with changes in adoption. For " +
        "each economy the pipeline pulls APNIC's full daily series and samples the last " +
        "published day of each quarter-end month (30-day smoothed window), plus the " +
        "newest available day. Delivery of APNIC's measurement ads varies by economy, " +
        "and where it is thin the measured rate is noisier; at this module's launch in " +
        "mid-2026, Russia yielded a small fraction of the samples of comparable " +
        "economies.",
    },

    // --------------------------------------------- hygiene.html · 3
    spread: {
      num: "03",
      kicker: "Distribution by economy",
      source: "APNIC Labs DNSSEC measurement",
      headline: "In most measured economies, at least half of users have validating resolvers.",
      caption:
        "Each measured economy, grouped by its current validation rate and counted once " +
        "regardless of size. The user-weighted world rate is lower than this count " +
        "suggests because a few populous economies have low rates, such as China at " +
        "nearly zero.",
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
        "(lower edges inclusive). Values are parsed nightly from the world-map table " +
        "APNIC publishes.",
    },
    // --------------------------------------------- guards.html · 1 · hero
    guards: {
      num: "01",
      kicker: "Security-product share",
      source: "CISA KEV",
      headline: "More than one KEV entry in nine is in a security product.",
      caption:
        "Every entry in CISA's Known Exploited Vulnerabilities (KEV) catalog, classified " +
        "by what the product is for. Bars show the share of each year's listings that " +
        "are security products: VPN appliances, firewalls, endpoint protection, secure " +
        "gateways and similar products sold to enforce security. The stat gives the " +
        "catalog-wide share, and each of the last two complete years was above it.",
      statLabel: "Security products' share of the KEV catalog",
      statNote: "{security} of {total} KEV entries · classifier v{version}, {rules} rules, published in the repo",
      methodology:
        "“Security product” here means a product whose primary function is security " +
        "enforcement or secure access: firewalls and unified threat management (UTM) " +
        "appliances, VPN and secure-access appliances, endpoint protection, email " +
        "security gateways, identity and privileged-access management, mobile device " +
        "management, security operations tooling, and dedicated secure file-transfer " +
        "appliances from security vendors. Where that line falls is a judgment, written " +
        "down as a curated, versioned table (pipeline/security_products.py). Mixed " +
        "vendors get explicit product rules: Cisco counts only its security products " +
        "(ASA, Firepower/FTD, AnyConnect, ISE; not IOS or routers), Microsoft only " +
        "Defender and Forefront TMG (not Exchange), Zyxel only its firewalls, Juniper " +
        "only ScreenOS. Other calls: MOVEit is file transfer; application delivery " +
        "controllers count only where the exploited deployment is a secure-access " +
        "gateway (F5 BIG-IP, Citrix NetScaler); desktop management, remote monitoring " +
        "and remote-support tools are IT operations; mail servers do not count, although " +
        "email security gateways do; backup does not count; Zoho ManageEngine is not " +
        "counted, because the catalog's product labels are too coarse to separate its " +
        "security products. The data file records the classifier version behind its " +
        "numbers. To dispute a call, open an issue; a change to the table reclassifies " +
        "the full history on the next nightly run. Years with fewer than 10 entries do " +
        "not plot. The current year (marked *) is partial and refills nightly.",
      labels: {
        tipShare: "security products",
        tipCount: "{n} of {total} entries added",
      },
    },

    // --------------------------------------------- guards.html · 2
    recidivism: {
      num: "02",
      kicker: "Repeat vendors",
      source: "CISA KEV",
      headline: "For the five most-listed security vendors, the median gap between KEV listings is days to weeks.",
      caption:
        "Every vendor with at least five entries in the catalog, ranked by how many of " +
        "its vulnerabilities CISA has listed, with first and last listing dates and the " +
        "median gap in days between consecutive listings. Rows where security products " +
        "make up at least half the vendor's entries are flagged.",
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
        "last dateAdded, and the median gap in days between consecutive listings. A " +
        "median gap of 0 means at least half of the vendor's listings came on the same " +
        "day as its previous listing. Vendors with fewer than five entries are left off, " +
        "because a median gap needs several listings. Default sort: total entries, " +
        "descending. Click any column header to re-sort.",
    },

    // --------------------------------------------- guards.html · 3
    overlap: {
      num: "03",
      kicker: "Ransomware overlap",
      source: "CISA KEV",
      headline: "KEV entries in security products carry the ransomware flag about twice as often.",
      caption:
        "The share of KEV entries that CISA flags as known to have been used in " +
        "ransomware campaigns, for security products (by the classifier in section 01) " +
        "and for the rest of the catalog.",
      barSecurity: "Security products",
      barOther: "Rest of the catalog",
      methodology:
        "Both bars use the catalog's knownRansomwareCampaignUse field (“Known” against " +
        "anything else; a missing field counts as not Known) over the full current " +
        "catalog. Together the two bars cover the catalog; each bar's entry counts are " +
        "in its tooltip. The flag is CISA's current assessment of each entry and carries " +
        "no date, campaign or victim count.",
      labels: {
        tipShare: "flagged for ransomware use",
        tipCount: "{n} of {total} catalog entries",
      },
    },

    // --------------------------------------------- epss.html · 1 · hero
    grade: {
      num: "01",
      kicker: "Day-before scores",
      source: "EPSS (FIRST.org) · CISA KEV",
      headline: "More than half of scored KEV additions since 2023 had an EPSS score under 1% the day before listing.",
      caption:
        "Each year's additions to CISA's Known Exploited Vulnerabilities (KEV) catalog, " +
        "by their EPSS score the day before listing, in three bands. EPSS, FIRST's " +
        "Exploit Prediction Scoring System, estimates the probability that a CVE is " +
        "exploited in the next 30 days. The chart describes scores before listing; it " +
        "does not test forecast accuracy, because KEV's dateAdded is not the date " +
        "exploitation occurred. The 2022-to-2023 shift coincides with a model change (v2 " +
        "to v3, March 2023) and with the end of the catalog's 2021–22 seeding era, when " +
        "CISA bulk-imported older CVEs; the two cannot be separated here.",
      statLabel: "Scored KEV additions under 1% the day before listing",
      statLatest: "{latest_year}",
      statAgo: "full catalog, all model eras pooled",
      legendBelow: "under 1% the day before",
      legendMid: "1–10%",
      legendAbove: "10% or higher",
      // Filled by the renderer from catalog counts; the pending sentence is
      // appended only while the historical backfill is still incomplete.
      note:
        "{ungradeable} of {total} catalog entries have no day-before score and are not " +
        "in the bands: {before_pub} were listed on or before the day their CVE record " +
        "was published, and the rest had no row in FIRST's data for that day.",
      pendingNote:
        "{pending} entries are still awaiting their historical day-before lookup; the " +
        "numbers on this page cover only the lookups fetched so far.",
      methodology:
        "For each current KEV entry, the pipeline retrieves FIRST's historical EPSS " +
        "score for the day before dateAdded. Bands are shares of entries with a score; " +
        "entries listed on or before their CVE record's publication, unavailable scores " +
        "and pending lookups are counted separately. A year needs at least 10 scored " +
        "entries; the current year is partial. KEV confirms exploitation but gives no " +
        "date for it, so these scores cannot be checked against EPSS's 30-day window: " +
        "the chart is not a calibration test or a false-negative rate. Seeding-era " +
        "entries may concern exploitation years before listing. The published file " +
        "keeps the historical lookups.",
      labels: {
        tipBelow: "under 1%",
        tipMid: "1–10%",
        tipAbove: "10%+",
        tipScored: "{n} scored entries",
        tipNoPrior: "{n} with no prior score",
        tipPending: "{n} awaiting lookup",
      },
    },

    // --------------------------------------------- epss.html · 2
    distribution: {
      num: "02",
      kicker: "Scores by model version",
      source: "EPSS (FIRST.org) · CISA KEV",
      headline: "EPSS v2 scored most of these entries above 1%; v3 scored most below, and v4 about half.",
      caption:
        "The same scored entries in four probability buckets, split by EPSS model " +
        "version. Versions v1 through v5 are different models with different score " +
        "distributions, so they are not pooled. The v5 model has been in use since June " +
        "2026, and so far more than half of its small cohort scored below 1%.",
      methodology:
        "Each scored entry contributes its day-before probability to one bucket: " +
        "under 0.1%, 0.1–1%, 1–10%, or 10% and higher (lower edges inclusive, the same " +
        "buckets as the severity-vs-exploitation grid on the CVE Ecosystem page). The " +
        "historical API does not return the model version, so it is derived from the " +
        "score date using the era table in the data file, checked against the version " +
        "headers of FIRST's daily CSV files: v1 through 2022-02-03, " +
        "v2 (v2022.01.01) through 2023-03-06, v3 (v2023.03.01) through 2025-03-16, " +
        "v4 (v2025.03.14) through 2026-06-14, v5 (v2026.06.15) since. Day-before " +
        "probabilities are stored at five decimals, an exception to CyberMon's " +
        "one-decimal rounding, because the difference between 0.04% and 0.4% is what " +
        "this chart separates.",
      labels: {
        yAxis: "scored entries",
        seriesEra: "EPSS {model} ({from}–{to})",
        seriesModel: "EPSS {model}",
        eraOpen: "now",
        tipCount: "{n} of {total} scored",
        tipBucket: "day-before score {bucket}",
      },
    },

    // --------------------------------------------- epss.html · 3
    percentile: {
      num: "03",
      kicker: "Day-before percentile",
      source: "EPSS (FIRST.org) · CISA KEV",
      headline: "About three in ten scored KEV additions ranked in EPSS's bottom half the day before.",
      caption:
        "The same scored entries by their EPSS percentile the day before listing: the " +
        "share of all CVEs scored that day with an equal or lower score. Unlike raw " +
        "probabilities, percentiles can be compared across model versions. For a typical " +
        "entry in the bottom half, more than a hundred thousand CVEs ranked above it on " +
        "the day before listing.",
      statBig: "{n} of {total}",
      statLead: "scored entries ranked in EPSS's bottom half the day before listing",
      statNote: "median day-before percentile: {median}",
      yAxisLabel: "share of scored entries",
      methodology:
        "Each scored entry contributes the percentile EPSS published with its " +
        "day-before score. FIRST recomputes percentiles daily against that day's full " +
        "set of scored CVEs, so a percentile places an entry in its own day's ranking " +
        "under any model version. Buckets are shares of scored entries. Every scored " +
        "entry carries a day-before percentile, so this chart covers the same entries " +
        "as the two probability charts.",
      labels: {
        tipBucket: "day-before percentile {bucket}",
        tipShare: "of ranked entries",
        tipCount: "{n} of {total} scored entries",
      },
    },

    // --------------------------------------------- calendar.html · 1 · hero
    reservation: {
      num: "01",
      kicker: "ID age",
      source: "cvelistV5 (MITRE)",
      headline: "From 2021 to 2025, about one in five CVEs published each year carried an earlier year's ID.",
      caption:
        "Every CVE ID contains a year (CVE-2025-12345). Under CVE rules that year can " +
        "be the year the ID was reserved or the year the flaw was made public, and " +
        "either can be years before the record is published. The bands split each " +
        "year's newly published records by the age of their ID: same year, one year " +
        "earlier, or two or more years earlier. The 2026 share of earlier-year IDs is " +
        "the lowest since 2008. The age of an ID is not the age of the flaw it describes.",
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
        "IDs stack to 100%; the tooltip carries the counts. CNAs (CVE Numbering " +
        "Authorities, the organizations that assign IDs) reserve blocks of IDs and " +
        "publish against them later, and the Linux kernel CNA gives many years-old " +
        "fixes an ID with the year the fix was made public. An old ID can " +
        "therefore mean a queued reservation, a long coordinated disclosure, a batch " +
        "conversion, or a new record for an old, already public flaw. The rare " +
        "inverse, a next-year ID published in late December, is counted as age zero " +
        "(the corpus currently contains none). Records without a datePublished take " +
        "their year from the ID and count as same-year. A year plots only with " +
        "at least 500 published records. The current year (marked *) is partial and " +
        "refills nightly. The stat compares the latest complete year with the year " +
        "ten years earlier.",
      labels: {
        tipRecords: "{n} records",
      },
    },

    // --------------------------------------------- calendar.html · 2
    weekbeat: {
      num: "02",
      kicker: "Weekday pattern",
      source: "cvelistV5 (MITRE)",
      headline: "In the latest complete year, Tuesday carried about a quarter of all CVE publications.",
      caption:
        "The share of each year's records published on each weekday, for the latest " +
        "complete year and the year a decade before it. In the latest complete year " +
        "Saturday and Sunday carry few records, and a decade earlier the peak sat later " +
        "in the week.",
      weekdayLabels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
      seriesYearLabel: "{year}",
      tooltipN: "{n} dated records in {year}",
      methodology:
        "Each published record with a day-precision datePublished contributes its " +
        "weekday; records without one are left out. Bars are the share of that " +
        "year's dated records on each day. Weekdays are judged in UTC, " +
        "on the date the record carries. A late-evening publication in a US timezone " +
        "falls on the next UTC day, so a Tuesday release in California can count as " +
        "Wednesday here; a publisher east of UTC can shift the other way. The shift " +
        "is not corrected, because the record carries no reliable local timezone. A " +
        "year enters the comparison only with at least 500 dated records.",
    },

    // --------------------------------------------- calendar.html · 3
    patchtuesday: {
      num: "03",
      kicker: "Patch Tuesday",
      source: "cvelistV5 (MITRE)",
      headline: "In the latest complete year, Patch Tuesdays carried two to three times their calendar share of CVEs.",
      caption:
        "Microsoft releases security updates on the second Tuesday of each month, and " +
        "several other vendors, Adobe and SAP among them, publish on the same day. " +
        "Bars show the share of each year's published records that land on those " +
        "twelve days. The dashed line, 3.3 percent, is the share twelve days out of " +
        "365 would hold if publication were spread evenly over the year. The bar has " +
        "cleared that line in every complete year since 2014. Tuesday has been the " +
        "busiest weekday since 2022, so a dotted step line shows what the same twelve " +
        "days would carry as ordinary Tuesdays in the same year. Every year since " +
        "2019 the bar has cleared what its own ordinary Tuesdays would carry.",
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
        "is 12 of 365 days (12 of 366 in a leap year also rounds to 3.3%). The dotted " +
        "baseline is the ordinary-Tuesday share: within the year's observation window " +
        "(first to last dated record), the records on the other Tuesdays are averaged " +
        "per Tuesday, multiplied by the window's count of Patch Tuesdays and divided " +
        "by the year's dated records. Tuesdays are counted from the actual dates, and " +
        "the baseline is left empty when the window holds no other Tuesday. The " +
        "excess over the Tuesday line is not attributed to a cause, and the share " +
        "published on release days says nothing about the records' severity or " +
        "exploitation. The tooltip also names the year's busiest single publication " +
        "day. UTC day boundaries as in the weekday chart. A year plots " +
        "only with at least 500 dated records. The current year (marked *) is " +
        "partial and refills nightly.",
    },

    // --------------------------------------------- rescores.html · 1 · hero
    week: {
      num: "01",
      kicker: "Edits per week",
      source: "cvelistV5 (MITRE) · CyberMon nightly diffs",
      headline: "CNAs change severity scores on CVE records after publication.",
      caption:
        "Each night CyberMon compares every CVE record's severity score, as set by " +
        "its CVE Numbering Authority (CNA), with the previous night's. In the lower " +
        "panel, bars above the line are scores raised and bars below are scores " +
        "lowered. The upper panel counts first scores added to existing records, " +
        "CVSS version changes and removed scores.",
      legendUp: "Score raised",
      legendDown: "Score lowered",
      legendFirst: "First score backfilled",
      legendShift: "CVSS version shift",
      legendRemoved: "Score removed",
      statLabel: "Events on the log",
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
        "record carries, read the same way as on the CVE Ecosystem page's CVSS " +
        "charts. Tonight's fingerprints are compared with the previous night's, " +
        "which are stored in the repository together with the corpus release tag. " +
        "A re-run against the same release is detected and skipped, so no night is " +
        "counted twice. A changed score on the same CVSS version is a rescore, " +
        "raised or lowered. A change in the record's newest scored version is a " +
        "version shift; shifts are logged separately and not charted as raised or " +
        "lowered, because each CVSS version computes the score with its own formula. " +
        "The version is the exact one the record names, so a 3.0-to-3.1 re-issue is " +
        "also a version shift. Before 2026-09-20 the log stored only the version " +
        "family (v3 or v4), so until then a 3.0-to-3.1 re-issue that changed the " +
        "score was logged as a rescore, and one that kept the score was not " +
        "logged. A record gaining its first CNA-assigned score is " +
        "counted separately as a backfill; a score disappearing from a live record " +
        "is logged as removed. Brand-new records produce no event. Events are " +
        "appended to a CSV in the repository (data/history/rescore_log.csv), and the " +
        "comparison state is stored beside it, so the two cannot diverge. They " +
        "diverged once, in July 2026, while the state was cached outside the " +
        "repository, and the duplicated events were removed from the log. If the " +
        "state is lost, it is rebuilt from that night's corpus and that night logs " +
        "zero events, so at most one night of edits goes unrecorded. Bars group by " +
        "ISO week of the observation date (UTC); the current week keeps filling " +
        "until it closes.",
    },

    // --------------------------------------------- rescores.html · 2
    magnitude: {
      num: "02",
      kicker: "Magnitude",
      source: "cvelistV5 (MITRE) · CyberMon nightly diffs",
      headline: "Most rescores lower the score, and most move it by less than two points.",
      caption:
        "Each bar counts rescores by their change: the new score minus the old, on " +
        "the same CVSS version. The buckets separate changes of under two points " +
        "from changes of four points or more.",
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
        "Delta is the new score minus the old for each rescore event. Since " +
        "2026-09-20 both scores are on the same exact CVSS version, so a 3.0-to-3.1 " +
        "re-issue is a version shift and is not charted here. Rescores logged " +
        "before that date matched on version family only (v3 or v4). Deltas fall into " +
        "fixed signed buckets (−4 and under, over −4 to −2, over −2 to −0.1, +0.1 to " +
        "under +2, +2 to under +4, +4 and over) at the scores' one-decimal " +
        "precision. A delta of zero cannot occur, since an unchanged score is not an " +
        "event. The distribution and its median are drawn once the log holds at " +
        "least 30 rescores; until then the panel shows the count.",
    },

    // --------------------------------------------- rescores.html · 3
    editors: {
      num: "03",
      kicker: "Rescores by CNA",
      source: "cvelistV5 (MITRE) · CyberMon nightly diffs",
      headline: "A handful of CNAs made most of the rescores logged since July 2026.",
      caption:
        "Each rescore is filed under the CNA named as assigner on the record the night " +
        "the edit was seen. That CNA is responsible for the score but may not be " +
        "the party that made the change. The board counts rescore events per CNA, " +
        "split into raised and lowered.",
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
        "The board counts each CNA's rescore events across the whole log, with no " +
        "rolling window, split by direction. Version shifts, backfilled first scores " +
        "and removals are excluded. CNAs with fewer than 3 logged rescores are left " +
        "off the board. Default sort: rescore count, descending. Click any column " +
        "header to re-sort.",
    },

    // --------------------------------------------- changelog.html · 1 · hero
    edits: {
      num: "01",
      kicker: "Catalog edits",
      source: "CISA KEV · CyberMon nightly diffs",
      headline: "CISA edits KEV entries in place after they are published.",
      caption:
        "Edits per month to entries already in CISA's Known Exploited Vulnerabilities " +
        "(KEV) catalog: remediation deadlines moved, ransomware flags changed, text " +
        "revised and entries removed. The catalog page and feed carry no changelog; " +
        "CyberMon compares each catalog with the previous one it saw and logs every " +
        "difference by field.",
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
        "(data/history/kev_changelog.csv). The catalog feeds carry only the current " +
        "snapshot, and CISA's kev-data git repository keeps whole-file commits, not " +
        "per-field events. A missing ransomware flag reads as “Unknown,” so the first " +
        "capture carrying that column logged a flip for each entry already flagged as " +
        "Known; section 02 names that step month and keeps it out of its statistics, " +
        "while the edit total above includes it. Additions are logged but not charted " +
        "as edits; removals are charted here and listed by name in section 04. Events " +
        "carry a granularity flag. “Daily” events are dated to the nightly run that first saw them (if the " +
        "pipeline misses nights, changes pool on the next run's date). “Capture” " +
        "events come from the one-time Internet Archive backfill; with weeks to months " +
        "between captures, a capture-era month is a lower-resolution bucket, and a " +
        "single-capture spike can be one bulk revision by CISA. The record's first " +
        "observation is a baseline: it writes the fingerprints and logs nothing.",
      labels: {
        tipTotal: "{n} edits",
      },
    },

    // --------------------------------------------- changelog.html · 2
    flagflip: {
      num: "02",
      kicker: "Ransomware-flag flips",
      source: "CISA KEV · CyberMon nightly diffs",
      headline: "CISA has changed the ransomware flag to “Known” on more than a hundred KEV entries after listing them.",
      caption:
        "Each KEV entry records whether CISA knows the vulnerability to have been used " +
        "in ransomware campaigns (“Known” or “Unknown”; the feed had no such field " +
        "before October 2023). Bars count the changes from “Unknown” to “Known” " +
        "(flips) observed each month on entries already listed, and the line " +
        "accumulates them.",
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
        "entry's dateAdded to the date the flip was first observed, so it is an upper " +
        "bound. CISA added the ransomware column to the feed in October 2023, so the " +
        "first capture carrying it logs a flip for each entry already flagged at that " +
        "point: the step at the start of the curve. For those entries the gap mostly " +
        "measures how long the entry sat in the catalog before the column existed. The " +
        "median is published only with at least 10 observed flips. Flips back to " +
        "“Unknown” are reported in the data file as reversals, separately from the " +
        "total.",
    },

    // --------------------------------------------- changelog.html · 3
    flaglag: {
      num: "03",
      kicker: "Time to the flag",
      source: "CISA KEV · CyberMon nightly diffs · Internet Archive captures",
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
        "“Unknown” to “Known” on an entry already in the catalog, minus the step-month " +
        "flips described in section 02. The lag is the flip's first observation date " +
        "minus the entry's dateAdded, in days. “Daily” flips were seen by the nightly " +
        "diff and are accurate to the day; “capture” flips come from the Internet " +
        "Archive backfill and can trail the real change by weeks to months. For " +
        "entries listed before CISA added the column in October 2023, the lag includes " +
        "time before the flag existed. The listing-year view groups flips by the year " +
        "of dateAdded; its median and quartiles are published only with at least 10 " +
        "flips in the year. A flip that later went back to “Unknown” stays in the " +
        "cohort and is counted separately.",
    },

    // --------------------------------------------- changelog.html · 4
    receipts: {
      num: "04",
      kicker: "Most-edited entries",
      source: "CISA KEV · CyberMon nightly diffs",
      headline: "Some KEV entries have been edited eight or more times after listing.",
      caption:
        "The twelve entries with the most logged edits since listing (the one-time " +
        "ransomware-flag step of December 2023 included) and, below them, every entry " +
        "observed leaving the catalog. A removed entry no longer carries a federal " +
        "remediation deadline under Binding Operational Directive 22-01.",
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
        "“last change” is the date of the entry's most recent logged edit, which for " +
        "capture-era edits is the first capture showing it. Removals come from the " +
        "pipeline's removal ledger: an entry present in one observation and absent " +
        "from the next is logged as removed and kept on this list even if it later " +
        "returns (the return is logged as a new addition).",
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
        "Blizzard, Sofacy and STRONTIUM. This table counts the names besides the " +
        "canonical one. MITRE notes that an associated name may describe an " +
        "overlapping activity cluster rather than the same group.",
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
        "Roughly four in ten groups have none in ATT&CK, and a short tail of groups " +
        "has ten or more.",
      xAxis: "alternate names per group",
      yAxis: "tracked groups",
      nodata: "Not enough data yet.",
      methodology:
        "The same active intrusion sets as the table above, grouped by how many " +
        "alternate names each has. Every count from zero to the maximum is shown, " +
        "including empty ones. The zero bucket (groups ATT&CK lists under a single " +
        "name) is drawn muted.",
      labels: {
        groups: "Tracked groups",
        tipName: "{n} alternate name",
        tipNames: "{n} alternate names",
        tipGroup: "{n} tracked group",
        tipGroups: "{n} tracked groups",
      },
    },

    // --------------------------------- top25.html · 1 · hero
    top25_ranks: {
      num: "01",
      kicker: "Official rank vs. measured rank",
      source: "CVE List V5 (MITRE) · CISA KEV · CWE Top 25 (MITRE)",
      headline: "The CWE Top 25 order differs from weakness frequency in CVE records.",
      caption:
        "MITRE publishes the CWE Top 25 each year, ranking the Common Weakness " +
        "Enumeration (CWE) classes it considers most dangerous. The table sets each " +
        "class's official rank beside its measured rank: how often the class is the " +
        "first-listed CWE on a published CVE record. The two orders differ, and not " +
        "every official pick ranks among the 25 most common weaknesses in the " +
        "measured window. MITRE multiplies each class's frequency in the National " +
        "Vulnerability Database (NVD) by the average CVSS severity of its CVEs over " +
        "one year; the measured rank counts frequency alone over five years. A gap " +
        "between the two ranks reflects these different definitions, not an error " +
        "in MITRE's list. KEV hits are the class's entries in CISA's Known Exploited " +
        "Vulnerabilities (KEV) catalog.",
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
        "The official column is MITRE's CWE Top 25, copied by hand from " +
        "cwe.mitre.org/top25; the year above the table is the newest list copied. " +
        "The measured column ranks every weakness class that appears as the " +
        "first-listed CWE on a published CVE record over the last five complete " +
        "calendar years, by how often it appears. An official pick can land " +
        "anywhere in that ranking; a class that is never the first-listed CWE in " +
        "the window is shown as “outside.” The CWE is read from the container of " +
        "the assigning CVE Numbering Authority (CNA), or from CISA's ADP container " +
        "when the CNA lists none. Prevalence is the class's share of all CWE-tagged " +
        "published records in the window. KEV hits count the class among KEV " +
        "entries that match a corpus record, from all years, not only the window. " +
        "MITRE's published methodology multiplies each CWE's normalized frequency " +
        "among NVD CVEs in a one-year window (June 1, 2024 through June 1, 2025 for " +
        "the 2025 list) by the normalized average CVSS v3 base score of those CVEs. " +
        "Its mapping review can consider several CWE mappings per record, and KEV " +
        "counts are shown beside its list but are not an input to its score. " +
        "Recomputed nightly. Click a column header to sort.",
    },

    // --------------------------------- top25.html · 2
    top25_exploited: {
      num: "02",
      kicker: "Official classes in KEV",
      source: "CVE List V5 (MITRE) · CISA KEV · CWE Top 25 (MITRE)",
      headline:
        "Almost every CWE Top 25 class appears in KEV, from over a hundred entries " +
        "for some classes to one or none for others.",
      caption:
        "The same official Top 25, counted against the KEV catalog. Each bar is the " +
        "number of KEV entries whose first-listed weakness is that class; classes " +
        "with no KEV entry are drawn in gray.",
      statTemplate:
        "{in_kev} of {total} official classes appear in the exploited set · " +
        "together {coverage} of CWE-tagged KEV entries",
      xAxis: "exploited (KEV) entries",
      nodata: "Not enough data yet.",
      methodology:
        "Each bar is one of the official Top 25 classes: the number of KEV entries " +
        "whose first-listed CWE (CNA container preferred, CISA-ADP as fallback) is " +
        "that class. Only KEV entries that match a published record in the CVE " +
        "corpus carry a CWE here, so the counts are a lower bound. Bars are sorted " +
        "by count, highest first. The combined share above the chart is the share " +
        "of all CWE-tagged KEV entries whose class is on the official list. " +
        "Recomputed nightly.",
      labels: {
        series: "Exploited (KEV) entries",
        tipEntry: "{n} exploited (KEV) entry",
        tipEntries: "{n} exploited (KEV) entries",
        tipShare: "{pct} of tagged KEV entries · official rank #{rank}",
      },
    },

    // --------------------------------- adp.html · 1 · hero
    adp_handoff: {
      num: "01",
      kicker: "Enrichment by month",
      source: "CVE List V5 (MITRE) — CISA-ADP containers",
      headline: "Since mid-2024, CISA has enriched more than half of all published CVE records.",
      caption:
        "An Authorized Data Publisher (ADP) adds its own container to a CVE record, " +
        "separate from that of the CVE Numbering Authority (CNA) that assigned the " +
        "ID. Each bar counts the records whose CISA-ADP block, the container CISA's " +
        "Vulnrichment program adds, was last updated that month. The date is the " +
        "block's dateUpdated, a last-modified date: a record updated again moves to " +
        "the later month, so early months are lower bounds. The series starts at " +
        "Vulnrichment's 2024 launch. Red bars mark back-fill months, when at least " +
        "half of the month's enrichments went to old CVEs.",
      statLabel: "Share of published CVE records carrying a CISA-ADP block",
      statNote: "{cisa} of {total} published records carry a CISA-ADP block",
      partialMonth: "month in progress",
      sweepTooltip: "Back-fill month",
      sweepNote:
        "A newly published record with an old ID, enriched the same month, also " +
        "counts as an old CVE, so a red month is not proof of a bulk pass over old " +
        "records.",
      nvdContext:
        "For comparison, NVD's analysis backlog stands at {backlog} CVEs in " +
        "tonight's edition.",
      nodata: "Not enough data yet.",
      methodology:
        "Every published CVE record is checked for a CISA-ADP container, matched by " +
        "its provider shortName “CISA-ADP” or by the Vulnrichment orgId. Each such " +
        "record is placed in the month of that container's own dateUpdated, not the " +
        "CVE's datePublished: CISA adds blocks to older records (a 2019 CVE's " +
        "CISA-ADP block can be dated 2025), so a publication-date axis would show " +
        "CISA activity before 2024 that did not happen then. A month is flagged as a " +
        "back-fill month (red) when it has at least 50 enrichments and at least half " +
        "of them went to old CVEs, whose ID year is two or more years before the " +
        "enrichment year. The series starts at the first month with at least 50 " +
        "enrichments and continues without gaps to the latest month. The NVD backlog " +
        "figure shown for comparison is read from the current nvd_decay.json and " +
        "left out when that file was carried forward from an earlier night. " +
        "CyberMon's NVD backlog record begins in July 2026, so there is no 2024 NVD " +
        "series to chart beside this one.",
      labels: {
        enriched: "Enriched",
        tipEnriched: "records enriched",
        tipParts: "SSVC {ssvc} · CVSS {cvss} · CWE {cwe}",
        tipLegacy: "{legacy} of {enriched} on legacy CVEs",
      },
    },

    // --------------------------------- adp.html · 2
    adp_adds: {
      num: "02",
      kicker: "Fields added",
      source: "CVE List V5 (MITRE) — CISA-ADP containers",
      headline: "Nearly every CISA-ADP block carries SSVC decision points.",
      caption:
        "Of the records CISA enriched, the share carrying each machine-readable " +
        "addition. SSVC decision points are CISA's assessment of exploitation, " +
        "automatability and technical impact. A CVSS score and a CWE weakness class " +
        "each appear on about a fifth of the records. A record can carry all three, " +
        "so the bars do not sum to 100.",
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
        "CISA-ADP records carrying that field. The denominator is every published " +
        "record with a CISA-ADP block, whether or not its container is dated.",
      labels: {
        share: "Share",
        tipShare: "of CISA-ADP records",
        tipCount: "{n} of {total}",
      },
    },

    // --------------------------------- adp.html · 3
    adp_providers: {
      num: "03",
      kicker: "ADP publishers",
      source: "CVE List V5 (MITRE) — ADP containers",
      headline: "CISA adds almost all of the substantive ADP enrichment on CVE records.",
      caption:
        "The board ranks ADP publishers by the records where they added SSVC " +
        "decision points, a CVSS score or a CWE; references alone do not count. One " +
        "other publisher does so: Red Hat's supplier ADP (redhat-SADP), which " +
        "covers products Red Hat ships, on well under 1% of records. The CVE " +
        "Program's own ADP container (the “CVE Program Container”) adds only " +
        "references, so it does not appear.",
      statTemplate: "{shown} ADP publishers with substantive enrichment · CISA-ADP on {pct} of the published corpus",
      colProvider: "Publisher",
      colRecords: "records",
      colShare: "% of corpus",
      nodata: "Not enough data yet.",
      methodology:
        "Each published record's ADP containers are read for their provider " +
        "shortName. A publisher is credited with a record when its container adds " +
        "SSVC decision points, a CVSS score or a CWE. Share is of all published " +
        "records in the cvelistV5 corpus.",
    },

    // --------------------------------- epssvol.html · 1 · hero
    epssvol_gap: {
      num: "01",
      kicker: "Percentile vs probability",
      source: "EPSS (FIRST.org) · CyberMon nightly diffs",
      headline: "On an average night, EPSS percentiles move for nearly all CVEs and probabilities for about 1%.",
      caption:
        "EPSS, FIRST's Exploit Prediction Scoring System, publishes two figures per " +
        "CVE: a probability of exploitation in the next 30 days and a percentile " +
        "that ranks that probability against all other scored CVEs. The two lines " +
        "are the nightly shares of compared CVEs whose percentile and whose " +
        "probability changed. A percentile can change while the probability stays " +
        "the same, because other CVEs' scores move and the scored set grows by a " +
        "few hundred CVEs a day.",
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
      statLabel: "Average share of compared CVEs whose EPSS percentile moved overnight",
      statVersus: "vs {prob} whose probability moved · {days} clean nights on record",
      legendPct: "Percentile moved",
      legendProb: "Probability moved",
      yAxisLabel: "share of compared CVEs",
      methodology:
        "Each night the pipeline compares every CVE's raw probability and published " +
        "percentile in the EPSS feed with the previous night's values. A re-run " +
        "against the same EPSS score_date is skipped, so no night is counted twice. " +
        "Only CVEs present on both nights are compared; new arrivals have no prior " +
        "value, but they shift the percentiles of the rest. “Moved” means the value " +
        "changed at the five-decimal precision EPSS publishes. FIRST recomputes " +
        "every percentile nightly against that day's full set of scored CVEs; the " +
        "probability is the model's estimate for that CVE alone. Three kinds of " +
        "night are excluded from every chart on this page and listed with their " +
        "reason in the data file's catalog block. The first is a night on which the " +
        "feed's model_version changed, since a new model rescores the whole corpus. " +
        "The second is a night whose diff pools more than one snapshot because the " +
        "runs before it failed. The third is an anomalous night, on which the share " +
        "of probabilities that moved is more than five times the clean-night median " +
        "(and above five percent) with no model change. This rule covers " +
        "corpus-wide jumps like those first seen in August 2026, when about one CVE " +
        "in eight moved and then moved back. Excluded and missed nights are left " +
        "off the date axis, not drawn as gaps. This measures how often EPSS values " +
        "change, not whether the model is right.",
      labels: {
        quarantineReasons: {
          reset: "model reset",
          gap: "pooled",
          anomaly: "anomalous",
        },
      },
    },

    // --------------------------------- epssvol.html · 2
    epssvol_churn: {
      num: "02",
      kicker: "Threshold crossings",
      source: "EPSS (FIRST.org) · CyberMon nightly diffs",
      headline: "Crossings of the 0.1%, 1% and 5% probability thresholds are rare next to percentile moves.",
      caption:
        "These bars count CVEs whose raw probability crossed 0.1%, 1% or 5%, in " +
        "either direction, summed per week. Over the clean nights, crossings number " +
        "fewer than one for every thousand percentile changes. Weeks differ in how " +
        "many clean nights they sum; the tooltip gives each week's count.",
      legendLo: "crossed 0.1%",
      legendMid: "crossed 1%",
      legendHi: "crossed 5%",
      yAxisLabel: "CVEs crossing a threshold",
      emptyChart:
        "No diff-nights on the log yet; crossings appear once there are two nights " +
        "to compare.",
      methodology:
        "For each CVE compared on two consecutive nights (rules and exclusions in " +
        "section 01's methodology), the pipeline checks whether its raw probability " +
        "crossed 0.001, 0.01 or 0.05: at or above the threshold on one night and " +
        "below it on the other. The three counts are independent, so a jump from " +
        "near zero to above 5% counts under all three. Bars sum the nightly counts " +
        "by ISO week of the observation date (UTC). The week in progress is starred, " +
        "and a week with no observed night would chart at zero. The thresholds are " +
        "CyberMon's choice, not FIRST's.",
      labels: {
        tipNight: "{n} night",
        tipNights: "{n} nights",
      },
    },

    // --------------------------------- epssvol.html · 3
    epssvol_movers: {
      num: "03",
      kicker: "Biggest single-night moves",
      source: "EPSS (FIRST.org) · CyberMon nightly diffs",
      headline: "The twenty largest single-night EPSS probability moves each exceed 25 percentage points.",
      caption:
        "The largest single-night changes in raw EPSS probability on record, ranked " +
        "by size. Each row is the largest move of one night, so a night with " +
        "several large moves shows only its largest. On most clean nights some " +
        "CVE's probability moves by ten percentage points or more, but it is one " +
        "CVE among the hundreds of thousands compared.",
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
        "among the CVEs compared that night. The board ranks these nightly maxima by " +
        "absolute size and keeps the largest twenty at or above a minimum move of 10 " +
        "percentage points (min_delta in the data file). Probabilities are shown as " +
        "percentages to three decimals and moves in percentage points. Nights " +
        "excluded under section 01's rules contribute no rows.",
    },

    // --------------------------------- roster.html · 1 · hero
    roster_size: {
      num: "01",
      kicker: "Roster over time",
      source: "CVE.org organization roster · CyberMon nightly snapshots",
      headline: "The CVE Program roster has grown since tracking began in July 2026.",
      caption:
        "The CVE Program's roster lists every partner organization: the CVE " +
        "Numbering Authorities (CNAs) that assign IDs, plus the roots, Authorized " +
        "Data Publishers (ADPs) and the secretariat. It gives no date for when an " +
        "organization joined, left or changed scope. CyberMon reads the roster " +
        "every night, and the line shows how many organizations it lists, from the " +
        "first tracked night.",
      yAxis: "organizations",
      statLabel: "Organizations on the roster",
      statSince: "tracked since {first_date}",
      statNet: "net {net} since {first_date}",
      // {first_date} is filled from the data (the record's first snapshot
      // date); the empty variant renders while there is only one snapshot.
      note:
        "CyberMon has taken a nightly snapshot since {first_date}; the line has " +
        "one point per snapshot.",
      noteEmpty:
        "CyberMon's record starts with tonight's snapshot; the line begins once " +
        "there are two nights to compare.",
      emptyChart:
        "No snapshots on the record yet; the size series begins tonight.",
      methodology:
        "Each night the pipeline fetches the CVE Program's published organization " +
        "roster, the same CNAsList.json that feeds the List of Partners on cve.org, " +
        "and reduces it to one fingerprint per organization, keyed by the shortName " +
        "the organization uses on CVE records. The count of organizations is " +
        "appended to a size history stored in the repository " +
        "(data/history/cna_roster_state.json), and the line is drawn from it. A " +
        "night without a snapshot has no point, and the axis closes up around it. " +
        "The roster file's git history (CVEProject/cve-website) holds earlier " +
        "edits, but this log has not imported it, so the series begins with " +
        "CyberMon's first snapshot. A fetch that returns less than half of the " +
        "previous roster is treated as broken and is not charted.",
      labels: {
        size: "Roster size",
        tipOrgs: "{n} organizations",
      },
    },

    // --------------------------------- roster.html · 2
    roster_flux: {
      num: "02",
      kicker: "Onboardings & departures",
      source: "CVE.org organization roster · CyberMon nightly snapshots",
      headline: "Since July 2026, more organizations have joined the CVE roster than left it.",
      caption:
        "Organizations that joined or left the roster each month: joins stack above " +
        "the line, departures below it. Scope changes and renames stack in a " +
        "separate bar; a shortName that changes while the organization stays counts " +
        "as one rename. A join is dated to the night the organization first " +
        "appeared in CyberMon's snapshots, not to its accreditation, which the " +
        "program does not date.",
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
        "reconciliation, rows are only ever added. Bars group by calendar month of " +
        "the observation date, with empty months shown at zero. The first run " +
        "logged nothing, because there was no earlier snapshot to compare.",
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
        "provider and others. An organization can list more than one type, so the " +
        "bars sum to more than the roster total. The total counts every " +
        "organization listed, including the roots, ADPs and secretariat. Nearly all " +
        "of the listed organizations hold an assigning role (CNA or CNA-LR, a CNA of " +
        "Last Resort); that count is shown beside the total. Two top-level roots, " +
        "MITRE and CISA, oversee the rest.",
      statTemplate:
        "{total} organizations listed, {assigning} with an assigning role · " +
        "{countries} countries · top-level roots MITRE {mitre} / CISA {cisa}",
      xAxis: "organizations",
      nodata: "Not enough data yet.",
      methodology:
        "The composition is read from tonight's roster fetch, so unlike the two " +
        "charts above it is complete from the first night. Each organization's " +
        "CNA.type list is tallied once per listed type. The assigning count is the " +
        "organizations whose program roles include CNA or CNA-LR. The country count " +
        "and the MITRE / CISA split use each organization's listed country and " +
        "top-level root; an organization listed without one is left out.",
      labels: {
        orgs: "Organizations",
        tipOrgs: "{n} organizations",
        tipShare: "({pct}% of roster)",
      },
    },

    // --------------------------------- exploits.html · 1 · hero
    poc_gap: {
      num: "01",
      kicker: "Days to first public exploit",
      source: "Exploit-DB (OffSec) · cvelistV5 (MITRE)",
      headline: "Since 2022, the median first public exploit has come two weeks or more after the CVE record.",
      caption:
        "For every CVE with dated public exploit code (a proof of concept, or PoC): " +
        "the days from the CVE record's publication to the first public exploit, as " +
        "a median and interquartile range per publication year. Values below zero " +
        "mean the exploit was public before the CVE record. In the program's first " +
        "years the median was deeply negative: early CVE records catalogued exploits " +
        "that already existed. From the mid-2000s through 2020 the median sat within " +
        "a month of zero, and in most of those years it was negative. Since 2021 the " +
        "median has been positive. Only the 2024 cohort has a median above three " +
        "months. The cohorts since 2021 hold one to three hundred CVEs each, and the " +
        "youngest are still being indexed by the archive. This is public exploit " +
        "code in one archive, not exploitation in the wild, which vendors measure " +
        "from incident data and report as faster.",
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
        "used. Metasploit's module metadata carries a disclosure_date, which records " +
        "when the vulnerability was disclosed rather than when the module shipped. A " +
        "Metasploit exploit module therefore counts as public exploit code for its CVE " +
        "but never dates it, and a CVE with only a Metasploit module is absent from " +
        "this chart. Nuclei templates are detection checks, not exploits, and carry no " +
        "date; they appear only as a separate count in the severity chart's tooltip. " +
        "The gap is the Exploit-DB date minus the CVE record's datePublished, in days, " +
        "grouped by the CVE's publication year; a year plots only with at least 10 " +
        "matched CVEs. Negative gaps (an advisory shipped with its exploit, or an old " +
        "exploit assigned a CVE years later) are kept, not floored at zero. " +
        "Placeholder dates are treated as absent. The current year (marked *) is " +
        "partial. Limits: this counts public exploit code that one archive dates, a " +
        "lower bound that misses private exploits and code published elsewhere. The " +
        "cohort is self-selected: only a few percent of records ever get a tracked " +
        "public exploit, so the chart describes the CVEs that attracted one, and " +
        "recent years are also right-censored (a young CVE has had less time to " +
        "attract code). The source has also shrunk: the dated cohort per year is now " +
        "well under a fifth of its late-2000s size, so a trend here is also a trend " +
        "in what Exploit-DB indexes.",
      labels: {
        median: "Median gap",
        tipSpread: "median {median} · IQR {p25}–{p75}",
        tipCount: "{n} matched CVEs · {before} PoC before publish · {week} by day 7",
      },
    },

    // --------------------------------- exploits.html · 2
    poc_preempt: {
      num: "02",
      kicker: "Exploit code before KEV listing",
      source: "CISA KEV · Exploit-DB (OffSec)",
      headline: "Since 2023, public code preceded about half of KEV listings with a dated exploit.",
      caption:
        "CISA's Known Exploited Vulnerabilities (KEV) catalog lists vulnerabilities " +
        "the U.S. government has confirmed are exploited in the wild. For KEV entries " +
        "whose CVE has a dated public exploit, each bar is the share whose exploit code " +
        "was public before the day CISA listed the entry. The 2021–22 seeding years are " +
        "drawn muted: the catalog's launch imported years-old CVEs, and their exploit " +
        "code, where dated, almost always came first.",
      note:
        "Since {cutoff_year}: for {trend_pct} of the {trend_n} KEV listings with a " +
        "dated public PoC, the code was published before the listing day.",
      methodology:
        "Each KEV entry is joined to the first Exploit-DB date used in the chart " +
        "above. An entry counts toward the share when that date is strictly earlier " +
        "than the catalog's dateAdded; a PoC published on the listing day does not " +
        "count. The denominator is entries with a dated PoC, roughly a quarter of the " +
        "catalog; an entry with no tracked public exploit gives no information on " +
        "which came first and is excluded. Entries added before 2023-01-01, the " +
        "2021–22 seeding era (the same cutoff the KEV Latency module uses), are kept " +
        "out of the headline figure. A year plots only with at least 10 matched " +
        "entries. The exploit side has the limits of the chart above: tracked public " +
        "code only, so the share is a lower bound on how often exploit code was " +
        "public before the listing.",
      labels: {
        tipShare: "had public exploit code first",
        tipCount: "{n} of {matched} matched · {added} listings added",
        tipSeeding: "seeding-era listings — kept out of the headline figure",
      },
    },

    // --------------------------------- exploits.html · 3
    poc_coverage: {
      num: "03",
      kicker: "Exploit code by severity",
      source: "Exploit-DB (OffSec) · Metasploit (Rapid7) · Nuclei templates (ProjectDiscovery) · cvelistV5 (MITRE)",
      headline: "Public exploit code is most common on CVEs rated critical.",
      caption:
        "For CVE records published in the latest complete year, the share in each " +
        "CVSS severity bucket that has tracked public exploit code: an Exploit-DB " +
        "entry or a Metasploit exploit module. Records without a score are the muted " +
        "bar. Nuclei detection templates are a separate count in the tooltip, since a " +
        "detection check is not an exploit. In every bucket the overwhelming majority " +
        "of records have no tracked public exploit code. Critical-rated records have " +
        "it at more than ten times the rate of medium-rated records, and the rate is " +
        "below half a percent for low- and medium-rated ones.",
      note:
        "Records published in {window_year}, the latest complete year. A young record " +
        "has had limited time to attract code and coverage can only grow, so each bar " +
        "is a lower bound.",
      methodology:
        "For the latest complete calendar year, every published CVE record is bucketed " +
        "by the newest-version CVSS base score anywhere in the record, the same score " +
        "the CVE Ecosystem page uses; records without one count as unscored. A record " +
        "is covered when tracked public exploit code references its id: an Exploit-DB " +
        "entry, with or without a usable date, or a Metasploit module whose type is " +
        "exploit. Auxiliary scanners and post modules reference CVEs without being " +
        "exploits for them and do not count. Severity buckets with fewer than 10 " +
        "records are withheld. One complete year is used so the bars show a recent " +
        "rate, not decades of accumulation.",
      labels: {
        unscored: "unscored",
        tipShare: "have public exploit code",
        tipCount: "{n} of {total} records published in {year}",
        tipDetection: "{n} have a Nuclei detection template (counted separately)",
      },
    },

    // --------------------------------- c2.html · 1 (hero)
    c2_weather: {
      num: "01",
      kicker: "C2 servers over time",
      source: "abuse.ch Feodo Tracker · CyberMon nightly snapshots",
      headline: "Every nightly snapshot of Feodo Tracker's botnet C2 blocklist since July 2026 lists fewer than ten servers.",
      caption:
        "The botnet command-and-control (C2) servers on abuse.ch's Feodo Tracker " +
        "blocklist, counted each night; the tracker publishes only the current " +
        "list, so CyberMon stores the counts. Stacked bars count the servers the " +
        "tracker marks online, by malware family; the dashed line is the total " +
        "listed. The tracker's FAQ attributes its empty datasets to " +
        "law-enforcement takedowns, naming Emotet in 2021 and Operation Endgame " +
        "in 2024.",
      yAxis: "C2 servers",
      statLabel: "C2 servers the tracker marks online",
      statWhen: "of {listed} listed · snapshots since {first_date}",
      noReading: "no reading: the nightly run missed this date",
      legendListed: "All listed",
      // {first_date} fills from the record's actual start; the empty
      // variant renders while there is only one snapshot on file.
      note: "CyberMon has recorded the list nightly since {first_date}.",
      // Renders instead of `note` once the last {nights} snapshots are
      // identical (at least a week of them): the counts alone cannot say
      // whether the servers are unchanged or the feed has stalled.
      noteFlat:
        "The last {nights} snapshots, since {since}, all show the same counts: {listed} " +
        "listed, {online} online. Identical counts can mean no change in the " +
        "servers or a tracker that has stopped updating; the counts cannot tell " +
        "which.",
      noteEmpty:
        "CyberMon's record starts with tonight's snapshot and adds one each night.",
      methodology:
        "Each night the pipeline fetches Feodo Tracker's public botnet C2 " +
        "blocklist (ipblocklist.json) and reduces it to per-family counts: " +
        "listed (on tonight's blocklist) and online (the tracker's status for a " +
        "server that answered like a botnet C2 on its last probe). The pipeline " +
        "does not read the tracker's last-online dates, so an online status can " +
        "be old. The counts are appended to a committed history file " +
        "(data/history/botnet_c2.csv). The pipeline has no minimum-count check: " +
        "a drop to zero, as after a takedown, is recorded as data, while a " +
        "malformed or unreachable feed stops the run and records nothing.",
      labels: {
        tipTotals: "{online} online / {listed} listed",
      },
    },

    // --------------------------------- c2.html · 2
    c2_today: {
      num: "02",
      kicker: "Tonight's blocklist",
      source: "abuse.ch Feodo Tracker · CyberMon nightly snapshots",
      headline: "Tonight's blocklist holds a handful of C2 servers.",
      caption:
        "Every server on tonight's blocklist, counted by malware family. The " +
        "highlighted part of each bar is the servers the tracker marks online; " +
        "the rest are listed but offline. Below, the same servers counted by " +
        "hosting country and by network. The module publishes counts only, " +
        "never the blocklist itself.",
      statTemplate: "{listed} C2s listed · {online} online · {families} malware families",
      legendOnline: "Online (answered as C2)",
      legendDark: "Listed, offline",
      countriesLabel: "By hosting country",
      asnsLabel: "By network (AS name)",
      xAxis: "C2 servers",
      nodata:
        "The blocklist is empty tonight, as the tracker reports it.",
      methodology:
        "The composition comes from tonight's snapshot alone. Each listed server " +
        "counts once toward its malware family, its hosting country and its " +
        "network (tallied by autonomous-system number and labelled with the AS " +
        "name the tracker publishes). The tracker states that it adds an address " +
        "only after it returns a valid C2 response. Per-server details " +
        "(addresses, ports, hostnames) stay in the pipeline, and the output " +
        "contract rejects them.",
      labels: {
        tipCounts: "{listed} listed · {online} online",
      },
    },

    // --------------------------------- c2.html · 3
    c2_age: {
      num: "03",
      kicker: "Age on the tracker",
      source: "abuse.ch Feodo Tracker · CyberMon nightly snapshots",
      headline: "At least half of tonight's listed C2 servers were first seen by Feodo Tracker more than six months ago.",
      caption:
        "For every server on tonight's blocklist, the days since Feodo Tracker " +
        "first saw it. This is its age on the tracker; it does not show that the " +
        "server was listed throughout or that it still responds. The buckets run " +
        "from under 30 days to over two years; a bucket is empty when no listed " +
        "server was first seen in that range. The median changes when entries are " +
        "added or removed; while the list is unchanged it rises by one day each " +
        "night.",
      statLabel: "Median age of tonight's listed C2s",
      statValue: "{median} days",
      statWhen: "oldest {oldest} days",
      yAxis: "C2 servers",
      nodata: "The blocklist is empty tonight, so there are no ages to show.",
      methodology:
        "Age is the number of whole days between a server's first_seen " +
        "stamp on Feodo Tracker and tonight's snapshot date, grouped into fixed " +
        "buckets. The median and the oldest are computed over every listed " +
        "server, online or offline, since an offline server that remains listed " +
        "is still on the tracker's record.",
      labels: {
        servers: "C2 servers",
      },
    },

    // --------------------------------- ai.html · 1 · hero
    ai_clock: {
      num: "01",
      kicker: "Public exploit clock and AI timeline",
      source: "Exploit-DB (OffSec) · cvelistV5 (MITRE) · CyberMon AI timeline",
      headline: "Public exploit code in Exploit-DB has not appeared sooner since ChatGPT.",
      seeAlso: {
        text: "Which CVE records credit AI labs and vendors:",
        href: "credits.html",
        label: "AI Credits →",
      },
      caption:
        "This page measures when public exploit code appears, not when attackers " +
        "exploit a vulnerability, and the two can move in opposite directions. " +
        "Mandiant, which measures exploitation in the wild from its own incident " +
        "data, reports an average time-to-exploit of 63 days in 2018–19 and five " +
        "days in 2023, a year in which 70% of the vulnerabilities it saw exploited " +
        "were zero-days. Attackers can move sooner with private exploit code while " +
        "public archives receive fewer exploits, and receive them later; this page " +
        "cannot separate the two. " +
        "The red line is the raw median of days from a CVE record's publication to " +
        "its first public exploit code as Exploit-DB dates it, by publication year. " +
        "The pale line counts only exploits dated within 90 days either side " +
        "of publication, and only cohorts at least 90 days old, so every year is " +
        "measured over the same window and a year can be drawn before it ends. " +
        "Years the exploit trackers are still indexing are drawn hollow, and no " +
        "verdict on this page uses them. The dots along the top are the AI " +
        "timeline: model releases, threat-intelligence reports that looked for " +
        "offensive uplift, defensive milestones, lab research and the first " +
        "documented cases of AI used in real operations. Every dot is dated, " +
        "categorised and linked below the chart. The shaded band starts at the " +
        "AI-era date chosen in the menu. " +
        "The raw median made most of its move toward zero by 2013, a decade before " +
        "the ChatGPT band opens, and inside the band it moves later if it moves at " +
        "all. On the pale line, every settled year since 2005 has sat inside a " +
        "three-week band around zero. Where the two lines differ, the red line " +
        "includes exploits outside the 90-day window: on the left, old exploits " +
        "that received CVE ids years later; on the right, exploit code published " +
        "months after the CVE. Right of the marked edge there is no complete year " +
        "of data. The 2026 milestones, which include models and programmes aimed " +
        "at finding vulnerabilities, sit beyond what this page can test.",
      selectLabel: "AI era begins",
      evidenceEdge: "last complete year: {year}",
      rawLabel: "As recorded (all gaps)",
      lflLabel: "Like-for-like (±90d window)",
      axisSlower: "↑ exploit\n  arrives\n  later",
      axisFaster: "↓ exploit\n  arrives\n  sooner",
      provisionalFrom: "provisional →",
      statLabel: "Timing tests (one metric at one AI-era cutoff) in which public exploit code came earlier",
      statOf: "of {judged} judged",
      statUplift: "vendor threat reports (2024 to early 2025) that looked for offensive uplift and reported none",
      bandLabel: "AI era · from {label}",
      tipMonth: "{date} · month precision",
      railTitle: "AI timeline with dates and sources",
      railSourceLabel: "source",
      note:
        "The clock covers {first_year}–{last_year}: {n} matched CVEs over the " +
        "complete years, shown against {milestones} dated AI milestones. " +
        "Exploit-DB dated public exploits for {peak_n} CVEs published in " +
        "{peak_year} and for {latest_n} published in {latest_year}, so recent " +
        "medians rest on far fewer CVEs; exploits published only elsewhere, " +
        "such as on GitHub, are not counted.",
      methodology:
        "The red line is the Time to PoC module's series (time_to_poc.json), " +
        "unchanged, except that the current year is left out: a part-year at the " +
        "right-hand edge can look like a change of direction. The AI timeline is " +
        "a small hand-maintained table (pipeline/ai_timeline_data.py). Each row " +
        "has a source URL and a date precision; rows without a single " +
        "unambiguous date are marked month-precision and plotted at mid-month, " +
        "and the tooltip says so. Rows are categorised as capability releases, " +
        "no-uplift findings, offensive-use reports, defensive milestones and lab " +
        "research. An event gets a row if it is security-relevant, which " +
        "includes improvements in finding vulnerabilities as well as in " +
        "exploiting them; a frontier model release with no security claim " +
        "attached does not qualify. The stat's no-uplift reports are Microsoft " +
        "with OpenAI (February 2024) and Google's Threat Intelligence Group " +
        "(January 2025); both looked specifically for offensive capability " +
        "uplift and reported finding none. " +
        "The vertical axis is logarithmic in both directions and linear within a " +
        "month of zero, because the series runs from about -770 days to a few " +
        "months. On a linear axis everything from 2004 on would fill about a " +
        "fifth of the chart's height. The tooltips give the real values in days. " +
        "Vendor figures on exploitation in the wild, such as Mandiant's " +
        "time-to-exploit and the edge-device share in Verizon's Data Breach " +
        "Investigations Report (DBIR), come from private incident data and are " +
        "not plotted; they are recorded with attribution in the repository " +
        "(pipeline/ai_timeline_data.EXTERNAL_CONTEXT). " +
        "Three limits come from the clock. First, it counts public exploit code " +
        "that one archive dates, for the self-selected set of CVEs that got such " +
        "code. Second, recent years are right-censored: a CVE enters the cohort " +
        "only once it has a public exploit, so recent cohorts lack their slowest " +
        "cases and look faster, a bias that works against this page's finding. " +
        "Third, the dated cohort per year is well under a fifth of its " +
        "late-2000s size, so a later verdict is also consistent with Exploit-DB " +
        "indexing less.",
      labels: {
        yAxis: "days (log)",
        tipMedian: "median",
        tipCves: "{n} CVEs",
      },
    },

    // --------------------------------- ai.html · 2
    ai_banked: {
      num: "02",
      kicker: "Inflection test",
      source: "Exploit-DB (OffSec) · cvelistV5 (MITRE)",
      headline: "No judged timing metric moved toward earlier public exploit code after the cutoff.",
      caption:
        "The top bar is the like-for-like clock (chart 01's pale line), the only " +
        "measure here not biased by recent cohorts having had less time to attract " +
        "exploit code. The three bars below it read the full matched cohort in " +
        "three ways. For each metric the test takes three levels: the start of the " +
        "record, the five years before the cutoff, and the settled years since. " +
        "Each bar is the share of the metric's total movement that came after the " +
        "cutoff. Bars to the right mean public exploit code came earlier and are " +
        "drawn in the accent colour; bars to the left mean it came later. The table " +
        "below gives each level and how many CVEs it rests on. None of this " +
        "measures exploitation in the wild. Changing the cutoff at the top of the " +
        "page redraws the bars.",
      axisLabel: "share of the metric's total movement, since the cutoff (→ earlier)",
      primaryTag: "fixed 90-day window, no cohort-age bias",
      tableCaption: "Levels behind each bar, {era} cutoff ({date}):",
      tipEarly: "start of record:",
      tipPre: "5 years to {cut_year}:",
      tipPost: "since the cutoff:",
      tipBanked: "movement before the cutoff: {pct}% of the total",
      tipInsufficient:
        "Withheld: only {years} complete, settled year(s) after the cutoff year; the test needs two.",
      rowLevels: "{early} → {pre} → {post}   ({share}) · {post_n} CVEs since the cutoff",
      rowInsufficient: "withheld: {years} complete, settled year(s) after the cutoff year",
      verdicts: {
        accelerated: "earlier",
        decelerated: "later",
        no_inflection: "no inflection",
        insufficient: "withheld",
      },
      allWithheld: "Withheld: {years} complete, settled year(s) from {post_start_year} on.",
      note:
        "{accelerated} of {judged} judged metrics moved earlier after the cutoff" +
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
        "The like-for-like clock's window has a lower bound as well as an upper " +
        "one because a gap such as -4,452 days is an old exploit receiving a CVE " +
        "id, and such gaps pull a one-sided median far negative. The clock is not " +
        "a rate over all published CVEs. That rate was about 45% for " +
        "CVEs published in 2008 and 2009 and under 1% for those published in " +
        "2024. Over those years annual CVE volume grew from roughly 5,700 to " +
        "40,000, and the number of CVEs whose public exploit Exploit-DB dates " +
        "fell to under a tenth of its 2008 level. Exploit-DB adds entries for " +
        "older disclosures over time, so the newest cohorts are still missing " +
        "exploits that will be added later and read slightly slow; a cohort " +
        "still being indexed is drawn hollow and never counts toward a verdict. " +
        "The other three metrics are read from the full matched cohort and share " +
        "one denominator. They are the median gap in days from publication to " +
        "first public exploit, the share whose public code arrived no later than a " +
        "week after publication, and the share whose exploit code predates the " +
        "CVE record. The within-a-week share counts every gap of seven days or " +
        "less, negative gaps included, which is why the early years read above " +
        "95%. These three summarise one distribution and are not independent " +
        "tests: every negative gap also counts as within a week. The ChatGPT and " +
        "GPT-4 cutoffs likewise share most of their years. KEV latency (days " +
        "from CVE publication to listing in CISA's Known Exploited " +
        "Vulnerabilities catalog) is left out. Its trend series starts in 2023, " +
        "after the catalog's 2021–22 seeding era, so two of the three cutoffs " +
        "have no earlier years to compare against. Each level is a mean of " +
        "complete years: the first five years of the record, the five years " +
        "ending at the cutoff, and every settled year since. Single years are " +
        "not used because the 1999 cohort is about a hundred CVEs at a median " +
        "two years negative, and a ratio anchored on it would depend on one " +
        "small, unusual year. A cutoff's pre window ends with the last year that " +
        "ends before its date, and its post window starts with the first year " +
        "that begins after it. The year containing the cutoff (2022 for " +
        "ChatGPT) is therefore charted but counts for neither side. An era with " +
        "fewer than two complete, settled years after it is not judged. A falling " +
        "gap and a rising share both count as earlier.",
      labels: {
        tipPostN: "({years}y, {n} CVEs)",
      },
    },

    // --------------------------------- ai.html · 3
    ai_attention: {
      num: "03",
      kicker: "Attention and the public exploit clock",
      source: "GDELT 2.0 · Hacker News (Algolia) · arXiv cs.CR · Wikipedia pageviews · SEC EDGAR · Exploit-DB",
      headline: "Attention to AI security rose while the public exploit clock stayed within a narrow band.",
      caption:
        "The solid lines show attention to AI security: the five attention lanes " +
        "of the Buzzword Attention module, averaged per term, with each lane " +
        "indexed to its own peak. The dashed line is the like-for-like exploit " +
        "clock (the pale line in chart 01, settled years only) over the same " +
        "window, held flat across each year because it is measured annually. A " +
        "falling dashed line would mean public exploit code appearing sooner. It " +
        "measures public code, not attacks.",
      clockLabel: "Public exploit clock (median gap)",
      axisAttention: "attention index",
      axisClock: "median gap",
      unavailable:
        "The attention lanes are missing from this edition because the Buzzword " +
        "Attention data did not load. The two sections above are unaffected.",
      note:
        "{label} ran from an index of {index_first} in {month_first} to " +
        "{index_last} in {month_last}. Over the same window the clock's annual " +
        "median stayed between {clock_min}d and {clock_max}d ({year_first}–{year_last}).",
      methodology:
        "The attention lanes come from the Buzzword Attention module " +
        "(market_hype.json): the terms “AI Security” and “Agentic AI” from that " +
        "module's watchlist. Each term's monthly value is the mean of its " +
        "per-lane indexes over the lanes that have a value that month, so a term " +
        "whose Wikipedia lane starts late is not pulled down by the gap. The " +
        "number of lanes behind each point is in the data file. The two series " +
        "share no unit and no sampling rate, so they have separate axes, and the " +
        "chart claims no correlation between them. The clock's axis always spans " +
        "at least plus or minus 90 days, an editorial choice, and widens if the " +
        "data exceeds it. Over this window the clock varies by less than two " +
        "weeks, and an axis fitted to that range would stretch it to the full " +
        "chart height. The window is the Buzzword Attention module's 60 months, " +
        "and the note under the chart gives the month it starts. That is too " +
        "short for the long-run comparison, which charts 01 and 02 make.",
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
      headline: "The largest AI finder announcement alone counts more vulnerabilities than CVE records credit to all AI labs and vendors combined.",
      seeAlso: {
        text: "When public exploit code appears, before and after the AI era:",
        href: "ai.html",
        label: "AI and PoC Timing →",
      },
      caption:
        "Each column lists what its finders announce, in their own units, " +
        "above the published CVE records whose credits name the lab's model or " +
        "the vendor. The two sets differ, and neither verifies the other. An " +
        "announced finding may still be undisclosed, may be in private code that " +
        "never receives a CVE, or may be published without a credit. Only an " +
        "announcement counted in CVEs is drawn as a bar beside the credited " +
        "count. A vendor count is weaker evidence than a lab count. A lab counts " +
        "only when a finding credit names its model, while four or five in ten " +
        "vendor credits name the company only through a person there or in a " +
        "thank-you line. The two columns are never added together.",
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
        "CISA's Known Exploited Vulnerabilities catalog (KEV) lists exploitation " +
        "that CISA has confirmed. A CVE that is not on it has not been shown to " +
        "be unexploited, and these cohorts are young (last row of chart 02). " +
        "KEV-listed here: {cves}.",
      kevNoteNone:
        "CISA's Known Exploited Vulnerabilities catalog (KEV) lists exploitation " +
        "that CISA has confirmed. A CVE that is not on it has not been shown to " +
        "be unexploited, and these cohorts are young (last row of chart 02).",
      ledgerNote:
        "Every matched record, with its finder, evidence tier and credit role:",
      ledgerLinkText: "ai_credits_ledger.json",
      nodata: "Not enough data yet.",
      methodology:
        "A published CVE record can carry a credits field. Each credit is " +
        "matched against a hand-curated registry of AI finders in the pipeline " +
        "(ai_credits_data.py). The registry is narrow, because a loose match " +
        "catches Capgemini, a researcher named Ai and every .ai domain. It " +
        "matches only the names it lists, and its first version missed Google's " +
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
        "the record, taken from the CNA (the CVE Numbering Authority that " +
        "published the record) where the CNA scored that version and from " +
        "CISA's enrichment otherwise. “In an exploit corpus” means " +
        "Exploit-DB, a Metasploit module or a Nuclei template references the " +
        "CVE. Nuclei templates are detection checks and only sometimes exploits, " +
        "and exploit code published anywhere else is not seen. Each measured " +
        "row is a share of the credited CVEs; the rows are not nested. Announced " +
        "figures are not measured here. Each is the finder's own published " +
        "figure, recorded with its wording, date and source. " +
        "“Credited here to date” is this page's all-time count for that finder. " +
        "The announcement has its own cut-off date and its own list of CVEs, so " +
        "the pair is not a verification rate. Credit text is never republished " +
        "because it carries personal names and addresses; the ledger linked " +
        "above holds CVE ids, tiers and roles. Disclosure: the registry and this " +
        "copy were drafted with Claude, an Anthropic model, and an outside " +
        "review corrected an error that had inflated Anthropic's count. The " +
        "registry, the counting rule and every quoted claim are in the " +
        "repository.",
      labels: {
        sevTitle: "{label} {n} of {total}",
      },
    },

    // --------------------------------- credits.html · 2
    credits_profile: {
      num: "02",
      kicker: "Side by side",
      source: "CVE List V5 (MITRE) · EPSS (FIRST.org) · CISA KEV · Exploit-DB · Metasploit · Nuclei",
      headline: "Lab-credited CVEs are rated high or critical more often than all credited CVEs.",
      caption:
        "Nine measurements for three populations: CVEs crediting an LLM lab's " +
        "model, CVEs crediting an AI-security vendor, and all CVEs that carry a " +
        "credit (the baseline, which is not a human-only control group). Median " +
        "EPSS percentile is within ten points of the baseline in both AI " +
        "columns. On KEV membership, each AI column is within a handful of " +
        "records of what the baseline rate would give a population its size. " +
        "On exploit-corpus listing, the lab column has fewer records than that " +
        "rate would give and the vendor column has more. The comparison is not " +
        "adjusted for publication age, target mix or crediting practice. Exploit " +
        "listings and KEV entries accumulate over time, and the last row shows " +
        "that the lab-credited cohort is much younger than the baseline.",
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
        "time. The baseline is every published CVE whose record " +
        "carries a credit, the AI-credited ones included; they are under two " +
        "percent of it, and it may contain AI-assisted work whose credits do not " +
        "say so. The severity rows use the recorded CVSS score described under " +
        "chart 01. “High or critical” is a score of 7.0 or more, as a share of all the " +
        "population's CVEs, unscored ones included. EPSS (the Exploit Prediction " +
        "Scoring System) is FIRST's estimate of exploitation probability; the row " +
        "is the median of its published percentile, and all three medians are " +
        "well under 50. “In an exploit corpus” covers Exploit-DB, Metasploit and " +
        "Nuclei only. “Scored by its own CNA” is the share whose CVSS score came " +
        "from the assigning CNA and not from CISA's enrichment; it is low where " +
        "a CNA such as Mozilla's publishes no scores. One CVE moves the labs' " +
        "exploit-corpus row by half a point or less.",
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
        "to Google's OSS-Fuzz-Gen. A credit naming a system the registry does " +
        "not list is not counted, so this start date is the registry's. Lab " +
        "credits then arrive in single-month clusters with empty " +
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
      labels: {
        tipDistinct: "{n} distinct CVEs",
      },
    },

    // --------------------------------- credits.html · 4
    credits_board: {
      num: "04",
      kicker: "Who is credited",
      source: "CVE List V5 (MITRE) · CISA KEV",
      headline: "Among labs and among vendors, one or two finders hold most of the credits.",
      caption:
        "Every registry entity matched in at least one record, ranked by the " +
        "CVEs that count under its kind's rule. ZAST.AI's credits are almost " +
        "all medium-severity records published through one CNA. Anthropic's row " +
        "has the most criticals. “Names the AI” is how many of a row's records " +
        "name the system itself; for several vendors that is a minority or none, " +
        "because their credits name a person or only the company. “Not counted” " +
        "is what the rule leaves out: for a lab, records that name the " +
        "organisation but no model, and for any row, records that credit it " +
        "only for the fix. OpenAI is named without a model on most of the " +
        "records that name it, usually as a person's employer or as a " +
        "collaborator.",
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
        "“Credited CVEs” applies the kind's counting rule; the severity " +
        "strip, the high-plus-critical share and the KEV column describe those " +
        "CVEs. “Names the AI” counts records at the system tier. Hover over a " +
        "“not counted” cell for its make-up. “Credited most by” " +
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
        "Each CVE's first-listed weakness, grouped into six families. Injection " +
        "covers cross-site scripting, SQL injection and command injection. " +
        "Among lab-credited CVEs, the shares of memory-safety weaknesses and of " +
        "crypto and certificate weaknesses are each more than twice the " +
        "baseline's, and injection is small. The vendor-credited " +
        "population falls between the two on injection and has a larger " +
        "memory-safety share than the baseline. " +
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
      headline: "Lab-credited CVEs are more concentrated by affected product than vendor-credited CVEs.",
      caption:
        "The affected product each record lists first, ranked per kind. In the " +
        "lab-credited list, Bouncy Castle's Java crypto library and the Firefox " +
        "browser are both in the top five. The record does not say how those " +
        "targets were chosen. The vendor-credited list's first row is Red Hat " +
        "Enterprise Linux, which Red Hat, as CNA, lists first in its records, " +
        "including records for flaws in upstream packages.",
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
        "year is partial; the tooltip gives the count behind its share. " +
        "Credits are written by the CNA, not the finder, and practice " +
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
        "filings by the date the 8-K reached EDGAR. The date of the incident " +
        "appears only in a filing's text, and not every filing gives one. " +
        "Amendments (8-K/A) are a separate series. The third series counts " +
        "Item 8.01 filings that describe a cybersecurity incident. SEC staff " +
        "guidance of May 2024 suggested this voluntary item for incidents a " +
        "company has not, or not yet, judged material.",
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
        "Hollow bars mark partial periods: the first, because the rule " +
        "took effect on 18 December 2023, and the current one.",
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
        "per primary filer (CIK, EDGAR's company identifier). Months are " +
        "calendar months of the filing date EDGAR records. Where a response " +
        "lacks a filing's item list, the " +
        "phrase match decides, and the edition records how many filings " +
        "rested on that fallback. If EDGAR cannot be read, the previous " +
        "edition is carried forward and marked as such in the footer.",
    },

    // --------------------------------- incidents.html · 2
    incidents_amend: {
      num: "02",
      kicker: "Amendments",
      source: "SEC EDGAR full-text search (Forms 8-K, 8-K/A)",
      headline: "More than one in four Item 1.05 disclosures has been amended, most within 90 days.",
      caption:
        "Item 1.05 lets a company file before it knows an incident's full " +
        "scope or impact; it must then amend the 8-K once it does. The bars " +
        "count the days from each original disclosure to its first amendment.",
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
        "and left out.",
    },

    // --------------------------------- incidents.html · 3
    incidents_receipts: {
      num: "03",
      kicker: "Latest filings",
      source: "SEC EDGAR (sec.gov/Archives)",
      headline: "Each recent Item 1.05 filing below links to its record on EDGAR.",
      caption:
        "Originals and amendments, newest first; the filing date links to the " +
        "filing index on EDGAR. Filers are named as EDGAR records them.",
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
        "original it was matched to, as in the chart above; an unmatched " +
        "amendment shows no lag.",
    },

    // --------------------------------- advisories.html · 1 (hero)
    gap_years: {
      num: "01",
      kicker: "Advisories without a CVE",
      source: "GitHub Advisory Database (CC-BY 4.0) via OSV.dev",
      headline: "Fewer than one GitHub-reviewed advisory in ten carries no CVE id.",
      // {placeholders} fill from data/advisory_gap.json at render time.
      caption:
        "GitHub-reviewed security advisories for open-source packages, by " +
        "the year GitHub published them, split by whether the advisory " +
        "carries a CVE id. {without_pct} of the {advisories} live " +
        "advisories carry none. Those {without} advisories would not appear " +
        "in a vulnerability program that tracks only CVE ids. Some are " +
        "notices of malicious packages, most of them npm packages GitHub " +
        "listed in 2020. The year is GitHub's " +
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
        "advisories whose CVE has a publication date in NIST's National " +
        "Vulnerability Database (NVD), the CVE reached NVD more than 90 days " +
        "after the advisory for {later_90}, and more than a year after for " +
        "{later_365}.",
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
        "the two. Advisories published in the {days} days before the edition " +
        "are drawn as provisional. The lag figures in the note use " +
        "the NVD publication date GitHub records for the aliased CVE.",
      labels: {
        tipTotal: "{n} total",
      },
    },

    // --------------------------------- advisories.html · 2
    gap_ecosystems: {
      num: "02",
      kicker: "By ecosystem",
      source: "GitHub Advisory Database (CC-BY 4.0) via OSV.dev",
      headline: "Rust advisories lack a CVE id more often than those of any other large registry, while almost every Maven advisory has one.",
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
        "that ecosystem, split by whether OSV lists a CVE alias. An ecosystem " +
        "with fewer " +
        "than {min_n} advisories gets no share, because a percentage over so " +
        "few advisories moves with each one. In the headline, a large registry " +
        "has 1,000 or more advisories.",
    },

    // --------------------------------- advisories.html · 3
    gap_severity: {
      num: "03",
      kicker: "Severity",
      source: "GitHub Advisory Database (CC-BY 4.0) via OSV.dev",
      headline: "No-CVE advisories are rated Critical or Low more often, and hundreds of the Criticals are malware notices.",
      caption:
        "GitHub's own severity rating, as a share of the advisories with a " +
        "CVE and of those without. {crit_without} of the no-CVE advisories " +
        "are rated Critical, against {crit_with} of those with a CVE. Without " +
        "the malicious-package notices, the no-CVE advisories are rated " +
        "Critical less often than the ones with a CVE.",
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
        "malicious-package notices. By GitHub's advisory API, checked on 23 " +
        "September 2026, about 400 of the no-CVE Critical advisories are such " +
        "notices, 367 of them npm advisories from 2020.",
    },

    // --------------------------------- malware.html · 1 (hero)
    mal_months: {
      num: "01",
      kicker: "Reports per month",
      source: "OpenSSF malicious-packages (Apache-2.0) via OSV.dev",
      headline: "More than half of the feed's reports were published in a single month.",
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
        "published date. That is not the date the package appeared on the " +
        "registry or the date it was removed. Withdrawn reports stay in the " +
        "counts. The contributor named for a month is the " +
        "source the feed credits most often in that month's reports; a " +
        "report can credit several sources, or none. Registries beyond the " +
        "four largest are folded into Other.",
      labels: {
        tipReports: "{n} reports",
        tipWithdrawn: "{n} withdrawn",
      },
    },

    // --------------------------------- malware.html · 2
    mal_share: {
      num: "02",
      kicker: "By registry",
      source: "OpenSSF malicious-packages (Apache-2.0) via OSV.dev",
      headline: "npm accounts for almost every report on file, but PyPI had most of 2023's.",
      // {share_year} is the current year once it holds at least a median
      // month's reports, otherwise the latest complete year (charts/mal_share.js),
      // so a few days of January never name a registry.
      caption:
        "Each year's reports, split by registry. npm holds {npm_share} of " +
        "all reports on file. Among the registries other than npm, {second} " +
        "has the largest share in {share_year} ({second_share}).",
      shareYearPartial: "{year} so far",
      yAxis: "% of the year's reports",
      tooltip: "{name}: {n} reports · {pct}",
      nodata:
        "No edition yet. The nightly pipeline fills this page from OSV's exports.",
      methodology:
        "Per publication year, each registry's reports over all the year's " +
        "reports. The registry is the one the report names. OSV files a VS " +
        "Code extension under VSCode whether it was published to the " +
        "Microsoft marketplace or to Open VSX, and this page does the same. " +
        "The current year is partial, so one large month can still shift its " +
        "shares.",
      labels: {
        tipReports: "{n} reports",
      },
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
        "Each bar counts withdrawn reports by the year they were first " +
        "published, not the year they were withdrawn.",
      yAxis: "withdrawn reports",
      byEcosystem: "By registry",
      ecoTemplate: "{name} {n} of {reports}",
      tooltip: "{year}: {n} of {total} reports withdrawn",
      nodata:
        "No edition yet. The nightly pipeline fills this page from OSV's exports.",
      methodology:
        "A report counts as withdrawn when its record carries a withdrawn " +
        "timestamp; a withdrawn report stays in the export. The record has " +
        "no field for a reason, so this page gives none.",
    },

    // --------------------------------------------- tags.html · 1 · hero
    tags_trend: {
      num: "01",
      kicker: "Unsupported when assigned",
      source: "CVE List V5 (MITRE)",
      headline: "More CVEs are tagged as issued for products the vendor no longer supports.",
      caption:
        "The CVE record format lets the CVE Numbering Authority (CNA) that " +
        "assigned the ID attach tags to the record. " +
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
      labels: {
        none: "none",
      },
    },

    // --------------------------------------------- tags.html · 2
    tags_board: {
      num: "02",
      kicker: "Who tags",
      source: "CVE List V5 (MITRE)",
      headline: "Most CNAs active in recent years set neither tag.",
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
        "CNAs' other records and {all_crit} across all records. The same-CNA " +
        "baseline draws on the same CNAs as the tagged row but weights them " +
        "differently: a CNA that tags heavily makes up more of the tagged row than " +
        "of the baseline.",
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
        "least once in the window, minus the tagged ones. Bars are shares of each " +
        "row's records; the tooltip carries the counts.",
      labels: {
        tipOf: "{row} of {total}",
      },
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
    // Appended (after a space) to a source's fetch date or count in
    // sourcesTemplate when the nightly read failed and the last good value
    // was kept.
    carriedForward: "(carried forward)",
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
    // {year} (twice below) is the edition's year, from meta.json's
    // generated_at; common.js fills it and keeps the note hidden until it
    // knows the year, so the designations never go stale on 1 January.
    dataNote:
      // The CVE Terms of Use grant reuse provided MITRE's copyright designation is
      // reproduced; CVE® and CWE™ are MITRE trademarks. Do not paraphrase.
      "Data: CVE List V5 and the CNA roster from CVE.org (Copyright © 1999–{year} The MITRE " +
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
      "MITRE ATT&CK® (© {year} The MITRE Corporation. This work is reproduced and distributed " +
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
  // tools/make_motion.py). Same rule as everywhere else: a scene file holds
  // no copy beyond the exceptions the header of this file lists, so
  // pipeline/tests/test_claims_motion.py can audit every claim here against
  // the committed data.
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
        headline: "CVE records carrying a Critical score went from a handful a year to thousands.",
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
          "the gray band counts records with no score in the record. {gen}* is partial.",
        eraMarker: "scored in NVD, not in the record",
        // {era} in meta when the payload names no record-era year.
        eraFallback: "the marker",
        // The count under the clock: CVEs published in the year on screen.
        // The band names come from sections.flood.labels, so the clip's
        // legend matches the site's chart.
        sub: "{n} published",
      },
      "cna-concentration": {
        kicker: "CNA concentration",
        headline: "Hundreds of CNAs now assign CVEs; the five largest issue about half.",
        source: "CVE List V5 (MITRE)",
        meta:
          "share of each year's CVEs issued by the five largest CNAs, and the number of " +
          "CNAs that published or rejected a record that year. {gen}* is partial.",
        shareLabel: "Top-5 share",
        countLabel: "Active CNAs",
      },
    },
  },

  carousel: {
    edition: "Edition {generated_at}",
    // The cover's module line, from the module's home.modules entry.
    coverModule: "Module {num} — {label}",
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
      exploits: "Exploit-DB (OffSec) · Metasploit (Rapid7) · Nuclei (ProjectDiscovery) · CVE List V5 (MITRE) · CISA KEV",
      c2: "abuse.ch Feodo Tracker (CC0) · CyberMon nightly snapshots",
      ai: "Exploit-DB (OffSec) · CVE List V5 (MITRE) · CyberMon AI timeline · GDELT · Hacker News · arXiv · Wikipedia · SEC EDGAR",
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
