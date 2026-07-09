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

  // Tabs in the shared top-nav. href values stay RELATIVE (GitHub Pages subpath).
  // Every tab is its own page — direct-linkable and bookmarkable.
  nav: [
    { id: "home", href: "index.html", label: "Overview" },
    { id: "cve", href: "cve.html", label: "CVE Ecosystem" },
    { id: "market", href: "market.html", label: "Security Market" },
    { id: "kev", href: "kev.html", label: "KEV Latency" },
    { id: "concentration", href: "concentration.html", label: "CNA Concentration" },
  ],

  // ------------------------------------------------- index.html (landing)
  home: {
    kicker: "Overview",
    headline: "Pick a module.",
    caption:
      "CyberMon watches the machinery of the security industry itself — the scoring systems, " +
      "the institutions, the market — not the vulnerability of the week. Each module below is " +
      "its own page with its own nightly pipeline stage, its own data contracts, and its own " +
      "expandable “how this is computed” footnotes.",
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
          "decay, CNA scoring habits. Six charts, rebuilt every night.",
        live: true,
      },
      {
        id: "market",
        href: "market.html",
        num: "02",
        label: "Security Market",
        headline: "The security industry runs on a hype curve. Nobody publishes the curve.",
        blurb:
          "Buzzword hype curves across news coverage (GDELT), practitioner chatter " +
          "(Hacker News), and research output (arXiv) — every term graded against its " +
          "own five-year peak, rebuilt nightly.",
        live: true,
      },
      {
        id: "kev",
        href: "kev.html",
        num: "03",
        label: "KEV Latency",
        headline: "By the time the government confirms it's exploited, you've been exposed for months.",
        blurb:
          "Days from CVE publication to CISA's Known Exploited Vulnerabilities listing, " +
          "remediation deadlines, and the catalog's 2021–22 seeding era kept honestly separate from " +
          "the real trend.",
        live: true,
      },
      {
        id: "concentration",
        href: "concentration.html",
        num: "04",
        label: "CNA Concentration",
        headline: "The CVE database is becoming a handful of vendors grading themselves at scale.",
        blurb:
          "CNA count, top-5/10 volume share, a formal concentration index, and who rejects " +
          "more of their own reservations than they publish — rebuilt nightly from the same " +
          "corpus as CVE Ecosystem.",
        live: true,
      },
    ],
  },

  sampleBanner:
    "SYNTHETIC SAMPLE DATA — first real pipeline run pending. " +
    "Numbers below are shaped placeholders, not claims.",

  loadError: {
    title: "This section's data failed to load.",
    // {file} is rendered as an inline <code> element by the error card builder.
    body: "Couldn't fetch {file}. The rest of the page still works — reload to retry.",
  },

  methodologyLabel: "How this is computed",
  methodologySourcePrefix: "Source of truth: ",
  methodologySourceLinkText: "pipeline/metrics.py",

  sections: {
    // ------------------------------------------- market.html · 1 · hero
    hype: {
      num: "01",
      kicker: "Hype curves",
      headline: "Every term is graded against its own best month.",
      caption:
        "Media mentions (GDELT news coverage), practitioner chatter (Hacker News), and " +
        "research output (arXiv cs.CR preprints) for one term at a time, each indexed to " +
        "its own five-year peak so a slow-burning research topic and a marketing blitz " +
        "can share an axis without one drowning the other. Pick a term; the cards are " +
        "shortcuts.",
      selectLabel: "Term",
      termCountNote: "Tracking {n} terms — curated list: pipeline/market_terms.py",
      sparklineNote:
        "Click a card to load it above. Sparklines show the media (GDELT) index only — terms " +
        "still waiting on a media fetch show an honest blank, not an invented curve.",
      methodology:
        "For each tracked term and each of three sources — GDELT 2.0 (news article volume), " +
        "Hacker News (Algolia search API, stories and comments), arXiv (cs.CR preprint " +
        "count) — the pipeline pulls a monthly count over a rolling five-year window. Each " +
        "series is indexed to its own highest month in that window (peak = 100); this is " +
        "recomputed nightly, so a new peak nudges every earlier point down proportionally. " +
        "Raw counts ride along in the tooltip for every point. Series are deliberately not " +
        "shown as a share of the tracked term list — adding or retiring a term would " +
        "silently reshape every other term's history under that scheme. If a source's fetch " +
        "fails or is rate-limited (GDELT throttles aggressively), that stretch stays blank " +
        "until a nightly run heals it — a line that starts partway through the window is a " +
        "gap in collection, not in the world.",
    },

    // ------------------------------------------- market.html · 2
    risers: {
      num: "02",
      kicker: "Risers & fallers",
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
        "populated months and the twelve months before that; YoY change is the percentage " +
        "difference between the two sums. Pairs with fewer than twenty-four populated " +
        "months, a zero-count prior-year baseline, or fewer than thirty raw hits across " +
        "both windows are excluded — a percentage of almost nothing is a rumor, not a " +
        "rate, and a missing number is honest where a fabricated one is not. Sort any " +
        "column; default is steepest riser first.",
    },

    // ------------------------------------------- market.html · 3
    divergence: {
      num: "03",
      kicker: "Research vs. media divergence",
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
        "averaged over the three most recent populated months, for GDELT (x) and arXiv " +
        "(y). A term's divergence score is the y-axis value minus the x-axis value, in " +
        "index points; scores beyond ±10 are labeled “research leads” or “media leads,” " +
        "everything inside that band is “aligned” — a deliberately wide dead zone, since " +
        "both indices carry real month-to-month noise. Terms missing three recent " +
        "populated months in either source — usually a source still waiting on " +
        "collection — are omitted.",
    },

    // -------------------------------------------------------------- 1 · hero
    inflation: {
      num: "01",
      kicker: "Severity inflation",
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
        "score ≥ 7.0; unscored CVEs are excluded. Vertical markers are CVSS spec releases. " +
        "Honesty filters: a point is plotted only if that year has at least 100 scored CVEs in " +
        "that series; per-version points cannot predate the version's spec release (CNAs " +
        "backfill scores onto old records); and the blended line additionally requires scores " +
        "on at least 20% of the CVEs published that year — years with 1% coverage chart which " +
        "records got backfilled, not what was published. The headline compares the latest " +
        "COMPLETE year against the earliest year that clears these filters — the current year " +
        "plots (labeled partial, refilled nightly) but never headlines: six months of data " +
        "would fake a trend.",
    },

    // ------------------------------------------------------------------- 2
    flood: {
      num: "02",
      kicker: "The 9.8 flood",
      headline: "“Critical” was an exception. Now it's a product line.",
      caption:
        "Published CVEs per year, bucketed by base score. Watch the red band: a rating that " +
        "was measured in dozens a decade ago is now a four-thousand-a-year product line. And " +
        "unlike the early corpus — where most records shipped unscored — nearly everything " +
        "now arrives pre-labeled, so the label does all the triage. The current year is " +
        "partial; its bars are still filling in.",
      toggleAbsolute: "Absolute",
      toggleShare: "Share of year",
      methodology:
        "CVEs are bucketed by their base score (highest CVSS version available per record): " +
        "Critical ≥ 9.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9. “Unscored” counts CVEs " +
        "published that year with no base score anywhere in the CVE record itself — CNA or " +
        "CISA-ADP container. Read the early years carefully: before ~2018 scoring wasn't " +
        "done in the record at all — CNAs filed bare entries and NVD assigned CVSS " +
        "downstream, in its own database (which this chart deliberately does not ingest). " +
        "The unscored band's collapse since is the scoring duty migrating to the source: " +
        "CNA self-scoring rose from ~1% of records (2017) to ~80% (now), and when NVD's " +
        "enrichment stalled in 2024, CISA's Vulnrichment program (the ADP container) began " +
        "backstopping the rest — a quarter of all 2024 records carry only a CISA score. " +
        "The share view normalizes each year to 100%. The current year (marked *) is " +
        "partial and refills nightly.",
    },

    // ------------------------------------------------------------------- 3
    reality: {
      num: "03",
      kicker: "Score vs. reality",
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
      statKevNote: "{below_high} of {total} CISA KEV entries score under 7.0",
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
      headline: "The scorekeeper stopped keeping score.",
      caption:
        "NVD's job is to enrich CVEs — analyze, score, tag. The bars show every CVE by NVD's " +
        "own status label; the live queue is the sliver at the bottom, and it looks small for " +
        "a reason: tens of thousands of CVEs were quietly stamped “Deferred” — analysis not " +
        "pending, analysis cancelled. The queue wasn't worked off; it was reclassified away. " +
        "The line tracks the remaining queue, one nightly snapshot at a time. An ecosystem " +
        "whose referee retires from grading is an ecosystem grading itself.",
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
    cna: {
      num: "05",
      kicker: "CNA rubber-stamp board",
      headline: "Who grades their own homework hardest?",
      caption:
        "CVE Numbering Authorities score the vulnerabilities they publish. These are their own " +
        "assigned numbers — not NVD's — ranked by how often they reach for 9-point-something. " +
        "Some CNAs hand a 9+ to two of every five CVEs they score; others, at a hundred times " +
        "the volume, almost never reach that shelf. Same scale, same spec. The difference is " +
        "policy, not physics.",
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

    // ------------------------------------------------------------------- 6
    volume: {
      num: "06",
      kicker: "Volume curve",
      headline: "More CVEs than anyone can read.",
      caption:
        "CVE records published per year, with rejections alongside. The curve explains the rest " +
        "of the page: at this volume, triage runs on the severity label alone — which is exactly " +
        "why an inflated label is expensive. The rejection line is the system's error-correction " +
        "budget: as a share of what ships, it keeps shrinking. The current year is partial — " +
        "the apparent dip at the right edge is a year still being written.",
      toggleLinear: "Linear",
      toggleLog: "Log scale",
      methodology:
        "Counts come from the cvelistV5 corpus: “published” is CVE records by original " +
        "publication year; “rejected” is records with state REJECTED, counted by the same year. " +
        "The log toggle only rescales the axis — same data. The current year is labeled " +
        "partial and refills nightly; comparing it to a finished year is a category error.",
    },

    // --------------------------------------------- kev.html · 1 · hero
    latency: {
      num: "01",
      kicker: "Listing latency",
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
        "of 2022 additions is 1,436 days; of 2023 additions, 12), so a seeding-era entry's " +
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
      headline: "A third of KEV listings land inside a week. Six percent land three years late.",
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
      headline: "The deadline shrank as the list grew.",
      caption:
        "How long federal agencies get to fix each KEV entry: the gap from the day CISA " +
        "lists a vulnerability to the remediation deadline it attaches, median and " +
        "interquartile range per year of listing. Unlike the latency chart, the seeding era " +
        "belongs here — the deadline is set the day the entry lands, back-catalog included, " +
        "so this is a policy timeline, not a backlog artifact. The early catalog handed out " +
        "months; the standing rule since has been three weeks.",
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

    // --------------------------------- concentration.html · 1 · hero
    concentration: {
      num: "01",
      kicker: "Volume concentration",
      headline: "More assignors than ever. The volume still belongs to a handful.",
      caption:
        "Three lines from one corpus: how many CVE Numbering Authorities published at least " +
        "one record each year, and what share of the year's volume came from the top 5 and " +
        "top 10 of them. The CNA program keeps growing — federation is the point — but growth " +
        "in assignors has not meant dispersion in output. Most of the database still ships " +
        "from the same short list of vendors, and the largest of them are scoring their own " +
        "products while they're at it.",
      statLabel: "Share of published CVEs from the year's top 5 CNAs",
      statLatest: "{latest_year}",
      statAgo: "{ago_year}",
      methodology:
        "Each CVE record's assigner (the CNA of record in cvelistV5) is counted by original " +
        "publication year; a CNA is active in a year if it published at least one record. " +
        "Top-5/top-10 share is the fraction of that year's volume from its five or ten " +
        "largest assignors, membership recomputed every year — the names in the top 5 " +
        "change, the concentration doesn't. The pipeline also computes a " +
        "Herfindahl–Hirschman Index per year (the sum of squared volume shares, on the " +
        "0–10,000 scale antitrust regulators use; {hhi_latest} for the latest year) as a " +
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
      headline: "New CNAs keep arriving. Most of them don't move the needle.",
      caption:
        "Bars count CNAs publishing their first-ever CVE record that year; the line is the " +
        "total active roster. Recruitment is real — the program is adding assignors faster " +
        "than it ever has. Hold that against the chart above and the punchline writes " +
        "itself: the newcomers add count, not share. The head of the table absorbs the " +
        "growth.",
      methodology:
        "A newcomer in year Y is a CNA whose earliest published record in the entire corpus " +
        "falls in Y — first appearance in the data, not accreditation date, which the corpus " +
        "doesn't carry. The active-roster line counts CNAs with at least one published " +
        "record that year, the same definition as the concentration chart. Because first " +
        "appearance is computed against the full corpus, the first charted year counts " +
        "every CNA as new by construction — read the left edge accordingly. The current " +
        "year is partial and refills nightly.",
    },

    // --------------------------------- concentration.html · 3
    rejection: {
      num: "03",
      kicker: "Rejection board",
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
        "For each assigner in cvelistV5, count records first published in the last " +
        "{window_years} years by state: PUBLISHED versus REJECTED. Rejection rate is " +
        "rejected over (published + rejected). CNAs with fewer than {min_total} total " +
        "records in the window are excluded — a two-for-two rejection record is an " +
        "anecdote, not a rate. Reserved-but-never-published IDs don't appear in the public " +
        "corpus at all and can't be counted here: this board measures what was shipped and " +
        "then withdrawn, not what was quietly never used. Default sort: rejection rate, " +
        "descending. Click any column header to re-sort.",
    },
  },

  footer: {
    generatedTemplate: "Edition generated {generated_at}",
    sourcesTemplate:
      "Sources — cvelistV5 release {cvelist_release} ({cve_count} CVEs) · " +
      "EPSS {epss_version} scores of {epss_date} · CISA KEV {kev_version} ({kev_count} entries) · " +
      "NVD statuses fetched {nvd_fetched} · market terms fetched {market_fetched}",
    metaError: "Edition metadata (data/meta.json) failed to load.",
    disclaimer:
      "CyberMon is an independent project. Not affiliated with, endorsed by, or speaking for " +
      "MITRE, NVD/NIST, CISA, FIRST, GDELT, Y Combinator/Algolia, or arXiv. Charts aggregate " +
      "public data; no individual CVE is news here.",
    dataNote:
      "Data: CVE List V5 (MITRE), EPSS (FIRST.org), Known Exploited Vulnerabilities catalog (CISA), " +
      "NVD API 2.0 (NIST), GDELT 2.0 (news volume), Hacker News via Algolia Search API, " +
      "arXiv cs.CR metadata (thank you to arXiv for use of its open access interoperability).",
    repoLabel: "Pipeline, methodology & issues → github.com/Devko/CyberMon",
  },
};

// Tiny template helper: tpl("{a} vs {b}", {a: 1, b: 2}) -> "1 vs 2"
export function tpl(str, vars) {
  return str.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
}
