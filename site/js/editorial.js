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
      sparklineNote: "Click a card to load it above. Sparklines show the media (GDELT) index only.",
      methodology:
        "For each tracked term and each of three sources — GDELT 2.0 (news article volume), " +
        "Hacker News (Algolia search API, stories and comments), arXiv (cs.CR preprint " +
        "count) — the pipeline pulls a monthly count over a rolling five-year window. Each " +
        "series is indexed to its own highest month in that window (peak = 100); this is " +
        "recomputed nightly, so a new peak nudges every earlier point down proportionally. " +
        "Raw counts ride along in the tooltip for every point. Series are deliberately not " +
        "shown as a share of the tracked term list — adding or retiring a term would " +
        "silently reshape every other term's history under that scheme. Hacker News has no " +
        "per-month histogram endpoint, so five years of monthly history backfills over the " +
        "first weeks; a term's line may start partway through the window until backfill " +
        "catches up.",
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
        "Rows need a full two years of collected data to post a YoY figure; recently added " +
        "or still-backfilling terms are omitted until then.",
      methodology:
        "For each (term, source) pair, sum raw monthly counts for the most recent twelve " +
        "populated months and the twelve months before that; YoY change is the percentage " +
        "difference between the two sums. Pairs with fewer than twenty-four populated " +
        "months, or a zero-count prior-year baseline, are excluded — a missing number is " +
        "honest, a fabricated one is not. Sort any column; default is steepest riser first.",
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
      methodology:
        "Each axis is the term's own attention index (see Hype curves methodology), " +
        "averaged over the three most recent populated months, for GDELT (x) and arXiv " +
        "(y). A term's divergence score is the y-axis value minus the x-axis value, in " +
        "index points; scores beyond ±10 are labeled “research leads” or “media leads,” " +
        "everything inside that band is “aligned” — a deliberately wide dead zone, since " +
        "both indices carry real month-to-month noise. Terms missing three recent " +
        "populated months in either source (usually mid-backfill) are omitted.",
    },

    // -------------------------------------------------------------- 1 · hero
    inflation: {
      num: "01",
      kicker: "Severity inflation",
      headline: "Nearly half of everything ships as “High” or worse.",
      caption:
        "Median CVSS base score of newly published CVEs, year by year, split by scoring " +
        "version — v3 runs structurally higher than v2, so the per-version lines and release " +
        "markers keep a methodology change from masquerading as drift. The chart begins where " +
        "CNA-assigned scores become dense enough to chart honestly (the footnote has the bar). " +
        "What the dense years show: medians parked at the doorstep of “High,” and four to five " +
        "of every ten scored CVEs rated 7.0 or worse. A scale whose midpoint lives that far up " +
        "has stopped ranking anything.",
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
        "records got backfilled, not what was published. The headline compares the latest year " +
        "against the earliest year that clears these filters. The current year is partial and " +
        "moves nightly.",
    },

    // ------------------------------------------------------------------- 2
    flood: {
      num: "02",
      kicker: "The 9.8 flood",
      headline: "“Critical” was an exception. Now it's a product line.",
      caption:
        "Published CVEs per year, bucketed by base score. Watch the red band: Critical (≥ 9.0) " +
        "grows faster than the corpus itself. Flip to share-of-year and the mix shift is plain — " +
        "a rating that once flagged the rare emergency now arrives by the thousands, alongside a " +
        "growing pile of CVEs that ship with no score at all.",
      toggleAbsolute: "Absolute",
      toggleShare: "Share of year",
      methodology:
        "CVEs are bucketed by their base score (highest CVSS version available per record): " +
        "Critical ≥ 9.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9. “Unscored” counts CVEs " +
        "published that year with no base score anywhere in the record. The share view " +
        "normalizes each year to 100%.",
    },

    // ------------------------------------------------------------------- 3
    reality: {
      num: "03",
      kicker: "Score vs. reality",
      headline: "Severity is not risk. The two barely correlate.",
      caption:
        "Every scored CVE with a current EPSS estimate, placed on a grid: CVSS severity on one " +
        "axis, real-world exploitation probability on the other. If scores tracked risk, the mass " +
        "would sit on the diagonal. It doesn't — most Critical-rated CVEs cluster in the " +
        "lowest-probability column, while the catalog of vulnerabilities actually being exploited " +
        "(CISA KEV) includes entries CVSS rated below High.",
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
        "NVD's job is to enrich CVEs — analyze, score, tag. The bars show what its queue looks " +
        "like right now, by NVD's own status labels. The line shows where that backlog is " +
        "heading, one nightly snapshot at a time. A severity ecosystem whose referee runs a " +
        "five-digit backlog is an ecosystem grading itself.",
      note:
        "NVD publishes no backlog history — this series is CyberMon's own nightly record.",
      barsTitle: "Current backlog by NVD status",
      lineTitle: "Backlog total, nightly snapshots",
      methodology:
        "Statuses come from the NVD 2.0 API's vulnStatus field at fetch time. “Backlog total” = " +
        "Received + Awaiting Analysis + Undergoing Analysis. Because NVD exposes no historical " +
        "series, CyberMon appends one row per nightly run to its own committed CSV " +
        "(data/history/nvd_backlog.csv, last run per date wins) — the history you see starts " +
        "when this project did.",
    },

    // ------------------------------------------------------------------- 5
    cna: {
      num: "05",
      kicker: "CNA rubber-stamp board",
      headline: "Who grades their own homework hardest?",
      caption:
        "CVE Numbering Authorities score the vulnerabilities they publish. These are their own " +
        "assigned numbers — not NVD's — ranked by how often they reach for 9-point-something. " +
        "Some CNAs hand out a 9+ to nearly half their CVEs; others, publishing comparable " +
        "volume, almost never do. Same scale, same spec. The difference is policy, not physics.",
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
        "budget. It is not keeping pace.",
      toggleLinear: "Linear",
      toggleLog: "Log scale",
      methodology:
        "Counts come from the cvelistV5 corpus: “published” is CVE records by original " +
        "publication year; “rejected” is records with state REJECTED, counted by the same year. " +
        "The log toggle only rescales the axis — same data.",
    },
  },

  footer: {
    generatedTemplate: "Edition generated {generated_at}",
    sourcesTemplate:
      "Sources — cvelistV5 release {cvelist_release} ({cve_count} CVEs) · " +
      "EPSS {epss_version} scores of {epss_date} · CISA KEV {kev_version} ({kev_count} entries) · " +
      "NVD statuses fetched {nvd_fetched}",
    metaError: "Edition metadata (data/meta.json) failed to load.",
    disclaimer:
      "CyberMon is an independent project. Not affiliated with, endorsed by, or speaking for " +
      "MITRE, NVD/NIST, CISA, or FIRST. Charts aggregate public data; no individual CVE is news here.",
    dataNote:
      "Data: CVE List V5 (MITRE), EPSS (FIRST.org), Known Exploited Vulnerabilities catalog (CISA), " +
      "NVD API 2.0 (NIST).",
    repoLabel: "Pipeline, methodology & issues → github.com/Devko/CyberMon",
  },
};

// Tiny template helper: tpl("{a} vs {b}", {a: 1, b: 2}) -> "1 vs 2"
export function tpl(str, vars) {
  return str.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
}
