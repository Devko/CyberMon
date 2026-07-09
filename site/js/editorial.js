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
    kicker: "A nightly ledger of security ecosystem health · rebuilt from open data every 24h",
    thesis: "CVE severity has become meaningless — here are the receipts.",
    sub: "Every chart below pairs a claim with the exact method that produced it. Disagree with a number? The pipeline is open; rerun it.",
  },

  // Tabs in the shared top-nav. href values stay RELATIVE (GitHub Pages subpath).
  nav: [
    { id: "cve", href: "index.html", label: "CVE Ecosystem" },
    { id: "market", href: "market.html", label: "Security Market" },
  ],

  // ------------------------------------------------- market.html (stub tab)
  market: {
    pageTitle: "CyberMon — Security Market (module under construction)",
    kicker: "Module 02 — Security Market",
    headline: "The security industry runs on a hype curve. Nobody publishes the curve.",
    caption:
      "Analysts sell you their read of the cycle once a year, methodology sealed. This module " +
      "will track the hype itself, continuously and in the open: which words the industry is " +
      "betting on, where the money follows, and how long each wave takes to break. Same house " +
      "rules as the CVE dashboard — provocative headline, auditable methodology, nightly " +
      "pipeline, raw JSON you can check.",
    statusTag: "signal pending",
    statusLine: "COMING SOON — the pipeline for this module is under construction.",
    signalsTitle: "Planned signal sources",
    signals: [
      { name: "Vendor marketing language", note: "buzzword trajectories across product pages and press releases" },
      { name: "Funding rounds", note: "where investors say the hype is" },
      { name: "Job postings", note: "what the market actually staffs for" },
      { name: "Conference CFPs", note: "what practitioners want to talk about next year" },
    ],
    promise:
      "Nothing ships here until its nightly pipeline does. When this tab goes live, every curve " +
      "on it will come with the same expandable “how this is computed” footnote as everything else " +
      "on CyberMon.",
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
    // -------------------------------------------------------------- 1 · hero
    inflation: {
      num: "01",
      kicker: "Severity inflation",
      headline: "The average vulnerability is now “High.”",
      caption:
        "Median CVSS base score of newly published CVEs, year by year. Part of the climb is " +
        "methodology — CVSS v3 scores run structurally higher than v2, which is why the " +
        "per-version lines and the release markers are on the chart — but the drift continues " +
        "inside each version's own era. When the middle of the distribution sits at “High,” " +
        "the word stops ranking anything.",
      statLabel: "Share of scored CVEs rated High or Critical (base score ≥ 7.0)",
      statTemplate: "{latest_pct} today vs {ago_pct} a decade ago",
      statLatest: "{latest_year}",
      statAgo: "{ago_year}",
      methodology:
        "For every CVE in the cvelistV5 corpus we take the CNA-assigned base score, split by " +
        "CVSS version (v2 / v3.x / v4). Lines are the median score of CVEs published each year; " +
        "shaded bands span the 25th–75th percentile (IQR). A record scored under several versions " +
        "appears in each version's series, but exactly once in the blended line, using its newest " +
        "version's score. “% High or Critical” is the share of scored CVEs that year with base " +
        "score ≥ 7.0; unscored CVEs are excluded. Vertical markers are CVSS spec releases.",
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
