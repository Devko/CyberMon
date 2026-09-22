// =============================================================================
// cve.js — CVE Ecosystem tab (cve.html). Builds the ten chart sections from
// editorial.js, fetches each contract file independently, renders charts.
// A failed fetch only takes down its own section (inline error card).
// Shared chrome (masthead/nav/banner/footer) comes from common.js.
// =============================================================================
import { editorial, tpl } from "./editorial.js";
import { hookResize, fmtInt, fmtPct } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderInflation } from "./charts/inflation.js";
import { render as renderFlood } from "./charts/flood.js";
import { render as renderReality } from "./charts/reality.js";
import { render as renderDecay } from "./charts/decay.js";
import { render as renderThroughput } from "./charts/throughput.js";
import { render as renderCna } from "./charts/cna.js";
import { render as renderVolume } from "./charts/volume.js";
import { render as renderQuality } from "./charts/quality.js";
import { render as renderCweShare } from "./charts/cwe_share.js";
import { render as renderCvss4 } from "./charts/cvss4.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const SECTIONS = [
  { id: "inflation", file: "data/severity_inflation.json", render: renderInflation, hero: true },
  { id: "flood", file: "data/nine_eight_flood.json", render: renderFlood },
  { id: "reality", file: "data/score_vs_reality.json", render: renderReality },
  { id: "decay", file: "data/nvd_decay.json", render: renderDecay },
  { id: "throughput", file: "data/nvd_throughput.json", render: renderThroughput },
  { id: "cna", file: "data/cna_leaderboard.json", render: renderCna },
  { id: "volume", file: "data/volume_curve.json", render: renderVolume },
  { id: "quality", file: "data/advisory_quality.json", render: renderQuality },
  { id: "cwe", file: "data/cwe_distribution.json", render: renderCweShare },
  { id: "cvss4", file: "data/cvss_v4.json", render: renderCvss4 },
];

// CVSS 4.0 section: headline, caption and methodology carry numbers, all
// filled from the contract (headline stays the static fallback until then).
function fillCvss4(section, caption, methodText, data) {
  const ed = editorial.sections.cvss4;
  const h = data.headline || {};
  const cur = (data.years || []).find((r) => r.year === h.current_year);
  const since = data.since_month || "";
  const month = since ? new Date(`${since}-01T00:00:00Z`).toLocaleString("en-US",
    { month: "short", year: "numeric", timeZone: "UTC" }) : "n/a";
  if (cur?.published) {
    section.querySelector(".section-headline").textContent =
      tpl(ed.headlineTemplate, { pct: fmtPct(h.v4_share_current_pct) });
  }
  caption.textContent = tpl(ed.caption, {
    latest_year: h.latest_year || "n/a",
    latest_pct: fmtPct(h.v4_share_latest_pct),
    current_year: h.current_year || "n/a",
    current_pct: fmtPct(h.v4_share_current_pct),
    v4_current: fmtInt(h.v4_current),
    published_current: fmtInt(h.published_current),
    v4_cnas: fmtInt(h.v4_cnas_current),
  });
  methodText.textContent = tpl(ed.methodology, {
    since: month, min_v4: fmtInt(data.adopters?.min_v4),
  });
}

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("cve")];

  for (const cfg of SECTIONS) {
    const { section, slots, caption, methodText } = buildSection(cfg);
    main.append(section);
    jobs.push(
      fetchJSON(cfg.file)
        .then((data) => {
          if (cfg.id === "cna") {
            // fill methodology placeholders from the contract itself
            methodText.textContent = tpl(editorial.sections.cna.methodology, {
              window_years: data.window_years,
              min_cves: data.min_cves,
            });
          }
          if (cfg.id === "cvss4") fillCvss4(section, caption, methodText, data);
          if (cfg.id === "throughput") {
            methodText.textContent = tpl(
              editorial.sections.throughput.methodology,
              { min_known: data.min_known_duration });
          }
          cfg.render(slots, data);
        })
        .catch((err) => {
          console.warn(`[CyberMon] section "${cfg.id}" failed:`, err);
          showError(slots, cfg.file, err);
        })
    );
  }

  await Promise.allSettled(jobs);
}

if (!window.echarts) {
  // ECharts CDN failed: sections degrade to error cards, the prose survives.
  console.warn("[CyberMon] ECharts failed to load from CDN.");
}
boot().catch((err) => console.error("[CyberMon] page boot failed:", err));
