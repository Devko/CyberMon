// =============================================================================
// tags.js — Record Tags tab (tags.html). Builds the three tag sections from
// editorial.js. Like c2.js, all sections share ONE contract file
// (data/cve_tags.json), fetched once and passed to each renderer; each
// renderer runs inside its own try/catch so one bad chart yields one inline
// error card, not a dead page. Captions and methodology carry editorial
// {placeholders} filled from the payload (the concentration.js pattern).
// Shared chrome: common.js.
// =============================================================================
import { editorial, tpl } from "./editorial.js";
import { hookResize, fmtInt, fmtPct } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderTrend } from "./charts/tags_trend.js";
import { render as renderBoard } from "./charts/tags_board.js";
import { render as renderSeverity } from "./charts/tags_severity.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/cve_tags.json";
const UWA = "unsupported-when-assigned";

const SECTIONS = [
  { id: "tags_trend", render: renderTrend, hero: true },
  { id: "tags_board", render: renderBoard },
  { id: "tags_severity", render: renderSeverity },
];

const pctOf = (counts, key) => {
  const total = Object.values(counts || {}).reduce((a, b) => a + b, 0);
  return total ? fmtPct((counts[key] / total) * 100) : "n/a";
};

// Fill editorial {placeholders} from the contract itself.
export function fillTemplates(id, refs, data) {
  const ed = editorial.sections[id];
  const h = data.headline || {};
  const w = data.window || {};
  const common = { window_years: w.years ?? "?", from: w.from ?? "?", to: w.to ?? "?" };
  let vars = common;
  if (id === "tags_trend") {
    vars = {
      first: fmtInt(h.unsupported_first), first_year: h.unsupported_first_year ?? "n/a",
      latest: fmtInt(h.unsupported_latest), latest_year: h.latest_year ?? "n/a",
      current: fmtInt(h.unsupported_current), current_year: h.current_year ?? "n/a",
      dmin: fmtInt(h.disputed_min), dmax: fmtInt(h.disputed_max),
      dfrom: h.disputed_from ?? "n/a", dto: h.disputed_to ?? "n/a",
    };
  } else if (id === "tags_board") {
    const u = data.boards?.[UWA] || {};
    const d = data.boards?.disputed || {};
    vars = {
      ...common,
      u_cnas: fmtInt(u.cna_count), active: fmtInt(u.active_cnas),
      u_top3: fmtPct(u.top3_share_pct),
      d_top: d.cnas?.[0]?.cna ?? "n/a", d_top1: fmtPct(d.top1_share_pct),
      min_n: fmtInt(u.min_n),
    };
  } else if (id === "tags_severity") {
    const s = data.severity || {};
    vars = {
      ...common,
      u_crit: pctOf(s[UWA]?.tagged, "critical"),
      u_same: pctOf(s[UWA]?.same_cnas_untagged, "critical"),
      all_crit: pctOf(s.all, "critical"),
    };
  }
  refs.caption.textContent = tpl(ed.caption, vars);
  refs.methodText.textContent = tpl(ed.methodology, vars);
}

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("tags")];

  const built = [];
  for (const cfg of SECTIONS) {
    const { section, slots, caption, methodText } = buildSection(cfg);
    main.append(section);
    built.push({ cfg, slots, refs: { caption, methodText } });
  }

  jobs.push(
    fetchJSON(DATA_FILE)
      .then((data) => {
        for (const { cfg, slots, refs } of built) {
          // Per-section isolation: the payload is shared, the failures aren't.
          try {
            fillTemplates(cfg.id, refs, data);
            cfg.render(slots, data);
          } catch (err) {
            console.warn(`[CyberMon] section "${cfg.id}" failed:`, err);
            showError(slots, DATA_FILE, err);
          }
        }
      })
      .catch((err) => {
        console.warn(`[CyberMon] ${DATA_FILE} failed:`, err);
        for (const { slots } of built) showError(slots, DATA_FILE, err);
      })
  );

  await Promise.allSettled(jobs);
}

if (!window.echarts) {
  // ECharts CDN failed: chart sections degrade to error cards, the prose survives.
  console.warn("[CyberMon] ECharts failed to load from CDN.");
}
boot().catch((err) => console.error("[CyberMon] page boot failed:", err));
