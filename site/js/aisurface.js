// =============================================================================
// aisurface.js — AI Product CVEs tab (aisurface.html). Builds the four
// sections from editorial.js. Like tags.js, every section reads ONE contract
// file (data/ai_products.json), fetched once and passed to each renderer;
// each renderer runs inside its own try/catch so one bad chart yields one
// inline error card, not a dead page. Captions and methodology carry
// editorial {placeholders} filled from the payload. Shared chrome: common.js.
// =============================================================================
import { editorial, tpl } from "./editorial.js";
import { hookResize, fmtInt, fmtPct } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderYears } from "./charts/aisurface_years.js";
import { render as renderCwe } from "./charts/aisurface_cwe.js";
import { render as renderExploited } from "./charts/aisurface_exploited.js";
import { render as renderProducts } from "./charts/aisurface_products.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/ai_products.json";

const SECTIONS = [
  { id: "aisurface_years", render: renderYears, hero: true },
  { id: "aisurface_cwe", render: renderCwe },
  { id: "aisurface_exploited", render: renderExploited },
  { id: "aisurface_products", render: renderProducts },
];

const na = () => editorial.ui.na;

// Fill editorial {placeholders} from the contract itself.
export function fillTemplates(id, refs, data) {
  const ed = editorial.sections[id];
  const h = data.headline || {};
  const w = data.window || {};
  const cl = data.classifier || {};
  const common = {
    from: w.from ?? na(), to: w.to ?? na(), window_years: w.years ?? na(),
    version: cl.version ?? na(), reviewed: cl.reviewed ?? na(),
    products: fmtInt(cl.products), rules: fmtInt(cl.rules),
  };
  let vars = common;
  if (id === "aisurface_years") {
    vars = {
      ...common,
      latest_year: h.latest_year || na(), latest_ai: fmtInt(h.latest_ai),
      latest_share: fmtPct(h.latest_share_pct),
      current_year: h.current_year || na(), current_ai: fmtInt(h.current_ai),
      current_share: fmtPct(h.current_share_pct),
    };
  } else if (id === "aisurface_cwe") {
    const c = data.cwe || {};
    vars = {
      ...common,
      n: fmtInt(c.n), ai_specific: fmtInt(c.ai_specific?.n),
      no_cwe: fmtPct(c.no_cwe_pct), baseline_no_cwe: fmtPct(c.baseline_no_cwe_pct),
    };
  } else if (id === "aisurface_exploited") {
    const e = data.exploited || {};
    // expected counts are fractional (n x a weighted rate): one decimal
    const exp = (v) => (Number.isFinite(v) ? v.toFixed(1) : na());
    vars = {
      ...common,
      n: fmtInt(e.n), kev: fmtInt(e.kev), kev_exp: exp(e.kev_expected),
      poc: fmtInt(e.poc), poc_exp: exp(e.poc_expected),
      nuclei: fmtInt(e.nuclei), nuclei_exp: exp(e.nuclei_expected),
    };
  } else if (id === "aisurface_products") {
    const c = data.cnas || {};
    vars = {
      ...common,
      lead: h.lead_label || na(), lead_n: fmtInt(h.lead_n), lead_pct: fmtPct(h.lead_pct),
      product_count: fmtInt(data.product_count),
      top3: fmtPct(c.top3_pct), cna_count: fmtInt(c.cna_count),
      cna_list: (c.top || []).slice(0, 3).map((r) => r.cna).join(", ") || na(),
    };
  }
  refs.caption.textContent = tpl(ed.caption, vars);
  refs.methodText.textContent = tpl(ed.methodology, vars);
}

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("aisurface")];

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
