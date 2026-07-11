// =============================================================================
// carousel.js — print template behind carousel.html?page=<moduleId>.
// Renders one module as a stack of fixed-size 1080×1350 slides — cover, one
// per chart section, closing — for tools/make_carousels.py to print into the
// LinkedIn document-post PDF. All copy comes from editorial.js and the charts
// are the site's own renderers; interactive sections render their DEFAULT
// view (controls are hidden by css/carousel.css).
//
// Contract with the generator:
//   window.__carouselModules  — every printable module id (from editorial.nav)
//   window.__carouselDone     — true once rendering (or failing) has settled
//   window.__carouselFailures — human-readable problems; non-empty = broken
//   window.__carouselSlideCount / window.__carouselOverflows — layout checks
// =============================================================================
import { editorial, tpl } from "./editorial.js";
import { el } from "./dom.js";
import { fetchJSON } from "./common.js";
import { render as renderInflation } from "./charts/inflation.js";
import { render as renderFlood } from "./charts/flood.js";
import { render as renderReality } from "./charts/reality.js";
import { render as renderDecay } from "./charts/decay.js";
import { render as renderThroughput } from "./charts/throughput.js";
import { render as renderCna } from "./charts/cna.js";
import { render as renderVolume } from "./charts/volume.js";
import { render as renderQuality } from "./charts/quality.js";
import { render as renderCweShare } from "./charts/cwe_share.js";
import { render as renderHype } from "./charts/market_hype.js";
import { render as renderRisers } from "./charts/market_risers.js";
import { render as renderDivergence } from "./charts/market_divergence.js";
import { render as renderLatency } from "./charts/kev_latency.js";
import { render as renderBuckets } from "./charts/kev_buckets.js";
import { render as renderRemediation } from "./charts/kev_remediation.js";
import { render as renderRansomware } from "./charts/kev_ransomware.js";
import { render as renderConcentration } from "./charts/concentration_trend.js";
import { render as renderEntrants } from "./charts/concentration_entrants.js";
import { render as renderRejection } from "./charts/concentration_rejection.js";
import { render as renderLag } from "./charts/breach_lag.js";
import { render as renderBreachVolume } from "./charts/breach_volume.js";
import { render as renderClasses } from "./charts/breach_classes.js";
import { render as renderRevenue } from "./charts/extortion_revenue.js";
import { render as renderPayments } from "./charts/extortion_payments.js";
import { render as renderFamilies } from "./charts/extortion_families.js";
import { render as renderMap } from "./charts/attack_map.js";
import { render as renderChurn } from "./charts/attack_churn.js";
import { render as renderCatalog } from "./charts/attack_catalog.js";
import { render as renderWorld } from "./charts/hygiene_world.js";
import { render as renderEconomies } from "./charts/hygiene_economies.js";
import { render as renderSpread } from "./charts/hygiene_spread.js";
import { render as renderGuardShare } from "./charts/guards_share.js";
import { render as renderRecidivism } from "./charts/guards_recidivism.js";
import { render as renderOverlap } from "./charts/guards_overlap.js";
import { render as renderGrade } from "./charts/epss_grade.js";
import { render as renderEpssDistribution } from "./charts/epss_distribution.js";
import { render as renderEpssPercentile } from "./charts/epss_percentile.js";
import { render as renderIdAge } from "./charts/calendar_idage.js";
import { render as renderWeekday } from "./charts/calendar_weekday.js";
import { render as renderPatch } from "./charts/calendar_patch.js";

// Section lists per module — the same ids, files, and renderers as the page
// scripts (cve.js, market.js, …), which cannot be imported here because they
// boot their page on import. A section without a file shares the module's
// data file (fetched once). `table: true` marks board sections rendered as
// HTML tables: they lay out at full size with enlarged type instead of the
// 2× chart scale, and get trimmed to their top rows to stay phone-readable.
const MODULES = {
  cve: {
    sections: [
      { id: "inflation", file: "data/severity_inflation.json", render: renderInflation },
      { id: "flood", file: "data/nine_eight_flood.json", render: renderFlood },
      { id: "reality", file: "data/score_vs_reality.json", render: renderReality },
      { id: "decay", file: "data/nvd_decay.json", render: renderDecay },
      { id: "throughput", file: "data/nvd_throughput.json", render: renderThroughput },
      { id: "cna", file: "data/cna_leaderboard.json", render: renderCna, table: true },
      { id: "volume", file: "data/volume_curve.json", render: renderVolume },
      { id: "quality", file: "data/advisory_quality.json", render: renderQuality },
      { id: "cwe", file: "data/cwe_distribution.json", render: renderCweShare },
    ],
  },
  market: {
    file: "data/market_hype.json",
    sections: [
      { id: "hype", render: renderHype },
      { id: "risers", render: renderRisers, table: true },
      { id: "divergence", render: renderDivergence },
    ],
  },
  kev: {
    file: "data/kev_latency.json",
    sections: [
      { id: "latency", render: renderLatency },
      { id: "buckets", render: renderBuckets },
      { id: "remediation", render: renderRemediation },
      { id: "ransomware", render: renderRansomware, file: "data/kev_ransomware.json" },
    ],
  },
  concentration: {
    file: "data/cna_concentration.json",
    sections: [
      { id: "concentration", render: renderConcentration },
      { id: "entrants", render: renderEntrants },
      { id: "rejection", render: renderRejection, table: true },
    ],
  },
  breaches: {
    file: "data/breach_ledger.json",
    sections: [
      { id: "disclosure", render: renderLag },
      { id: "exposure", render: renderBreachVolume },
      { id: "leaks", render: renderClasses },
    ],
  },
  extortion: {
    file: "data/extortion_ledger.json",
    sections: [
      { id: "revenue", render: renderRevenue },
      { id: "payments", render: renderPayments },
      { id: "families", render: renderFamilies, table: true },
    ],
  },
  attack: {
    file: "data/attack_churn.json",
    sections: [
      { id: "map", render: renderMap },
      { id: "churn", render: renderChurn },
      { id: "catalog", render: renderCatalog },
    ],
  },
  hygiene: {
    file: "data/dnssec_adoption.json",
    sections: [
      { id: "validation", render: renderWorld },
      { id: "economies", render: renderEconomies },
      { id: "spread", render: renderSpread },
    ],
  },
  guards: {
    file: "data/kev_guards.json",
    sections: [
      { id: "guards", render: renderGuardShare },
      { id: "recidivism", render: renderRecidivism, table: true },
      { id: "overlap", render: renderOverlap },
    ],
  },
  epss: {
    file: "data/epss_report.json",
    sections: [
      { id: "grade", render: renderGrade },
      { id: "distribution", render: renderEpssDistribution },
      { id: "percentile", render: renderEpssPercentile },
    ],
  },
  calendar: {
    file: "data/cve_calendar.json",
    sections: [
      { id: "reservation", render: renderIdAge },
      { id: "weekbeat", render: renderWeekday },
      { id: "patchtuesday", render: renderPatch },
    ],
  },
};

// Printable module ids come from the shared nav — the single source of truth
// for what modules exist. Exposed immediately (before boot) so the generator
// can read the list from a bare carousel.html load.
const MODULE_IDS = editorial.nav.filter((t) => t.id !== "home").map((t) => t.id);
window.__carouselModules = MODULE_IDS;

const failures = [];
const charts = []; // every ECharts instance made on this page (for the fit pass)

// Boards keep at most this many rows — carousels are read on phones.
const TABLE_ROWS_MAX = 10;
const TABLE_ROWS_MIN = 6;

// ---- ECharts print patch ------------------------------------------------------

// The renderers animate their entry; print must snapshot the FINAL frame.
// Wrapping init lets every chart pass through here without touching theme.js.
function patchECharts() {
  const origInit = window.echarts.init;
  window.echarts.init = function (dom, theme, opts) {
    const chart = origInit.call(window.echarts, dom, theme, opts);
    charts.push(chart);
    const setOption = chart.setOption.bind(chart);
    chart.setOption = (option, ...rest) => setOption({ animation: false, ...option }, ...rest);
    return chart;
  };
}

// ---- slide builders -----------------------------------------------------------

function wordmark() {
  const p = el("p", "slide-wordmark");
  p.append("CYBER", el("span", "accent", "MON"));
  return p;
}

function buildCover(moduleEd, meta) {
  const slide = el("section", "slide slide-cover");
  const top = el("div");
  top.append(wordmark(), el("p", "cover-module", `Module ${moduleEd.num} — ${moduleEd.label}`));
  const mid = el("div", "cover-mid");
  mid.append(
    el("h1", "cover-headline", moduleEd.headline),
    el("p", "cover-thesis", editorial.masthead.thesis)
  );
  const edition = meta?.generated_at
    ? tpl(editorial.carousel.edition, { generated_at: meta.generated_at })
    : "";
  slide.append(top, mid, el("p", "cover-edition", edition));
  return slide;
}

function buildClosing(moduleId) {
  const slide = el("section", "slide slide-closing");
  const sources = editorial.carousel.sources[moduleId] ?? "";
  const mid = el("div", "closing-mid");
  mid.append(
    el("p", "closing-url", editorial.carousel.siteUrl),
    el("p", "closing-reuse", editorial.footer.reuseNote)
  );
  slide.append(
    wordmark(),
    mid,
    el("p", "closing-sources", tpl(editorial.carousel.closingSources, { sources }))
  );
  return slide;
}

// One slide per chart section: kicker + headline up top, the section's own
// panel markup in the middle (so the untouched renderers find every slot and
// note element they expect), footer strip at the bottom.
function buildChartSlide(moduleId, cfg) {
  const ed = editorial.sections[cfg.id];
  const slide = el("section", `slide slide-chart slide-${cfg.id}`);

  const head = el("header");
  head.append(
    el("p", "slide-kicker", `${ed.num} — ${ed.kicker}`),
    el("h2", "slide-headline", ed.headline)
  );

  const stat = el("div", "section-stat");
  const panel = el("div", "panel");
  const controls = el("div", "panel-controls");
  const chart = el("div", "chart");
  const extra = el("div", "panel-extra");
  panel.append(controls, chart, extra);

  // Union of the page scripts' panel-note slots; the renderers fill the
  // templated ones ({placeholders}) and remove them when the data is absent.
  const noteTpl = ed.note ?? ed.backfillNote ?? ed.importNote ?? ed.catalogNote;
  if (noteTpl) panel.append(el("p", "panel-note", noteTpl));

  const box = el("div", cfg.table ? "slide-tablebox" : "slide-scalebox");
  const inner = el("div", cfg.table ? "slide-tableinner" : "slide-scale");
  inner.append(stat, panel);
  box.append(inner);

  const sources = editorial.carousel.sources[moduleId] ?? "";
  slide.append(head, box, el("p", "slide-foot", tpl(editorial.carousel.slideFooter, { sources })));

  return { slide, slots: { stat, panel, controls, chart, extra } };
}

// ---- print fixups ---------------------------------------------------------------

// The renderers size their option layout for the full-width page; at the
// slide's half logical width several assumptions break and are re-measured
// here, per chart, without touching the renderers themselves:
//   - a legend wraps to more rows (and a scroll legend would print a pager
//     with most entries hidden) → flatten it, count the wrapped rows, and
//     give the grid the room they actually need;
//   - a y-axis name at the default "end" location renders horizontally
//     around the axis top → at this width it clips at the canvas edge and
//     collides with the legend, so anchor it inward over the plot and add
//     headroom below the legend block;
//   - a long rotated middle-located y name can outrun the (fit-shrunk) plot
//     height → drop its font a point;
//   - the last x label of a tight grid can clip at the right canvas edge →
//     keep a minimum right padding;
//   - interval-0 month axes label the first month of each year by formatter
//     (hygiene): the record's partial first year sits too close to the next
//     one at this width → blank the very first tick label.
function fixChartLayout() {
  for (const chart of charts) {
    const opt = chart.getOption();
    const patch = {};

    // ---- legend rows at printed width ----
    let rows = 0;
    const legend = opt.legend?.[0];
    if (legend && legend.show !== false) {
      const names = (legend.data?.length ? legend.data : (opt.series ?? []).map((s) => s.name))
        .map((d) => (typeof d === "string" ? d : d?.name))
        .filter((n) => n && !n.startsWith("_")); // helper series never chart in legends
      if (names.length) {
        // estimated legend item: 14px swatch + padding + ~7px/char of 11px mono
        const width = chart.getWidth() - 10;
        rows = 1;
        let x = 0;
        for (const n of names) {
          const w = 14 + 6 + n.length * 7 + 10;
          if (x && x + w > width) {
            rows += 1;
            x = w;
          } else {
            x += w;
          }
        }
        if (legend.type === "scroll") patch.legend = { type: "plain" };
      }
    }

    // ---- y-axis names ----
    let hasEndName = false;
    let hasLongMiddleName = false;
    const yPatch = (opt.yAxis ?? []).map((ax) => {
      if (!ax.name) return {};
      if (ax.nameLocation === "middle") {
        if (ax.name.length <= 30) return {};
        // centered on the plot, a long rotated name overruns both plot ends;
        // the top overrun clips at the canvas edge (grid.top raised below)
        hasLongMiddleName = true;
        return { nameTextStyle: { fontSize: 9 } };
      }
      hasEndName = true;
      // anchor over the plot, away from the canvas edge on either side
      return { nameTextStyle: { align: ax.position === "right" ? "right" : "left" } };
    });
    if (yPatch.some((p) => Object.keys(p).length)) patch.yAxis = yPatch;

    // ---- grid padding ----
    const grid = opt.grid?.[0];
    if (grid) {
      const gridPatch = {};
      const top = Number(grid.top);
      const need = Math.max(
        rows ? 18 + rows * 21 + (hasEndName ? 16 : 0) : hasEndName ? 30 : 0,
        hasLongMiddleName ? 34 : 0
      );
      if (Number.isFinite(top) && need > top) gridPatch.top = need;
      const right = Number(grid.right);
      if (Number.isFinite(right) && right < 36) gridPatch.right = 36;
      if (Object.keys(gridPatch).length) patch.grid = gridPatch;
    }

    // ---- first tick of hand-labelled month axes ----
    const xl = opt.xAxis?.[0]?.axisLabel;
    if (opt.xAxis?.[0]?.type === "category" && xl?.interval === 0 && typeof xl.formatter === "function") {
      const orig = xl.formatter;
      patch.xAxis = { axisLabel: { formatter: (v, i) => (i === 0 ? "" : orig(v, i)) } };
    }

    if (Object.keys(patch).length) chart.setOption(patch);
  }
}

// The hype hero charts ONE selected term; on the page the selector shows
// which, but controls are hidden in print — surface the selection as a
// subtitle above the chart instead.
function labelSelectedTerm() {
  for (const select of document.querySelectorAll(".slide .term-select")) {
    const label = select.selectedOptions?.[0]?.textContent;
    const panel = select.closest(".panel");
    if (label && panel) {
      panel.insertBefore(
        el("div", "panel-subtitle", `${editorial.sections.hype.selectLabel}: ${label}`),
        panel.querySelector(".chart")
      );
    }
  }
}

// ---- fit pass -------------------------------------------------------------------

// Slides are fixed sheets; the section markup is content-sized. After render
// (and after the webfonts settle, since headline height depends on them):
//   scaled sections — measure how far the 2× stack overflows its box and take
//   the overflow out of the ECharts hosts, the stretchy part of the layout;
//   board sections  — cap at TABLE_ROWS_MAX rows, then drop further rows
//   until the board fits (never below TABLE_ROWS_MIN).
function fitSlides() {
  for (const slide of document.querySelectorAll(".slide-chart")) {
    const scaleBox = slide.querySelector(".slide-scalebox");
    if (scaleBox) {
      const inner = scaleBox.querySelector(".slide-scale");
      const hosts = [...inner.querySelectorAll(".chart")].filter((h) => h.querySelector("canvas"));
      const FLOOR = 120; // logical px — below this a chart stops being a chart
      // The cut is split by capacity (height above the floor), so a big
      // heatmap gives up space before an already-small companion bar does.
      // Side-by-side hosts (decay's split) each absorb only their share of
      // a shared row, so iterate until the measurement settles.
      for (let pass = 0; pass < 8 && hosts.length; pass++) {
        const over = inner.getBoundingClientRect().height - scaleBox.clientHeight;
        if (over <= 2) break;
        const logicalOver = Math.ceil(over / 2) + 2; // inner lays out at half scale
        const capacity = hosts.map((h) => Math.max(0, h.clientHeight - FLOOR));
        const total = capacity.reduce((s, c) => s + c, 0);
        if (total <= 0) break; // everything at the floor — reported as overflow
        hosts.forEach((host, i) => {
          if (!capacity[i]) return;
          const cut = Math.ceil(logicalOver * (capacity[i] / total));
          host.style.height = `${Math.max(FLOOR, host.clientHeight - cut)}px`;
          window.echarts.getInstanceByDom(host)?.resize();
        });
      }
    }

    const tableBox = slide.querySelector(".slide-tablebox");
    if (tableBox) {
      const rows = [...tableBox.querySelectorAll("tbody tr")];
      let keep = Math.min(rows.length, TABLE_ROWS_MAX);
      rows.slice(keep).forEach((tr) => tr.remove());
      while (keep > TABLE_ROWS_MIN && tableBox.scrollHeight > tableBox.clientHeight) {
        rows[--keep].remove();
      }
    }
  }
}

// Anything still spilling out of its 1080×1350 sheet after the fit pass is a
// clipped slide; the generator fails the build on it rather than shipping it.
function measureOverflows() {
  const overflows = [];
  document.querySelectorAll(".slide").forEach((slide, i) => {
    const boxes = [slide, ...slide.querySelectorAll(".slide-scalebox, .slide-tablebox")];
    for (const box of boxes) {
      const scaled = box.querySelector?.(":scope > .slide-scale");
      const contentH = scaled ? scaled.getBoundingClientRect().height : box.scrollHeight;
      const over = Math.round(contentH - box.clientHeight);
      if (over > 4) {
        overflows.push({ slide: i + 1, id: slide.className, px: over });
        break;
      }
    }
  });
  return overflows;
}

// ---- boot -----------------------------------------------------------------------

const fileCache = new Map();
function load(file) {
  if (!fileCache.has(file)) fileCache.set(file, fetchJSON(file));
  return fileCache.get(file);
}

const nextFrame = () => new Promise((r) => requestAnimationFrame(() => r()));

async function boot() {
  const pageId = new URLSearchParams(location.search).get("page");
  const main = document.getElementById("slides");

  if (!pageId) {
    // Bare load: the generator reads window.__carouselModules and moves on.
    return;
  }

  const mod = MODULES[pageId];
  const moduleEd = editorial.home.modules.find((m) => m.id === pageId);
  if (!MODULE_IDS.includes(pageId) || !moduleEd) {
    failures.push(`unknown page "${pageId}" — printable modules: ${MODULE_IDS.join(", ")}`);
    return;
  }
  if (!mod) {
    // A module exists in the nav but has no carousel wiring here — fail the
    // build loudly instead of quietly shipping a deck without it.
    failures.push(`module "${pageId}" is in editorial.nav but has no section list in carousel.js`);
    return;
  }
  if (!window.echarts) {
    failures.push("ECharts failed to load from CDN");
    return;
  }
  patchECharts();

  let meta = null;
  try {
    meta = await load("data/meta.json");
  } catch (err) {
    failures.push(`data/meta.json: ${err?.message ?? err}`);
  }
  main.append(buildCover(moduleEd, meta));

  const jobs = [];
  for (const cfg of mod.sections) {
    const { slide, slots } = buildChartSlide(pageId, cfg);
    main.append(slide);
    jobs.push(
      load(cfg.file ?? mod.file)
        .then((data) => cfg.render(slots, data))
        .catch((err) => failures.push(`section "${cfg.id}": ${err?.message ?? err}`))
    );
  }
  await Promise.allSettled(jobs);

  main.append(buildClosing(pageId));

  fixChartLayout();
  labelSelectedTerm();

  // Headline metrics depend on the webfonts; measure only after they settle.
  await document.fonts.ready;
  await nextFrame();
  fitSlides();
  await nextFrame();
  window.__carouselOverflows = measureOverflows();
}

window.__carouselReady = boot()
  .catch((err) => failures.push(String(err?.stack ?? err)))
  .finally(() => {
    window.__carouselFailures = failures;
    window.__carouselSlideCount = document.querySelectorAll(".slide").length;
    window.__carouselDone = true;
  });
