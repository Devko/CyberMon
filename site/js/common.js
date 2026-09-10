// =============================================================================
// common.js — shared chrome for every CyberMon tab/page.
//
// A new tab module needs exactly this:
//   1. Copy the HTML skeleton (masthead ids, #site-nav, #sample-banner, footer ids).
//   2. Link css/shared.css.
//   3. In its page script: import { initChrome, fetchJSON, buildSection,
//      showError } and call initChrome("<nav id from editorial.nav>").
//
// initChrome renders masthead + tabs + footer, loads data/meta.json, and shows
// the synthetic-sample banner when meta.sample === true. buildSection builds
// one chart section's skeleton from editorial.sections; showError turns it
// into an inline error card (data failure vs. chart-library failure).
// =============================================================================
import { editorial, tpl } from "./editorial.js";
import { el, link, clear } from "./dom.js";

// ---- data loading -----------------------------------------------------------

// Dev hook: ?fail=nine_eight_flood,meta simulates fetch failures (error cards).
const SIMULATE_FAIL = new Set(
  (new URLSearchParams(location.search).get("fail") || "").split(",").filter(Boolean)
);

// Every failure fetchJSON raises is a DataError, so a section's catch can
// tell "the JSON never arrived" from "the JSON arrived and the renderer
// threw" (showError uses that to pick the right card).
export class DataError extends Error {}

export async function fetchJSON(path) {
  const key = path.replace(/^data\//, "").replace(/\.json$/, "");
  if (SIMULATE_FAIL.has(key) || SIMULATE_FAIL.has(path)) {
    throw new DataError(`${path}: simulated failure (?fail=)`);
  }
  let res;
  try {
    res = await fetch(path, { cache: "no-cache" });
  } catch (err) {
    throw new DataError(`${path}: ${err.message}`, { cause: err });
  }
  if (!res.ok) throw new DataError(`${path}: HTTP ${res.status}`);
  try {
    return await res.json();
  } catch (err) {
    throw new DataError(`${path}: ${err.message}`, { cause: err });
  }
}

// ---- inline error card (section-level resilience) ---------------------------

// kind: "data" (default — the JSON could not be fetched) or "library" (the
// JSON is fine but ECharts never loaded, so the chart cannot draw).
export function errorCard(file, kind = "data") {
  const copy = editorial.loadError;
  const title = kind === "library" ? copy.libraryTitle : copy.title;
  const bodyTpl = kind === "library" ? copy.libraryBody : copy.body;
  const card = el("div", "error-card");
  const body = el("p");
  const [before, after] = bodyTpl.split("{file}");
  body.append(before, el("code", null, file), after ?? "");
  card.append(el("strong", null, title), body);
  return card;
}

// ---- chart section skeleton -------------------------------------------------
//
// One skeleton for every module page (was a per-module copy). Layout:
//   <section class="chart-section[ hero]" id="s-<id>">
//     <header class="section-head">  kicker · headline · caption
//     <div class="section-stat">      (hero numbers, filled by the renderer)
//     <div class="panel">             controls · chart · extra · [note] · [source]
//     <details class="method">        methodology + source-of-truth link
//
// cfg:  { id, hero?, ... } — the module's SECTIONS entry (id keys editorial).
// ed:   the editorial.sections entry; defaults to editorial.sections[cfg.id].
// opts.noteKeys: which `ed` keys feed the panel-note slot, first present wins
//       (default ["note"]; kev uses ["backfillNote"], breaches
//       ["importNote", "catalogNote"]). The note is rendered as a template
//       now and filled by the renderer once the payload is here.
// Returns { section, slots: { stat, panel, controls, chart, extra }, caption,
// methodText } — caption/methodText so renderers can fill {placeholders}
// from the contract (cve.js, concentration.js).
export function buildSection(cfg, ed = null, opts = {}) {
  ed = ed ?? editorial.sections[cfg.id];
  if (!ed) throw new Error(`no editorial.sections entry for section "${cfg.id}"`);
  const { noteKeys = ["note"] } = opts;

  const section = el("section", "chart-section" + (cfg.hero ? " hero" : ""));
  section.id = `s-${cfg.id}`;

  const head = el("header", "section-head");
  const caption = el("p", "section-caption", ed.caption);
  head.append(
    el("p", "section-kicker", `${ed.num} — ${ed.kicker}`),
    el("h2", "section-headline", ed.headline),
    caption
  );

  const stat = el("div", "section-stat");
  const panel = el("div", "panel");
  const controls = el("div", "panel-controls");
  const chart = el("div", "chart" + (cfg.hero ? " chart-tall" : ""));
  // Accessible name for the chart canvas; mkChart (theme.js) adds role="img"
  // once a canvas is actually drawn here (boards render a <table> instead,
  // which must stay reachable, so the role is not set up front).
  chart.setAttribute("aria-label", ed.headline);
  const extra = el("div", "panel-extra");
  panel.append(controls, chart, extra);

  const noteKey = noteKeys.find((k) => ed[k]);
  if (noteKey) panel.append(el("p", "panel-note", ed[noteKey]));

  if (ed.source) {
    const src = el("p", "chart-source");
    src.append(editorial.chartSourcePrefix + ed.source + " \u00b7 ");
    src.append(link("#footer", editorial.chartSourceLinkText, "mono"));
    panel.append(src);
  }

  const details = el("details", "method");
  const summary = el("summary", null, editorial.methodologyLabel);
  const methodBody = el("div", "method-body");
  const methodText = el("p", null, ed.methodology);
  const methodSrc = el("p", "method-src", editorial.methodologySourcePrefix);
  methodSrc.append(link(editorial.metricsUrl, editorial.methodologySourceLinkText, "mono"));
  methodBody.append(methodText, methodSrc);
  details.append(summary, methodBody);

  section.append(head, stat, panel, details);

  return { section, slots: { stat, panel, controls, chart, extra }, caption, methodText };
}

// Collapse a built section into one inline error card. `err` (optional) is
// what the section's catch received: a DataError means the JSON never
// arrived; anything else while window.echarts is missing means the data is
// fine and the chart library is what failed — say so, and point at the file.
export function showError(slots, file, err = null) {
  clear(slots.stat);
  clear(slots.controls);
  clear(slots.extra);
  // Never leave an unfilled {placeholder} note next to an error card.
  slots.panel.querySelector(".panel-note")?.remove();
  clear(slots.chart).classList.remove("chart", "chart-tall");
  slots.chart.removeAttribute("role");
  const kind = !window.echarts && !(err instanceof DataError) ? "library" : "data";
  slots.chart.append(errorCard(file, kind));
}

// ---- shared chrome -----------------------------------------------------------

// Fold the FLAT editorial.nav into the thematic groups declared in
// editorial.navGroups. One fold, used by the nav below AND the landing
// page's card groups (home.js), so the two can never disagree about where
// a module lives. Rules:
//   - ungrouped entries at the head of the array (Overview) come back as
//     `leading` — standalone tabs before any group;
//   - every other entry lands in its declared group, or — when the group id
//     is missing or unknown — in the LAST navGroups entry ("More"), so a
//     module merged without a tag still ships navigable;
//   - groups with no entries are dropped, never rendered empty.
export function groupNav() {
  const groups = editorial.navGroups.map((g) => ({ ...g, tabs: [] }));
  const byId = new Map(groups.map((g) => [g.id, g]));
  const more = groups[groups.length - 1];
  const leading = [];
  let grouped = false;
  for (const tab of editorial.nav) {
    if (!tab.group && !grouped) {
      leading.push(tab);
      continue;
    }
    grouped = true;
    (byId.get(tab.group) ?? more).tabs.push(tab);
  }
  return { leading, groups: groups.filter((g) => g.tabs.length) };
}

// Grouped nav: one centered row of standalone tabs (Overview), then one row
// per group — group label on the left of its tabs, rows separated by
// hairlines, tabs wrapping within their row. Plain <a> elements throughout:
// navigation needs no JS beyond this render (progressive enhancement only).
function renderNav(activeId) {
  const nav = document.getElementById("site-nav");
  if (!nav) return;
  clear(nav);

  const tabEl = (tab) => {
    const a = el("a", "site-nav-tab" + (tab.id === activeId ? " is-active" : ""), tab.label);
    a.href = tab.href; // relative — works under GitHub Pages subpaths
    if (tab.id === activeId) a.setAttribute("aria-current", "page");
    return a;
  };

  const { leading, groups } = groupNav();

  if (leading.length) {
    const row = el("div", "site-nav-row site-nav-row-lead");
    for (const tab of leading) row.append(tabEl(tab));
    nav.append(row);
  }
  for (const g of groups) {
    const active = g.tabs.some((t) => t.id === activeId);
    const row = el("div", "site-nav-row" + (active ? " is-active" : ""));
    row.append(el("span", "site-nav-group-label", g.label));
    for (const tab of g.tabs) row.append(tabEl(tab));
    nav.append(row);
  }
  const instruments = el("div", "site-nav-row");
  instruments.append(el("span", "site-nav-group-label", "Instruments"), link("field.html", "The Field →", "site-nav-tab"));
  nav.prepend(instruments);
}

function renderMasthead() {
  document.getElementById("masthead-kicker").textContent = editorial.masthead.kicker;
  document.getElementById("masthead-thesis").textContent = editorial.masthead.thesis;
  document.getElementById("masthead-sub").textContent = editorial.masthead.sub;
}

function renderFooterText(activeTabId) {
  const ft = clear(document.getElementById("footer-text"));
  const repo = el("p", "footer-repo");
  repo.append(link(editorial.repoUrl, editorial.footer.repoLabel, "mono"));
  ft.append(
    el("p", "muted", editorial.footer.dataNote),
    el("p", "muted", editorial.footer.disclaimer),
    el("p", "muted", editorial.footer.reuseNote),
    repo
  );
  // Module pages only — the Overview aggregates every module and has no
  // single carousel. The PDF is generated at deploy time
  // (tools/make_carousels.py) and shipped only inside the Pages artifact,
  // so on a local checkout this link 404s until the generator has run —
  // acceptable for a deploy-time build product.
  if (activeTabId && activeTabId !== "home") {
    const dl = el("p", "footer-carousel");
    const a = el("a", "mono", tpl(editorial.footer.carouselTemplate, { id: activeTabId }));
    a.href = `carousels/${activeTabId}.pdf`; // relative — works under GitHub Pages subpaths
    dl.append(a);
    ft.append(dl);
  }
  // Animated clip, for the modules that have one (editorial.motion.byModule).
  // Same deploy-time-build-product caveat as the carousel above: generated by
  // tools/make_motion.py into the Pages artifact, so this link 404s on a local
  // checkout until the generator has run.
  const sceneId = editorial.motion.byModule[activeTabId];
  if (sceneId) {
    const dl = el("p", "footer-carousel");
    const a = el("a", "mono", tpl(editorial.motion.linkTemplate, { scene: sceneId }));
    a.href = `motion/${sceneId}.mp4`; // relative — works under GitHub Pages subpaths
    dl.append(a);
    ft.append(dl);
  }
}

function renderMeta(meta) {
  const banner = document.getElementById("sample-banner");
  if (meta.sample === true) {
    banner.textContent = editorial.sampleBanner;
    banner.hidden = false;
  } else {
    // Stale-edition check: if the nightly pipeline breaks, the site quietly
    // ages — make it loud. Reuses the #sample-banner element deliberately so
    // every page's HTML skeleton stays unchanged (one banner slot per page;
    // the sample banner wins when both would apply).
    const generated = Date.parse(meta.generated_at);
    if (Number.isFinite(generated)) {
      const ageMs = Date.now() - generated;
      const staleAfterMs = 48 * 60 * 60 * 1000;
      if (ageMs > staleAfterMs) {
        banner.textContent = tpl(editorial.staleBanner, {
          age_days: Math.floor(ageMs / (24 * 60 * 60 * 1000)),
          generated_at: meta.generated_at,
        });
        banner.hidden = false;
      }
    }
    // Unparsable generated_at: do nothing — a broken date is not proof of age.
  }
  const s = meta.sources || {};
  const metaEl = clear(document.getElementById("footer-meta"));
  metaEl.append(
    el("p", "mono", tpl(editorial.footer.generatedTemplate, { generated_at: meta.generated_at })),
    el("p", "mono muted", tpl(editorial.footer.sourcesTemplate, {
      cvelist_release: s.cvelist?.release ?? "?",
      cve_count: (s.cvelist?.cve_count ?? 0).toLocaleString("en-US"),
      epss_version: s.epss?.model_version ?? "?",
      epss_date: s.epss?.score_date ?? "?",
      kev_version: s.kev?.catalog_version ?? "?",
      kev_count: (s.kev?.count ?? 0).toLocaleString("en-US"),
      nvd_fetched: (s.nvd?.fetched_at ?? "?") + (s.nvd?.stale ? " (carried forward)" : ""),
      market_fetched: (s.market?.fetched_at ?? "?") + (s.market?.stale ? " (carried forward)" : ""),
      hibp_fetched: (s.hibp?.fetched_at ?? "?") + (s.hibp?.stale ? " (carried forward)" : ""),
      hibp_count: (s.hibp?.breach_count ?? 0).toLocaleString("en-US"),
      ransomwhere_addresses: (s.ransomwhere?.address_count ?? 0).toLocaleString("en-US"),
      ransomwhere_txs: (s.ransomwhere?.tx_count ?? 0).toLocaleString("en-US"),
      ransomwhere_fetched: (s.ransomwhere?.fetched_at ?? "?") + (s.ransomwhere?.stale ? " (carried forward)" : ""),
      attack_version: (s.attack?.latest_version ?? "?") + (s.attack?.stale ? " (carried forward)" : ""),
      attack_versions: (s.attack?.version_count ?? 0).toLocaleString("en-US"),
      apnic_fetched: (s.apnic?.fetched_at ?? "?") + (s.apnic?.stale ? " (carried forward)" : ""),
      epss_graded: (s.epss_history?.graded ?? 0).toLocaleString("en-US"),
      rescore_events: (s.rescores?.events_total ?? 0).toLocaleString("en-US"),
      kev_changelog_events: (s.kev_changelog?.events_total ?? 0).toLocaleString("en-US"),
      exploitdb_entries: (s.exploitdb?.entry_count ?? 0).toLocaleString("en-US"),
      metasploit_modules: (s.metasploit?.module_count ?? 0).toLocaleString("en-US"),
      nuclei_cves: (s.nuclei?.cve_count ?? 0).toLocaleString("en-US"),
      feodo_listed: (s.feodo?.listed ?? 0).toLocaleString("en-US"),
      feodo_online: (s.feodo?.online ?? 0).toLocaleString("en-US"),
      feodo_fetched: s.feodo?.fetched_at ?? "?",
    }))
  );
}

// Renders masthead, nav, footer; loads meta.json (banner + edition stamp).
// Returns a promise that settles when meta handling is done.
export function initChrome(activeTabId) {
  renderMasthead();
  renderNav(activeTabId);
  renderFooterText(activeTabId);
  return fetchJSON("data/meta.json")
    .then(renderMeta)
    .catch((err) => {
      console.warn("[CyberMon] meta.json failed:", err);
      const metaEl = clear(document.getElementById("footer-meta"));
      metaEl.append(el("p", "mono muted", editorial.footer.metaError));
    });
}
