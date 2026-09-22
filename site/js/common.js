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
  // Optional pointer to a sibling module that answers the adjacent question
  // (ed.seeAlso = { text, href, label }). Same tab: it is this site.
  if (ed.seeAlso) {
    const also = el("p", "section-seealso", ed.seeAlso.text + " ");
    also.append(link(ed.seeAlso.href, ed.seeAlso.label, "mono", { sameTab: true }));
    head.append(also);
  }

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
  const srcFile = editorial.sourceFiles[cfg.id] ?? "metrics.py";
  methodSrc.append(link(editorial.pipelineUrl + srcFile, `pipeline/${srcFile}`, "mono"));
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
  // Captions and methodology whose templates the renderer never got to fill
  // (the payload did not arrive) would otherwise show raw {braces}.
  const section = slots.panel.closest(".chart-section");
  section?.querySelectorAll(".section-caption, .method-body > p:first-child").forEach((p) => {
    if (/\{\w+\}/.test(p.textContent)) p.textContent = p.textContent.replace(/\{\w+\}/g, "n/a");
  });
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

// [id, href, label] — the nav's instrument links, in display order.
const INSTRUMENT_LINKS = [
  ["field", "field.html", "The Field →"],
  ["observatory", "observatory.html", "Observatory →"],
];

// Grouped nav. Phones: one row per group (label over its tabs) inside a
// fold. Desktop: a single bar of group buttons, with one group's pages open
// beneath it. Every destination is a plain <a>; the buttons only choose
// which row is visible.
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

  // Phones get every row stacked (inside the fold below); desktop shows one
  // line of groups and opens ONE group's pages beneath it — the current
  // page's group by default, none on the landing page, whose cards are the
  // directory. The rows are the same either way; CSS picks the layout.
  const activeGroup = groups.find((g) => g.tabs.some((t) => t.id === activeId))?.id ?? null;
  const groupBar = el("div", "site-nav-row site-nav-groups");
  for (const tab of leading) groupBar.append(tabEl(tab));
  const buttons = new Map();
  const rows = new Map();
  const showGroup = (id) => {
    for (const [gid, row] of rows) {
      const on = gid === id;
      row.classList.toggle("is-shown", on);
      buttons.get(gid).setAttribute("aria-expanded", String(on));
    }
  };
  for (const g of groups) {
    const btn = el("button", "site-nav-group-btn" + (g.id === activeGroup ? " is-current" : ""), g.label);
    btn.type = "button";
    btn.setAttribute("aria-controls", `site-nav-row-${g.id}`);
    btn.addEventListener("click", () =>
      showGroup(btn.getAttribute("aria-expanded") === "true" ? null : g.id));
    buttons.set(g.id, btn);
    groupBar.append(btn);
  }
  // Instruments (not modules, so not in editorial.nav): after the groups on
  // desktop, their own row on phones.
  const instrumentLinks = (first) => INSTRUMENT_LINKS.map(([id, href, label], i) => {
    const a = link(href, label, "site-nav-tab" + (i === 0 && first ? ` ${first}` : "") +
      (id === activeId ? " is-active" : ""), { sameTab: true });
    if (id === activeId) a.setAttribute("aria-current", "page");
    return a;
  });
  groupBar.append(...instrumentLinks("site-nav-field"));

  const instruments = el("div", "site-nav-row site-nav-row-instruments");
  instruments.append(el("span", "site-nav-group-label", "Instruments"), ...instrumentLinks(null));
  nav.append(groupBar, instruments);

  if (leading.length) {
    const row = el("div", "site-nav-row site-nav-row-lead");
    for (const tab of leading) row.append(tabEl(tab));
    nav.append(row);
  }
  for (const g of groups) {
    const row = el("div", "site-nav-row site-nav-group-row" + (g.id === activeGroup ? " is-active" : ""));
    row.id = `site-nav-row-${g.id}`;
    row.append(el("span", "site-nav-group-label", g.label));
    for (const tab of g.tabs) row.append(tabEl(tab));
    rows.set(g.id, row);
    nav.append(row);
  }
  showGroup(activeGroup);

  // Phones: 27 links would fill the whole first screen before any content,
  // so the rows fold behind one summary naming the current page. Desktop
  // keeps them open (the summary is hidden there by CSS).
  const current = editorial.nav.find((t) => t.id === activeId) ??
    editorial.home.instruments?.items.find((t) => t.id === activeId);
  const fold = el("details", "site-nav-fold");
  const summary = el("summary", "site-nav-summary");
  summary.append(
    el("span", "site-nav-summary-label", editorial.navFoldLabel),
    el("span", "site-nav-summary-current", current?.label ?? "")
  );
  fold.append(summary, ...nav.childNodes);
  nav.append(fold);
  const wide = window.matchMedia?.("(min-width: 721px)");
  const sync = () => { fold.open = !wide || wide.matches; };
  sync();
  wide?.addEventListener?.("change", sync);
}

// "On this page": a jump list over the page's sections, for the long module
// pages (a phone scroll of 15,000px otherwise has no table of contents).
// Runs after the page script has appended its sections (same tick).
function renderToc() {
  const main = document.getElementById("sections");
  const sections = main ? [...main.querySelectorAll(":scope > .chart-section[id]")] : [];
  if (sections.length < 3) return;
  const toc = el("nav", "page-toc");
  toc.setAttribute("aria-label", editorial.tocLabel);
  toc.append(el("span", "page-toc-label", editorial.tocLabel));
  const list = el("ol", "page-toc-list");
  for (const s of sections) {
    const kicker = s.querySelector(".section-kicker")?.textContent?.trim();
    if (!kicker) continue;
    const a = el("a", "page-toc-link", kicker);
    a.href = `#${s.id}`;
    const li = el("li");
    li.append(a);
    list.append(li);
  }
  toc.append(list);
  main.prepend(toc);
}

function renderMasthead() {
  // On module pages the wordmark is the way home.
  const title = document.querySelector(".masthead-title");
  if (title && document.body.classList.contains("page-module") && !title.querySelector("a")) {
    const home = el("a", "masthead-home");
    home.href = "index.html";
    home.setAttribute("aria-label", "CyberMon overview");
    home.append(...title.childNodes);
    title.append(home);
  }
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
  // Instruments have no carousel.
  if (activeTabId && activeTabId !== "home" && editorial.nav.some((t) => t.id === activeTabId)) {
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
      epss_graded: (s.epss_history?.graded ?? 0).toLocaleString("en-US") +
        (s.epss_history?.stale ? " (carried forward)" : ""),
      rescore_events: (s.rescores?.events_total ?? 0).toLocaleString("en-US"),
      kev_changelog_events: (s.kev_changelog?.events_total ?? 0).toLocaleString("en-US"),
      exploitdb_entries: (s.exploitdb?.entry_count ?? 0).toLocaleString("en-US"),
      metasploit_modules: (s.metasploit?.module_count ?? 0).toLocaleString("en-US"),
      nuclei_cves: (s.nuclei?.cve_count ?? 0).toLocaleString("en-US"),
      feodo_listed: (s.feodo?.listed ?? 0).toLocaleString("en-US"),
      feodo_online: (s.feodo?.online ?? 0).toLocaleString("en-US"),
      feodo_fetched: s.feodo?.fetched_at ?? "?",
      sec_incidents: s.sec_incidents?.fetched_at
        ? tpl(editorial.footer.secFetched, {
            filings_105: (s.sec_incidents.filings_105 ?? 0).toLocaleString("en-US"),
            filings_801: (s.sec_incidents.filings_801 ?? 0).toLocaleString("en-US"),
            fetched: s.sec_incidents.fetched_at +
              (s.sec_incidents.stale ? " (carried forward)" : ""),
          })
        : editorial.footer.secPending,
      osv_ghsa: (s.osv?.ghsa_advisories ?? 0).toLocaleString("en-US"),
      osv_mal: (s.osv?.mal_reports ?? 0).toLocaleString("en-US"),
      osv_fetched: (s.osv?.fetched_at ?? "?") + (s.osv?.stale ? " (carried forward)" : ""),
    }))
  );
}

// Renders masthead, nav, footer; loads meta.json (banner + edition stamp).
// Returns a promise that settles when meta handling is done.
export function initChrome(activeTabId) {
  // Module pages get the compact masthead; the manifesto lines stay on the
  // landing page, where they introduce the site.
  document.body.classList.add(activeTabId === "home" ? "page-home" : "page-module");
  renderMasthead();
  renderNav(activeTabId);
  if (activeTabId !== "home") queueMicrotask(renderToc);
  renderFooterText(activeTabId);
  return fetchJSON("data/meta.json")
    .then(renderMeta)
    .catch((err) => {
      console.warn("[CyberMon] meta.json failed:", err);
      const metaEl = clear(document.getElementById("footer-meta"));
      metaEl.append(el("p", "mono muted", editorial.footer.metaError));
    });
}
