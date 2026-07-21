// =============================================================================
// common.js — shared chrome for every CyberMon tab/page.
//
// A new tab module needs exactly this:
//   1. Copy the HTML skeleton (masthead ids, #site-nav, #sample-banner, footer ids).
//   2. Link css/shared.css.
//   3. In its page script: import { initChrome, fetchJSON, errorCard } and call
//      initChrome("<nav id from editorial.nav>").
//
// initChrome renders masthead + tabs + footer, loads data/meta.json, and shows
// the synthetic-sample banner when meta.sample === true.
// =============================================================================
import { editorial, tpl } from "./editorial.js";
import { el, link, clear } from "./dom.js";

// ---- data loading -----------------------------------------------------------

// Dev hook: ?fail=nine_eight_flood,meta simulates fetch failures (error cards).
const SIMULATE_FAIL = new Set(
  (new URLSearchParams(location.search).get("fail") || "").split(",").filter(Boolean)
);

export async function fetchJSON(path) {
  const key = path.replace(/^data\//, "").replace(/\.json$/, "");
  if (SIMULATE_FAIL.has(key) || SIMULATE_FAIL.has(path)) {
    throw new Error(`${path}: simulated failure (?fail=)`);
  }
  const res = await fetch(path, { cache: "no-cache" });
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json();
}

// ---- inline error card (section-level resilience) ---------------------------

export function errorCard(file) {
  const card = el("div", "error-card");
  const title = el("strong", null, editorial.loadError.title);
  const body = el("p");
  const [before, after] = editorial.loadError.body.split("{file}");
  body.append(before, el("code", null, file), after ?? "");
  card.append(title, body);
  return card;
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
      hibp_fetched: s.hibp?.fetched_at ?? "?",
      hibp_count: (s.hibp?.breach_count ?? 0).toLocaleString("en-US"),
      ransomwhere_addresses: (s.ransomwhere?.address_count ?? 0).toLocaleString("en-US"),
      ransomwhere_txs: (s.ransomwhere?.tx_count ?? 0).toLocaleString("en-US"),
      ransomwhere_fetched: s.ransomwhere?.fetched_at ?? "?",
      attack_version: (s.attack?.latest_version ?? "?") + (s.attack?.stale ? " (carried forward)" : ""),
      attack_versions: (s.attack?.version_count ?? 0).toLocaleString("en-US"),
      apnic_fetched: s.apnic?.fetched_at ?? "?",
      epss_graded: (s.epss_history?.graded ?? 0).toLocaleString("en-US"),
      rescore_events: (s.rescores?.events_total ?? 0).toLocaleString("en-US"),
      kev_changelog_events: (s.kev_changelog?.events_total ?? 0).toLocaleString("en-US"),
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
