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

function renderNav(activeId) {
  const nav = document.getElementById("site-nav");
  if (!nav) return;
  clear(nav);
  for (const tab of editorial.nav) {
    const a = el("a", "site-nav-tab" + (tab.id === activeId ? " is-active" : ""), tab.label);
    a.href = tab.href; // relative — works under GitHub Pages subpaths
    if (tab.id === activeId) a.setAttribute("aria-current", "page");
    nav.append(a);
  }
}

function renderMasthead() {
  document.getElementById("masthead-kicker").textContent = editorial.masthead.kicker;
  document.getElementById("masthead-thesis").textContent = editorial.masthead.thesis;
  document.getElementById("masthead-sub").textContent = editorial.masthead.sub;
}

function renderFooterText() {
  const ft = clear(document.getElementById("footer-text"));
  const repo = el("p", "footer-repo");
  repo.append(link(editorial.repoUrl, editorial.footer.repoLabel, "mono"));
  ft.append(
    el("p", "muted", editorial.footer.dataNote),
    el("p", "muted", editorial.footer.disclaimer),
    el("p", "muted", editorial.footer.reuseNote),
    repo
  );
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
    }))
  );
}

// Renders masthead, nav, footer; loads meta.json (banner + edition stamp).
// Returns a promise that settles when meta handling is done.
export function initChrome(activeTabId) {
  renderMasthead();
  renderNav(activeTabId);
  renderFooterText();
  return fetchJSON("data/meta.json")
    .then(renderMeta)
    .catch((err) => {
      console.warn("[CyberMon] meta.json failed:", err);
      const metaEl = clear(document.getElementById("footer-meta"));
      metaEl.append(el("p", "mono muted", editorial.footer.metaError));
    });
}
