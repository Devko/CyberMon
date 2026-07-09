// =============================================================================
// home.js — landing page (index.html). Shared chrome plus one card per
// module. Adding a module = one entry in editorial.home.modules; the card
// links straight to that module's page (every tab is direct-linkable).
// =============================================================================
import { editorial } from "./editorial.js";
import { el } from "./dom.js";
import { initChrome } from "./common.js";

function moduleCard(mod, ed) {
  const card = el("a", "module-card" + (mod.live ? "" : " is-pending"));
  card.href = mod.href; // relative — works under GitHub Pages subpaths

  const row = el("div", "module-card-row");
  row.append(
    el("span", "module-card-num mono", mod.num),
    el("span", "tag" + (mod.live ? " tag-live" : ""), mod.live ? ed.statusLive : ed.statusSoon)
  );

  card.append(
    row,
    el("h3", "module-card-label", mod.label),
    el("p", "module-card-headline", mod.headline),
    el("p", "module-card-blurb", mod.blurb)
  );
  return card;
}

function boot() {
  const jobs = [initChrome("home")];

  const ed = editorial.home;
  const main = document.getElementById("sections");

  const section = el("section", "chart-section hero");
  section.id = "s-modules";

  const head = el("header", "section-head");
  head.append(
    el("p", "section-kicker", ed.kicker),
    el("h2", "section-headline", ed.headline),
    el("p", "section-caption", ed.caption)
  );

  const grid = el("div", "module-grid");
  for (const mod of ed.modules) grid.append(moduleCard(mod, ed));

  const note = el("p", "panel-note", ed.backlogNote);

  section.append(head, grid, note);
  main.append(section);

  return Promise.allSettled(jobs);
}

boot();
