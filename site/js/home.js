// =============================================================================
// home.js — landing page (index.html). Shared chrome plus one card per
// module, grouped under the same thematic headers as the nav (the grouping
// itself lives on editorial.nav; groupNav() in common.js is the one fold).
// Adding a module = one entry in editorial.home.modules plus its nav entry's
// `group` tag; the card links straight to that module's page and files
// itself under the right header (untagged modules land under "More").
// =============================================================================
import { editorial } from "./editorial.js";
import { el } from "./dom.js";
import { initChrome, groupNav } from "./common.js";

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

  section.append(head);

  // Cards grouped by the nav's group assignments (join on module id). A card
  // whose module the nav doesn't know — merged mid-flight — still renders,
  // in the trailing catch-all group.
  const cardsById = new Map(ed.modules.map((m) => [m.id, m]));
  const { groups } = groupNav();
  const more = editorial.navGroups[editorial.navGroups.length - 1];
  const blocks = groups.map((g) => ({
    group: g,
    cards: g.tabs.map((t) => cardsById.get(t.id)).filter(Boolean),
  }));
  const seen = new Set(blocks.flatMap((b) => b.cards.map((m) => m.id)));
  const leftovers = ed.modules.filter((m) => !seen.has(m.id));
  if (leftovers.length) {
    const tail = blocks.find((b) => b.group.id === more.id) ??
      blocks[blocks.push({ group: more, cards: [] }) - 1];
    tail.cards.push(...leftovers);
  }
  for (const { group, cards } of blocks) {
    if (!cards.length) continue;
    const block = el("div", "module-group");
    block.append(
      el("h3", "module-group-label", group.label),
      el("p", "module-group-lede", group.lede)
    );
    const grid = el("div", "module-grid");
    for (const mod of cards) grid.append(moduleCard(mod, ed));
    block.append(grid);
    section.append(block);
  }

  section.append(el("p", "panel-note", ed.backlogNote));
  main.append(section);

  return Promise.allSettled(jobs);
}

boot();
