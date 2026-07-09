// =============================================================================
// market.js — Security Market tab (market.html). Stub module: shared chrome
// plus an on-brand "under construction" teaser. Replace the teaser with real
// sections when this module's pipeline ships.
// =============================================================================
import { editorial } from "./editorial.js";
import { el } from "./dom.js";
import { initChrome } from "./common.js";

function boot() {
  const jobs = [initChrome("market")];

  const ed = editorial.market;
  const main = document.getElementById("sections");

  const section = el("section", "chart-section hero");
  section.id = "s-market-teaser";

  const head = el("header", "section-head");
  head.append(
    el("p", "section-kicker", ed.kicker),
    el("h2", "section-headline", ed.headline),
    el("p", "section-caption", ed.caption)
  );

  const panel = el("div", "panel teaser");
  panel.append(el("p", "teaser-status", ed.statusLine));
  panel.append(el("div", "panel-subtitle", ed.signalsTitle));

  const list = el("ul", "teaser-list");
  for (const sig of ed.signals) {
    const li = el("li", "teaser-item");
    const row = el("div", "teaser-row");
    row.append(el("span", "teaser-name", sig.name), el("span", "tag", ed.statusTag));
    li.append(row, el("span", "teaser-note", sig.note));
    list.append(li);
  }
  panel.append(list);
  panel.append(el("p", "panel-note", ed.promise));

  section.append(head, panel);
  main.append(section);

  return Promise.allSettled(jobs);
}

boot();
