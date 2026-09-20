// 06 — where the tools were pointed: the most-credited affected products per
// kind. Contract: site/data/ai_credits.json (targets). Plain HTML ranked
// lists in the funnel's two-column layout; the bar is the product's share of
// that kind's CVEs that name a product at all.
import { C, fmtInt, fmtPct } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

const KINDS = ["llm", "vendor"];

function column(kind, t, ed, labels) {
  const col = el("div", "funnel-col");
  col.append(el("h3", "funnel-kind", labels[kind]));
  if (!t.projects.length) {
    col.append(el("div", "nodata-card", ed.nodata));
    return col;
  }
  col.append(el("p", "funnel-rule target-share", tpl(ed.shareTemplate, {
    top_n: t.top_share_n,
    share: fmtPct(t.top_share_pct),
    named: fmtInt(t.named),
    distinct: fmtInt(t.distinct),
  })));

  const list = el("ol", "target-list");
  const max = t.projects[0].n;
  t.projects.forEach((p, i) => {
    const li = el("li", "target" + (i < t.top_share_n ? " is-top" : ""));
    const track = el("div", "funnel-track");
    const fill = el("div", "funnel-fill");
    fill.style.width = `${((p.n / max) * 100).toFixed(1)}%`;
    if (i < t.top_share_n) fill.style.background = kind === "llm" ? C.sev.high : C.versions.v4;
    track.append(fill);
    const val = el("span", "stage-val", fmtInt(p.n));
    val.append(el("span", "muted", fmtPct(p.pct)));
    const name = el("span", "target-name", p.label);
    name.title = p.label; // long vendor / product pairs truncate
    li.append(name, track, val);
    list.append(li);
  });
  col.append(list);
  return col;
}

export function render(slots, data) {
  const ed = editorial.sections.credits_targets;
  const labels = editorial.sections.credits_funnel.kindLabels;
  slots.chart.classList.remove("chart", "chart-tall");
  if (!data.targets) {
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }
  const cols = el("div", "funnel-cols");
  for (const kind of KINDS) cols.append(column(kind, data.targets[kind], ed, labels));
  slots.chart.append(cols);
}
