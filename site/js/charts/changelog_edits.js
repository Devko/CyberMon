// Changelog 1 (hero) — the edit stream: edits per month by kind, stacked.
// Contract: site/data/kev_changelog.json (shared by all three sections;
// changelog.js fetches it once). Additions are deliberately absent — the
// chart counts revisions to already-published entries (the caption says
// why). Accent ink on the ransomware-flag band on purpose: a flipped flag
// is the catalog's costliest kind of correction.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

const CATEGORIES = [
  { key: "due_date", legendKey: "legendDueDate", color: "#c08a45" },
  { key: "ransomware_flag", legendKey: "legendFlag", color: C.accent },
  { key: "text", legendKey: "legendText", color: "#77715f" },
  { key: "removed", legendKey: "legendRemoved", color: "#ded7c2" },
];

export function render(slots, data) {
  const ed = editorial.sections.edits;
  const catalog = data.catalog || {};

  // ---- headline stat ----------------------------------------------------
  const h = data.headline;
  const stat = el("div", "hero-stat");
  stat.append(el("div", "hero-stat-label", ed.statLabel));
  const row = el("div", "hero-stat-row");
  if (h && Number.isFinite(h.edits_total)) {
    row.append(
      el("span", "hero-num accent", fmtInt(h.edits_total)),
      el("span", "hero-when", tpl(ed.statNote, {
        entries: fmtInt(catalog.entries ?? 0),
        additions: fmtInt(catalog.additions_excluded ?? 0),
      }))
    );
  } else {
    // Baseline night: the record exists but holds no events yet.
    row.append(el("span", "hero-when muted", "Not enough data yet."));
  }
  stat.append(row);
  slots.stat.append(stat);

  // ---- record-start note (data-driven, kev_latency backfillNote pattern) --
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    if (catalog.first_observed) {
      const parts = [tpl(ed.note, { first_observed: catalog.first_observed })];
      if ((catalog.backfill_captures ?? 0) > 0) {
        parts.push(tpl(ed.waybackNote, {
          captures: fmtInt(catalog.backfill_captures),
        }));
      }
      noteEl.textContent = parts.join(" ");
    } else {
      noteEl.remove(); // never show a template with holes in it
    }
  }

  // ---- chart --------------------------------------------------------------
  const rows = data.months || [];
  if (!rows.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // The generation month plots but is partial — mark it (volume.js pattern).
  const genMonth = data.generated_at.slice(0, 7);
  const cats = rows.map((r) => (r.month === genMonth ? `${r.month}*` : r.month));

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 40, bottom: 48 },
    legend: {
      ...baseLegend,
      data: CATEGORIES.map((c) => ed[c.legendKey]),
    },
    tooltip: {
      ...baseTooltip,
      formatter: (p) => {
        const r = rows[p.dataIndex];
        if (!r) return "";
        const lines = [
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(p.name))}</div>`,
        ];
        for (const c of CATEGORIES) {
          if (r[c.key] > 0) {
            lines.push(
              `<span style="color:${c.color}">${escapeHtml(ed[c.legendKey])}</span> ` +
              `<strong>${fmtInt(r[c.key])}</strong><br>`
            );
          }
        }
        lines.push(`${fmtInt(r.total)} edits`);
        return lines.join("");
      },
    },
    xAxis: catAxis(cats, {
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 10, rotate: 45 },
    }),
    yAxis: valAxis(),
    series: CATEGORIES.map((c) => ({
      name: ed[c.legendKey],
      type: "bar",
      stack: "edits",
      barCategoryGap: "25%",
      data: rows.map((r) => r[c.key]),
      itemStyle: { color: c.color, opacity: 0.88 },
    })),
  });
}
