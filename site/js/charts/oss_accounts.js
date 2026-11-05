// Open-Source Maintainers 1 (hero) — how many registry accounts can publish
// each of a registry's 250 most-depended-on packages. Contract:
// site/data/oss_maintainers.json (ecosystems[].accounts, single_account,
// team_or_org). One 100% bar per registry, never pooled: "maintainer" is
// defined per registry. The accent segment is the single-account case (one
// account, no team or organisation); a one-account package that a team or
// organisation can also publish sits in its own segment beside it.
import { C, fmtInt, fmtPct } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";
import {
  fillRef, noEdition, regLabel, stackedShares, tally, universeVars,
} from "./oss_common.js";

const bucketN = (eco, label) =>
  (eco.accounts?.buckets || []).find((b) => b.label === label)?.n ?? 0;

export function render(slots, data, refs) {
  const ed = editorial.sections.oss_accounts;
  const L = ed.labels;
  const ecos = data.ecosystems || [];
  if (!ecos.length) {
    noEdition(slots, ed.nodata, refs);
    return;
  }
  fillRef(refs?.methodText, universeVars(data));
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    noteEl.textContent = tpl(ed.note, {
      first: data.observed?.first,
      last: data.observed?.last,
      selected_at: data.universe?.selected_at,
    });
  }

  // ---- headline stat: the single-account share, per registry ---------------
  // Site only: on a carousel slide (carousel.js) the bars carry the same
  // shares as labels, and the slide needs the height for the bars.
  const onSlide = !!slots.panel.closest(".slide");
  const stat = el("div", "hero-stat");
  const row = el("div", "hero-stat-row");
  for (const e of ecos) {
    // Number and registry wrap as one unit, never apart.
    const pair = el("span");
    Object.assign(pair.style, { display: "inline-flex", alignItems: "baseline",
                                gap: "10px", marginRight: "18px" });
    pair.append(
      el("span", "hero-num accent", fmtPct(e.single_account?.pct)),
      el("span", "hero-when", `${regLabel(e.id)} · ${tpl(L.statOf, {
        n: fmtInt(e.single_account?.n),
        measured: fmtInt(e.measured),
      })}`)
    );
    row.append(pair);
  }
  stat.append(el("div", "hero-stat-label", ed.statLabel), frag(row));
  if (!onSlide) slots.stat.append(stat);

  // ---- the bars --------------------------------------------------------------
  const single = (e) => e.single_account?.n ?? 0;
  // An array, not an object: integer-like keys ("2", "3", "0") would
  // otherwise jump the queue and reorder the segments.
  const COLORS = [
    ["single", C.accent], ["1t", C.sev.high], ["2", "#ded7c2"], ["3", "#bdb5a0"],
    ["4–5", "#9c947f"], ["6–10", "#7b7462"], ["11+", "#5c5749"], ["0", "#8a6a3f"],
  ];
  const segments = COLORS.map(([key, color]) => {
    const label = key === "single" ? "1" : key;
    return { key, color, name: L.legend[label], tipName: L.buckets[label] };
  });
  const count = (e, key) => {
    if (key === "single") return single(e);
    if (key === "1t") return bucketN(e, "1") - single(e);
    return bucketN(e, key);
  };
  // A segment no registry has would only add a legend entry.
  const shown = segments.filter((s) => ecos.some((e) => count(e, s.key) > 0));
  stackedShares(slots, ecos, {
    segments: shown,
    count,
    total: (e) => e.measured,
    xAxis: ed.xAxis,
    labelKey: "single",
    tip: (e, seg, n, total, pct) => tpl(L.tip, {
      registry: regLabel(e.id),
      bucket: seg.tipName,
      n: fmtInt(n),
      measured: fmtInt(total),
      pct: fmtPct(pct),
    }),
  });

  // ---- the same packages, two more counts ---------------------------------
  if (onSlide) return;
  slots.extra.append(
    tally(ed.soleLabel, ecos.map((e) => tpl(ed.soleTemplate, {
      name: regLabel(e.id),
      largest: fmtInt(e.single_account?.largest),
      n: fmtInt(e.single_account?.n),
    }))),
    tally(ed.teamLabel, ecos.map((e) => tpl(ed.teamTemplate, {
      name: regLabel(e.id),
      n: fmtInt(e.team_or_org?.n),
    })))
  );
}
