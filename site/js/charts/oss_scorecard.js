// Open-Source Maintainers 3 — OpenSSF Scorecard checks for the GitHub
// repositories behind each registry's 250 packages. Contract:
// site/data/oss_maintainers.json (ecosystems[].scorecard). A check picker
// (Maintained by default) above one 100% bar per registry, split by the
// check's score; "inconclusive" is Scorecard's -1, kept apart from 0. Each
// repository counts once per registry, and only results Scorecard produced
// within the edition's age limit are scored.
import { C, fmtInt, fmtPct } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { clear } from "../dom.js";
import { mkToggle } from "../ui.js";
import {
  fillRef, noEdition, regLabel, stackedShares, tally, universeVars, wrapToggle,
} from "./oss_common.js";

const CHECKS = ["Maintained", "Code-Review", "Branch-Protection", "Signed-Releases"];
// Score 0 in accent (the headline's case); higher scores in lighter
// neutrals; inconclusive in the faintest, since it is no score at all.
const BUCKET_COLORS = {
  "0": C.accent,
  "1–4": C.sev.high,
  "5–7": "#a89f8a",
  "8–10": "#ded7c2",
  inconclusive: "#5c5749",
};
const BUCKETS = ["0", "1–4", "5–7", "8–10", "inconclusive"];

export function render(slots, data, refs) {
  const ed = editorial.sections.oss_scorecard;
  const L = ed.labels;
  const ecos = data.ecosystems || [];
  if (!ecos.length || !ecos.some((e) => e.scorecard?.scored)) {
    noEdition(slots, ed.nodata, refs);
    return;
  }
  fillRef(refs?.methodText, universeVars(data));
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    noteEl.textContent = tpl(ed.note, {
      first: data.scorecard_dates?.first,
      last: data.scorecard_dates?.last,
    });
  }

  const judged = (e, check) => (e.scorecard?.scored ?? 0) -
    (e.scorecard?.not_reported?.[check] ?? 0);
  const bucket = (e, check, key) =>
    (e.scorecard?.checks?.[check] || []).find((b) => b.label === key)?.n ?? 0;

  const draw = (check) => {
    window.echarts?.getInstanceByDom(slots.chart)?.dispose();
    clear(slots.chart);
    stackedShares(slots, ecos, {
      segments: BUCKETS.map((key) => ({
        key, name: L.buckets[key], color: BUCKET_COLORS[key],
      })),
      count: (e, key) => bucket(e, check, key),
      total: (e) => judged(e, check),
      xAxis: ed.xAxis,
      labelKey: "0",
      tip: (e, seg, n, total, pct) => tpl(L.tip, {
        registry: regLabel(e.id),
        check: L.checks[check],
        bucket: seg.name,
        n: fmtInt(n),
        scored: fmtInt(total),
        pct: fmtPct(pct),
      }),
    });
  };
  slots.controls.append(wrapToggle(mkToggle(CHECKS.map((c) => L.checks[c]),
    (i) => draw(CHECKS[i]))));
  draw(CHECKS[0]);

  slots.extra.append(
    tally(ed.coverageLabel, ecos.map((e) => tpl(ed.coverageTemplate, {
      name: regLabel(e.id),
      scored: fmtInt(e.scorecard?.scored),
      repos: fmtInt(e.scorecard?.repos),
    }))),
    tally(ed.medianLabel, ecos.map((e) => tpl(ed.medianTemplate, {
      name: regLabel(e.id),
      median: Number.isFinite(e.scorecard?.median_score)
        ? e.scorecard.median_score.toFixed(1) : editorial.ui.na,
    })))
  );
}
