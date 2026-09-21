// Hero — claimed -> credited -> high/critical -> public exploit -> KEV, one
// column per kind. Each measured stage is a share of credited, not nested.
// Contract: site/data/ai_credits.json
// Plain HTML (no ECharts): the two kinds are never on one axis. Claims are
// grouped per finder under the one measured number that applies to all of
// them, and a claim is drawn to the measured scale ONLY when its unit is
// itself "CVEs assigned" — every other claim is a number with its unit and
// receipt, and no bar, because a track that encodes nothing is noise.
import { fmtInt, fmtPct } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, link, withCveLinks } from "../dom.js";
import { sevStrip, sevLegend } from "./credits_sev.js";

const KINDS = ["llm", "vendor"];
// closest-to-a-CVE-count first (mirrors CLAIM_UNIT_KINDS in ai_credits_data.py)
const UNIT_RANK = ["cves", "advisories", "vulnerabilities", "submissions"];
const pctWidth = (n, max) =>
  `${Math.max(0, Math.min(100, max ? (n / max) * 100 : 0)).toFixed(1)}%`;

function claimValue(c) {
  return `${c.qualifier ? c.qualifier + " " : ""}${fmtInt(c.value)}`;
}

// One finder's announcements, grouped under one head: the finder's name
// and the one measured number that applies to all of its claims (CVEs
// credited here), stated once instead of under every claim. Each claim is
// its own number + unit + receipt. A claim is drawn to the measured scale
// ONLY when its unit is itself "CVEs assigned": announced and credited
// share one axis and read as two labelled bars. Every other unit gets no
// bar at all — a track that encodes nothing is noise, so the mismatch is
// said in words instead.
function finderGroup(finder, claims, ed) {
  const group = el("div", "finder");
  const head = el("div", "finder-head");
  head.append(
    el("span", "finder-name", claims[0].label),
    el("span", "finder-credited", tpl(ed.claimCredited, { n: fmtInt(claims[0].credited) }))
  );
  group.append(head);
  for (const c of claims) group.append(claimRow(c, ed));
  return group;
}

function claimRow(c, ed) {
  const row = el("div", "claim" + (c.unit_kind === "cves" ? " is-comparable" : ""));
  const head = el("div", "claim-head");
  head.append(el("span", "claim-num", claimValue(c)), el("span", "claim-unit", c.unit));
  row.append(head);

  if (c.unit_kind === "cves") {
    // Same unit as the measured count: announced and credited on one scale.
    const max = Math.max(c.value, c.credited, 1);
    const cmp = el("div", "claim-compare");
    for (const [label, n, cls] of [[ed.compareAnnounced, c.value, "hatched"],
                                   [ed.compareCredited, c.credited, "credited"]]) {
      const line = el("div", "cmp-row");
      const track = el("div", "funnel-track");
      const fill = el("div", "funnel-fill " + cls + (n ? "" : " is-zero"));
      fill.style.width = pctWidth(n, max);
      track.append(fill);
      line.append(el("span", "cmp-label", label), track, el("span", "cmp-val", fmtInt(n)));
      cmp.append(line);
    }
    row.append(cmp);
  }

  const meta = el("div", "claim-meta");
  meta.append(c.live ? tpl(ed.claimLive, { date: c.date }) : c.date, " · ");
  meta.append(link(c.source, new URL(c.source).hostname.replace(/^www\./, "")));
  if (c.unit_kind !== "cves") meta.append(" · ", el("span", "claim-unit-note", ed.claimUnitNote));
  row.append(meta);
  if (c.note) row.append(el("p", "claim-note", c.note));
  return row;
}

function stageRow(label, n, max, share, accent) {
  const row = el("div", "stage");
  const track = el("div", "funnel-track");
  const fill = el("div", "funnel-fill" + (accent ? " accent" : "") + (n ? "" : " is-zero"));
  fill.style.width = pctWidth(n, max);
  track.append(fill);
  const val = el("span", "stage-val", fmtInt(n));
  if (share !== null) val.append(el("span", "muted", fmtPct(share)));
  row.append(el("span", null, label), track, val);
  return row;
}

function kindColumn(kind, data, ed) {
  const k = data.kinds[kind];
  const col = el("div", "funnel-col");
  // How strong is the evidence behind this column? The share of its counted
  // records that name the AI system itself; the rest name a person or the
  // company. Summed over board rows — a CVE naming two finders of one kind is
  // rare enough (2 in ~700) not to move one decimal.
  const mine = data.board.filter((r) => r.kind === kind && r.counted);
  const counted = mine.reduce((n, r) => n + r.counted, 0);
  const system = mine.reduce((n, r) => n + Math.min(r.system, r.counted), 0);
  col.append(
    el("h3", "funnel-kind", ed.kindLabels[kind]),
    el("p", "funnel-rule", tpl(ed.kindRules[kind], {
      system_pct: fmtPct(counted ? (100 * system) / counted : null),
    }))
  );

  col.append(el("p", "funnel-part", ed.claimsLabel));
  const claims = data.claims.filter((c) => c.kind === kind);
  // The printed slide (css/carousel.css) keeps ONE claim per finder to fit
  // a sheet. Which one is a choice, so it is made here and stated on the
  // slide: the claim whose unit sits closest to a CVE count (newest wins a
  // tie); the rest are tagged claim-more and the kept row says how many.
  const primary = new Map();
  for (const c of claims) {
    const best = primary.get(c.finder);
    const rank = UNIT_RANK.indexOf(c.unit_kind);
    if (!best || rank < UNIT_RANK.indexOf(best.unit_kind) ||
        (rank === UNIT_RANK.indexOf(best.unit_kind) && c.date > best.date)) {
      primary.set(c.finder, c);
    }
  }
  // Group by finder, in order of first appearance (the payload is ordered
  // by the registry, so this is stable night to night).
  const byFinder = new Map();
  for (const c of claims) {
    if (!byFinder.has(c.finder)) byFinder.set(c.finder, []);
    byFinder.get(c.finder).push(c);
  }
  for (const [finder, mine] of byFinder) {
    const group = finderGroup(finder, mine, ed);
    const rows = [...group.querySelectorAll(".claim")];
    rows.forEach((row, i) => {
      const c = mine[i];
      if (primary.get(finder) !== c) {
        row.classList.add("claim-more");
      } else if (mine.length > 1) {
        row.append(el("p", "claim-more-note", tpl(ed.claimMoreTemplate, { n: mine.length - 1 })));
      }
    });
    col.append(group);
  }
  if (!claims.length) col.append(el("p", "claim-note", ed.claimsNone));

  col.append(el("p", "funnel-part", ed.measuredLabel));
  if (!k.headline) {
    col.append(el("div", "nodata-card", ed.nodata));
    return col;
  }
  const f = k.funnel;
  col.append(
    stageRow(ed.stageCredited, f.credited, f.credited, null, false),
    stageRow(ed.stageSerious, f.high_or_critical, f.credited, f.high_or_critical_pct, false),
    stageRow(ed.stagePoc, f.poc, f.credited, f.poc_pct, false),
    stageRow(ed.stageKev, f.kev, f.credited, f.kev_pct, true)
  );
  // The severity split as one more labelled row, in the same grid as the
  // stages, so the strip reads as part of the measured block.
  const sev = el("div", "stage stage-sev");
  const sevCell = el("div");
  sevCell.append(sevStrip(k.severity, ed.severityLabels), sevLegend(k.severity, ed.severityLabels));
  sev.append(el("span", null, ed.stageSeverity), sevCell, el("span", "stage-val"));
  col.append(sev);
  return col;
}

export function render(slots, data) {
  const ed = editorial.sections.credits_funnel;
  slots.chart.classList.remove("chart", "chart-tall");

  const { llm, vendor } = data.kinds;
  if (!llm.headline && !vendor.headline) {
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }

  slots.stat.append(el("div", "table-context", tpl(ed.statTemplate, {
    llm: fmtInt(llm.funnel.credited),
    vendor: fmtInt(vendor.funnel.credited),
    kev: fmtInt(new Set([...llm.kev_cves, ...vendor.kev_cves]).size),
  })));

  const cols = el("div", "funnel-cols");
  for (const kind of KINDS) cols.append(kindColumn(kind, data, ed));
  slots.chart.append(cols);

  const foot = el("div", "funnel-foot");
  const b = data.baseline;
  if (b) {
    foot.append(el("p", "panel-note", tpl(ed.baselineTemplate, {
      from: b.from_month,
      serious_pct: fmtPct(b.high_or_critical_pct),
      poc_pct: fmtPct(b.poc_pct),
      kev_pct: fmtPct(b.kev_pct),
      kev: fmtInt(b.kev),
      credited: fmtInt(b.credited),
    })));
  }
  const kevCves = [...new Set([...llm.kev_cves, ...vendor.kev_cves])].sort();
  const kevNote = el("p", "panel-note");
  kevNote.append(kevCves.length
    ? withCveLinks(tpl(ed.kevNote, { cves: kevCves.join(", ") }))
    : ed.kevNoteNone);
  foot.append(kevNote);
  // The audit trail: every matched record with its finder, tier and role.
  const ledger = el("p", "panel-note");
  ledger.append(ed.ledgerNote, " ");
  ledger.append(link("data/ai_credits_ledger.json", ed.ledgerLinkText, "mono"));
  foot.append(ledger);
  slots.extra.append(foot);
}
