// Hero — claimed -> credited -> high/critical -> public exploit -> KEV, one
// column per kind. Each measured stage is a share of credited, not nested.
// Contract: site/data/ai_credits.json
// Plain HTML (no ECharts): the two kinds are never on one axis, and a claim
// is drawn to the measured scale ONLY when its unit is itself "CVEs
// assigned" — every other claim gets a hatched, unscaled track that says so.
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

function claimRow(c, ed) {
  const row = el("div", "claim");
  const head = el("div", "claim-head");
  head.append(
    el("span", "claim-who", c.label),
    el("span", "claim-num", claimValue(c)),
    el("span", null, c.unit)
  );
  row.append(head);

  const track = el("div", "funnel-track");
  if (c.unit_kind === "cves") {
    // Same unit as the measured count: claimed (hatched) and credited
    // (solid tick) share one scale.
    const max = Math.max(c.value, c.credited);
    const claimed = el("div", "funnel-fill hatched");
    claimed.style.width = pctWidth(c.value, max);
    const credited = el("div", "funnel-fill credited" + (c.credited ? "" : " is-zero"));
    credited.style.width = pctWidth(c.credited, max);
    track.append(claimed, credited);
  } else {
    track.classList.add("hatched");
  }
  row.append(track);

  const meta = el("div", "claim-meta");
  meta.append(
    tpl(ed.claimCredited, { n: fmtInt(c.credited) }), " · ",
    c.live ? tpl(ed.claimLive, { date: c.date }) : c.date, " · "
  );
  meta.append(link(c.source, new URL(c.source).hostname.replace(/^www\./, "")));
  if (c.unit_kind !== "cves") meta.append(" · ", ed.claimUnitNote);
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
  for (const c of claims) {
    const row = claimRow(c, ed);
    if (primary.get(c.finder) !== c) {
      row.classList.add("claim-more");
    } else {
      const more = claims.filter((x) => x.finder === c.finder).length - 1;
      if (more) row.append(el("p", "claim-more-note", tpl(ed.claimMoreTemplate, { n: more })));
    }
    col.append(row);
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
    stageRow(ed.stageKev, f.kev, f.credited, f.kev_pct, true),
    sevStrip(k.severity, ed.severityLabels),
    sevLegend(k.severity, ed.severityLabels)
  );
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
