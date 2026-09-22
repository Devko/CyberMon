// =============================================================================
// observatory.js — Mutation Observatory (observatory.html). An instrument,
// not a module: every event on CyberMon's own histories — CNA score changes
// (rescore_log.csv), KEV additions / edits / removals (kev_changelog.csv) and
// each night's biggest EPSS move (epss_volatility.csv) — on one stream,
// dated by first observation. Contract: data/observatory.json, built by
// pipeline/observatory.py (the event encoding is documented there).
//
// Three sections: the daily stream (brush a window with the zoom bar), one
// record's trail (search, deep link #cve=CVE-…), and the events in the
// window as a sortable table with a CSV download. Copy is kept here, not in
// editorial.js, like the Field's: the instrument is not a module, so it has
// no carousel, no motion clip and no claims audit — and no hard-coded
// numbers; every count and date below is filled from the data.
// =============================================================================
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, fmtInt, escapeHtml, hookResize, MONO } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { el, clear, link } from "./dom.js";
import { sortHeader } from "./ui.js";
import { tpl } from "./editorial.js";

const DATA_FILE = "data/observatory.json";
const TABLE_CAP = 100;

// ---- copy -------------------------------------------------------------------

const KIND_LABELS = {
  kev_added: "KEV · listed",
  kev_removed: "KEV · removed",
  kev_flag: "KEV · ransomware flag",
  kev_due: "KEV · due date moved",
  kev_field: "KEV · field edited",
  kev_text: "KEV · text revised",
  rescore: "Score · rescored",
  version_shift: "Score · CVSS version shift",
  first_score: "Score · first CNA score",
  score_removed: "Score · removed",
  epss_move: "EPSS · night's biggest move",
};
const GRAIN_LABELS = {
  daily: "nightly run",
  capture: "archive capture — at or before this date",
  pooled: "first run after missed nights",
};
const SOURCE_LABELS = { kev: "KEV Changelog", rescore: "Silent Rescores", epss: "EPSS Volatility" };

// Chart lanes: the eleven kinds folded into six stacks a legend can carry.
const LANES = [
  { name: "KEV listed", kinds: ["kev_added"], color: C.accent },
  { name: "KEV removed", kinds: ["kev_removed"], color: "#ff9a92" }, // accent tint: KEV's hue
  { name: "KEV edited", kinds: ["kev_flag", "kev_due", "kev_field", "kev_text"], color: C.sev.high },
  { name: "Score edited", kinds: ["rescore", "version_shift", "score_removed"], color: C.versions.v3 },
  { name: "First CNA score", kinds: ["first_score"], color: C.sev.medium },
  { name: "EPSS biggest move", kinds: ["epss_move"], color: C.versions.v4 },
];

const ED = {
  stream: {
    num: "01",
    kicker: "The event stream",
    source: "CyberMon's own histories — rescore log, KEV changelog, EPSS volatility log",
    headline: "Score edits, KEV edits and EPSS jumps, by the day CyberMon saw them.",
    caption:
      "Every event on the three histories CyberMon keeps, stacked by kind on the day it was " +
      "first observed. Drag the handles of the bar under the chart (or pinch and scroll on " +
      "the chart) to pick a window; the table below lists that window's events. Click a " +
      "legend entry to hide a kind.",
    note: "When each history begins: loading…",
    methodology:
      "Each event is dated by its first observation by CyberMon, never by when the change was " +
      "made upstream: the nightly run that saw it, or — for the KEV record before the nightly " +
      "diffs — the first Internet Archive capture of the catalog that shows it, so the change " +
      "happened at or before that date. Before the nightly KEV diffs began, KEV is seen only " +
      "on capture dates: the days between captures are unobserved, not quiet, and carry no " +
      "bar. Each history is drawn from its own first observation on (the markers on the " +
      "chart); nothing is drawn before monitoring began. EPSS contributes one event per night " +
      "— the single biggest probability move — except on the nights the EPSS Volatility " +
      "module quarantines as a model reset or a whole-corpus anomaly; a night that follows " +
      "missed nights pools their change and is marked as such. Rescore events are the " +
      "Silent Rescores taxonomy: rescore (same CVSS version, new score), version shift, a " +
      "first CNA score on an existing record, and a removed score.",
  },
  trail: {
    num: "02",
    kicker: "One record's trail",
    source: "CyberMon's own histories",
    headline: "Follow one CVE through every history.",
    caption:
      "Search a CVE id to see every event CyberMon has logged for it, oldest first. The page " +
      "address keeps the record (#cve=…), so a trail can be shared by its link.",
    methodology:
      "The trail lists the record's events from all three histories in the order they were " +
      "first observed. A CVE with no trail has not been rescored by its CNA, listed or edited " +
      "in KEV, or been a night's biggest EPSS move since each history began — which says " +
      "nothing about changes made before monitoring began.",
  },
  window: {
    num: "03",
    kicker: "The window's events",
    source: "CyberMon's own histories",
    headline: "The events in the window, one row each.",
    caption:
      "Every event in the window picked on the stream above. Sort by any column; the " +
      "download carries the whole window, not just the rows shown.",
    methodology:
      "The table lists at most {cap} rows in the current sort order; the CSV download holds " +
      "every event in the window with its first-observed date, CVE, kind, source history, " +
      "change and dating granularity.",
  },
};

// ---- data -------------------------------------------------------------------

const dayMs = 86400000;
const isoOf = (baseMs, day) => new Date(baseMs + day * dayMs).toISOString().slice(0, 10);
const arrow = (s) => String(s).replace(/->/g, " → ");

function decode(data) {
  const baseMs = Date.parse(`${data.base_date}T00:00:00Z`);
  return data.events.map((s, i) => {
    const [day, cve, kind, detail, grain] = s.split("|");
    const k = data.kinds[+kind];
    return {
      i, day: +day, date: isoOf(baseMs, +day), cve, kind: k,
      source: data.kind_source[+kind], detail, grain: data.granularities[+grain],
    };
  });
}

function detailText(e) {
  if (e.kind === "kev_text") return `${e.detail} (text changed)`;
  return e.detail ? arrow(e.detail) : "—";
}

// ---- section 1: the stream ------------------------------------------------------

function renderStream(slots, data, events, onWindow) {
  const src = data.sources;
  const baseMs = Date.parse(`${data.base_date}T00:00:00Z`);
  const lastDay = Math.round((Date.parse(`${data.last_observed}T00:00:00Z`) - baseMs) / dayMs);
  const days = Array.from({ length: lastDay + 1 }, (_, d) => isoOf(baseMs, d));

  // Per lane, per day: null before the lane's history began (and, for KEV,
  // on the unobserved days between archive captures), a count otherwise.
  const laneOf = {};
  LANES.forEach((l, li) => l.kinds.forEach((k) => (laneOf[k] = li)));
  const counts = LANES.map(() => new Array(days.length).fill(0));
  const captureDay = new Set();
  for (const e of events) {
    counts[laneOf[e.kind]][e.day] += 1;
    if (e.grain === "capture") captureDay.add(e.day);
  }
  const startDay = (iso) => (iso ? Math.round((Date.parse(`${iso}T00:00:00Z`) - baseMs) / dayMs) : Infinity);
  const kevNightly = startDay(src.kev.nightly_from);
  const starts = { kev: startDay(src.kev.first_observed), rescore: startDay(src.rescore.first_observed), epss: startDay(src.epss.first_observed) };
  const laneSource = (l) => data.kind_source[data.kinds.indexOf(l.kinds[0])];
  const series = LANES.map((l, li) => {
    const s = laneSource(l);
    return counts[li].map((n, d) => {
      if (d < starts[s]) return null;
      if (s === "kev" && d < kevNightly && !captureDay.has(d)) return null;
      return n;
    });
  });

  // Window: stat line above the chart, kept in sync with the zoom.
  const statLine = el("div", "table-context obs-window-line");
  statLine.setAttribute("aria-live", "polite");
  slots.stat.append(statLine);

  // Default window: from the first night all nightly histories ran.
  const nightlyStart = Math.min(kevNightly, starts.rescore, starts.epss);
  const win = { from: Number.isFinite(nightlyStart) ? Math.max(0, nightlyStart) : 0, to: lastDay };

  const markers = [
    src.kev.nightly_from && [src.kev.nightly_from, "KEV nightly"],
    src.rescore.first_observed && [src.rescore.first_observed, "rescores"],
    src.epss.first_observed && [src.epss.first_observed, "EPSS"],
  ].filter(Boolean);

  const chart = mkChart(slots.chart);
  slots.chart.setAttribute("aria-label",
    "Stacked bar chart of events per day by kind, first-observed dates " +
    `${data.base_date} to ${data.last_observed}; the table below lists the selected window.`);
  const narrow = () => slots.chart.clientWidth < 560;
  chart.setOption({
    grid: { left: 44, right: 14, top: narrow() ? 72 : 48, bottom: 78 },
    legend: { ...baseLegend, data: LANES.map((l) => l.name), type: "plain" },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (ps) => {
        const d = ps[0]?.dataIndex;
        if (d === undefined) return "";
        const rows = ps.filter((p) => p.value !== null && p.value !== undefined && p.value > 0)
          .map((p) => `${p.marker} ${escapeHtml(p.seriesName)} <strong>${fmtInt(p.value)}</strong>`);
        const head = `<div style="color:${C.muted};margin-bottom:4px;">first observed ${escapeHtml(days[d])}</div>`;
        return head + (rows.length ? rows.join("<br>") : `<span style="color:${C.muted}">no events</span>`);
      },
    },
    xAxis: catAxis(days, {
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 10, hideOverlap: true },
      name: "first observed (UTC day)", nameLocation: "middle", nameGap: 26,
      nameTextStyle: { color: C.faint, fontSize: 10 },
    }),
    yAxis: valAxis({ minInterval: 1 }),
    dataZoom: [
      { type: "inside", xAxisIndex: 0, startValue: win.from, endValue: win.to, zoomOnMouseWheel: "shift" },
      { type: "slider", xAxisIndex: 0, startValue: win.from, endValue: win.to, bottom: 8, height: 22,
        borderColor: C.rule, fillerColor: "rgba(255,74,63,0.10)", handleStyle: { color: C.muted },
        textStyle: { color: C.muted, fontFamily: MONO, fontSize: 10 },
        dataBackground: { lineStyle: { color: C.faint }, areaStyle: { color: C.rule } } },
    ],
    series: LANES.map((l, li) => ({
      name: l.name, type: "bar", stack: "events", data: series[li], barMaxWidth: 18,
      itemStyle: { color: l.color }, large: true,
      ...(li === 0 ? {
        markLine: {
          silent: true, symbol: "none",
          lineStyle: { color: C.faint, type: [3, 3], width: 1 },
          // Labels only where there is room; the note under the chart
          // names every start date either way.
          label: { show: !narrow(), color: C.muted, fontFamily: MONO, fontSize: 10, formatter: (p) => p.name, position: "insideEndBottom" },
          data: markers.map(([d, name]) => ({ xAxis: d, name: `${name} from here` })),
        },
      } : {}),
    })),
  });

  const emit = () => {
    const from = days[win.from], to = days[win.to];
    const inWin = events.filter((e) => e.day >= win.from && e.day <= win.to);
    const cves = new Set(inWin.map((e) => e.cve)).size;
    statLine.textContent =
      `Window: first observed ${from} to ${to} · ${fmtInt(inWin.length)} events on ${fmtInt(cves)} CVEs`;
    onWindow(inWin, from, to);
  };
  let t = null;
  chart.on("datazoom", () => {
    const dz = chart.getOption().dataZoom[0];
    win.from = Math.max(0, Math.round(dz.startValue ?? 0));
    win.to = Math.min(lastDay, Math.round(dz.endValue ?? lastDay));
    clearTimeout(t);
    t = setTimeout(emit, 120);
  });
  emit();
}

// ---- section 2: one record's trail ------------------------------------------------

function renderTrail(slots, data, events) {
  const byCve = new Map();
  for (const e of events) {
    if (!byCve.has(e.cve)) byCve.set(e.cve, []);
    byCve.get(e.cve).push(e);
  }
  slots.chart.classList.remove("chart");
  slots.chart.removeAttribute("aria-label");

  const form = el("form", "obs-search");
  form.setAttribute("role", "search");
  const label = el("label", "obs-search-label", "CVE id");
  label.htmlFor = "obs-cve";
  const input = el("input", "obs-search-input");
  Object.assign(input, { id: "obs-cve", type: "search", placeholder: "CVE-2024-3400", autocomplete: "off", spellcheck: false });
  input.setAttribute("aria-describedby", "obs-search-hint");
  const btn = el("button", "obs-search-btn", "Show trail");
  btn.type = "submit";
  const hint = el("p", "obs-search-hint", `${fmtInt(byCve.size)} CVEs have at least one event on record.`);
  hint.id = "obs-search-hint";
  form.append(label, input, btn);
  slots.controls.append(form, hint);

  const out = el("div", "obs-trail");
  out.id = "obs-trail";
  out.setAttribute("aria-live", "polite");
  slots.chart.append(out);

  const normalize = (raw) => {
    const s = String(raw || "").trim().toUpperCase().replace(/\s+/g, "");
    if (!s) return "";
    return /^CVE-/.test(s) ? s : /^\d{4}-\d{4,}$/.test(s) ? `CVE-${s}` : s;
  };

  const show = (raw, { updateHash = true } = {}) => {
    const cve = normalize(raw);
    clear(out);
    if (!cve) return;
    input.value = cve;
    if (updateHash) history.replaceState(null, "", `#cve=${encodeURIComponent(cve)}`);
    const trail = byCve.get(cve);
    const head = el("div", "obs-trail-head");
    head.append(el("h3", "obs-trail-title", cve));
    if (/^CVE-\d{4}-\d{4,}$/.test(cve)) {
      const a = link(`field.html#cve=${encodeURIComponent(cve)}`, "Open this record in the Field →", "mono obs-field-link", { sameTab: true });
      head.append(a);
    }
    out.append(head);
    if (!trail) {
      out.append(el("p", "obs-trail-empty",
        `No event on record for ${cve}: since each history began, it has not been rescored by its CNA, ` +
        "listed or edited in KEV, or been a night's biggest EPSS move."));
      return;
    }
    const sources = new Set(trail.map((e) => e.source));
    out.append(el("p", "obs-trail-sum",
      `${fmtInt(trail.length)} event${trail.length === 1 ? "" : "s"} across ` +
      `${[...sources].map((s) => SOURCE_LABELS[s]).join(", ")} · oldest first`));
    const ol = el("ol", "obs-timeline");
    for (const e of trail) {
      const li = el("li", `obs-ev obs-ev-${e.source}`);
      const when = el("span", "obs-ev-date", `first observed ${e.date}`);
      if (e.grain !== "daily") when.append(el("span", "obs-ev-grain", ` · ${GRAIN_LABELS[e.grain]}`));
      li.append(when, el("span", "obs-ev-kind", KIND_LABELS[e.kind] ?? e.kind), el("span", "obs-ev-detail", detailText(e)));
      ol.append(li);
    }
    out.append(ol);
  };

  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    show(input.value);
  });
  const fromHash = () => {
    const m = /(?:^#|&)cve=([^&]+)/.exec(location.hash);
    if (m) show(decodeURIComponent(m[1]), { updateHash: false });
    return Boolean(m);
  };
  window.addEventListener("hashchange", () => {
    if (fromHash()) document.getElementById("s-obs_trail")?.scrollIntoView({ block: "start" });
  });
  if (!fromHash()) {
    out.append(el("p", "obs-trail-empty", "Enter a CVE id, or pick one from the table below."));
  }
}

// ---- section 3: the window's events ------------------------------------------------

const COLS = [
  { key: "date", label: "First observed" },
  { key: "cve", label: "CVE" },
  { key: "kind", label: "Event", text: (e) => KIND_LABELS[e.kind] ?? e.kind },
  { key: "detail", label: "Change", text: detailText },
  { key: "grain", label: "Dated by", text: (e) => GRAIN_LABELS[e.grain] },
];

function csvCell(v) {
  const s = String(v ?? "");
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function makeTable(slots) {
  slots.chart.classList.remove("chart");
  slots.chart.removeAttribute("aria-label");
  const state = { key: "date", dir: -1, rows: [], from: "", to: "" };

  const dl = el("button", "obs-download", "Download CSV of this window");
  dl.type = "button";
  const info = el("div", "table-context");
  info.setAttribute("aria-live", "polite");
  slots.controls.append(dl);
  slots.stat.append(info);

  const wrap = el("div", "table-wrap obs-table-wrap");
  wrap.tabIndex = 0;
  wrap.setAttribute("role", "region");
  wrap.setAttribute("aria-label", "Events in the selected window");
  const table = el("table", "cna-table obs-table");
  const thead = el("thead");
  const hr = el("tr");
  const tbody = el("tbody");
  const ths = COLS.map((col) => {
    const th = el("th", "", col.label);
    th.scope = "col";
    sortHeader(th, () => {
      if (state.key === col.key) state.dir = -state.dir;
      else { state.key = col.key; state.dir = col.key === "date" ? -1 : 1; }
      draw();
    });
    hr.append(th);
    return { th, col };
  });
  thead.append(hr);
  table.append(thead, tbody);
  wrap.append(table);
  const more = el("p", "panel-note obs-more");
  slots.chart.append(wrap, more);

  const sortVal = (e, key) => (key === "date" ? e.day * 1e6 + e.i : COLS.find((c) => c.key === key).text?.(e) ?? e[key]);

  function draw() {
    ths.forEach(({ th, col }) => {
      th.classList.toggle("is-sorted", col.key === state.key);
      th.setAttribute("aria-sort", col.key === state.key ? (state.dir === -1 ? "descending" : "ascending") : "none");
    });
    const rows = [...state.rows].sort((a, b) => {
      const av = sortVal(a, state.key), bv = sortVal(b, state.key);
      const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv)) || a.day - b.day;
      return cmp * state.dir;
    });
    clear(tbody);
    for (const e of rows.slice(0, TABLE_CAP)) {
      const tr = el("tr");
      tr.append(el("td", "mono obs-td-date", e.date));
      const td = el("td", "mono");
      const a = link(`#cve=${encodeURIComponent(e.cve)}`, e.cve, "cve-link", { sameTab: true });
      a.title = "Show this record's trail";
      td.append(a);
      tr.append(td, el("td", "", KIND_LABELS[e.kind] ?? e.kind), el("td", "mono obs-td-detail", detailText(e)),
        el("td", "obs-td-grain", GRAIN_LABELS[e.grain]));
      tbody.append(tr);
    }
    more.textContent = rows.length > TABLE_CAP
      ? `${fmtInt(rows.length - TABLE_CAP)} more events in this window — narrow the window, or download the CSV for all ${fmtInt(rows.length)}.`
      : "";
    more.hidden = rows.length <= TABLE_CAP;
    info.textContent = rows.length
      ? `${fmtInt(rows.length)} events first observed ${state.from} to ${state.to}` +
        (rows.length > TABLE_CAP ? ` · showing ${fmtInt(TABLE_CAP)}` : "")
      : `No events first observed ${state.from} to ${state.to}.`;
    dl.disabled = rows.length === 0;
  }

  dl.addEventListener("click", () => {
    const lines = ["first_observed,cve,kind,source,change,dated_by"];
    const rows = [...state.rows].sort((a, b) => a.day - b.day || a.i - b.i);
    for (const e of rows) {
      lines.push([e.date, e.cve, e.kind, e.source, e.detail.replace(/->/g, "→"), e.grain].map(csvCell).join(","));
    }
    const blob = new Blob([lines.join("\n") + "\n"], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `cybermon_observatory_${state.from}_${state.to}.csv`;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });

  return (rows, from, to) => {
    Object.assign(state, { rows, from, to });
    draw();
  };
}

// ---- the history-begins note ----------------------------------------------------

function historiesNote(data) {
  const s = data.sources;
  const parts = [];
  if (s.kev.first_observed) {
    parts.push(s.kev.capture_until
      ? `KEV catalog — first observed ${s.kev.first_observed} in an Internet Archive capture; ` +
        `captures through ${s.kev.capture_until} (a capture-dated change happened at or before its date)` +
        (s.kev.nightly_from ? `, nightly diffs from ${s.kev.nightly_from}` : "")
      : `KEV catalog — nightly diffs, first observed ${s.kev.first_observed}`);
  }
  if (s.rescore.first_observed) parts.push(`CNA scores — nightly, first event observed ${s.rescore.first_observed}`);
  if (s.epss.first_observed) {
    const dropped = (s.epss.excluded_reset ?? 0) + (s.epss.excluded_anomaly ?? 0);
    parts.push(`EPSS — nightly, first observed ${s.epss.first_observed}` +
      (dropped ? ` (${fmtInt(dropped)} of ${fmtInt(s.epss.nights)} nights left out as model resets or whole-corpus anomalies)` : ""));
  }
  return parts.length ? `When each history begins: ${parts.join(" · ")}. Nothing is drawn before these dates.` : "";
}

// ---- boot -----------------------------------------------------------------------

async function boot() {
  hookResize();
  const main = document.getElementById("sections");
  const jobs = [initChrome("observatory")];

  const cfgs = [{ id: "obs_stream", ed: ED.stream, hero: true }, { id: "obs_trail", ed: ED.trail }, { id: "obs_window", ed: ED.window }];
  const built = cfgs.map((cfg) => {
    const ed = { ...cfg.ed, methodology: tpl(cfg.ed.methodology, { cap: TABLE_CAP }) };
    const b = buildSection(cfg, ed);
    main.append(b.section);
    return { cfg, ...b };
  });
  const [stream, trail, windowSec] = built;

  jobs.push(
    fetchJSON(DATA_FILE)
      .then((data) => {
        const events = decode(data);
        const note = stream.slots.panel.querySelector(".panel-note");
        if (!events.length) {
          note?.remove();
          for (const b of built) {
            b.slots.chart.classList.remove("chart", "chart-tall");
            b.slots.chart.removeAttribute("aria-label");
            b.slots.chart.append(el("div", "nodata-card", "No edition yet — the nightly fills it."));
          }
          return;
        }
        const noteText = historiesNote(data);
        if (note) note.textContent = noteText;
        else if (noteText) stream.slots.panel.append(el("p", "panel-note", noteText));
        let update = () => {};
        try { update = makeTable(windowSec.slots); } catch (err) { console.warn("[CyberMon] window table failed:", err); showError(windowSec.slots, DATA_FILE, err); }
        try { renderTrail(trail.slots, data, events); } catch (err) { console.warn("[CyberMon] trail failed:", err); showError(trail.slots, DATA_FILE, err); }
        try { renderStream(stream.slots, data, events, (rows, from, to) => update(rows, from, to)); } catch (err) {
          console.warn("[CyberMon] stream failed:", err);
          showError(stream.slots, DATA_FILE, err);
          // Without the chart the table still works over the whole record.
          update(events, data.base_date, data.last_observed);
        }
      })
      .catch((err) => {
        console.warn(`[CyberMon] ${DATA_FILE} failed:`, err);
        for (const b of built) showError(b.slots, DATA_FILE, err);
      })
  );
  await Promise.allSettled(jobs);
}

boot().catch((err) => console.error("[CyberMon] page boot failed:", err));
