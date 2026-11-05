// =============================================================================
// ledger.js — Claims Ledger (ledger.html). An instrument, not a module: one
// row per claims guard, read from data/claims_ledger.json, which
// tools/claims_ledger.py writes in the nightly run right after the claims
// check. Each row gives the guarded sentence, where it appears on the site,
// the data file, the guard's source line, tonight's result and, where the
// guard records it (claims_support.record), the measured value, its bound
// and the margin left.
//
// One section: the summary line as the headline, the counts, then a table
// that sorts by any column (smallest margin first by default) and filters by
// page, result, margin and text. Filters live in the page address (#page=…).
// Copy is kept here, not in editorial.js, like the other instruments'; the
// file has no hard-coded numbers, every count is filled from the data.
// =============================================================================
import { fmtInt } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError, DataError } from "./common.js";
import { el, clear, link } from "./dom.js";
import { sortHeader } from "./ui.js";
import { editorial, tpl } from "./editorial.js";

const DATA_FILE = "data/claims_ledger.json";
const TOOL_URL = "https://github.com/Devko/CyberMon/blob/main/tools/claims_ledger.py";

// ---- copy -------------------------------------------------------------------

const ED = {
  num: "01",
  kicker: "Claims and margins",
  source: "the claims tests in pipeline/tests, run against site/data",
  headline: "Every sentence the claims tests check, with tonight's result and margin.",
  caption:
    "A guard is a test in the repository that quotes one sentence from this site word for " +
    "word and checks it against the published data. If any guard fails, the nightly run " +
    "publishes nothing. Each row below is one guard: the sentence and where it appears, " +
    "tonight's result and, where the guard records it, the measured value, the bound it is " +
    "held to and the margin left.",
  methodology:
    "tools/claims_ledger.py runs every guard right after the nightly claims check, against " +
    "the same data. A guard reports the value it checks and its bounds through record() in " +
    "pipeline/tests/claims_support.py. The margin is the distance from that value to the " +
    "nearest bound, in the value's unit, and as a share of the value (of the bound when the " +
    "value is zero). A guard that checks several values, one per year for example, is listed " +
    "by the value closest to its bound; the row lists the others. A sentence held to an exact " +
    "count, or to none, has no room at all and is marked exact. Guards that record no value " +
    "show their result only. Each sentence is found in site/js/editorial.js with the matching " +
    "the anchor test (test_claims_anchors.py) uses, so a sentence shown in two places lists " +
    "both. A … in a quoted sentence stands for a number the page fills in from the data. A " +
    "margin is tonight's distance to the bound, not a trend. A margin on a complete year's " +
    "figure moves only if the upstream data is revised.",
  loadFailed: "The claims ledger did not load.",
  statLabel: "Tonight's audit · edition {edition}",
  stats: {
    claims: "claims checked",
    pass: "passing",
    fail: "failing",
    skip: "skipped",
    near: "within {near} of a bound",
    measured: "with a recorded value",
  },
  written: "Ledger written {written} for the edition of {edition}.",
  mismatch:
    "This ledger was written for the edition of {edition}; the site now shows the edition " +
    "of {current}. Its results describe the earlier edition.",
  filters: {
    page: "Page",
    allPages: "All pages",
    result: "Result",
    allResults: "All results",
    near: "Only claims within {near} of a bound",
    search: "Search",
    searchPlaceholder: "sentence, file or guard",
  },
  results: { pass: "pass", fail: "fail", skip: "skip" },
  resultNames: { pass: "Passing", fail: "Failing", skip: "Skipped" },
  cols: {
    claim: "Claim",
    where: "Where",
    result: "Result",
    value: "Value · bound",
    margin: "Margin",
    guard: "Guard",
  },
  showing: "{shown} of {total} claims",
  sortedBy: {
    margin: "smallest margin first",
    claim: "by sentence",
    where: "by page",
    result: "by result",
    guard: "by guard",
  },
  none: "No claim matches these filters.",
  noValue: "not recorded",
  exact: "exact",
  exactNote: "any change breaks it",
  toFloor: "to the floor",
  toCeiling: "to the ceiling",
  pastFloor: "below the floor",
  pastCeiling: "above the ceiling",
  floor: "floor {v}",
  ceiling: "ceiling {v}",
  range: "{lo} to {hi}",
  exactly: "exactly {v}",
  moreValues: "{n} values recorded",
  guardSource: "source line on GitHub",
};

// ---- number formatting ------------------------------------------------------------

const DASH = "—";

function fmtNum(v) {
  if (v === null || v === undefined || !Number.isFinite(v)) return DASH;
  const a = Math.abs(v);
  if (Number.isInteger(v) || a >= 1000) return fmtInt(Math.round(v));
  const digits = a >= 100 ? 1 : a >= 1 ? 2 : 3;
  return v.toLocaleString("en-US", { maximumFractionDigits: digits });
}

const trim = (s) => s.replace(/\.0+$|(\.\d*?)0+$/, "$1");

function fmtUsd(v) {
  const a = Math.abs(v);
  if (a >= 1e9) return `$${trim((v / 1e9).toFixed(3))}B`;
  if (a >= 1e6) return `$${trim((v / 1e6).toFixed(1))}M`;
  return `$${fmtInt(Math.round(v))}`;
}

// A number with its unit; a percentage or a multiple takes no space.
function fmtVal(v, unit) {
  if (v === null || v === undefined || !Number.isFinite(v)) return DASH;
  if (unit === "USD") return fmtUsd(v);
  return withUnit(fmtNum(v), unit);
}

function withUnit(text, unit) {
  if (!unit || text === DASH) return text;
  if (unit.startsWith("%") || unit.startsWith("×")) return `${text}${unit}`;
  return `${text} ${unit}`;
}

// Margin in the value's unit; a percentage's margin is in percentage points.
function marginUnit(unit) {
  if (unit.startsWith("%")) return "pp";
  if (unit.startsWith("×")) return "×";
  return unit;
}

const fmtShare = (s) => `${fmtNum(Math.round(s * 1000) / 10)}%`;

function boundText(m) {
  const v = (x) => fmtVal(x, m.unit);
  if (m.lo !== null && m.hi !== null) {
    if (m.lo === m.hi) return tpl(ED.exactly, { v: v(m.lo) });
    // "40 to 60%", "7 to 60 days", but "$1B to $10B"
    const lo = m.unit === "USD" ? v(m.lo) : fmtNum(m.lo);
    return tpl(ED.range, { lo, hi: v(m.hi) });
  }
  if (m.lo !== null) return tpl(ED.floor, { v: v(m.lo) });
  if (m.hi !== null) return tpl(ED.ceiling, { v: v(m.hi) });
  return "";
}

// Template placeholders in a quote stand for numbers the page fills in.
const showQuote = (q) => q.replace(/\{\w+\}/g, "…");

// ---- the rows -----------------------------------------------------------------------

function prepare(data) {
  const pageOrder = Object.keys(data.pages);
  const seen = new Map();
  return data.claims.map((c, i) => {
    // A guard quoted by several CLAIMS rows gets one id per row.
    const base = `${c.suite.replace(/^test_/, "")}.${c.guard}`;
    seen.set(base, (seen.get(base) ?? 0) + 1);
    const id = seen.get(base) === 1 ? base : `${base}.${seen.get(base)}`;
    const path = c.path ?? `pipeline/tests/${c.suite}.py`;
    const tight = c.tightest === null ? null : c.measures[c.tightest];
    const where = c.where.map((w) => ({ ...w, sec: data.sections[w.section] })).filter((w) => w.sec);
    const pages = [...new Set(where.map((w) => w.sec.page))];
    const firstPage = Math.min(...where.map((w) => pageOrder.indexOf(w.sec.page)), pageOrder.length);
    const near = Boolean(tight && tight.share !== null && tight.share < data.near_share);
    const text = [c.quote, c.file, c.guard, c.suite, ...where.map((w) => `${data.pages[w.sec.page]?.label} ${w.sec.label}`)]
      .join(" ").toLowerCase();
    return { ...c, i, id, path, tight, where, pages, firstPage, near, text, message: c.message ?? "" };
  });
}

const RESULT_RANK = { fail: 0, skip: 1, pass: 2 };

// Margin order: failing guards first, then the smallest share, then the
// exact claims, then guards with no recorded value.
function marginKey(r) {
  if (r.status === "fail") return [0, r.tight?.share ?? -Infinity];
  if (r.tight && r.tight.share !== null) return [1, r.tight.share];
  if (r.tight && r.tight.exact) return [2, 0];
  return [3, 0];
}

const SORTS = {
  margin: (a, b) => {
    const [ka, va] = marginKey(a), [kb, vb] = marginKey(b);
    return ka - kb || va - vb || a.firstPage - b.firstPage || a.i - b.i;
  },
  claim: (a, b) => showQuote(a.quote).localeCompare(showQuote(b.quote)) || a.i - b.i,
  where: (a, b) => a.firstPage - b.firstPage ||
    String(a.where[0]?.sec.num ?? "").localeCompare(String(b.where[0]?.sec.num ?? "")) || a.i - b.i,
  result: (a, b) => RESULT_RANK[a.status] - RESULT_RANK[b.status] || SORTS.margin(a, b),
  // identifiers: plain code-point order, underscores included
  guard: (a, b) => (a.guard < b.guard ? -1 : a.guard > b.guard ? 1 : a.i - b.i),
};

// ---- cells --------------------------------------------------------------------------

function whereCell(r, data) {
  const td = el("td", "ledger-where");
  td.dataset.label = ED.cols.where;
  for (const w of r.where) {
    const page = data.pages[w.sec.page]?.label ?? w.sec.page;
    const label = `${page} · ${w.sec.num ? `${w.sec.num} ` : ""}${w.sec.label}`;
    const line = el("span", "ledger-where-line");
    line.append(w.sec.href ? link(w.sec.href, label, "", { sameTab: true }) : el("span", null, label));
    if (w.field) line.append(el("span", "ledger-field", w.field));
    td.append(line);
  }
  if (!r.where.length) td.append(el("span", "ledger-faint", DASH));
  return td;
}

function measureLines(m) {
  const value = el("span", "ledger-value", fmtVal(m.value, m.unit));
  const bound = el("span", "ledger-bound", boundText(m));
  const out = [value, bound];
  if (m.note) out.push(el("span", "ledger-note", m.note));
  return out;
}

function marginText(m) {
  if (m.exact) return `${ED.exact} · ${ED.exactNote}`;
  if (m.margin === null) return "";
  const past = m.margin < 0;
  const side = m.side === "lo" ? (past ? ED.pastFloor : ED.toFloor) : (past ? ED.pastCeiling : ED.toCeiling);
  return `${fmtVal(Math.abs(m.margin), marginUnit(m.unit))} ${side}`;
}

// One line per recorded value in the row's "N values recorded" list.
function measureItem(m, tightestOne) {
  const li = el("li", tightestOne ? "is-tightest" : "");
  li.append(el("span", "ledger-value", fmtVal(m.value, m.unit)));
  const rest = [boundText(m), m.note, marginText(m)].filter(Boolean).join(" · ");
  if (rest) li.append(el("span", "ledger-item-rest", ` · ${rest}`));
  return li;
}

function valueCell(r) {
  const td = el("td", "ledger-measure");
  td.dataset.label = ED.cols.value;
  if (!r.tight) {
    td.append(el("span", "ledger-faint", r.measures.length ? fmtVal(r.measures[0].value, r.measures[0].unit) : ED.noValue));
    return td;
  }
  td.append(...measureLines(r.tight));
  if (r.measures.length > 1) {
    const det = el("details", "ledger-more");
    det.append(el("summary", null, tpl(ED.moreValues, { n: fmtInt(r.measures.length) })));
    const ol = el("ol", "ledger-more-list");
    for (const m of r.measures) ol.append(measureItem(m, m === r.tight));
    det.append(ol);
    td.append(det);
  }
  return td;
}

function marginCell(r) {
  const td = el("td", "ledger-margin");
  td.dataset.label = ED.cols.margin;
  const m = r.tight;
  if (!m) {
    td.append(el("span", "ledger-faint", DASH));
    return td;
  }
  if (m.exact) {
    td.append(el("span", "tag ledger-exact", ED.exact), el("span", "ledger-margin-text", ED.exactNote));
    return td;
  }
  if (m.share === null) {
    td.append(el("span", "ledger-faint", DASH));
    return td;
  }
  const bar = el("span", "cellbar ledger-bar");
  const fill = el("span", "cellbar-fill" + (r.near || m.share < 0 ? " accent" : ""));
  fill.style.width = `${Math.max(0, Math.min(1, m.share)) * 100}%`;
  bar.append(fill, el("span", "cellbar-val", fmtShare(m.share)));
  td.append(bar, el("span", "ledger-margin-text", marginText(m)));
  return td;
}

function row(r, data) {
  const tr = el("tr", `ledger-row is-${r.status}` + (r.near ? " is-near" : ""));
  tr.id = `claim-${r.id}`;

  const claim = el("td", "ledger-claim");
  claim.dataset.label = ED.cols.claim;
  claim.append(el("q", "ledger-quote", showQuote(r.quote)));
  // Why a guard failed or was skipped, in the guard's own words.
  if (r.message) claim.append(el("span", "ledger-message", r.message));

  const result = el("td", "ledger-result");
  result.dataset.label = ED.cols.result;
  result.append(el("span", `tag ledger-status ledger-status-${r.status}`, ED.results[r.status] ?? r.status));

  const guard = el("td", "ledger-guard");
  guard.dataset.label = ED.cols.guard;
  const a = link(`${data.repo_blob}${r.path}#L${r.line}`, r.guard, "ledger-guard-link");
  a.title = ED.guardSource;
  guard.append(a);
  if (r.file) guard.append(el("span", "ledger-file", r.file));

  tr.append(claim, whereCell(r, data), result, valueCell(r), marginCell(r), guard);
  return tr;
}

// ---- the table ----------------------------------------------------------------------

function readHash() {
  const p = new URLSearchParams(location.hash.replace(/^#/, ""));
  return {
    page: p.get("page") || "",
    result: p.get("result") || "",
    near: p.get("near") === "1",
    q: p.get("q") || "",
    sort: SORTS[p.get("sort")] ? p.get("sort") : "margin",
    dir: p.get("dir") === "desc" ? -1 : 1,
  };
}

function writeHash(state) {
  const p = new URLSearchParams();
  if (state.page) p.set("page", state.page);
  if (state.result) p.set("result", state.result);
  if (state.near) p.set("near", "1");
  if (state.q) p.set("q", state.q);
  if (state.sort !== "margin") p.set("sort", state.sort);
  if (state.dir === -1) p.set("dir", "desc");
  const hash = p.toString();
  history.replaceState(null, "", hash ? `#${hash}` : location.pathname + location.search);
}

function select(id, label, options, value) {
  const wrap = el("label", "ledger-filter");
  wrap.htmlFor = id;
  wrap.append(el("span", "ledger-filter-label", label));
  const s = el("select", "ledger-select");
  s.id = id;
  for (const [v, text] of options) {
    const o = el("option", null, text);
    o.value = v;
    s.append(o);
  }
  s.value = options.some(([v]) => v === value) ? value : "";
  wrap.append(s);
  return { wrap, input: s };
}

function renderTable(slots, data, rows) {
  const nearPct = `${Math.round(data.near_share * 100)}%`;
  const state = readHash();

  // filters
  const countBy = (pred) => rows.filter(pred).length;
  const pageOpts = [["", ED.filters.allPages],
    ...Object.entries(data.pages).map(([id, p]) => [id, `${p.label} (${fmtInt(countBy((r) => r.pages.includes(id)))})`])];
  const resultOpts = [["", ED.filters.allResults],
    ...["fail", "skip", "pass"].map((s) => [s, `${ED.resultNames[s]} (${fmtInt(countBy((r) => r.status === s))})`])];
  const page = select("ledger-page", ED.filters.page, pageOpts, state.page);
  const result = select("ledger-result", ED.filters.result, resultOpts, state.result);
  state.page = page.input.value;
  state.result = result.input.value;

  const nearWrap = el("label", "ledger-filter ledger-check");
  const near = el("input");
  near.type = "checkbox";
  near.id = "ledger-near";
  near.checked = state.near;
  nearWrap.htmlFor = "ledger-near";
  nearWrap.append(near, el("span", null, tpl(ED.filters.near, { near: nearPct })));

  const searchWrap = el("label", "ledger-filter ledger-search");
  searchWrap.htmlFor = "ledger-q";
  const search = el("input", "ledger-input");
  search.type = "search";
  search.id = "ledger-q";
  search.placeholder = ED.filters.searchPlaceholder;
  search.value = state.q;
  search.autocomplete = "off";
  searchWrap.append(el("span", "ledger-filter-label", ED.filters.search), search);

  const bar = el("div", "ledger-filters");
  bar.append(page.wrap, result.wrap, searchWrap, nearWrap);
  slots.controls.append(bar);

  // table
  slots.chart.classList.remove("chart", "chart-tall");
  slots.chart.removeAttribute("aria-label");
  const info = el("div", "table-context ledger-context");
  info.setAttribute("aria-live", "polite");
  const wrap = el("div", "table-wrap ledger-wrap");
  const table = el("table", "cna-table ledger-table");
  const thead = el("thead");
  const hr = el("tr");
  const keys = ["claim", "where", "result", "value", "margin", "guard"];
  const ths = keys.map((key) => {
    const th = el("th", `ledger-th-${key}`, ED.cols[key]);
    th.scope = "col";
    if (SORTS[key]) {
      sortHeader(th, () => {
        if (state.sort === key) state.dir = -state.dir;
        else { state.sort = key; state.dir = 1; }
        draw();
      });
    } else {
      th.classList.add("is-static");
    }
    hr.append(th);
    return { th, key };
  });
  thead.append(hr);
  const tbody = el("tbody");
  table.append(thead, tbody);
  wrap.append(table);
  const empty = el("p", "nodata-card ledger-empty", ED.none);
  slots.chart.append(info, wrap, empty);

  function draw() {
    const q = state.q.trim().toLowerCase();
    const shown = rows.filter((r) =>
      (!state.page || r.pages.includes(state.page)) &&
      (!state.result || r.status === state.result) &&
      (!state.near || r.near) &&
      (!q || r.text.includes(q)));
    shown.sort((a, b) => SORTS[state.sort](a, b) * state.dir);
    ths.forEach(({ th, key }) => {
      const on = key === state.sort;
      th.classList.toggle("is-sorted", on);
      if (SORTS[key]) th.setAttribute("aria-sort", on ? (state.dir === 1 ? "ascending" : "descending") : "none");
    });
    clear(tbody);
    for (const r of shown) tbody.append(row(r, data));
    wrap.hidden = shown.length === 0;
    empty.hidden = shown.length > 0;
    info.textContent = `${tpl(ED.showing, { shown: fmtInt(shown.length), total: fmtInt(rows.length) })} · ` +
      ED.sortedBy[state.sort];
    writeHash(state);
  }

  page.input.addEventListener("change", () => { state.page = page.input.value; draw(); });
  result.input.addEventListener("change", () => { state.result = result.input.value; draw(); });
  near.addEventListener("change", () => { state.near = near.checked; draw(); });
  search.addEventListener("input", () => { state.q = search.value; draw(); });
  draw();
}

// ---- the summary ----------------------------------------------------------------------

function headlineText(s, nearPct) {
  const parts = [`${fmtInt(s.claims)} claims checked tonight`];
  if (!s.fail && !s.skip) parts.push("all passing");
  else {
    if (s.pass) parts.push(`${fmtInt(s.pass)} passing`);
    if (s.fail) parts.push(`${fmtInt(s.fail)} failing`);
    if (s.skip) parts.push(`${fmtInt(s.skip)} skipped`);
  }
  parts.push(`${fmtInt(s.near)} within ${nearPct} of a bound`);
  return `${parts.join(", ")}.`;
}

const stamp = (iso) => (iso ? String(iso).replace("T", " ").replace(/:\d\dZ$/, " UTC") : DASH);

function renderSummary(section, slots, data, meta) {
  const s = data.summary;
  const nearPct = `${Math.round(data.near_share * 100)}%`;
  section.querySelector(".section-headline").textContent = headlineText(s, nearPct);

  const box = el("div", "hero-stat ledger-stat");
  box.append(el("div", "hero-stat-label", tpl(ED.statLabel, { edition: stamp(data.edition) })));
  const grid = el("div", "ledger-stat-row");
  const items = [
    ["claims", s.claims, ""],
    ["pass", s.pass, ""],
    ["fail", s.fail, s.fail ? " is-alarm" : ""],
    ["near", s.near, s.near ? " is-alarm" : ""],
    ["measured", s.measured, ""],
  ];
  if (s.skip) items.splice(3, 0, ["skip", s.skip, ""]);
  for (const [key, n, cls] of items) {
    const cell = el("div", "ledger-stat-cell" + cls);
    cell.append(el("span", "ledger-stat-num", fmtInt(n)),
      el("span", "ledger-stat-text", tpl(ED.stats[key], { near: nearPct })));
    grid.append(cell);
  }
  box.append(grid);
  slots.stat.append(box);

  const notes = [tpl(ED.written, { written: stamp(data.generated_at), edition: stamp(data.edition) })];
  if (meta?.generated_at && data.edition && meta.generated_at !== data.edition) {
    notes.push(tpl(ED.mismatch, { edition: stamp(data.edition), current: stamp(meta.generated_at) }));
  }
  slots.panel.insertBefore(el("p", "panel-note", notes.join(" ")), slots.panel.querySelector(".chart-source"));
}

// ---- boot ---------------------------------------------------------------------------

async function boot() {
  const main = document.getElementById("sections");
  const jobs = [initChrome("ledger")];
  const cfg = { id: "ledger_audit", hero: true };
  const { section, slots } = buildSection(cfg, ED);
  // The source-of-truth link: the tool, not a pipeline module.
  const src = section.querySelector(".method-src");
  if (src) {
    clear(src).append(editorial.methodologySourcePrefix, link(TOOL_URL, "tools/claims_ledger.py", "mono"));
  }
  main.append(section);

  jobs.push(
    Promise.all([fetchJSON(DATA_FILE), fetchJSON("data/meta.json").catch(() => null)])
      .then(([data, meta]) => {
        try {
          const rows = prepare(data);
          renderSummary(section, slots, data, meta);
          renderTable(slots, data, rows);
        } catch (err) {
          console.warn("[CyberMon] claims ledger failed:", err);
          section.querySelector(".section-headline").textContent = ED.loadFailed;
          showError(slots, DATA_FILE, err instanceof DataError ? err : new DataError(String(err)));
        }
      })
      .catch((err) => {
        console.warn(`[CyberMon] ${DATA_FILE} failed:`, err);
        section.querySelector(".section-headline").textContent = ED.loadFailed;
        showError(slots, DATA_FILE, err);
      })
  );
  await Promise.allSettled(jobs);
}

boot().catch((err) => console.error("[CyberMon] page boot failed:", err));
