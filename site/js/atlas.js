// =============================================================================
// atlas.js — Adversary Atlas (atlas.html). An instrument, not a module: the
// current enterprise MITRE ATT&CK release as a graph of groups, software and
// techniques joined by ATT&CK's "uses" relationships. The page never draws
// the whole graph: it shows one group's neighbourhood (its software, then its
// techniques by tactic) or two groups side by side with what they share.
// Contract: data/attack_atlas.json, built by pipeline/attack_atlas.py (the
// encoding is documented there and in docs/data-contracts.md).
//
// Three sections: the graph (2D canvas, searchable group pickers, details
// for any node, keyboard navigation), the view as a sortable table with a
// CSV download, and the groups whose technique sets overlap most with the
// selected one. The URL hash keeps the selection (#g=G0007&vs=G0016&n=…).
// Copy is kept here, not in editorial.js, like the Field's and the
// Observatory's; it carries no hard-coded numbers — every count, version
// and date below is filled from the data.
// =============================================================================
import { C, fmtInt, MONO } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { el, clear, link } from "./dom.js";
import { sortHeader } from "./ui.js";
import { tpl } from "./editorial.js";

const DATA_FILE = "data/attack_atlas.json";
const ATTACK_SITE = "https://attack.mitre.org/";
const CLOSEST_N = 10;
const PIVOT_CAP = 12;
const ALIAS_CAP = 8;
const LABEL_CHARS = 22;
const LABEL_ROOM = 14 + LABEL_CHARS * 6.4; // px beyond the ring for a full label

// ---- copy -------------------------------------------------------------------

const ED = {
  graph: {
    num: "01",
    kicker: "One group, or two",
    headline: "Pick a group to see the software and techniques ATT&CK links to it.",
    headlineOne: "ATT&CK v{version} links {group} to {software} and {techniques}, sub-techniques included.",
    headlineTwo: "{a} and {b} share {software} and {techniques} in ATT&CK v{version}, sub-techniques included.",
    caption:
      "The selected group sits in the centre. Around it come its software, then its techniques, " +
      "grouped and coloured by tactic in the order of the ATT&CK matrix. Hover over a node for " +
      "its name; click or tap it for its ATT&CK page and counts. Pick a second group to compare: each " +
      "group's own entries then sit on its side and the shared ones in the middle. The page " +
      "address keeps the selection and opens on the latest release the site has read.",
    note:
      "Shared software or techniques do not show that two groups are the same actor or that they " +
      "work together, and ATT&CK records only what public reporting has described.",
    source: "MITRE ATT&CK® (enterprise)",
    methodology:
      "Read from the enterprise ATT&CK STIX bundle of the latest release in MITRE's " +
      "attack-stix-data index: v{version}, released {released}, with {groups} groups, " +
      "{software} software entries and {techniques} techniques and sub-techniques. Groups are " +
      "intrusion-set objects, software is malware and tool objects, and techniques are " +
      "attack-pattern objects. Objects marked revoked or deprecated are left out. The edges " +
      "are ATT&CK's \"uses\" relationships from group to software, group to technique and " +
      "software to technique ({edges} in this release); uses recorded for campaigns are left " +
      "out. A group's techniques are those ATT&CK links to the group itself. \"Add techniques " +
      "its software uses\" also draws, as hollow nodes, the techniques linked only to the " +
      "group's software, and the faint curves join each software entry to the techniques in " +
      "view that it uses. A technique listed under several tactics sits under the first in " +
      "matrix order and takes its colour; the table lists every tactic. The edges carry no " +
      "dates, because ATT&CK does not record when a group used a technique. Each entry's " +
      "ATT&CK page lists the procedure descriptions and citations behind its edges. The " +
      "export is rebuilt when MITRE publishes a new release.{stale}",
    staleNote: " This edition was carried forward from the read of {fetched}, because the latest ATT&CK fetch failed.",
    pick: "Group",
    pickHint: "name, alias or ATT&CK id",
    compare: "Compare with",
    compareHint: "a second group (optional)",
    clear: "Clear",
    via: "Add techniques its software uses",
    viaOff: "(one group at a time)",
    statOne: "{group} ({id}). {via}",
    viaN: [
      "Another {n} technique is linked only to its software.",
      "Another {n} techniques are linked only to its software.",
      "No other technique is linked only to its software.",
    ],
    statTwo:
      "Jaccard index (entries both use ÷ entries either uses): software {js} ({ss} of {su}), " +
      "techniques {jt} ({ts} of {tu}), all entries {ja}.",
    canvasLabel:
      "Graph. {subject} Arrow keys move between nodes, Enter or Space shows a node's details, " +
      "Escape clears. The table below lists the same entries.",
    legend: "Legend",
    keys: "Keyboard: Tab to the graph, arrow keys to move between nodes, Enter for details, Escape to clear.",
    legendGroup: "selected group",
    legendSecond: "second group",
    legendSoftware: "software",
    legendTechnique: "technique",
    legendSub: "sub-technique",
    legendVia: "only through its software",
    onlyOf: "{group} only · {n}",
    both: "Both · {n}",
  },
  detail: {
    label: "Selected entry",
    empty: "Click a node, or select a name in the table, to see its ATT&CK page and counts.",
    close: "Close",
    attackLink: "ATT&CK page for {id} →",
    tactics: "Tactics",
    aka: "Also known as",
    akaMore: "and {n} more",
    groupsUsing: "Groups that use it",
    softwareUsing: "Software that uses it",
    techniquesUsed: "Techniques it uses",
    softwareUsed: "Software",
    techniquesOfGroup: "Techniques",
    direct: "{group} uses it directly.",
    viaOnly: "{group} is linked to it only through its software.",
    throughSoftware: "{group}'s software that uses it: {list}.",
    inViewSoftwareUses: "It uses {n} of the techniques in view.",
    usedByBoth: "Both groups use it.",
    usedByOne: "Only {group} uses it.",
    pivot: "Groups that use it",
    pivotMore: "and {n} more; the ATT&CK page lists them all.",
    showGroup: "Show",
    showLabel: "Show {group}",
    compareGroup: "Compare",
    compareLabel: "Compare {b} with {a}",
  },
  table: {
    num: "02",
    kicker: "The view as a table",
    source: "MITRE ATT&CK® (enterprise)",
    headline: "The table lists each software entry and technique in the view.",
    caption:
      "Sort by any column. Select a name to show its details in the graph above. The CSV holds " +
      "the same rows.",
    methodology:
      "\"Groups\" counts every group in the release that ATT&CK links to the entry directly. " +
      "\"In view as\" says whether the selected group uses the entry itself (direct) or only through " +
      "its software, or, in a comparison, which of the two groups uses it. \"Through its " +
      "software\" counts the selected group's software entries that use the technique.",
    download: "Download CSV of this view",
    context: "{n} entries in view",
    empty: "No entries in view.",
    cols: {
      id: "ATT&CK id",
      name: "Name",
      kind: "Kind",
      tactics: "Tactics",
      rel: "In view as",
      groups: "Groups",
      through: "Through its software",
    },
    rel: { direct: "direct", via: "its software only", both: "both", a: "{group} only", b: "{group} only" },
  },
  closest: {
    num: "03",
    kicker: "Closest groups",
    source: "MITRE ATT&CK® (enterprise)",
    headline: "The table ranks the groups whose techniques overlap most with the selected group's.",
    headlineTop: "{top} has the highest technique overlap with {group}, a Jaccard index of {j}.",
    headlineTie: "{n} groups tie for the highest technique overlap with {group}, a Jaccard index of {j}.",
    headlineNone: "No other group shares a technique with {group} in this release.",
    caption:
      "The {n} groups with the highest Jaccard index against {group}: the techniques both use " +
      "divided by the techniques either uses. Compare opens the pair in the graph.",
    methodology:
      "The index counts only the edges ATT&CK draws to each group itself, not those of its " +
      "software, and a technique and its sub-techniques count as separate entries. Software " +
      "overlap is computed the same way. Groups that share no technique " +
      "with the selected group are left out. Ties are ordered by shared techniques, then by " +
      "name. A group with few recorded " +
      "techniques can reach a high index from a handful of shared ones, so the shared count " +
      "is shown beside it.",
    cols: {
      group: "Group",
      sharedT: "Shared techniques",
      jt: "Technique Jaccard",
      sharedS: "Shared software",
      js: "Software Jaccard",
    },
    compare: "Compare",
    current: "in view",
  },
  kinds: { group: "Group", malware: "Software (malware)", tool: "Software (tool)", technique: "Technique", sub: "Sub-technique" },
  kindsShort: { group: "Group", malware: "Malware", tool: "Tool", technique: "Technique", sub: "Sub-technique" },
  softwareN: ["{n} software entry", "{n} software entries", "no software entries"],
  techniqueN: ["{n} technique", "{n} techniques", "no techniques"],
};

// ---- palette ------------------------------------------------------------------
// Tactics are ordered (matrix order), and fifteen is past what one hue can
// step through legibly, so colour is composite: five hues for consecutive
// runs of three tactics, light to dark within each run. Position (sectors in
// matrix order) and the legend carry the tactic too. Checked against the
// panel with the dataviz validator: every neighbouring pair differs (normal
// vision ΔE ≥ 15, CVD ≥ 14) and every step is ≥ 3:1 on the panel.
const TACTIC_COLORS = [
  "#ffc47f", "#c78f49", "#915c08",
  "#7fdfff", "#45a8d2", "#00739c",
  "#a3e4a4", "#6ead70", "#3b793f",
  "#dcc1ff", "#a68bd5", "#73599e",
  "#ffb3ba", "#d67e85", "#9e4b54",
];
const PANEL = C.panel;
const SOFT = C.versions.v3;
const tacticColor = (k) => TACTIC_COLORS[k] ?? C.muted;

// ---- helpers ------------------------------------------------------------------

const plural = (n, [one, many, none]) => tpl(n === 0 ? none : n === 1 ? one : many, { n: fmtInt(n) });
const jac = (shared, union) => (union ? shared / union : null);
const fmtJ = (v) => (v === null ? "—" : v.toFixed(2));
const truncate = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

function attackUrl(id) {
  if (id.startsWith("G")) return `${ATTACK_SITE}groups/${id}/`;
  if (id.startsWith("S")) return `${ATTACK_SITE}software/${id}/`;
  if (id.startsWith("TA")) return `${ATTACK_SITE}tactics/${id}/`;
  return `${ATTACK_SITE}techniques/${id.replace(".", "/")}/`;
}

const ints = (s) => (s ? s.split(" ").map(Number) : []);

// ---- the model ------------------------------------------------------------------

function decode(data) {
  const { groups: G, software: S, techniques: T } = data.counts;
  const N = G + S + T;
  const ids = data.ids;
  const names = data.names;
  const kind = new Array(N);
  for (let i = 0; i < N; i++) {
    if (i < G) kind[i] = "group";
    else if (i < G + S) kind[i] = data.software_types[i - G] === "t" ? "tool" : "malware";
    else kind[i] = ids[i].includes(".") ? "sub" : "technique";
  }
  const byId = new Map(ids.map((id, i) => [id, i]));
  // A sub-technique's own name is short ("PowerShell"); the full name
  // carries its parent ("Command and Scripting Interpreter: PowerShell").
  const fullName = names.map((n, i) => {
    if (kind[i] !== "sub") return n;
    const parent = byId.get(ids[i].split(".")[0]);
    return parent === undefined ? n : `${names[parent]}: ${n}`;
  });
  const tactics = new Array(N).fill(null);
  for (let t = 0; t < T; t++) tactics[G + S + t] = ints(data.technique_tactics[t]);

  const out = data.uses.map(ints);
  const groupUsers = Array.from({ length: N }, () => []);
  const softwareUsers = Array.from({ length: N }, () => []);
  for (let src = 0; src < out.length; src++) {
    for (const dst of out[src]) (src < G ? groupUsers : softwareUsers)[dst].push(src);
  }
  const softOf = [];
  const techOf = [];
  for (let g = 0; g < G; g++) {
    softOf.push(out[g].filter((x) => x < G + S));
    techOf.push(out[g].filter((x) => x >= G + S));
  }
  const aliases = data.aliases;
  const groupOrder = Array.from({ length: G }, (_, g) => g)
    .sort((a, b) => names[a].localeCompare(names[b], "en", { sensitivity: "base" }));
  return {
    G, S, T, N, ids, names, fullName, kind, byId, tactics, out, groupUsers, softwareUsers,
    softOf, techOf, aliases, groupOrder, tacticList: data.tactics,
    version: data.version, released: data.released, counts: data.counts,
  };
}

const isGroup = (m, i) => i < m.G;
const isSoftware = (m, i) => i >= m.G && i < m.G + m.S;
const isTechnique = (m, i) => i >= m.G + m.S;
const firstTactic = (m, i) => (m.tactics[i] && m.tactics[i].length ? m.tactics[i][0] : -1);

function viaTechniques(m, g) {
  const direct = new Set(m.techOf[g]);
  const via = new Set();
  for (const s of m.softOf[g]) for (const t of m.out[s]) if (!direct.has(t)) via.add(t);
  return [...via];
}

function overlap(m, a, b) {
  const inter = (x, y) => { const s = new Set(y); return x.filter((v) => s.has(v)); };
  const ss = inter(m.softOf[a], m.softOf[b]);
  const ts = inter(m.techOf[a], m.techOf[b]);
  const su = m.softOf[a].length + m.softOf[b].length - ss.length;
  const tu = m.techOf[a].length + m.techOf[b].length - ts.length;
  return { ss, ts, su, tu, js: jac(ss.length, su), jt: jac(ts.length, tu), ja: jac(ss.length + ts.length, su + tu) };
}

// The entries in view and how each relates to the selection.
function computeView(m, st) {
  const nodes = new Map(); // node -> rel
  const edges = [];
  if (st.b === null) {
    const a = st.a;
    for (const s of m.softOf[a]) nodes.set(s, "direct");
    for (const t of m.techOf[a]) nodes.set(t, "direct");
    const via = viaTechniques(m, a);
    if (st.via) for (const t of via) nodes.set(t, "via");
    for (const [n, rel] of nodes) if (rel === "direct") edges.push([a, n, "spoke"]);
    for (const s of m.softOf[a]) {
      for (const t of m.out[s]) if (nodes.has(t)) edges.push([s, t, "chord"]);
    }
    return { mode: "one", a, b: null, nodes, edges, viaCount: via.length };
  }
  const { a, b } = st;
  const inA = new Set(m.out[a]);
  const inB = new Set(m.out[b]);
  for (const n of inA) nodes.set(n, inB.has(n) ? "both" : "a");
  for (const n of inB) if (!inA.has(n)) nodes.set(n, "b");
  for (const [n, rel] of nodes) {
    if (rel !== "b") edges.push([a, n, "spokeA"]);
    if (rel !== "a") edges.push([b, n, "spokeB"]);
  }
  return { mode: "two", a, b, nodes, edges, ov: overlap(m, a, b) };
}

// Software first (by name), then techniques by first tactic, then ATT&CK id.
function orderEntries(m, list) {
  return list.sort((x, y) => {
    const kx = isSoftware(m, x) ? -1 : firstTactic(m, x);
    const ky = isSoftware(m, y) ? -1 : firstTactic(m, y);
    if (kx !== ky) return kx - ky;
    if (kx === -1) return m.names[x].localeCompare(m.names[y], "en", { sensitivity: "base" });
    return m.ids[x] < m.ids[y] ? -1 : 1;
  });
}

// ---- layout ------------------------------------------------------------------------

function nodeRadius(m, i) {
  if (isGroup(m, i)) return 9;
  if (isSoftware(m, i)) return 4.5;
  return m.kind[i] === "sub" ? 3 : 4;
}

// One group: the group in the centre, every entry on one ring in sectors —
// software first, then one sector per tactic in matrix order.
function layoutOne(m, view, w, h) {
  const entries = orderEntries(m, [...view.nodes.keys()]);
  const sectors = [];
  for (const n of entries) {
    const key = isSoftware(m, n) ? -1 : firstTactic(m, n);
    if (!sectors.length || sectors[sectors.length - 1].key !== key) sectors.push({ key, items: [] });
    sectors[sectors.length - 1].items.push(n);
  }
  const gap = 1.6;
  const slots = entries.length + gap * Math.max(1, sectors.length);
  const cx = w / 2, cy = h / 2;
  const half = Math.min(w, h) / 2;
  const roomy = w >= 560 && h >= 420;
  let R = Math.max(40, half - (roomy ? LABEL_ROOM : 24));
  const labels = roomy && (2 * Math.PI * R) / slots >= 7;
  if (!labels) R = Math.max(40, half - 24);
  const step = (2 * Math.PI) / slots;
  const pos = new Map();
  pos.set(view.a, { x: cx, y: cy, r: nodeRadius(m, view.a) });
  const arcs = [];
  let ang = -Math.PI / 2 + (gap * step) / 2;
  for (const sec of sectors) {
    const start = ang;
    for (const n of sec.items) {
      pos.set(n, { x: cx + R * Math.cos(ang), y: cy + R * Math.sin(ang), r: nodeRadius(m, n), ang });
      ang += step;
    }
    arcs.push({ key: sec.key, from: start - step * 0.4, to: ang - step * 0.6, n: sec.items.length });
    ang += gap * step;
  }
  return { kind: "ring", pos, order: [view.a, ...entries], cx, cy, R, labels, arcs, step };
}

// Two groups: A at the left edge, B at the right, and three regions between
// them — A's own entries, the shared ones, B's own — each a grid filled
// column by column in the same order as the ring.
function layoutTwo(m, view, w, h) {
  const own = { a: [], both: [], b: [] };
  for (const [n, rel] of view.nodes) own[rel].push(n);
  for (const k of Object.keys(own)) orderEntries(m, own[k]);
  const pad = 14;
  const ax = pad + 10, bx = w - pad - 10, cy = h / 2;
  const left = ax + 28, right = bx - 28;
  const inner = Math.max(60, right - left - 2 * 18);
  const total = own.a.length + own.both.length + own.b.length || 1;
  const raw = ["a", "both", "b"].map((k) => Math.max(0.16, Math.min(0.5, own[k].length / total)));
  const sum = raw.reduce((x, y) => x + y, 0);
  const widths = raw.map((v) => (v / sum) * inner);
  const top = 40, bottom = h - 14;
  const pos = new Map();
  pos.set(view.a, { x: ax, y: cy, r: nodeRadius(m, view.a) });
  pos.set(view.b, { x: bx, y: cy, r: nodeRadius(m, view.b) });
  const regions = [];
  let x0 = left;
  ["a", "both", "b"].forEach((k, ri) => {
    const rw = widths[ri], rh = bottom - top, list = own[k];
    let best = { cell: 0, cols: 1, rows: list.length };
    for (let c = 1; c <= Math.max(1, list.length); c++) {
      const r = Math.ceil(list.length / c);
      const cell = Math.min(rw / c, rh / Math.max(1, r), 26);
      if (cell > best.cell) best = { cell, cols: c, rows: r };
    }
    const gw = best.cols * best.cell, gh = best.rows * best.cell;
    const gx = x0 + (rw - gw) / 2, gy = top + (rh - gh) / 2;
    list.forEach((n, i) => {
      const col = Math.floor(i / best.rows), row = i % best.rows;
      pos.set(n, {
        x: gx + (col + 0.5) * best.cell, y: gy + (row + 0.5) * best.cell,
        r: Math.min(nodeRadius(m, n), Math.max(2, best.cell / 2 - 1.5)),
      });
    });
    regions.push({ key: k, x: x0, w: rw, n: list.length, cell: best.cell, cols: best.cols, list });
    x0 += rw + 18;
  });
  return { kind: "columns", pos, order: [view.a, ...own.a, ...own.both, ...own.b, view.b], regions };
}

// ---- drawing ----------------------------------------------------------------------

function drawLabel(ctx, text, x, y, align, color, font = `10.5px ${MONO}`) {
  ctx.font = font;
  ctx.textAlign = align;
  ctx.textBaseline = "middle";
  ctx.lineWidth = 3;
  ctx.strokeStyle = PANEL;
  ctx.strokeText(text, x, y);
  ctx.fillStyle = color;
  ctx.fillText(text, x, y);
}

function nodeColor(m, i, view) {
  if (i === view.a) return C.accent;
  if (i === view.b) return C.ink;
  if (isSoftware(m, i)) return SOFT;
  return tacticColor(firstTactic(m, i));
}

function drawNode(ctx, m, i, p, view, hollow) {
  const color = nodeColor(m, i, view);
  ctx.lineWidth = 1.5;
  ctx.strokeStyle = PANEL;
  ctx.beginPath();
  if (isSoftware(m, i)) {
    const s = p.r * 1.7;
    ctx.rect(p.x - s / 2, p.y - s / 2, s, s);
  } else {
    ctx.arc(p.x, p.y, p.r, 0, 2 * Math.PI);
  }
  if (hollow) {
    ctx.fillStyle = PANEL;
    ctx.fill();
    ctx.strokeStyle = color;
    ctx.stroke();
  } else {
    ctx.fillStyle = color;
    ctx.fill();
    ctx.stroke();
  }
}

// ---- the graph section ----------------------------------------------------------

function makeCombo({ id, label, hint, m, onPick, clearable, clearLabel }) {
  const wrap = el("div", "atlas-combo");
  const lab = el("label", "atlas-combo-label", label);
  lab.htmlFor = id;
  const field = el("div", "atlas-combo-field");
  const input = el("input", "atlas-combo-input");
  Object.assign(input, { id, type: "text", autocomplete: "off", spellcheck: false, placeholder: hint });
  input.setAttribute("role", "combobox");
  input.setAttribute("aria-autocomplete", "list");
  input.setAttribute("aria-expanded", "false");
  const list = el("ul", "atlas-combo-list");
  list.id = `${id}-list`;
  list.setAttribute("role", "listbox");
  list.setAttribute("aria-label", label);
  list.hidden = true;
  input.setAttribute("aria-controls", list.id);
  field.append(input, list);
  wrap.append(lab, field);
  let clearBtn = null;
  if (clearable) {
    clearBtn = el("button", "atlas-btn atlas-combo-clear", clearLabel);
    clearBtn.type = "button";
    clearBtn.addEventListener("click", () => { onPick(null); input.focus(); });
    wrap.append(clearBtn);
  }

  let current = null;
  let options = [];
  let active = -1;

  const match = (q) => {
    const s = q.trim().toLowerCase();
    const scored = [];
    for (const g of m.groupOrder) {
      if (!s) { scored.push([0, g, null]); continue; }
      const name = m.names[g].toLowerCase();
      const gid = m.ids[g].toLowerCase();
      let score = null, alias = null;
      if (gid === s || name === s) score = 0;
      else if (name.startsWith(s)) score = 1;
      else if (name.includes(s)) score = 3;
      for (const al of m.aliases[g]) {
        const a = al.toLowerCase();
        const sc = a === s ? 1 : a.startsWith(s) ? 2 : a.includes(s) ? 4 : null;
        if (sc !== null && (score === null || sc < score)) { score = sc; alias = al; }
      }
      if (score !== null) scored.push([score, g, alias]);
    }
    scored.sort((x, y) => x[0] - y[0]);
    return scored;
  };

  const close = () => {
    list.hidden = true;
    input.setAttribute("aria-expanded", "false");
    input.removeAttribute("aria-activedescendant");
    active = -1;
  };
  const setActive = (k) => {
    active = k;
    [...list.children].forEach((li, j) => li.setAttribute("aria-selected", String(j === k)));
    if (k >= 0 && list.children[k]) {
      input.setAttribute("aria-activedescendant", list.children[k].id);
      list.children[k].scrollIntoView({ block: "nearest" });
    } else input.removeAttribute("aria-activedescendant");
  };
  const open = () => {
    options = match(input.value);
    clear(list);
    options.forEach(([, g, alias], k) => {
      const li = el("li", "atlas-combo-opt");
      li.id = `${id}-opt-${k}`;
      li.setAttribute("role", "option");
      li.setAttribute("aria-selected", "false");
      li.append(el("span", "atlas-opt-name", m.names[g]), el("span", "atlas-opt-id", m.ids[g]));
      if (alias) li.append(el("span", "atlas-opt-alias", alias));
      li.addEventListener("mousedown", (ev) => ev.preventDefault());
      li.addEventListener("click", () => pick(g));
      list.append(li);
    });
    list.hidden = options.length === 0;
    input.setAttribute("aria-expanded", String(!list.hidden));
    setActive(options.length ? 0 : -1);
  };
  const pick = (g) => {
    close();
    onPick(g);
  };
  const restore = () => { input.value = current === null ? "" : m.names[current]; };

  input.addEventListener("input", open);
  input.addEventListener("click", () => { if (list.hidden) open(); });
  input.addEventListener("keydown", (ev) => {
    if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
      ev.preventDefault();
      if (list.hidden) { open(); return; }
      const d = ev.key === "ArrowDown" ? 1 : -1;
      setActive(Math.max(0, Math.min(options.length - 1, active + d)));
    } else if (ev.key === "Enter") {
      if (!list.hidden && active >= 0) { ev.preventDefault(); pick(options[active][1]); }
    } else if (ev.key === "Escape") {
      if (!list.hidden) { ev.preventDefault(); close(); restore(); }
    }
  });
  input.addEventListener("blur", () => { close(); restore(); });

  return {
    node: wrap,
    set(g) {
      current = g;
      restore();
      if (clearBtn) clearBtn.disabled = g === null;
    },
  };
}

function renderGraph(slots, built, m, st, emit) {
  const ed = ED.graph;
  const head = built.section.querySelector(".section-headline");
  slots.chart.classList.remove("chart", "chart-tall");
  slots.chart.removeAttribute("aria-label");

  // ---- controls
  const comboA = makeCombo({ id: "atlas-a", label: ed.pick, hint: ed.pickHint, m, onPick: (g) => g !== null && emit({ a: g, b: st.b === g ? null : st.b, sel: null }) });
  const comboB = makeCombo({ id: "atlas-b", label: ed.compare, hint: ed.compareHint, m, clearable: true, clearLabel: ed.clear, onPick: (g) => emit({ b: g === st.a ? null : g, sel: null }) });
  const viaLabel = el("label", "atlas-check");
  const viaBox = el("input");
  viaBox.type = "checkbox";
  viaBox.id = "atlas-via";
  const viaText = el("span", null, ed.via);
  const viaOff = el("span", "atlas-check-off", ` ${ed.viaOff}`);
  viaLabel.append(viaBox, viaText, viaOff);
  viaBox.addEventListener("change", () => emit({ via: viaBox.checked }));
  slots.controls.classList.add("atlas-controls");
  slots.controls.append(comboA.node, comboB.node, viaLabel);

  const stat = el("p", "table-context atlas-stat");
  stat.setAttribute("aria-live", "polite");
  slots.stat.append(stat);

  // ---- stage
  const stage = el("div", "atlas-stage");
  const wrap = el("div", "atlas-canvas-wrap");
  const canvas = el("canvas", "atlas-canvas");
  canvas.tabIndex = 0;
  canvas.setAttribute("role", "application");
  canvas.setAttribute("aria-describedby", "atlas-keys");
  const tip = el("div", "atlas-tip");
  tip.hidden = true;
  tip.setAttribute("aria-hidden", "true");
  const live = el("p", "atlas-sr");
  live.setAttribute("aria-live", "polite");
  wrap.append(canvas, tip, live);
  const detail = el("aside", "atlas-detail");
  detail.tabIndex = -1;
  detail.setAttribute("aria-label", ED.detail.label);
  stage.append(wrap, detail);
  const keys = el("p", "atlas-keys", ed.keys);
  keys.id = "atlas-keys";
  slots.chart.append(stage, keys);

  const legend = el("ul", "atlas-legend");
  legend.setAttribute("aria-label", ed.legend);
  slots.extra.append(legend);

  const ctx = canvas.getContext("2d");
  let W = 0, H = 0, view = null, lay = null;
  let hover = null, focus = null;

  const resize = () => {
    const r = wrap.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    W = Math.max(200, Math.round(r.width));
    H = Math.max(200, Math.round(r.height));
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    canvas.style.width = `${W}px`;
    canvas.style.height = `${H}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    if (view) { lay = view.mode === "one" ? layoutOne(m, view, W, H) : layoutTwo(m, view, W, H); draw(); }
  };

  const activeNode = () => hover ?? focus ?? st.sel;

  function neighbours(n) {
    const set = new Set([n]);
    for (const [x, y] of view.edges) {
      if (x === n) set.add(y);
      else if (y === n) set.add(x);
    }
    return set;
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    if (!view || !lay) return;
    const act = activeNode();
    const near = act !== null && lay.pos.has(act) ? neighbours(act) : null;
    const lit = (x, y) => near && (x === act || y === act);

    // edges: faint first, lit on top
    const litEdges = [];
    for (const e of view.edges) {
      const [x, y, kind] = e;
      const p = lay.pos.get(x), q = lay.pos.get(y);
      if (!p || !q) continue;
      if (lit(x, y)) { litEdges.push(e); continue; }
      ctx.globalAlpha = near ? 0.35 : 1;
      strokeEdge(p, q, kind, false, y);
    }
    ctx.globalAlpha = 1;
    for (const [x, y, kind] of litEdges) strokeEdge(lay.pos.get(x), lay.pos.get(y), kind, true, y);

    // ring decorations: a thin tactic arc inside each sector
    if (lay.kind === "ring") {
      for (const a of lay.arcs) {
        ctx.beginPath();
        ctx.arc(lay.cx, lay.cy, lay.R - 11, a.from, Math.max(a.from + 0.01, a.to));
        ctx.strokeStyle = a.key === -1 ? SOFT : tacticColor(a.key);
        ctx.globalAlpha = near ? 0.35 : 0.8;
        ctx.lineWidth = 2;
        ctx.stroke();
      }
      ctx.globalAlpha = 1;
    } else {
      for (const r of lay.regions) {
        const name = r.key === "both" ? tpl(ed.both, { n: fmtInt(r.n) })
          : tpl(ed.onlyOf, { group: m.names[r.key === "a" ? view.a : view.b], n: fmtInt(r.n) });
        drawLabel(ctx, truncate(name, Math.max(6, Math.floor(r.w / 6.6))), r.x + r.w / 2, 18, "center", C.muted, `11px ${MONO}`);
        ctx.strokeStyle = C.rule;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(r.x, 30);
        ctx.lineTo(r.x + r.w, 30);
        ctx.stroke();
      }
    }

    // nodes
    for (const [n, p] of lay.pos) {
      ctx.globalAlpha = near && !near.has(n) ? 0.22 : 1;
      drawNode(ctx, m, n, p, view, view.nodes.get(n) === "via");
    }
    ctx.globalAlpha = 1;

    // selection and keyboard focus rings
    for (const [n, style] of [[st.sel, "sel"], [focus, "focus"]]) {
      const p = n !== null && lay.pos.get(n);
      if (!p) continue;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r + 4, 0, 2 * Math.PI);
      ctx.setLineDash(style === "focus" ? [3, 2] : []);
      ctx.strokeStyle = style === "focus" ? C.accent : C.ink;
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.setLineDash([]);
    }

    drawLabels(act, near);
  }

  function strokeEdge(p, q, kind, on, target) {
    ctx.beginPath();
    ctx.moveTo(p.x, p.y);
    if (kind === "chord" && lay.kind === "ring") {
      // pulled toward the centre so chords bundle inside the ring
      const mx = (p.x + q.x) / 2, my = (p.y + q.y) / 2;
      ctx.quadraticCurveTo(mx + (lay.cx - mx) * 0.7, my + (lay.cy - my) * 0.7, q.x, q.y);
    } else {
      ctx.lineTo(q.x, q.y);
    }
    if (on) {
      ctx.strokeStyle = kind === "chord" ? tacticColor(firstTactic(m, target)) : kind === "spokeA" ? C.accent : C.ink;
      ctx.lineWidth = 1.2;
      ctx.globalAlpha = 0.9;
    } else if (kind === "chord") {
      ctx.strokeStyle = SOFT;
      ctx.lineWidth = 1;
      ctx.globalAlpha *= 0.07;
    } else {
      ctx.strokeStyle = kind === "spokeA" ? C.accent : C.ink;
      ctx.lineWidth = 1;
      ctx.globalAlpha *= kind === "spokeA" ? 0.2 : 0.14;
    }
    ctx.stroke();
    ctx.globalAlpha = 1;
  }

  // Labels, collision-managed: the active node and its neighbours first,
  // then software, then techniques by how many groups use them. A label is
  // drawn only where it does not crowd one already placed.
  function drawLabels(act, near) {
    const centre = [view.a, view.b].filter((x) => x !== null);
    for (const g of centre) {
      const p = lay.pos.get(g);
      if (lay.kind === "ring") {
        drawLabel(ctx, truncate(m.names[g], 28), p.x, p.y + 20, "center", C.ink, `600 12px ${MONO}`);
      } else {
        // the two groups sit at the edges: label above, reading inward
        const left = g === view.a;
        drawLabel(ctx, truncate(m.names[g], 18), left ? p.x - p.r : p.x + p.r, p.y - 20,
          left ? "left" : "right", C.ink, `600 12px ${MONO}`);
      }
    }
    const prio = (n) => (n === act ? 1e9 : near && near.has(n) ? 1e6 : 0) +
      (isSoftware(m, n) ? 1e4 : 0) + m.groupUsers[n].length;
    const cands = [...view.nodes.keys()].sort((x, y) => prio(y) - prio(x));
    if (lay.kind === "ring") {
      const rr = lay.R + 9;
      const minAng = 11.5 / rr;
      const placed = [];
      for (const n of cands) {
        if (!lay.labels && n !== act) continue;
        const p = lay.pos.get(n);
        if (n !== act && placed.some((a) => {
          const d = Math.abs(a - p.ang) % (2 * Math.PI);
          return Math.min(d, 2 * Math.PI - d) < minAng;
        })) continue;
        placed.push(p.ang);
        const color = near && !near.has(n) ? C.faint : n === act ? C.ink : C.muted;
        const text = truncate(m.names[n], LABEL_CHARS);
        if (!lay.labels) {
          // no room for a ring of labels: the active one sits beside its node
          const right = p.x < lay.cx;
          drawLabel(ctx, text, p.x + (right ? 9 : -9), p.y, right ? "left" : "right", C.ink);
          continue;
        }
        ctx.save();
        ctx.translate(lay.cx, lay.cy);
        const flip = Math.cos(p.ang) < 0;
        ctx.rotate(flip ? p.ang + Math.PI : p.ang);
        drawLabel(ctx, text, flip ? -rr : rr, 0, flip ? "right" : "left", color);
        ctx.restore();
      }
    } else {
      const placed = [];
      for (const n of cands) {
        const p = lay.pos.get(n);
        const reg = lay.regions.find((r) => r.list.includes(n));
        const roomy = reg && reg.cols === 1 && reg.cell >= 12;
        if (!roomy && n !== act) continue;
        const text = truncate(m.names[n], roomy ? Math.max(4, Math.floor((reg.w - reg.cell) / 6.4)) : LABEL_CHARS);
        const box = { x0: p.x + 6, x1: p.x + 8 + text.length * 6.4, y0: p.y - 6, y1: p.y + 6 };
        if (n !== act && placed.some((b) => b.x0 < box.x1 && box.x0 < b.x1 && b.y0 < box.y1 && box.y0 < b.y1)) continue;
        placed.push(box);
        const flipLeft = n === act && !roomy && p.x > W * 0.6;
        const color = near && !near.has(n) ? C.faint : n === act ? C.ink : C.muted;
        drawLabel(ctx, text, flipLeft ? p.x - 8 : p.x + 8, p.y, flipLeft ? "right" : "left", color);
      }
    }
  }

  function hit(x, y) {
    if (!lay) return null;
    let best = null, bestD = Infinity;
    for (const [n, p] of lay.pos) {
      const d = (p.x - x) ** 2 + (p.y - y) ** 2;
      const reach = Math.max(p.r + 5, 9);
      if (d <= reach * reach && d < bestD) { best = n; bestD = d; }
    }
    return best;
  }

  function showTip(n) {
    if (n === null || !lay?.pos.has(n)) { tip.hidden = true; return; }
    const p = lay.pos.get(n);
    clear(tip);
    tip.append(el("strong", null, m.fullName[n]), el("span", "atlas-tip-id", `${m.ids[n]} · ${ED.kindsShort[m.kind[n]]}`));
    if (isTechnique(m, n)) tip.append(el("span", "atlas-tip-tac", m.tactics[n].map((k) => m.tacticList[k].name).join(", ")));
    tip.hidden = false;
    const tw = tip.offsetWidth, th = tip.offsetHeight;
    let x = p.x + 12, y = p.y + 12;
    if (x + tw > W - 4) x = p.x - tw - 12;
    if (y + th > H - 4) y = p.y - th - 12;
    tip.style.left = `${Math.max(4, x)}px`;
    tip.style.top = `${Math.max(4, y)}px`;
  }

  canvas.addEventListener("mousemove", (ev) => {
    const r = canvas.getBoundingClientRect();
    const n = hit(ev.clientX - r.left, ev.clientY - r.top);
    canvas.style.cursor = n === null ? "default" : "pointer";
    if (n !== hover) { hover = n; showTip(n); draw(); }
  });
  canvas.addEventListener("mouseleave", () => { hover = null; showTip(focus); draw(); });
  canvas.addEventListener("click", (ev) => {
    const r = canvas.getBoundingClientRect();
    const n = hit(ev.clientX - r.left, ev.clientY - r.top);
    emit({ sel: n === st.sel ? null : n });
  });
  canvas.addEventListener("keydown", (ev) => {
    if (!lay) return;
    const order = lay.order;
    const k = focus === null ? -1 : order.indexOf(focus);
    let next = null;
    if (ev.key === "ArrowRight" || ev.key === "ArrowDown") next = order[(k + 1) % order.length];
    else if (ev.key === "ArrowLeft" || ev.key === "ArrowUp") next = order[(k - 1 + order.length) % order.length];
    else if (ev.key === "Home") next = order[0];
    else if (ev.key === "End") next = order[order.length - 1];
    else if (ev.key === "Enter" || ev.key === " ") {
      ev.preventDefault();
      if (focus !== null) emit({ sel: focus });
      return;
    }
    else if (ev.key === "Escape") { focus = null; showTip(null); emit({ sel: null }); return; }
    else return;
    ev.preventDefault();
    focus = next;
    showTip(focus);
    live.textContent = `${m.fullName[focus]}, ${m.ids[focus]}, ${ED.kindsShort[m.kind[focus]]}` +
      (isTechnique(m, focus) ? `, ${m.tactics[focus].map((t) => m.tacticList[t].name).join(", ")}` : "");
    draw();
  });
  canvas.addEventListener("blur", () => { if (focus !== null) { focus = null; showTip(hover); draw(); } });

  new ResizeObserver(() => resize()).observe(wrap);

  // ---- legend
  function renderLegend() {
    clear(legend);
    const item = (swatch, text) => {
      const li = el("li", "atlas-legend-item");
      li.append(swatch, el("span", null, text));
      legend.append(li);
    };
    const sw = (cls, color) => {
      const s = el("span", `atlas-sw ${cls}`);
      s.style.setProperty("--sw", color);
      s.setAttribute("aria-hidden", "true");
      return s;
    };
    item(sw("is-dot is-big", C.accent), ed.legendGroup);
    if (view.mode === "two") item(sw("is-dot is-big", C.ink), ed.legendSecond);
    item(sw("is-square", SOFT), ed.legendSoftware);
    item(sw("is-dot", C.muted), ed.legendTechnique);
    item(sw("is-dot is-small", C.muted), ed.legendSub);
    if (view.mode === "one" && st.via) item(sw("is-dot is-hollow", C.muted), ed.legendVia);
    const perTactic = new Map();
    for (const n of view.nodes.keys()) {
      if (!isTechnique(m, n)) continue;
      const k = firstTactic(m, n);
      perTactic.set(k, (perTactic.get(k) ?? 0) + 1);
    }
    m.tacticList.forEach((t, k) => {
      if (!perTactic.has(k)) return;
      const li = el("li", "atlas-legend-item");
      const a = link(attackUrl(t.id), t.name, "atlas-legend-tac");
      li.append(sw("is-dot", tacticColor(k)), a, el("span", "atlas-legend-n", fmtInt(perTactic.get(k))));
      legend.append(li);
    });
  }

  // ---- details
  function renderDetail() {
    clear(detail);
    const n = st.sel;
    if (n === null) {
      detail.append(el("p", "atlas-detail-empty", ED.detail.empty));
      return;
    }
    const D = ED.detail;
    const top = el("div", "atlas-detail-top");
    top.append(el("p", "atlas-detail-kind", `${ED.kinds[m.kind[n]]} · ${m.ids[n]}`));
    const close = el("button", "atlas-btn atlas-detail-close", D.close);
    close.type = "button";
    close.addEventListener("click", () => { emit({ sel: null }); canvas.focus(); });
    top.append(close);
    const title = el("h3", "atlas-detail-name", m.fullName[n]);
    detail.append(top, title, link(attackUrl(m.ids[n]), tpl(D.attackLink, { id: m.ids[n] }), "atlas-detail-link mono"));

    const dl = el("dl", "atlas-detail-counts");
    const row = (k, v) => dl.append(el("dt", null, k), el("dd", null, v));
    if (isGroup(m, n)) {
      row(D.softwareUsed, fmtInt(m.softOf[n].length));
      row(D.techniquesOfGroup, fmtInt(m.techOf[n].length));
    } else if (isSoftware(m, n)) {
      row(D.groupsUsing, fmtInt(m.groupUsers[n].length));
      row(D.techniquesUsed, fmtInt(m.out[n].length));
    } else {
      row(D.tactics, m.tactics[n].map((k) => m.tacticList[k].name).join(", "));
      row(D.groupsUsing, fmtInt(m.groupUsers[n].length));
      row(D.softwareUsing, fmtInt(m.softwareUsers[n].length));
    }
    detail.append(dl);

    if (isGroup(m, n) && m.aliases[n].length) {
      const al = m.aliases[n];
      const more = al.length > ALIAS_CAP ? ` ${tpl(D.akaMore, { n: fmtInt(al.length - ALIAS_CAP) })}` : "";
      detail.append(el("p", "atlas-detail-note", `${D.aka}: ${al.slice(0, ALIAS_CAP).join(", ")}${more}`));
    }

    // How the entry relates to what is drawn.
    const rel = view.nodes.get(n);
    const lines = [];
    if (view.mode === "one" && rel) {
      const gname = m.names[view.a];
      if (isTechnique(m, n)) {
        lines.push(tpl(rel === "via" ? D.viaOnly : D.direct, { group: gname }));
        const through = m.softwareUsers[n].filter((s) => view.nodes.has(s)).map((s) => m.names[s]);
        if (through.length) lines.push(tpl(D.throughSoftware, { group: gname, list: through.join(", ") }));
      } else {
        lines.push(tpl(D.inViewSoftwareUses, { n: fmtInt(m.out[n].filter((t) => view.nodes.has(t)).length) }));
      }
    } else if (view.mode === "two" && rel) {
      lines.push(rel === "both" ? D.usedByBoth : tpl(D.usedByOne, { group: m.names[rel === "a" ? view.a : view.b] }));
    }
    for (const line of lines) detail.append(el("p", "atlas-detail-note", line));

    if (!isGroup(m, n) && m.groupUsers[n].length) {
      detail.append(el("h4", "atlas-detail-sub", D.pivot));
      const users = [...m.groupUsers[n]].sort((x, y) => m.names[x].localeCompare(m.names[y], "en", { sensitivity: "base" }));
      const ul = el("ul", "atlas-pivot");
      for (const g of users.slice(0, PIVOT_CAP)) {
        const li = el("li");
        li.append(el("span", "atlas-pivot-name", m.names[g]));
        if (g !== st.a && g !== st.b) {
          const show = el("button", "atlas-btn atlas-btn-small", D.showGroup);
          show.type = "button";
          show.setAttribute("aria-label", tpl(D.showLabel, { group: m.names[g] }));
          show.addEventListener("click", () => emit({ a: g, b: null, sel: null }));
          const cmp = el("button", "atlas-btn atlas-btn-small", D.compareGroup);
          cmp.type = "button";
          cmp.setAttribute("aria-label", tpl(D.compareLabel, { b: m.names[g], a: m.names[st.a] }));
          cmp.addEventListener("click", () => emit({ b: g, sel: null }));
          li.append(show, cmp);
        }
        ul.append(li);
      }
      detail.append(ul);
      if (users.length > PIVOT_CAP) detail.append(el("p", "atlas-detail-note", tpl(D.pivotMore, { n: fmtInt(users.length - PIVOT_CAP) })));
    }
  }

  // ---- update on every state change
  return {
    update(v) {
      view = v;
      comboA.set(st.a);
      comboB.set(st.b);
      viaBox.checked = st.via;
      viaBox.disabled = view.mode === "two";
      viaOff.hidden = view.mode !== "two";
      const A = m.names[view.a];
      if (view.mode === "one") {
        head.textContent = tpl(ed.headlineOne, {
          version: m.version, group: A,
          software: plural(m.softOf[view.a].length, ED.softwareN),
          techniques: plural(m.techOf[view.a].length, ED.techniqueN),
        });
        stat.textContent = tpl(ed.statOne, { group: A, id: m.ids[view.a], via: plural(view.viaCount, ed.viaN) });
      } else {
        const o = view.ov;
        head.textContent = tpl(ed.headlineTwo, {
          version: m.version, a: A, b: m.names[view.b],
          software: plural(o.ss.length, ED.softwareN), techniques: plural(o.ts.length, ED.techniqueN),
        });
        stat.textContent = tpl(ed.statTwo, {
          ss: fmtInt(o.ss.length), su: fmtInt(o.su), js: fmtJ(o.js),
          ts: fmtInt(o.ts.length), tu: fmtInt(o.tu), jt: fmtJ(o.jt), ja: fmtJ(o.ja),
        });
      }
      canvas.setAttribute("aria-label", tpl(ed.canvasLabel, { subject: head.textContent }));
      if (focus !== null && !view.nodes.has(focus) && focus !== view.a && focus !== view.b) focus = null;
      hover = null;
      tip.hidden = true;
      lay = null;
      resize();
      showTip(focus);
      renderLegend();
      renderDetail();
    },
    revealDetail() {
      stage.scrollIntoView({ block: "nearest" });
      detail.focus({ preventScroll: true });
    },
  };
}

// ---- section 2: the view as a table --------------------------------------------------

function csvCell(v) {
  const s = String(v ?? "");
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function makeTable(slots, m, st, emit, reveal) {
  const T = ED.table;
  slots.chart.classList.remove("chart");
  slots.chart.removeAttribute("aria-label");
  const dl = el("button", "atlas-btn", T.download);
  dl.type = "button";
  slots.controls.classList.add("atlas-table-controls");
  slots.controls.append(dl);
  const info = el("div", "table-context");
  info.setAttribute("aria-live", "polite");
  slots.stat.append(info);

  const wrap = el("div", "table-wrap atlas-table-wrap");
  wrap.tabIndex = 0;
  wrap.setAttribute("role", "region");
  wrap.setAttribute("aria-label", T.headline);
  const table = el("table", "cna-table atlas-table");
  const thead = el("thead");
  const tbody = el("tbody");
  table.append(thead, tbody);
  wrap.append(table);
  slots.chart.append(wrap);

  const state = { key: "rel", dir: 1, rows: [], view: null };

  const relText = (r) => {
    const v = state.view;
    if (r.rel === "a" || r.rel === "b") return tpl(T.rel[r.rel], { group: m.names[r.rel === "a" ? v.a : v.b] });
    return T.rel[r.rel];
  };
  const relRank = { direct: 0, both: 0, a: 1, via: 1, b: 2 };
  const cols = () => [
    { key: "id", label: T.cols.id, val: (r) => m.ids[r.n] },
    { key: "name", label: T.cols.name, val: (r) => m.fullName[r.n].toLowerCase() },
    { key: "kind", label: T.cols.kind, val: (r) => ED.kindsShort[m.kind[r.n]] },
    { key: "tactics", label: T.cols.tactics, val: (r) => (isTechnique(m, r.n) ? firstTactic(m, r.n) : -1) },
    { key: "rel", label: T.cols.rel, val: (r) => relRank[r.rel] * 1e5 + (isSoftware(m, r.n) ? 0 : 1e4 + (firstTactic(m, r.n) + 1) * 100) },
    { key: "groups", label: T.cols.groups, val: (r) => m.groupUsers[r.n].length, num: true },
    ...(state.view?.mode === "one" ? [{ key: "through", label: T.cols.through, val: (r) => r.through ?? -1, num: true }] : []),
  ];
  const tacticText = (n) => (isTechnique(m, n) ? m.tactics[n].map((k) => m.tacticList[k].name).join(", ") : "—");

  function drawHead() {
    clear(thead);
    const tr = el("tr");
    for (const col of cols()) {
      const th = el("th", col.num ? "num" : "", col.label);
      th.scope = "col";
      sortHeader(th, () => {
        if (state.key === col.key) state.dir = -state.dir;
        else { state.key = col.key; state.dir = col.num ? -1 : 1; }
        drawBody();
      });
      th.dataset.key = col.key;
      tr.append(th);
    }
    thead.append(tr);
  }

  function sorted() {
    const col = cols().find((c) => c.key === state.key) ?? cols()[0];
    return [...state.rows].sort((a, b) => {
      const av = col.val(a), bv = col.val(b);
      const c = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
      return c * state.dir || (m.ids[a.n] < m.ids[b.n] ? -1 : 1);
    });
  }

  function drawBody() {
    thead.querySelectorAll("th").forEach((th) => {
      const on = th.dataset.key === state.key;
      th.classList.toggle("is-sorted", on);
      th.setAttribute("aria-sort", on ? (state.dir === -1 ? "descending" : "ascending") : "none");
    });
    clear(tbody);
    for (const r of sorted()) {
      const tr = el("tr");
      if (r.n === st.sel) tr.classList.add("is-current");
      const idTd = el("td", "mono");
      idTd.append(link(attackUrl(m.ids[r.n]), m.ids[r.n], "atlas-id-link"));
      const nameTd = el("td");
      const b = el("button", "atlas-name-btn", m.fullName[r.n]);
      b.type = "button";
      b.addEventListener("click", () => { emit({ sel: r.n }); reveal(); });
      nameTd.append(b);
      const tacTd = el("td", "atlas-td-tac");
      if (isTechnique(m, r.n)) {
        const sw = el("span", "atlas-sw is-dot");
        sw.style.setProperty("--sw", tacticColor(firstTactic(m, r.n)));
        sw.setAttribute("aria-hidden", "true");
        tacTd.append(sw);
      }
      tacTd.append(tacticText(r.n));
      tr.append(idTd, nameTd, el("td", "atlas-td-kind", ED.kindsShort[m.kind[r.n]]), tacTd,
        el("td", "atlas-td-rel", relText(r)), el("td", "num mono", fmtInt(m.groupUsers[r.n].length)));
      if (state.view.mode === "one") tr.append(el("td", "num mono", r.through === null ? "—" : fmtInt(r.through)));
      tbody.append(tr);
    }
    info.textContent = state.rows.length ? tpl(T.context, { n: fmtInt(state.rows.length) }) : T.empty;
    dl.disabled = state.rows.length === 0;
  }

  dl.addEventListener("click", () => {
    const v = state.view;
    const one = v.mode === "one";
    const head = ["attack_id", "name", "kind", "tactics", "in_view_as", "groups_using", ...(one ? ["through_group_software"] : []), "attack_version"];
    const lines = [head.join(",")];
    for (const r of sorted()) {
      lines.push([m.ids[r.n], m.fullName[r.n], m.kind[r.n], isTechnique(m, r.n) ? m.tactics[r.n].map((k) => m.tacticList[k].name).join("; ") : "",
        relText(r), m.groupUsers[r.n].length, ...(one ? [r.through ?? ""] : []), m.version].map(csvCell).join(","));
    }
    const blob = new Blob([lines.join("\n") + "\n"], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `cybermon_atlas_v${m.version}_${m.ids[v.a]}${v.b !== null ? `_vs_${m.ids[v.b]}` : ""}.csv`;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });

  return {
    update(view) {
      const modeChanged = state.view?.mode !== view.mode;
      state.view = view;
      state.rows = [...view.nodes].map(([n, rel]) => {
        let through = null;
        if (view.mode === "one" && isTechnique(m, n)) through = m.softwareUsers[n].filter((s) => view.nodes.has(s)).length;
        return { n, rel, through };
      });
      if (modeChanged) {
        if (!cols().some((c) => c.key === state.key)) { state.key = "rel"; state.dir = 1; }
        drawHead();
      }
      drawBody();
    },
    mark() {
      tbody.querySelectorAll("tr").forEach((tr) => tr.classList.remove("is-current"));
      drawBody();
    },
  };
}

// ---- section 3: closest groups ---------------------------------------------------------

function makeClosest(slots, built, m, emit) {
  const E = ED.closest;
  slots.chart.classList.remove("chart");
  slots.chart.removeAttribute("aria-label");
  const head = built.section.querySelector(".section-headline");
  const wrap = el("div", "table-wrap atlas-table-wrap");
  wrap.tabIndex = 0;
  wrap.setAttribute("role", "region");
  wrap.setAttribute("aria-label", E.kicker);
  const table = el("table", "cna-table atlas-closest");
  const thead = el("thead");
  const tbody = el("tbody");
  table.append(thead, tbody);
  wrap.append(table);
  slots.chart.append(wrap);

  const COLS = [
    { key: "group", label: E.cols.group, val: (r) => m.names[r.g].toLowerCase() },
    { key: "sharedT", label: E.cols.sharedT, val: (r) => r.o.ts.length, num: true },
    { key: "jt", label: E.cols.jt, val: (r) => r.o.jt ?? -1, num: true },
    { key: "sharedS", label: E.cols.sharedS, val: (r) => r.o.ss.length, num: true },
    { key: "js", label: E.cols.js, val: (r) => r.o.js ?? -1, num: true },
  ];
  const state = { key: "jt", dir: -1, rows: [], a: null, b: null };
  const tr0 = el("tr");
  const ths = COLS.map((col) => {
    const th = el("th", col.num ? "num" : "", col.label);
    th.scope = "col";
    sortHeader(th, () => {
      if (state.key === col.key) state.dir = -state.dir;
      else { state.key = col.key; state.dir = col.num ? -1 : 1; }
      draw();
    });
    tr0.append(th);
    return { th, col };
  });
  const thAct = el("th", "", "");
  thAct.scope = "col";
  thAct.append(el("span", "atlas-sr", E.compare));
  tr0.append(thAct);
  thead.append(tr0);

  function draw() {
    ths.forEach(({ th, col }) => {
      th.classList.toggle("is-sorted", col.key === state.key);
      th.setAttribute("aria-sort", col.key === state.key ? (state.dir === -1 ? "descending" : "ascending") : "none");
    });
    const col = COLS.find((c) => c.key === state.key);
    const rows = [...state.rows].sort((x, y) => {
      const av = col.val(x), bv = col.val(y);
      const c = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
      return c * state.dir || x.rank - y.rank;
    });
    clear(tbody);
    for (const r of rows) {
      const tr = el("tr");
      if (r.g === state.b) tr.classList.add("is-current");
      const gTd = el("td");
      gTd.append(link(attackUrl(m.ids[r.g]), m.names[r.g], "atlas-id-link"), el("span", "atlas-td-id mono", ` ${m.ids[r.g]}`));
      const act = el("td", "atlas-td-act");
      if (r.g === state.b) act.append(el("span", "atlas-td-current", E.current));
      else {
        const b = el("button", "atlas-btn atlas-btn-small", E.compare);
        b.type = "button";
        b.setAttribute("aria-label", tpl(ED.detail.compareLabel, { b: m.names[r.g], a: m.names[state.a] }));
        b.addEventListener("click", () => emit({ b: r.g, sel: null }));
        act.append(b);
      }
      tr.append(gTd, el("td", "num mono", fmtInt(r.o.ts.length)), el("td", "num mono", fmtJ(r.o.jt)),
        el("td", "num mono", fmtInt(r.o.ss.length)), el("td", "num mono", fmtJ(r.o.js)), act);
      tbody.append(tr);
    }
  }

  return {
    update(view) {
      const a = view.a;
      state.b = view.b;
      if (state.a !== a) {
        state.a = a;
        const all = [];
        for (let g = 0; g < m.G; g++) {
          if (g === a) continue;
          const o = overlap(m, a, g);
          if (o.ts.length) all.push({ g, o });
        }
        all.sort((x, y) => y.o.jt - x.o.jt || y.o.ts.length - x.o.ts.length ||
          m.names[x.g].localeCompare(m.names[y.g], "en", { sensitivity: "base" }));
        state.rows = all.slice(0, CLOSEST_N).map((r, rank) => ({ ...r, rank }));
        const A = m.names[a];
        built.caption.textContent = tpl(E.caption, { n: fmtInt(state.rows.length), group: A });
        if (!all.length) head.textContent = tpl(E.headlineNone, { group: A });
        else {
          const top = all[0].o.jt;
          const tied = all.filter((r) => r.o.jt === top).length;
          head.textContent = tied > 1
            ? tpl(E.headlineTie, { n: fmtInt(tied), group: A, j: fmtJ(top) })
            : tpl(E.headlineTop, { top: m.names[all[0].g], group: A, j: fmtJ(top) });
        }
      }
      draw();
    },
  };
}

// ---- state and the URL hash ------------------------------------------------------

function readHash(m) {
  const p = new URLSearchParams(location.hash.slice(1));
  const group = (id) => {
    const i = m.byId.get(String(id || "").trim().toUpperCase());
    return i !== undefined && i < m.G ? i : null;
  };
  const a = group(p.get("g"));
  const b = group(p.get("vs"));
  const n = m.byId.get(String(p.get("n") || "").trim().toUpperCase());
  return { a, b: b === a ? null : b, sel: n === undefined ? null : n, via: p.get("via") === "1" };
}

function writeHash(m, st) {
  const p = new URLSearchParams();
  p.set("g", m.ids[st.a]);
  if (st.b !== null) p.set("vs", m.ids[st.b]);
  if (st.sel !== null) p.set("n", m.ids[st.sel]);
  if (st.via && st.b === null) p.set("via", "1");
  history.replaceState(null, "", `#${p.toString()}`);
}

// The page opens on the group with the most links in the release.
function defaultGroup(m) {
  let best = 0;
  for (let g = 1; g < m.G; g++) if (m.out[g].length > m.out[best].length) best = g;
  return best;
}

// ---- boot -------------------------------------------------------------------------

async function boot() {
  const main = document.getElementById("sections");
  const jobs = [initChrome("atlas")];
  const cfgs = [
    { id: "atlas_graph", ed: ED.graph, hero: true },
    { id: "atlas_table", ed: ED.table },
    { id: "atlas_closest", ed: ED.closest },
  ];
  const built = cfgs.map((cfg) => {
    const b = buildSection(cfg, cfg.ed);
    main.append(b.section);
    return { cfg, ...b };
  });
  const [graphSec, tableSec, closestSec] = built;

  jobs.push(
    fetchJSON(DATA_FILE)
      .then(async (data) => {
        const m = decode(data);
        let stale = "";
        if (data.stale === true) {
          const meta = await fetchJSON("data/meta.json").catch(() => null);
          const fetched = meta?.sources?.atlas?.fetched_at;
          if (fetched) stale = tpl(ED.graph.staleNote, { fetched });
        }
        graphSec.methodText.textContent = tpl(ED.graph.methodology, {
          version: m.version, released: m.released, groups: fmtInt(m.G), software: fmtInt(m.S),
          techniques: fmtInt(m.T), edges: fmtInt(m.counts.edges), stale,
        });

        const st = { a: defaultGroup(m), b: null, sel: null, via: false };
        let graph = null, table = null, closest = null;
        const render = (patch, { hash = true, reveal = false } = {}) => {
          const prev = { ...st };
          Object.assign(st, patch);
          if (st.b === st.a) st.b = null;
          const view = computeView(m, st);
          if (st.sel !== null && !view.nodes.has(st.sel) && st.sel !== st.a && st.sel !== st.b) st.sel = null;
          if (hash) writeHash(m, st);
          const viewChanged = prev.a !== st.a || prev.b !== st.b || prev.via !== st.via || !graph.ready;
          if (viewChanged) {
            graph.update(view);
            table?.update(view);
            closest?.update(view);
            graph.ready = true;
          } else {
            graph.update(view);
            table?.mark();
          }
          if (reveal) graph.revealDetail();
        };
        const emit = (patch) => render(patch);
        graph = renderGraph(graphSec.slots, graphSec, m, st, emit);
        try { table = makeTable(tableSec.slots, m, st, emit, () => graph.revealDetail()); } catch (err) {
          console.warn("[CyberMon] atlas table failed:", err);
          showError(tableSec.slots, DATA_FILE, err);
        }
        try { closest = makeClosest(closestSec.slots, closestSec, m, emit); } catch (err) {
          console.warn("[CyberMon] atlas closest failed:", err);
          showError(closestSec.slots, DATA_FILE, err);
        }
        const fromHash = () => {
          const h = readHash(m);
          return { a: h.a ?? st.a, b: h.a === null ? null : h.b, sel: h.sel, via: h.via };
        };
        render(location.hash ? fromHash() : {}, { hash: Boolean(location.hash) });
        window.addEventListener("hashchange", () => render(fromHash(), { hash: false }));
      })
      .catch((err) => {
        console.warn(`[CyberMon] ${DATA_FILE} failed:`, err);
        for (const b of built) showError(b.slots, DATA_FILE, err);
      })
  );
  await Promise.allSettled(jobs);
}

boot().catch((err) => console.error("[CyberMon] page boot failed:", err));
