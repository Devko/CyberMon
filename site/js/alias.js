// =============================================================================
// alias.js — The Alias Graph (alias.html): MITRE ATT&CK threat groups placed
// between the vendor naming schemes their names follow.
//
// Reads data/alias_graph.json, built nightly by pipeline/naming_metrics.py
// (build_alias_graph) from the Threat Group Aliases board. Every name there
// is already classified by the versioned rule table in
// pipeline/naming_schemes.py; this page never classifies anything itself.
//
// Drawing: schemes are hubs on a ring, the larger ones spaced apart. Each
// group with at least one
// classified name is pulled equally toward each of its schemes and pushed
// off its neighbours; the layout is computed once, deterministically, so
// the same edition always draws the same picture. Groups with no classified
// name are listed in the table only.
//
// An instrument, not a module (like the Field and the Observatory): its copy
// lives here and in alias.html, with no hard-coded numbers. Colours: the
// Field's categorical order, assigned by the rule table's fixed scheme order,
// never by rank; schemes past the eighth share the neutral and rely on their
// hub labels. The accent marks the pinned group only.
//
// Markup rule (as in field.js): every data-derived string that reaches
// innerHTML passes through escapeHtml first.
// =============================================================================
import { C, MONO, escapeHtml } from "./theme.js";

const $ = (id) => document.getElementById(id);
const DATA_FILE = "data/alias_graph.json";
const REPO = "https://github.com/Devko/CyberMon/blob/main/pipeline/";

const PALETTE = ["#c08a45", "#ded7c2", "#7fa7b8", "#9a8fc2", "#8fb08a", "#c2788f", "#b5a26a", "#6f9ea3"];
const NEUTRAL = "#7d776a";

// ---- copy -------------------------------------------------------------------

const COPY = {
  method:
    "Data: data/alias_graph.json, built nightly by pipeline/naming_metrics.py from MITRE " +
    "ATT&CK v{version} (enterprise, released {released}). It covers the {actors} active " +
    "ATT&CK groups whose entry lists at least one alias. Each group's ATT&CK name and each " +
    "alias is tested against the rules in pipeline/naming_schemes.py (version {rules}). A " +
    "scheme has a rule only where the vendor publishes its naming convention, and each rule " +
    "cites that page. A name with the form of exactly one scheme is assigned to it. A name " +
    "with the form of two schemes, or of none, is left unclassified. A name in a vendor's " +
    "form is counted under that vendor even when someone else coined it, except {exceptions} " +
    "names for which a cited publication names another source. {classified} of {names} names " +
    "({share}) are classified. Hubs sit on a ring, with the larger schemes spaced apart. Each " +
    "group is pulled with equal force toward every " +
    "scheme it has a classified name in, however many names it has there, and is pushed off " +
    "its neighbours. {unplaced} groups have no classified name: they are in the table but " +
    "not on the graph. ATT&CK's alias lists are MITRE's selection, not every name a vendor uses.",
  sources:
    "{actors} ATT&CK groups with at least one alias; {names} names in their entries.<br>" +
    "Rules: <a href=\"{repo}naming_schemes.py\">pipeline/naming_schemes.py</a>, version {rules}. " +
    "Built {generated} by <a href=\"{repo}naming_metrics.py\">pipeline/naming_metrics.py</a>.<br>" +
    "Naming documentation: {docs}.<br>" +
    "Source: MITRE ATT&CK v{version} (enterprise), released {released}. MITRE ATT&CK® " +
    "(© {year} The MITRE Corporation. This work is reproduced and distributed with the " +
    "permission of The MITRE Corporation.)<br>" +
    "<a href=\"naming.html\">Threat Group Aliases</a> counts the same aliases.",
  edition: "Edition {edition} · ATT&CK v{version} · rules v{rules}",
  noRule: "No rule",
  ambiguous: "Form of two schemes",
  exception: "Coined elsewhere",
  panelMeta: "{names} names in ATT&CK's entry · {schemes}",
  schemesN: (n) => (n === 1 ? "1 scheme" : `${n} schemes`),
  noScheme: "no classified name",
  notPlaced: "Not on the graph: none of its names has a rule.",
  candidates: "forms of {list}",
  exceptionNote: "{scheme}'s form; {source}",
  clear: "clear",
  hubTip: "{groups} · {names} names",
  groupsN: (n) => (n === 1 ? "1 group" : `${fmt(n)} groups`),
  legendItem: "{label}",
  search: {
    none: "No group or name contains “{q}”.",
    some: "{n} contain “{q}”. Press Enter to list them.",
    one: "1 group contains “{q}”. Press Enter to pin it.",
  },
  table: {
    summary: "{n} of {total} groups{filter}. Sorted by {sort}.",
    filterQ: " containing “{q}”",
    filterMulti: " named by 2+ schemes",
    sorts: { name: "group name", schemes: "scheme count", names: "name count" },
  },
  emptyTitle: "Not enough data yet.",
  empty: "No ATT&CK group carries an alias in this edition, so there is nothing to place.",
  failTitle: "The Alias Graph could not be loaded",
  missingTitle: "The Alias Graph data is not built here",
  failBody: "<p>{error}</p><p>The aliases are listed on <a href=\"naming.html\">naming.html</a>.</p>",
  missingBody:
    "<p>data/alias_graph.json is written by the nightly pipeline. Build it with</p>" +
    "<p><code>python -m pipeline --out site/data</code></p><p>and reload. The aliases are listed " +
    "on <a href=\"naming.html\">naming.html</a>.</p>",
};

const fmt = (n) => Number(n).toLocaleString("en-US");
const fill = (s, vals) => s.replace(/\{(\w+)\}/g, (m, k) => (k in vals ? String(vals[k]) : m));
const fold = (s) => String(s).toLowerCase();

// ---- boot -------------------------------------------------------------------

const notice = $("a-notice");
// `html` is authored markup; any data inside it is escaped by the caller.
function showNotice(title, html) {
  notice.innerHTML = `<div><strong>${escapeHtml(title)}</strong>${html}</div>`;
  notice.hidden = false;
}

async function boot() {
  let data;
  try {
    const res = await fetch(DATA_FILE, { cache: "no-cache" });
    if (!res.ok) throw new Error(`${DATA_FILE}: HTTP ${res.status}`);
    data = await res.json();
  } catch (err) {
    const missing = /HTTP 404/.test(String(err.message));
    showNotice(missing ? COPY.missingTitle : COPY.failTitle,
      missing ? COPY.missingBody : fill(COPY.failBody, { error: escapeHtml(err.message) }));
    return;
  }
  main(data);
}

// ---- layout -----------------------------------------------------------------

// Deterministic jitter from a name, so an edition always draws the same.
function hash(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return (h >>> 0) / 4294967295;
}

// Ring order: the larger half of the schemes (by groups named; ties in table
// order) alternate with the smaller half, so the large hubs sit apart and a
// group named by several of them lands inside the ring rather than in one arc.
function ringOrder(hubs) {
  const bySize = hubs.slice().sort((x, y) => y.actors - x.actors || x.order - y.order);
  const big = bySize.slice(0, Math.ceil(bySize.length / 2));
  const small = bySize.slice(big.length).reverse();
  const out = [];
  big.forEach((h, k) => { out.push(h); if (small[k]) out.push(small[k]); });
  return out;
}

const NOMINAL = 300; // px per world unit the collision radii assume

function nodeRadius(a, size) {
  if (size === "flat") return 4.5;
  if (size === "schemes") return 3 + 1.25 * a.schemes.length;
  return 2.2 + 1.25 * Math.sqrt(a.names.length);
}
const hubRadius = (h) => 7 + 1.6 * Math.sqrt(h.actors);

function simulate(hubs, nodes, size) {
  const hubAt = new Map(hubs.map((h) => [h.id, h]));
  const L = 0.2; // spring rest length, world units
  for (const n of nodes) {
    let x = 0, y = 0;
    for (const s of n.a.schemes) { x += hubAt.get(s).x; y += hubAt.get(s).y; }
    x /= n.a.schemes.length; y /= n.a.schemes.length;
    const t = hash(n.a.name) * Math.PI * 2, j = 0.05 + 0.1 * hash(`${n.a.name}#`);
    n.x = x * 0.85 + Math.cos(t) * j; n.y = y * 0.85 + Math.sin(t) * j;
    n.vx = 0; n.vy = 0;
    n.r = nodeRadius(n.a, size) / NOMINAL;
  }
  const ITER = 320;
  for (let it = 0; it < ITER; it++) {
    const alpha = 1 - it / ITER;
    for (const n of nodes) {
      for (const s of n.a.schemes) {
        const h = hubAt.get(s);
        const dx = h.x - n.x, dy = h.y - n.y, d = Math.hypot(dx, dy) || 1e-6;
        const f = 0.06 * (d - L) * alpha;
        n.vx += (dx / d) * f; n.vy += (dy / d) * f;
      }
      // keep clear of every hub disc
      for (const h of hubs) {
        const dx = n.x - h.x, dy = n.y - h.y, d = Math.hypot(dx, dy) || 1e-6;
        const min = h.r / NOMINAL + n.r + 0.012;
        if (d < min) { const p = (min - d) * 0.5; n.vx += (dx / d) * p; n.vy += (dy / d) * p; }
      }
    }
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let k = i + 1; k < nodes.length; k++) {
        const b = nodes[k];
        let dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy);
        if (d < 1e-6) { dx = 1e-3; dy = 0; d = 1e-3; }
        const min = a.r + b.r + 0.008;
        let p = 0;
        if (d < min) p = (min - d) * 0.5;
        else if (d < 0.18) p = (0.0000025 * alpha) / (d * d);
        if (p) {
          const ux = dx / d, uy = dy / d;
          a.vx -= ux * p; a.vy -= uy * p; b.vx += ux * p; b.vy += uy * p;
        }
      }
    }
    for (const n of nodes) {
      n.vx *= 0.55; n.vy *= 0.55;
      n.x += n.vx; n.y += n.vy;
    }
  }
}

// ---- page -------------------------------------------------------------------

function main(data) {
  const schemesAll = data.schemes.map((s, order) => ({
    ...s, order, color: order < PALETTE.length ? PALETTE[order] : NEUTRAL,
  }));
  const schemeById = new Map(schemesAll.map((s) => [s.id, s]));
  const exceptionOf = new Map((data.exceptions || []).map((e) => [fold(e.name), e]));
  const actors = data.actors.map((a, i) => ({ ...a, i, folded: [a.name, ...a.names.map((n) => n.name)].map(fold) }));
  const H = data.headline;
  const cov = data.coverage;
  const share = cov.names ? `${Math.round((100 * cov.classified) / cov.names)}%` : "—";

  // counters, edition, method, sources
  $("a-actors").textContent = H ? fmt(H.actors) : "0";
  $("a-multi").textContent = H ? fmt(H.three_plus) : "0";
  $("a-coverage").textContent = share;
  $("a-coverage").title = `${fmt(cov.classified)} of ${fmt(cov.names)} names`;
  const edition = String(data.generated_at).replace("T", " ").replace(/:\d\dZ$/, " UTC");
  $("a-edition").textContent = fill(COPY.edition, { edition, version: data.version, rules: data.rules_version });
  $("a-method").textContent = fill(COPY.method, {
    version: data.version, released: data.released, actors: fmt(H ? H.actors : 0),
    rules: data.rules_version, exceptions: fmt((data.exceptions || []).length),
    classified: fmt(cov.classified), names: fmt(cov.names), share,
    unplaced: fmt(H ? H.actors - H.placed : 0),
  });
  const docs = schemesAll.map((s) => `<a href="${escapeHtml(s.doc)}" target="_blank" rel="noopener">${escapeHtml(s.label)}</a>`).join(" · ");
  $("a-sources").innerHTML = fill(COPY.sources, {
    actors: fmt(H ? H.actors : 0), names: fmt(cov.names), repo: REPO, rules: escapeHtml(data.rules_version),
    generated: escapeHtml(data.generated_at), docs, version: escapeHtml(data.version),
    released: escapeHtml(data.released), year: escapeHtml(String(data.generated_at).slice(0, 4)),
  });

  if (!actors.length) {
    showNotice(COPY.emptyTitle, `<p>${escapeHtml(COPY.empty)}</p>`);
    document.body.dataset.ready = "1";
    return;
  }

  // ---- geometry ----------------------------------------------------------
  const hubs = ringOrder(schemesAll.filter((s) => s.actors > 0));
  hubs.forEach((h, k) => {
    const t = -Math.PI / 2 + (2 * Math.PI * k) / hubs.length;
    h.x = Math.cos(t); h.y = Math.sin(t); h.r = hubRadius(h);
  });
  const hubById = new Map(hubs.map((h) => [h.id, h]));
  const placed = actors.filter((a) => a.schemes.length > 0);
  let nodes = [];
  const nodeOf = new Map();
  function relayout() {
    nodes = placed.map((a) => ({ a }));
    simulate(hubs, nodes, state.size);
    nodeOf.clear();
    nodes.forEach((n) => nodeOf.set(n.a.i, n));
  }

  // ---- state + hash --------------------------------------------------------
  const state = { pinned: -1, scheme: null, q: "", multi: false, labels: true, size: "names", tableOpen: false };
  let hover = null; // { kind: "actor" | "hub", id }

  const byName = new Map(actors.map((a) => [a.name, a.i]));
  function writeHash() {
    const h = new URLSearchParams();
    if (state.pinned >= 0) h.set("actor", actors[state.pinned].name);
    if (state.scheme) h.set("scheme", state.scheme);
    if (state.q.trim()) h.set("q", state.q.trim());
    if (state.multi) h.set("multi", "1");
    if (!state.labels) h.set("labels", "0");
    if (state.size !== "names") h.set("size", state.size);
    const s = h.toString();
    history.replaceState(null, "", s ? `#${s}` : location.pathname + location.search);
  }
  function readHash() {
    const h = new URLSearchParams(location.hash.slice(1));
    const name = h.get("actor");
    state.pinned = name && byName.has(name) ? byName.get(name) : -1;
    state.scheme = hubById.has(h.get("scheme")) ? h.get("scheme") : null;
    state.q = h.get("q") || "";
    state.multi = h.get("multi") === "1";
    state.labels = h.get("labels") !== "0";
    state.size = ["names", "schemes", "flat"].includes(h.get("size")) ? h.get("size") : "names";
    if (state.multi && state.pinned >= 0 && actors[state.pinned].schemes.length < 2) state.pinned = -1;
    $("a-search").value = state.q;
    $("a-multi-only").checked = state.multi;
    $("a-labels").checked = state.labels;
    $("a-size").value = state.size;
  }

  const shown = (a) => !state.multi || a.schemes.length >= 2;
  const matches = (a) => { const q = fold(state.q.trim()); return !q || a.folded.some((n) => n.includes(q)); };

  // ---- canvas --------------------------------------------------------------
  const canvas = $("a-canvas");
  const ctx = canvas.getContext("2d");
  let W = 0, Hh = 0, dpr = 1;
  const view = { s: 1, ox: 0, oy: 0 }; // screen = world * s + o
  const toScreen = (x, y) => [x * view.s + view.ox, y * view.s + view.oy];

  function fit() {
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const p of [...hubs, ...nodes]) { x0 = Math.min(x0, p.x); y0 = Math.min(y0, p.y); x1 = Math.max(x1, p.x); y1 = Math.max(y1, p.y); }
    const padX = Math.min(80, W * 0.1), padY = Math.min(64, Hh * 0.13);
    // capped so a tiny graph (one hub, a group or two) is not blown up
    view.s = Math.max(10, Math.min((W - 2 * padX) / (x1 - x0 || 1), (Hh - 2 * padY) / (y1 - y0 || 1),
      Math.min(W, Hh) / 2.2));
    view.ox = W / 2 - ((x0 + x1) / 2) * view.s;
    view.oy = Hh / 2 - ((y0 + y1) / 2) * view.s;
    moved = false;
  }
  // Until the reader pans, zooms or a pin recentres, a resize refits.
  let moved = false;
  function resize() {
    const r = canvas.getBoundingClientRect();
    dpr = window.devicePixelRatio || 1;
    const first = !W;
    const cx = (W / 2 - view.ox) / view.s, cy = (Hh / 2 - view.oy) / view.s;
    W = Math.max(1, r.width); Hh = Math.max(1, r.height);
    canvas.width = Math.round(W * dpr); canvas.height = Math.round(Hh * dpr);
    if (first || !moved) fit();
    else { view.ox = W / 2 - cx * view.s; view.oy = Hh / 2 - cy * view.s; }
    draw();
  }

  // Which groups are emphasised: hover beats pin beats hub beats search.
  function focusSet() {
    if (hover?.kind === "actor") return new Set([hover.id]);
    const hubId = hover?.kind === "hub" ? hover.id : state.scheme;
    if (hubId) return new Set(placed.filter((a) => shown(a) && a.schemes.includes(hubId)).map((a) => a.i));
    if (state.q.trim()) return new Set(actors.filter((a) => shown(a) && matches(a)).map((a) => a.i));
    return null;
  }
  function focusHub() { return hover?.kind === "hub" ? hover.id : state.scheme; }

  function draw() {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, Hh);
    const focus = focusSet();
    const fh = focusHub();
    const lit = (i) => i === state.pinned || (focus ? focus.has(i) : true);
    const linkLit = (n, s) => (hover?.kind === "actor" ? hover.id === n.a.i : n.a.i === state.pinned || (fh ? s === fh && lit(n.a.i) : false));

    // links
    ctx.lineCap = "round";
    for (const n of nodes) {
      if (!shown(n.a)) continue;
      const [x, y] = toScreen(n.x, n.y);
      for (const s of n.a.schemes) {
        const h = hubById.get(s);
        const [hx, hy] = toScreen(h.x, h.y);
        const on = linkLit(n, s);
        ctx.globalAlpha = on ? 0.9 : focus || state.pinned >= 0 ? 0.05 : 0.16;
        ctx.strokeStyle = h.color;
        ctx.lineWidth = on ? 1.6 : 1;
        ctx.beginPath(); ctx.moveTo(x, y); ctx.lineTo(hx, hy); ctx.stroke();
      }
    }
    ctx.globalAlpha = 1;

    // hubs
    for (const h of hubs) {
      const [x, y] = toScreen(h.x, h.y);
      ctx.globalAlpha = fh && fh !== h.id ? 0.45 : 1;
      ctx.fillStyle = h.color;
      ctx.beginPath(); ctx.arc(x, y, h.r, 0, Math.PI * 2); ctx.fill();
      if (fh === h.id) { ctx.strokeStyle = C.ink; ctx.lineWidth = 2; ctx.stroke(); }
    }
    ctx.globalAlpha = 1;

    // groups
    for (const n of nodes) {
      if (!shown(n.a)) continue;
      const [x, y] = toScreen(n.x, n.y);
      const r = nodeRadius(n.a, state.size);
      const pinned = n.a.i === state.pinned;
      ctx.globalAlpha = lit(n.a.i) ? 1 : 0.18;
      ctx.fillStyle = pinned ? C.accent : C.ink;
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fill();
      ctx.lineWidth = 1.5; ctx.strokeStyle = C.bg; ctx.stroke();
      if (pinned || (hover?.kind === "actor" && hover.id === n.a.i)) {
        ctx.beginPath(); ctx.arc(x, y, r + 4, 0, Math.PI * 2);
        ctx.strokeStyle = pinned ? C.accent : C.ink; ctx.lineWidth = 1.5; ctx.stroke();
      }
    }
    ctx.globalAlpha = 1;
    drawLabels(focus);
  }

  const overlaps = (a, b) => a[0] < b[2] && a[2] > b[0] && a[1] < b[3] && a[3] > b[1];

  // Hub labels: outward from the ring centre, turned inward where the canvas
  // edge would clip them, and moved off one another. A narrow canvas drops
  // the group count (the legend and the hub's tooltip carry it).
  function hubLabels() {
    const narrow = W < 600;
    const [cx, cy] = toScreen(0, 0);
    const out = [];
    for (const h of hubs) {
      const [x, y] = toScreen(h.x, h.y);
      const ang = Math.atan2(y - cy, x - cx), c = Math.cos(ang), sn = Math.sin(ang);
      ctx.font = `600 ${narrow ? 11 : 12}px ${MONO}`;
      const lines = narrow ? [h.label] : [h.label, COPY.groupsN(h.actors)];
      const w = Math.max(...lines.map((t) => ctx.measureText(t).width));
      const lh = 13, hh = lines.length * lh;
      const gap = h.r + 6;
      let x0, y0;
      if (Math.abs(c) < 0.3) { // top or bottom of the ring: centred above or below
        y0 = sn < 0 ? y - gap - hh : y + gap;
        if (y0 < 2) y0 = y + gap;
        if (y0 + hh > Hh - 2) y0 = y - gap - hh;
        x0 = Math.max(4, Math.min(W - 4 - w, x - w / 2));
      } else {
        const right = c > 0 ? x + gap + w <= W - 4 : x - gap - w < 4;
        x0 = right ? x + gap : x - gap - w;
        y0 = y - hh / 2;
      }
      let box = [x0 - 2, y0, x0 + w + 2, y0 + hh];
      for (let k = 0; k < 4 && out.some((o) => overlaps(o.box, box)); k++) {
        y0 += (sn < 0 ? -1 : 1) * (hh + 2);
        box = [x0 - 2, y0, x0 + w + 2, y0 + hh];
      }
      out.push({ h, x0, y0, lines, box, narrow });
    }
    return out;
  }

  function halo(text, x, y) {
    ctx.save();
    ctx.lineWidth = 4; ctx.strokeStyle = C.bg; ctx.lineJoin = "round";
    ctx.strokeText(text, x, y); ctx.restore();
    ctx.fillText(text, x, y);
  }

  // Labels never overlap: hub labels first, then groups by priority; a group
  // label that would touch one already drawn is skipped. Hover and pin
  // always get theirs.
  function drawLabels(focus) {
    const boxes = [];
    for (const h of hubs) {
      const [x, y] = toScreen(h.x, h.y);
      boxes.push([x - h.r - 2, y - h.r - 2, x + h.r + 2, y + h.r + 2]);
    }
    const fh = focusHub();
    ctx.textBaseline = "middle";
    ctx.textAlign = "left";
    for (const L of hubLabels()) {
      ctx.globalAlpha = fh && fh !== L.h.id ? 0.55 : 1;
      L.lines.forEach((t, k) => {
        ctx.font = k ? `11px ${MONO}` : `600 ${L.narrow ? 11 : 12}px ${MONO}`;
        ctx.fillStyle = k ? C.muted : C.ink;
        halo(t, L.x0, L.y0 + 6.5 + k * 13);
      });
      boxes.push(L.box);
    }
    ctx.globalAlpha = 1;
    const prio = (n) => (n.a.i === state.pinned ? 4 : hover?.id === n.a.i && hover.kind === "actor" ? 5 : focus?.has(n.a.i) ? 3 : 0)
      * 100 + n.a.schemes.length * 10 + Math.min(9, n.a.names.length / 2);
    const order = nodes.filter((n) => shown(n.a)).sort((p, q) => prio(q) - prio(p) || (p.a.name < q.a.name ? -1 : 1));
    ctx.font = `11px ${MONO}`;
    for (const n of order) {
      const must = n.a.i === state.pinned || (hover?.kind === "actor" && hover.id === n.a.i);
      if (!must && (!state.labels || (focus && !focus.has(n.a.i)))) continue;
      const [x, y] = toScreen(n.x, n.y);
      const r = nodeRadius(n.a, state.size);
      const w = ctx.measureText(n.a.name).width;
      let box = [x + r + 3, y - 7, x + r + 5 + w, y + 7];
      if (box[2] > W - 2) box = [x - r - 5 - w, y - 7, x - r - 3, y + 7]; // no room on the right
      if (box[2] < 0 || box[0] > W || box[3] < 0 || box[1] > Hh) continue;
      if (!must && boxes.some((b) => overlaps(box, b))) continue;
      boxes.push(box);
      ctx.fillStyle = must ? C.ink : C.muted;
      halo(n.a.name, box[0] + 1, y);
    }
  }

  // ---- hit testing -----------------------------------------------------------
  function hit(px, py) {
    let best = null, bd = Infinity;
    for (const n of nodes) {
      if (!shown(n.a)) continue;
      const [x, y] = toScreen(n.x, n.y);
      const d = Math.hypot(px - x, py - y), r = nodeRadius(n.a, state.size) + 4;
      if (d <= r && d < bd) { bd = d; best = { kind: "actor", id: n.a.i }; }
    }
    if (best) return best;
    for (const h of hubs) {
      const [x, y] = toScreen(h.x, h.y);
      if (Math.hypot(px - x, py - y) <= h.r + 4) return { kind: "hub", id: h.id };
    }
    return null;
  }

  // ---- detail text -----------------------------------------------------------
  // [{label, color, names: [string]}] for a group, schemes in table order,
  // then the unclassified names grouped by why.
  function namesByScheme(a) {
    const rows = [];
    for (const s of a.schemes) {
      const sc = schemeById.get(s);
      rows.push({ label: sc.label, color: sc.color, names: a.names.filter((n) => n.scheme === s).map((n) => n.name) });
    }
    const amb = a.names.filter((n) => n.status === "ambiguous");
    if (amb.length) {
      rows.push({ label: COPY.ambiguous, color: null, names: amb.map((n) =>
        `${n.name} (${fill(COPY.candidates, { list: n.candidates.map((c) => schemeById.get(c)?.label ?? c).join(", ") })})`) });
    }
    const exc = a.names.filter((n) => n.status === "exception");
    if (exc.length) {
      rows.push({ label: COPY.exception, color: null, names: exc.map((n) => {
        const e = exceptionOf.get(fold(n.name));
        return `${n.name} (${fill(COPY.exceptionNote, { scheme: schemeById.get(n.candidates[0])?.label ?? "", source: e?.source ?? "" })})`;
      }) });
    }
    const none = a.names.filter((n) => n.status === "no_rule").map((n) => n.name);
    if (none.length) rows.push({ label: COPY.noRule, color: null, names: none });
    return rows;
  }
  const metaLine = (a) => fill(COPY.panelMeta, {
    names: fmt(a.names.length),
    schemes: a.schemes.length ? COPY.schemesN(a.schemes.length) : COPY.noScheme,
  });

  // ---- tooltip ---------------------------------------------------------------
  const tip = $("a-tip");
  function showTip(target, px, py) {
    if (!target) { tip.style.opacity = 0; return; }
    let html;
    if (target.kind === "actor") {
      const a = actors[target.id];
      html = `<b>${escapeHtml(a.name)}</b><p>${escapeHtml(metaLine(a))}</p><dl>` +
        namesByScheme(a).map((r) => `<dt>${escapeHtml(r.label)}</dt><dd>${escapeHtml(r.names.join(", "))}</dd>`).join("") + "</dl>";
    } else {
      const h = hubById.get(target.id);
      html = `<b>${escapeHtml(h.label)}</b><p>${escapeHtml(fill(COPY.hubTip, { groups: COPY.groupsN(h.actors), names: fmt(h.names) }))}</p><p>${escapeHtml(h.forms)}</p>`;
    }
    tip.innerHTML = html;
    const tw = tip.offsetWidth, th = tip.offsetHeight;
    tip.style.left = `${Math.max(4, Math.min(W - tw - 4, px + 14))}px`;
    tip.style.top = `${Math.max(4, Math.min(Hh - th - 4, py + 14))}px`;
    tip.style.opacity = 1;
  }

  // ---- pinned panel ------------------------------------------------------------
  const panel = $("a-panel");
  function renderPanel() {
    if (state.pinned < 0) { panel.hidden = true; return; }
    const a = actors[state.pinned];
    panel.innerHTML =
      `<div class="sel-head"><b>${escapeHtml(a.name)}</b><button type="button" class="sel-close" id="a-panel-close">${escapeHtml(COPY.clear)}</button></div>` +
      `<p class="canon">${escapeHtml(metaLine(a))}</p>` +
      namesByScheme(a).map((r) => `<div class="scheme"><i${r.color ? ` style="background:${r.color}"` : ' class="none"'}></i>` +
        `<div><b>${escapeHtml(r.label)}</b><span>${escapeHtml(r.names.join(", "))}</span></div></div>`).join("") +
      (a.schemes.length ? "" : `<p class="sel-note">${escapeHtml(COPY.notPlaced)}</p>`);
    panel.hidden = false;
    $("a-panel-close").addEventListener("click", () => { unpin(); canvas.focus(); });
  }

  function pin(i, { center = false } = {}) {
    state.pinned = i;
    if (center && nodeOf.has(i)) {
      const n = nodeOf.get(i);
      view.ox = W / 2 - n.x * view.s; view.oy = Hh / 2 - n.y * view.s;
      moved = true;
    }
    renderPanel(); writeHash(); draw();
  }
  function unpin() { state.pinned = -1; renderPanel(); writeHash(); draw(); }

  // ---- legend --------------------------------------------------------------------
  const legend = $("a-legend");
  legend.innerHTML = schemesAll.map((s) =>
    `<button type="button" data-scheme="${escapeHtml(s.id)}" aria-pressed="false"${s.actors ? "" : " disabled"}>` +
    `<i style="background:${s.color}"></i><span>${escapeHtml(s.label)}</span><em>${escapeHtml(COPY.groupsN(s.actors))}</em></button>`).join("");
  function showLegend() {
    legend.querySelectorAll("[data-scheme]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.scheme === state.scheme)));
  }
  legend.addEventListener("click", (e) => {
    const b = e.target.closest("[data-scheme]");
    if (!b || b.disabled) return;
    state.scheme = state.scheme === b.dataset.scheme ? null : b.dataset.scheme;
    showLegend(); writeHash(); draw(); renderTable();
  });

  // ---- search ------------------------------------------------------------------
  const search = $("a-search");
  function searchStatus() {
    const q = state.q.trim();
    if (!q) { $("a-search-status").textContent = ""; return []; }
    const hits = actors.filter((a) => shown(a) && matches(a));
    $("a-search-status").textContent = fill(hits.length === 0 ? COPY.search.none : hits.length === 1 ? COPY.search.one : COPY.search.some, { q, n: fmt(hits.length) });
    return hits;
  }
  let st = null;
  search.addEventListener("input", () => {
    clearTimeout(st);
    st = setTimeout(() => { state.q = search.value; searchStatus(); writeHash(); draw(); renderTable(); }, 150);
  });
  search.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    e.preventDefault(); // the Enter must not reach a button focused below
    clearTimeout(st); state.q = search.value;
    const hits = searchStatus();
    const q = fold(state.q.trim());
    const exact = hits.filter((a) => a.folded.includes(q));
    const one = exact.length === 1 ? exact[0] : hits.length === 1 ? hits[0] : null;
    if (one) { closeTable(false); pin(one.i, { center: true }); }
    else if (hits.length) { writeHash(); draw(); openTable({ focus: false }); }
    else { writeHash(); draw(); }
  });

  // ---- table ---------------------------------------------------------------------
  const tableSort = { key: "schemes", dir: -1 };
  function tableRows() {
    const rows = actors.filter((a) => shown(a) && matches(a) && (!state.scheme || a.schemes.includes(state.scheme)));
    const k = tableSort.key, d = tableSort.dir;
    const val = (a) => (k === "name" ? fold(a.name) : k === "schemes" ? a.schemes.length : a.names.length);
    return rows.sort((p, q) => {
      const vp = val(p), vq = val(q);
      if (vp !== vq) return (vp < vq ? -1 : 1) * d;
      return fold(p.name) < fold(q.name) ? -1 : 1;
    });
  }
  function renderTable() {
    if (!state.tableOpen) return;
    const rows = tableRows();
    const filter = (state.q.trim() ? fill(COPY.table.filterQ, { q: state.q.trim() }) : "") +
      (state.multi ? COPY.table.filterMulti : "") +
      (state.scheme ? ` · ${schemeById.get(state.scheme).label}` : "");
    $("a-table-summary").textContent = fill(COPY.table.summary, {
      n: fmt(rows.length), total: fmt(actors.length), filter, sort: COPY.table.sorts[tableSort.key],
    });
    $("a-table-rows").innerHTML = rows.map((a) =>
      `<tr${a.i === state.pinned ? ' class="is-pinned"' : ""}><td><button type="button" data-actor="${a.i}">${escapeHtml(a.name)}</button></td>` +
      `<td>${a.schemes.length}</td><td>${a.names.length}</td><td class="names">` +
      namesByScheme(a).map((r) => `<span><b>${escapeHtml(r.label)}:</b> ${escapeHtml(r.names.join(", "))}</span>`).join("") +
      "</td></tr>").join("");
    document.querySelectorAll("#a-table th[data-sort]").forEach((th) => {
      const on = th.dataset.sort === tableSort.key;
      th.setAttribute("aria-sort", on ? (tableSort.dir > 0 ? "ascending" : "descending") : "none");
      th.querySelector("span").textContent = on ? (tableSort.dir > 0 ? " ▲" : " ▼") : "";
    });
  }
  function openTable({ focus = true } = {}) {
    state.tableOpen = true; $("a-table").hidden = false;
    $("a-table-toggle").setAttribute("aria-expanded", "true");
    renderTable(); if (focus) $("a-table-close").focus();
  }
  function closeTable(focusToggle = true) {
    if (!state.tableOpen) return;
    state.tableOpen = false; $("a-table").hidden = true;
    $("a-table-toggle").setAttribute("aria-expanded", "false");
    if (focusToggle) $("a-table-toggle").focus();
  }
  $("a-table-toggle").addEventListener("click", () => (state.tableOpen ? closeTable() : openTable()));
  $("a-table-close").addEventListener("click", () => closeTable());
  document.querySelectorAll("#a-table th[data-sort] button").forEach((b) => b.addEventListener("click", () => {
    const key = b.parentElement.dataset.sort;
    tableSort.dir = key === tableSort.key ? -tableSort.dir : key === "name" ? 1 : -1;
    tableSort.key = key; renderTable();
  }));
  $("a-table-rows").addEventListener("click", (e) => {
    const b = e.target.closest("[data-actor]");
    if (!b) return;
    closeTable(false); pin(+b.dataset.actor, { center: true });
    if (!panel.hidden) $("a-panel-close").focus();
  });

  // ---- options ---------------------------------------------------------------------
  $("a-multi-only").addEventListener("change", (e) => {
    state.multi = e.target.checked;
    if (state.multi && state.pinned >= 0 && actors[state.pinned].schemes.length < 2) state.pinned = -1;
    renderPanel(); searchStatus(); writeHash(); draw(); renderTable();
  });
  $("a-labels").addEventListener("change", (e) => { state.labels = e.target.checked; writeHash(); draw(); });
  $("a-size").addEventListener("change", (e) => { state.size = e.target.value; relayout(); writeHash(); draw(); });
  $("a-reset").addEventListener("click", () => { fit(); draw(); });
  $("a-controls-toggle").addEventListener("click", () => {
    const open = document.body.classList.toggle("controls-open");
    $("a-controls-toggle").setAttribute("aria-expanded", String(open));
    if (open) search.focus();
  });

  // ---- pointer: hover, pin, pan, zoom, pinch ------------------------------------------
  const ptrs = new Map();
  let drag = null, pinch = null;
  const xy = (e) => { const r = canvas.getBoundingClientRect(); return [e.clientX - r.left, e.clientY - r.top]; };
  function zoomAt(px, py, f) {
    const s = Math.max(20, Math.min(view.s * 12, view.s * f));
    const k = s / view.s;
    view.ox = px - (px - view.ox) * k; view.oy = py - (py - view.oy) * k; view.s = s;
    moved = true;
  }
  canvas.addEventListener("pointerdown", (e) => {
    const [px, py] = xy(e);
    ptrs.set(e.pointerId, { x: px, y: py });
    try { canvas.setPointerCapture(e.pointerId); } catch (err) { /* synthetic pointer */ }
    if (ptrs.size === 2) {
      const [a, b] = [...ptrs.values()];
      pinch = { d: Math.hypot(a.x - b.x, a.y - b.y) || 1 }; drag = null; return;
    }
    drag = { x: px, y: py, ox: view.ox, oy: view.oy, moved: false };
    canvas.classList.add("dragging");
  });
  canvas.addEventListener("pointermove", (e) => {
    const [px, py] = xy(e);
    if (ptrs.has(e.pointerId)) ptrs.set(e.pointerId, { x: px, y: py });
    if (pinch && ptrs.size === 2) {
      const [a, b] = [...ptrs.values()];
      const d = Math.hypot(a.x - b.x, a.y - b.y) || 1;
      zoomAt((a.x + b.x) / 2, (a.y + b.y) / 2, d / pinch.d); pinch.d = d; draw(); return;
    }
    if (drag) {
      if (Math.hypot(px - drag.x, py - drag.y) > 4) drag.moved = true;
      if (drag.moved) { view.ox = drag.ox + px - drag.x; view.oy = drag.oy + py - drag.y; moved = true; showTip(null); draw(); return; }
    }
    const h = hit(px, py);
    const same = (h && hover && h.kind === hover.kind && h.id === hover.id) || (!h && !hover);
    hover = h;
    if (!same) draw();
    showTip(h, px, py);
  });
  function endPointer(e) {
    ptrs.delete(e.pointerId);
    if (ptrs.size < 2) pinch = null;
    canvas.classList.remove("dragging");
  }
  canvas.addEventListener("pointerup", (e) => {
    const wasDrag = drag?.moved;
    const [px, py] = xy(e);
    endPointer(e);
    if (drag && !wasDrag) {
      const h = hit(px, py);
      if (h?.kind === "actor") pin(h.id);
      else if (h?.kind === "hub") { state.scheme = state.scheme === h.id ? null : h.id; showLegend(); writeHash(); draw(); renderTable(); }
      else if (state.pinned >= 0) unpin();
    }
    drag = null;
  });
  canvas.addEventListener("pointercancel", (e) => { endPointer(e); drag = null; });
  canvas.addEventListener("pointerleave", () => { if (!drag) { hover = null; showTip(null); draw(); } });
  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const [px, py] = xy(e);
    zoomAt(px, py, Math.exp(-e.deltaY * 0.0015)); draw();
  }, { passive: false });

  // ---- keyboard ------------------------------------------------------------------------
  // ] and [ step through the shown groups on the graph in name order.
  function step(dir) {
    const list = placed.filter(shown).sort((p, q) => (fold(p.name) < fold(q.name) ? -1 : 1));
    if (!list.length) return;
    const at = list.findIndex((a) => a.i === state.pinned);
    const next = at < 0 ? (dir > 0 ? 0 : list.length - 1) : (at + dir + list.length) % list.length;
    pin(list[next].i, { center: true });
  }
  canvas.addEventListener("keydown", (e) => {
    const pan = 40;
    const acts = {
      ArrowLeft: () => { view.ox += pan; moved = true; }, ArrowRight: () => { view.ox -= pan; moved = true; },
      ArrowUp: () => { view.oy += pan; moved = true; }, ArrowDown: () => { view.oy -= pan; moved = true; },
      "+": () => zoomAt(W / 2, Hh / 2, 1.2), "=": () => zoomAt(W / 2, Hh / 2, 1.2),
      "-": () => zoomAt(W / 2, Hh / 2, 1 / 1.2), Home: () => fit(),
      "]": () => step(1), "[": () => step(-1),
    };
    if (acts[e.key]) { e.preventDefault(); acts[e.key](); draw(); }
  });
  addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if (state.tableOpen) closeTable();
    else if (document.body.classList.contains("controls-open")) $("a-controls-toggle").click();
    else if (state.pinned >= 0) unpin();
    else if (state.scheme) { state.scheme = null; showLegend(); writeHash(); draw(); }
  });

  // An edited address (or back/forward) re-reads the view; writeHash uses
  // replaceState, which never fires this.
  addEventListener("hashchange", () => {
    const size = state.size;
    readHash(); if (state.size !== size) relayout();
    showLegend(); searchStatus(); renderPanel(); draw(); renderTable();
  });

  // read-only view state for tools/alias_smoke.py
  window.aliasView = () => ({
    pinned: state.pinned >= 0 ? actors[state.pinned].name : null,
    scheme: state.scheme,
    nodes: nodes.filter((n) => shown(n.a)).map((n) => { const [x, y] = toScreen(n.x, n.y); return { name: n.a.name, x, y }; }),
    hubs: hubs.map((h) => { const [x, y] = toScreen(h.x, h.y); return { id: h.id, x, y }; }),
  });

  // ---- go ------------------------------------------------------------------------------
  readHash();
  relayout();
  showLegend(); searchStatus(); renderPanel();
  new ResizeObserver(resize).observe(canvas);
  resize();
  if (state.pinned >= 0 && nodeOf.has(state.pinned)) {
    const n = nodeOf.get(state.pinned);
    const [x, y] = toScreen(n.x, n.y);
    if (x < 0 || x > W || y < 0 || y > Hh) pin(state.pinned, { center: true });
  }
  document.body.dataset.ready = "1";
}

boot();
