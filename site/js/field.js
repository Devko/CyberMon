// =============================================================================
// field.js — The Field (field.html): every published CVE as one point in a
// WebGL space, arranged by the site's own theses.
//
// Reads field/field.json + field/cves.bin.gz, both built by the nightly with
// `python -m pipeline --field-out site/field` (pipeline/field_export.py owns
// the record layout; the decode below mirrors it field for field). The blob
// is a deploy-time build product — a fresh checkout has none, and the page
// says so instead of erroring.
//
// Deliberately NOT a module page: no initChrome, no editorial.nav entry, so
// the carousel and motion pipelines never see it. Point colours mirror
// theme.js the same way the charts do; the accent stays reserved for KEV.
//
// Markup rule (same as theme.js tooltips): every data-derived string that
// reaches innerHTML — CNA names, vendor names, status labels, error text —
// passes through escapeHtml first. Numbers are formatted, never interpolated
// raw from the record stream.
// =============================================================================
import { C, escapeHtml } from "./theme.js";

const REDUCE = matchMedia("(prefers-reduced-motion: reduce)").matches;
const $ = (id) => document.getElementById(id);

// ---- copy (kept here, not in editorial.js: the instrument is not a module) --

const ARRANGE = {
  time: {
    k: "Timeline · date × score × EPSS",
    thesis: "Twenty-seven years of records, placed by the day each was published and the score it shipped with. Depth is EPSS: the nearer a point, the likelier the exploit.",
    method: "x: datePublished (UTC day). y: the newest CVSS base score in the record, CNA container before CISA-ADP — the same precedence the severity-inflation chart uses; records with no in-record score sit on the floor. z: log10 of the current EPSS probability, so each lane back is ten times less likely; records EPSS has never scored sit in the back lane.",
  },
  grid: {
    k: "Score vs. reality",
    thesis: "Left to right: how likely exploitation is, by EPSS. Front to back: how severe the label says it is, by CVSS. If scores tracked risk, the mass would run along the diagonal.",
    method: "The same sixteen buckets as chart 3 on the CVE Ecosystem page (CVSS 0.1–3.9 / 4.0–6.9 / 7.0–8.9 / 9.0–10.0 × EPSS <0.1% / 0.1–1% / 1–10% / >10%), plus a row for records with no in-record score and a column for records EPSS has not scored. Pile height is the base score.",
  },
  cna: {
    k: "By assigner",
    thesis: "Who mints the record. The forty-eight largest assigners in the selection, each pile as tall as the scores it hands out.",
    method: "Grouped by the record's assignerShortName. Pile height is the base score, so a flat-topped pile is a CNA that scores everything alike. The KEV count under each pile is the exploited-in-the-wild cut of that CNA's records.",
  },
  cwe: {
    k: "By weakness",
    thesis: "Bug-class inertia in one room: the thirty weakness classes that carry most of the selection.",
    method: "Grouped by the first cweId in the record, CNA container preferred; records whose problemTypes carry no CWE id are grouped as untagged. Names are the site's own short labels for the common classes.",
  },
  status: {
    k: "By NVD queue status",
    thesis: "Where each record sits in NVD's queue tonight — the backlog the decay chart counts, one record at a time.",
    method: "vulnStatus from the nightly NVD sync (the same state the NVD decay and throughput charts diff). Unknown means NVD has no record of the id, or the NVD stage was skipped for this build.",
  },
  clock: {
    k: "The clock · publication → PoC → KEV",
    thesis: "How long the record had. Front lane: days from publication to the first public proof of concept. Back lane: days to the KEV listing. Left of zero, the exploit came first.",
    method: "Only records with a dated event are placed. x is the signed gap in days on a log scale (±10 years at the edges); y is the base score. PoC date is the earliest dated Exploit-DB or Metasploit entry (Nuclei publishes no dates); KEV date is CISA's dateAdded. A record with both sits in the KEV lane and the hover shows both gaps — the same joins the Time to PoC and KEV Latency modules use.",
  },
  vendor: {
    k: "By vendor",
    thesis: "Whose software. The forty-eight vendors carrying most of the selection, by the first affected vendor each record names.",
    method: "Grouped by the CNA container's first affected[].vendor, lower-cased and whitespace-normalised; placeholder vendors (n/a, unknown) and records naming none fall into \"other\" and are not shown here. Vendor spelling is the record's own, so one company can appear under two names.",
  },
};

const CWE_NAMES = {
  0: "untagged", 79: "XSS", 862: "Missing authorization", 74: "Injection",
  284: "Improper access control", 89: "SQL injection", 22: "Path traversal",
  416: "Use after free", 352: "CSRF", 119: "Buffer overflow",
  20: "Improper input validation", 125: "Out-of-bounds read",
  200: "Information exposure", 918: "SSRF", 78: "OS command injection",
  787: "Out-of-bounds write", 863: "Incorrect authorization",
  476: "NULL dereference", 639: "IDOR", 502: "Deserialization",
  122: "Heap overflow", 94: "Code injection", 400: "Resource consumption",
  306: "Missing authentication", 98: "File inclusion", 77: "Command injection",
  269: "Privilege management", 287: "Improper authentication",
  121: "Stack overflow", 770: "Unbounded allocation",
  266: "Incorrect privilege assignment", 434: "Unrestricted upload",
  362: "Race condition", 190: "Integer overflow", 120: "Classic overflow",
  285: "Improper authorization", 401: "Memory leak", 601: "Open redirect",
  693: "Protection mechanism failure", 59: "Link following",
  254: "Security features", 264: "Permissions and privileges",
  255: "Credentials management", 189: "Numeric errors", 16: "Configuration",
  399: "Resource management", 310: "Cryptographic issues", 17: "Code",
  704: "Incorrect type conversion", 732: "Incorrect permission assignment",
  798: "Hard-coded credentials", 611: "XXE", 1321: "Prototype pollution",
};
const cweName = (n) => (CWE_NAMES[n] ? (n ? `CWE-${n} ${CWE_NAMES[n]}` : "untagged") : `CWE-${n}`);

// ---- palette (theme.js, plus the one lane colour the charts don't need) -----

const col = (hex) => new THREE.Color(hex);
const PAL = {
  kev: col(C.accent),
  poc: col(C.sev.high),
  none: col("#7d776a"),
  sev: [col(C.sev.unscored), col(C.sev.low), col(C.sev.medium), col(C.sev.high), col(C.sev.critical)],
  ver: { 0: col(C.sev.unscored), 2: col(C.versions.v2), 3: col(C.versions.v3), 4: col(C.versions.v4) },
  cna: ["#c08a45", "#ded7c2", "#7fa7b8", "#9a8fc2", "#8fb08a", "#c2788f", "#b5a26a", "#6f9ea3"].map(col),
  lat: ["before_publish", "0-7d", "8-30d", "31-90d", "91-365d", "1-3y", "3y+"].map((k) => col(C.latency[k])),
  focus: col(C.ink),
};
const LEGEND = {
  expl: [[C.accent, "in KEV"], [C.sev.high, "public PoC"], ["#7d776a", "neither"]],
  sev: [[C.sev.critical, "Critical"], [C.sev.high, "High"], [C.sev.medium, "Medium"], [C.sev.low, "Low"], [C.sev.unscored, "no score in record"]],
  ver: [[C.versions.v4, "CVSS v4"], [C.versions.v3, "v3"], [C.versions.v2, "v2"], [C.sev.unscored, "no score"]],
  lat: [[C.latency.before_publish, "KEV before publication"], [C.latency["0-7d"], "0–7 d"], [C.latency["8-30d"], "8–30 d"], [C.latency["31-90d"], "31–90 d"], [C.latency["91-365d"], "91–365 d"], [C.latency["1-3y"], "1–3 y"], [C.latency["3y+"], "3 y+"], ["#7d776a", "not in KEV"]],
  cna: null, // built from the selection
};
// KEV latency buckets, the KEV Latency module's own edges.
const latBucket = (lag) => (lag < 0 ? 0 : lag <= 7 ? 1 : lag <= 30 ? 2 : lag <= 90 ? 3 : lag <= 365 ? 4 : lag <= 1095 ? 5 : 6);

// ---- boot ------------------------------------------------------------------

const notice = $("f-notice");
// `html` is authored markup; any data inside it is escaped by the caller.
function showNotice(title, html) {
  notice.innerHTML = `<div><strong>${escapeHtml(title)}</strong>${html}</div>`;
  notice.hidden = false;
}

async function loadField() {
  const metaRes = await fetch("field/field.json", { cache: "no-cache" });
  if (!metaRes.ok) throw new Error(`field/field.json: HTTP ${metaRes.status}`);
  const meta = await metaRes.json();
  if (meta.layout?.version !== 2 || meta.layout.record_bytes !== 24) {
    throw new Error(`field.json layout v${meta.layout?.version} is not the v2/24-byte layout this page decodes`);
  }
  if (typeof DecompressionStream === "undefined") {
    throw new Error("this browser cannot decompress the record stream (no DecompressionStream)");
  }
  showNotice("Loading the Field", `<span class="progress">${Number(meta.n).toLocaleString("en-US")} records · ${(Number(meta.bin_bytes) / 1048576).toFixed(1)} MB…</span>`);
  const binRes = await fetch(`field/${encodeURIComponent(meta.bin)}`, { cache: "no-cache" });
  if (!binRes.ok) throw new Error(`field/${meta.bin}: HTTP ${binRes.status}`);
  const buf = await new Response(binRes.body.pipeThrough(new DecompressionStream("gzip"))).arrayBuffer();
  if (buf.byteLength !== meta.raw_bytes) {
    throw new Error(`record stream is ${buf.byteLength} bytes, field.json promised ${meta.raw_bytes}`);
  }
  return { meta, buf };
}

function decode(meta, buf) {
  const N = meta.n, REC = 24, dv = new DataView(buf);
  const d = {
    N, year: new Uint16Array(N), seq: new Uint32Array(N), day: new Uint16Array(N),
    score: new Uint8Array(N), ver: new Uint8Array(N), epss: new Uint16Array(N),
    cna: new Uint16Array(N), cwe: new Uint16Array(N), vendor: new Uint16Array(N),
    kevday: new Uint16Array(N), pocday: new Uint16Array(N), flags: new Uint8Array(N),
  };
  for (let i = 0, o = 0; i < N; i++, o += REC) {
    d.year[i] = dv.getUint16(o, true);
    d.seq[i] = dv.getUint32(o + 2, true);
    d.day[i] = dv.getUint16(o + 6, true);
    d.score[i] = dv.getUint8(o + 8);
    d.ver[i] = dv.getUint8(o + 9);
    d.epss[i] = dv.getUint16(o + 10, true);
    d.cna[i] = dv.getUint16(o + 12, true);
    d.cwe[i] = dv.getUint16(o + 14, true);
    d.vendor[i] = dv.getUint16(o + 16, true);
    d.kevday[i] = dv.getUint16(o + 18, true);
    d.pocday[i] = dv.getUint16(o + 20, true);
    d.flags[i] = dv.getUint8(o + 22);
  }
  return d;
}

function main({ meta, buf }) {
  const D = decode(meta, buf);
  const { N } = D;
  const NO_SCORE = meta.layout.no_score, NO_EPSS = meta.layout.no_epss;
  const STATUS = meta.layout.status_codes.map(String);
  const CNAS = meta.cnas.map(String), VENDORS = meta.vendors.map(String);
  const EPOCH = Date.UTC(1999, 0, 1);
  const dstr = (day) => new Date(EPOCH + day * 864e5).toISOString().slice(0, 10);
  const cveId = (i) => `CVE-${D.year[i]}-${String(D.seq[i]).padStart(4, "0")}`;
  const KEV = (i) => D.flags[i] & 1, RANSOM = (i) => (D.flags[i] >> 1) & 1, POC = (i) => (D.flags[i] >> 2) & 1;
  const NVD = (i) => (D.flags[i] >> 3) & 7;

  // publication year per point, via a day -> year lookup (u16 day range)
  const LAST_DAY = meta.last_day;
  const yearOfDay = new Uint8Array(LAST_DAY + 1);
  const yearStart = [];
  for (let y = 1999; y <= 2100; y++) {
    const start = (Date.UTC(y, 0, 1) - EPOCH) / 864e5;
    if (start > LAST_DAY) break;
    yearStart.push(start);
    const end = Math.min(LAST_DAY, (Date.UTC(y + 1, 0, 1) - EPOCH) / 864e5 - 1);
    yearOfDay.fill(y - 1999, start, end + 1);
  }
  const MAX_YEAR = 1999 + yearStart.length - 1;
  const pubYear = new Uint8Array(N);
  for (let i = 0; i < N; i++) pubYear[i] = yearOfDay[D.day[i]];
  const dayOfYear = (y) => (y - 1999 < yearStart.length ? yearStart[y - 1999] : LAST_DAY + 1);

  // ---- renderer -------------------------------------------------------------
  const canvas = $("f-canvas"), labelsEl = $("f-labels"), tip = $("f-tip");
  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  } catch (err) {
    showNotice("WebGL is unavailable", `<p>This browser did not give the page a WebGL context, so the field cannot be drawn here. The same corpus is charted on <a href="cve.html">cve.html</a>.</p>`);
    return;
  }
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x0e0f11, 0.0016);
  const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 3000);
  const grid = new THREE.GridHelper(560, 56, 0x2a2c2e, 0x1b1d21);
  grid.position.y = -9;
  scene.add(grid);

  // point sprite + shader (size attenuates with depth; alpha per point)
  const sprite = (() => {
    const c = document.createElement("canvas"); c.width = c.height = 64;
    const g = c.getContext("2d"); const r = g.createRadialGradient(32, 32, 0, 32, 32, 32);
    r.addColorStop(0, "rgba(255,255,255,1)"); r.addColorStop(0.35, "rgba(255,255,255,.6)"); r.addColorStop(1, "rgba(255,255,255,0)");
    g.fillStyle = r; g.fillRect(0, 0, 64, 64);
    return new THREE.CanvasTexture(c);
  })();
  const geo = new THREE.BufferGeometry();
  const pos = new Float32Array(N * 3), colr = new Float32Array(N * 3), size = new Float32Array(N), alpha = new Float32Array(N);
  geo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
  geo.setAttribute("color", new THREE.BufferAttribute(colr, 3));
  geo.setAttribute("size", new THREE.BufferAttribute(size, 1));
  geo.setAttribute("alpha", new THREE.BufferAttribute(alpha, 1));
  const mat = new THREE.ShaderMaterial({
    uniforms: { map: { value: sprite } },
    vertexShader: "attribute float size;attribute float alpha;attribute vec3 color;varying vec3 vC;varying float vA;void main(){vC=color;vA=alpha;vec4 mv=modelViewMatrix*vec4(position,1.0);gl_PointSize=max(1.6,size*(640.0/-mv.z));gl_Position=projectionMatrix*mv;}",
    fragmentShader: "uniform sampler2D map;varying vec3 vC;varying float vA;void main(){vec4 t=texture2D(map,gl_PointCoord);if(t.a*vA<0.02)discard;gl_FragColor=vec4(vC,t.a*vA);}",
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
  });
  const points = new THREE.Points(geo, mat);
  points.frustumCulled = false;
  scene.add(points);

  // deterministic jitter so a pile never collapses to one pixel
  const jit = new Float32Array(N * 3);
  { let s = 12345; for (let i = 0; i < N * 3; i++) { s = (s * 16807) % 2147483647; jit[i] = s / 2147483647 - 0.5; } }

  const cam = { theta: 0.35, phi: 1.05, r: 560, tx: 0, ty: 8, tz: 0 };
  function resize() {
    const w = canvas.clientWidth, h = canvas.clientHeight;
    if (!w || !h) return;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  new ResizeObserver(resize).observe(canvas);
  resize();

  // ---- state & filter -------------------------------------------------------
  const state = {
    layout: "time", color: "expl", from: 1999, to: MAX_YEAR, minScore: 0,
    kevOnly: false, pocOnly: false, ransomOnly: false, cnaQ: "", vendorQ: "",
    sort: "count", size: 1, playing: false, playFrom: 1999, select: false,
  };
  const shown = new Uint8Array(N);
  let shownCount = 0, shownKev = 0;
  function applyFilter() {
    shownCount = 0; shownKev = 0;
    let cnaSet = null, vendSet = null;
    const cq = state.cnaQ.trim().toLowerCase(), vq = state.vendorQ.trim().toLowerCase();
    if (cq) { cnaSet = new Set(); CNAS.forEach((c, i) => { if (c.toLowerCase().includes(cq)) cnaSet.add(i); }); }
    if (vq) { vendSet = new Set(); VENDORS.forEach((v, i) => { if (v.includes(vq)) vendSet.add(i); }); }
    const lo = state.from - 1999, hi = state.to - 1999, minS = state.minScore * 10;
    for (let i = 0; i < N; i++) {
      const y = pubYear[i];
      let ok = y >= lo && y <= hi && (minS === 0 || (D.score[i] !== NO_SCORE && D.score[i] >= minS));
      if (ok && state.kevOnly) ok = KEV(i) === 1;
      if (ok && state.pocOnly) ok = POC(i) === 1;
      if (ok && state.ransomOnly) ok = RANSOM(i) === 1;
      if (ok && cnaSet) ok = cnaSet.has(D.cna[i]);
      if (ok && vendSet) ok = vendSet.has(D.vendor[i]);
      // the clock places only records with a dated event; the vendor room
      // has no pile for "other"
      if (ok && state.layout === "clock") ok = KEV(i) === 1 || D.pocday[i] > 0;
      if (ok && state.layout === "vendor") ok = D.vendor[i] !== 0;
      shown[i] = ok ? 1 : 0;
      if (ok) { shownCount++; shownKev += KEV(i); }
    }
  }

  // ---- layouts --------------------------------------------------------------
  const target = new Float32Array(N * 3), fromPos = new Float32Array(N * 3);
  let animStart = 0;
  const labels = [];
  function clearLabels() { labels.forEach((l) => l.el.remove()); labels.length = 0; }
  // `html` is authored markup; data inside it is escaped by the caller.
  function addLabel(x, y, z, html, cls) {
    const el = document.createElement("div");
    el.className = "f-label " + (cls || "");
    el.innerHTML = html;
    labelsEl.appendChild(el);
    labels.push({ el, p: new THREE.Vector3(x, y, z) });
  }
  const hide = (i) => { target[i * 3] = 0; target[i * 3 + 1] = -999; target[i * 3 + 2] = 0; };

  const TW = 460;
  const zOfEpss = (i) => {
    if (D.epss[i] === NO_EPSS) return -46 + jit[i * 3 + 2] * 5;
    const p = Math.max(D.epss[i] / 10000, 1e-4);
    return ((Math.log10(p) + 4) / 4) * 56 - 28 + jit[i * 3 + 2] * 3;
  };
  const yOfScore = (i) => (D.score[i] === NO_SCORE ? -6 + jit[i * 3 + 1] * 1.5 : (D.score[i] / 100) * 36 + jit[i * 3 + 1] * 0.6);

  function timelineLayout() {
    const spanFrom = state.playing ? state.playFrom : state.from;
    const spanTo = state.playing ? MAX_YEAR : state.to;
    const a = dayOfYear(spanFrom), b = Math.min(LAST_DAY + 1, dayOfYear(spanTo + 1));
    const span = Math.max(1, b - a);
    for (let i = 0; i < N; i++) {
      if (!shown[i]) { hide(i); continue; }
      target[i * 3] = ((D.day[i] - a) / span - 0.5) * TW + jit[i * 3] * 0.4;
      target[i * 3 + 1] = yOfScore(i);
      target[i * 3 + 2] = zOfEpss(i);
    }
    const years = spanTo - spanFrom + 1;
    const step = years > 20 ? 5 : years > 10 ? 2 : 1;
    for (let y = spanFrom; y <= spanTo; y++) {
      if ((y - spanFrom) % step) continue;
      const x = ((dayOfYear(y) - a) / span - 0.5) * TW;
      addLabel(x, -10, -56, String(y), "tick");
    }
    [0, 5, 10].forEach((s) => addLabel(-TW / 2 - 14, (s / 10) * 36, -50, `CVSS ${s}`, "tick"));
    addLabel(-TW / 2 - 14, -6, -50, "no score", "tick");
    [["no EPSS", -46], ["0.01%", -28], ["0.1%", -14], ["1%", 0], ["10%", 14], ["100%", 28]]
      .forEach(([t, z]) => addLabel(TW / 2 + 10, -6, z, t, "lane"));
    addLabel(TW / 2 + 10, -14, 44, "EPSS →", "axis");
  }

  // the clock: signed gap in days on a symmetric log scale, ±10 y at the edges
  const LAGMAX = 3650;
  const xOfLag = (lag) => {
    const a = Math.min(Math.abs(lag), LAGMAX);
    return Math.sign(lag) * (Math.log10(1 + a) / Math.log10(1 + LAGMAX)) * (TW / 2);
  };
  const kevLag = (i) => D.kevday[i] - D.day[i];
  const pocLag = (i) => D.pocday[i] - D.day[i];
  function clockLayout() {
    for (let i = 0; i < N; i++) {
      if (!shown[i]) { hide(i); continue; }
      const k = KEV(i);
      const lag = k ? kevLag(i) : pocLag(i);
      target[i * 3] = xOfLag(lag) + jit[i * 3] * 0.6;
      target[i * 3 + 1] = yOfScore(i);
      target[i * 3 + 2] = (k ? -26 : 26) + jit[i * 3 + 2] * 12;
    }
    [[-3650, "−10 y"], [-365, "−1 y"], [-30, "−30 d"], [0, "0"], [30, "+30 d"], [365, "+1 y"], [3650, "+10 y"]]
      .forEach(([v, t]) => addLabel(xOfLag(v), -10, -48, t, "tick"));
    addLabel(0, -10, -60, "before publication ← days → after", "axis");
    [0, 5, 10].forEach((s) => addLabel(-TW / 2 - 14, (s / 10) * 36, -44, `CVSS ${s}`, "tick"));
    addLabel(TW / 2 + 10, -6, -26, "→ KEV listing", "lane");
    addLabel(TW / 2 + 10, -6, 26, "→ first public PoC", "lane");
  }

  function spiral(k, n, R) { const a = k * 2.399963; const rr = R * Math.sqrt((k + 0.5) / n); return [Math.cos(a) * rr, Math.sin(a) * rr]; }
  function clusterLayout(keyFn, groups, cols, cellW, cellD, titleFn, labelY = -9) {
    const idx = new Map(); groups.forEach((g, i) => idx.set(g, i));
    const counts = new Map(), kevs = new Map();
    for (let i = 0; i < N; i++) {
      if (!shown[i]) continue;
      const k = keyFn(i);
      if (!idx.has(k)) continue;
      counts.set(k, (counts.get(k) || 0) + 1);
      if (KEV(i)) kevs.set(k, (kevs.get(k) || 0) + 1);
    }
    const rows = Math.ceil(groups.length / cols);
    const maxC = Math.max(1, ...groups.map((g) => counts.get(g) || 0));
    const rad = Math.min(0.34, (cellW * 0.44) / Math.sqrt(maxC));
    const gs = new Map();
    groups.forEach((g, gi) => {
      const cx = ((gi % cols) - (cols - 1) / 2) * cellW, cz = (Math.floor(gi / cols) - (rows - 1) / 2) * cellD;
      const n = counts.get(g) || 0;
      gs.set(g, { cx, cz, k: 0, n: Math.max(1, n), R: Math.max(3.5, rad * Math.sqrt(n)) });
    });
    for (let i = 0; i < N; i++) {
      if (!shown[i]) { hide(i); continue; }
      const s = gs.get(keyFn(i));
      if (!s) { hide(i); continue; }
      const [dx, dz] = spiral(s.k++, s.n, s.R);
      target[i * 3] = s.cx + dx;
      target[i * 3 + 1] = (D.score[i] === NO_SCORE ? 0 : (D.score[i] / 100) * 7) + jit[i * 3 + 1] * 0.8;
      target[i * 3 + 2] = s.cz + dz;
    }
    groups.forEach((g) => {
      const s = gs.get(g);
      addLabel(s.cx, labelY, s.cz + s.R + 4, titleFn(g, counts.get(g) || 0, kevs.get(g) || 0), "");
    });
  }
  function sortGroups(groups, keyFn, nameOf) {
    if (state.sort === "name") return groups.sort((a, b) => String(nameOf(a)).localeCompare(String(nameOf(b))));
    const c = new Map(), k = new Map();
    for (let i = 0; i < N; i++) {
      if (!shown[i]) continue;
      const g = keyFn(i);
      c.set(g, (c.get(g) || 0) + 1);
      if (KEV(i)) k.set(g, (k.get(g) || 0) + 1);
    }
    const m = state.sort === "kev" ? k : c;
    return groups.sort((a, b) => (m.get(b) || 0) - (m.get(a) || 0));
  }
  const fmt = (n) => Number(n).toLocaleString("en-US");
  const sevBucket = (i) => { const s = D.score[i]; return s === NO_SCORE ? 0 : s >= 90 ? 4 : s >= 70 ? 3 : s >= 40 ? 2 : 1; };
  const epssBucket = (i) => { const e = D.epss[i]; return e === NO_EPSS ? 0 : e >= 1000 ? 4 : e >= 100 ? 3 : e >= 10 ? 2 : 1; };

  function layout() {
    clearLabels();
    fromPos.set(pos);
    animStart = performance.now();
    if (state.layout === "time") timelineLayout();
    else if (state.layout === "clock") clockLayout();
    else if (state.layout === "vendor") {
      const cnt = new Map();
      for (let i = 0; i < N; i++) if (shown[i]) cnt.set(D.vendor[i], (cnt.get(D.vendor[i]) || 0) + 1);
      const groups = sortGroups([...cnt.keys()], (i) => D.vendor[i], (g) => VENDORS[g]).slice(0, 48);
      clusterLayout((i) => D.vendor[i], groups, 8, 40, 38, (g, n, k) => `<b>${escapeHtml(VENDORS[g])}</b>${fmt(n)} · KEV ${fmt(k)}`);
    } else if (state.layout === "cna") {
      const cnt = new Map();
      for (let i = 0; i < N; i++) if (shown[i]) cnt.set(D.cna[i], (cnt.get(D.cna[i]) || 0) + 1);
      const groups = sortGroups([...cnt.keys()], (i) => D.cna[i], (g) => CNAS[g]).slice(0, 48);
      clusterLayout((i) => D.cna[i], groups, 8, 40, 38, (g, n, k) => `<b>${escapeHtml(CNAS[g])}</b>${fmt(n)} · KEV ${fmt(k)}`);
    } else if (state.layout === "cwe") {
      const cnt = new Map();
      for (let i = 0; i < N; i++) if (shown[i]) cnt.set(D.cwe[i], (cnt.get(D.cwe[i]) || 0) + 1);
      const groups = sortGroups([...cnt.keys()], (i) => D.cwe[i], (g) => cweName(g)).slice(0, 30);
      clusterLayout((i) => D.cwe[i], groups, 6, 52, 46, (g, n, k) => `<b>${escapeHtml(cweName(g))}</b>${fmt(n)} · KEV ${fmt(k)}`);
    } else if (state.layout === "status") {
      const groups = sortGroups([1, 2, 3, 4, 5, 6, 7, 0], NVD, (g) => STATUS[g]);
      clusterLayout(NVD, groups, 4, 92, 80, (g, n, k) => `<b>${escapeHtml(STATUS[g])}</b>${fmt(n)} · KEV ${fmt(k)}`);
    } else if (state.layout === "grid") {
      const groups = []; for (let r = 4; r >= 0; r--) for (let c = 0; c < 5; c++) groups.push(r * 5 + c);
      clusterLayout((i) => sevBucket(i) * 5 + epssBucket(i), groups, 5, 48, 44, (g, n, k) => `${fmt(n)}${k ? ` · KEV ${fmt(k)}` : ""}`, -9);
      const EP = ["no EPSS", "<0.1%", "0.1–1%", "1–10%", ">10%"], SV = ["no score", "Low", "Medium", "High", "Critical"];
      EP.forEach((t, c) => addLabel((c - 2) * 48, -9, 2.5 * 44 + 14, escapeHtml(t), "tick"));
      addLabel(0, -9, 2.5 * 44 + 26, "EPSS exploitation probability →", "axis");
      SV.forEach((t, r) => addLabel(-2.5 * 48 - 14, -9, (2 - r) * 44, t, "tick"));
      addLabel(-2.5 * 48 - 14, -9, -2.5 * 44 - 12, "← CVSS", "axis");
    }
    const a = ARRANGE[state.layout];
    $("hud-k").textContent = a.k;
    $("hud-thesis").textContent = a.thesis;
    $("hud-method").textContent = a.method;
  }

  // ---- colour ---------------------------------------------------------------
  let cnaTop = [];
  function colour() {
    let cnaRank = null;
    if (state.color === "cna") {
      const cnt = new Map();
      for (let i = 0; i < N; i++) if (shown[i]) cnt.set(D.cna[i], (cnt.get(D.cna[i]) || 0) + 1);
      cnaTop = [...cnt.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map((e) => e[0]);
      cnaRank = new Map(cnaTop.map((c, i) => [c, i]));
    }
    for (let i = 0; i < N; i++) {
      let c, s = 1.0, a = 0.55;
      const k = KEV(i);
      if (state.color === "expl") {
        c = k ? PAL.kev : POC(i) ? PAL.poc : PAL.none;
        if (k) { s = 4.2; a = 0.95; } else if (POC(i)) { s = 1.6; a = 0.7; } else { s = 0.8; a = 0.22; }
      } else if (state.color === "sev") {
        const b = sevBucket(i); c = PAL.sev[b];
        if (b === 4) { s = 1.6; a = 0.75; } else if (b === 0) { s = 0.8; a = 0.2; } else { s = 0.9; a = 0.35; }
        if (k) { s = 4.2; a = 0.95; }
      } else if (state.color === "ver") {
        c = PAL.ver[D.ver[i]] || PAL.ver[0];
        if (D.ver[i] === 0) { s = 0.8; a = 0.2; } else { s = 0.9; a = 0.4; }
        if (k) { s = 4.2; a = 0.95; }
      } else if (state.color === "lat") {
        if (k) { c = PAL.lat[latBucket(kevLag(i))]; s = 4.2; a = 0.95; }
        else { c = PAL.none; s = 0.8; a = 0.18; }
      } else {
        const r = cnaRank.get(D.cna[i]);
        c = r === undefined ? PAL.none : PAL.cna[r];
        if (r === undefined) { s = 0.8; a = 0.18; } else { s = 0.9; a = 0.45; }
        if (k) { s = 4.2; a = 0.95; }
      }
      if (i === focusIdx) { c = PAL.focus; s = 9; a = 1; }
      // a live selection: the catch at full strength, the rest a ghost
      if (selCount) a = selected[i] ? Math.max(a, 0.9) : Math.min(a, 0.06);
      colr[i * 3] = c.r; colr[i * 3 + 1] = c.g; colr[i * 3 + 2] = c.b;
      size[i] = s * state.size; alpha[i] = a;
    }
    geo.attributes.color.needsUpdate = true;
    geo.attributes.size.needsUpdate = true;
    geo.attributes.alpha.needsUpdate = true;
    const leg = state.color === "cna"
      ? cnaTop.map((c, i) => [PAL.cna[i].getStyle(), CNAS[c]]).concat([["#7d776a", "other assigners"]])
      : LEGEND[state.color];
    $("f-legend").innerHTML = leg.map(([hex, t]) => `<span><i style="background:${escapeHtml(hex)}"></i>${escapeHtml(t)}</span>`).join("")
      + (state.color !== "expl" ? `<span><i style="background:${C.accent}"></i>KEV, always larger</span>` : "");
  }

  // ---- interaction ----------------------------------------------------------
  let drag = null, hoverAt = 0;
  // ---- selection: a drawn box becomes a receipt ----------------------------
  // In select mode a left-drag draws a screen-space box; on release every
  // shown point whose projection falls inside it is selected. The counters
  // and the panel then describe the catch; everything else dims. Positions
  // move on every refresh, so a selection never survives a re-layout.
  const rectEl = $("f-rect"), selEl = $("f-sel");
  const selected = new Uint8Array(N);
  let selCount = 0, selKev = 0, rect = null;
  function canvasXY(e) { const r = canvas.getBoundingClientRect(); return [e.clientX - r.left, e.clientY - r.top]; }
  function drawRect() {
    const x = Math.min(rect.x0, rect.x1), y = Math.min(rect.y0, rect.y1);
    rectEl.style.left = `${x}px`; rectEl.style.top = `${y}px`;
    rectEl.style.width = `${Math.abs(rect.x1 - rect.x0)}px`; rectEl.style.height = `${Math.abs(rect.y1 - rect.y0)}px`;
    rectEl.hidden = false;
  }
  const pv = new THREE.Vector3();
  function captureRect(r) {
    const w = canvas.clientWidth, h = canvas.clientHeight;
    const x0 = Math.min(r.x0, r.x1), x1 = Math.max(r.x0, r.x1), y0 = Math.min(r.y0, r.y1), y1 = Math.max(r.y0, r.y1);
    if (x1 - x0 < 3 || y1 - y0 < 3) return;
    camera.updateMatrixWorld();
    selCount = 0; selKev = 0;
    for (let i = 0; i < N; i++) {
      selected[i] = 0;
      if (!shown[i] || pos[i * 3 + 1] < -500) continue;
      pv.set(pos[i * 3], pos[i * 3 + 1], pos[i * 3 + 2]).project(camera);
      if (pv.z >= 1) continue;
      const sx = (pv.x * 0.5 + 0.5) * w, sy = (-pv.y * 0.5 + 0.5) * h;
      if (sx >= x0 && sx <= x1 && sy >= y0 && sy <= y1) { selected[i] = 1; selCount++; selKev += KEV(i); }
    }
    renderSelection(); colour(); updateCounters();
  }
  function clearSelection(recolour = true) {
    if (!selCount) return;
    selected.fill(0); selCount = 0; selKev = 0;
    selEl.hidden = true;
    if (recolour) { colour(); updateCounters(); }
  }
  function topN(keyFn, nameFn, n = 5) {
    const cnt = new Map();
    for (let i = 0; i < N; i++) if (selected[i]) cnt.set(keyFn(i), (cnt.get(keyFn(i)) || 0) + 1);
    return [...cnt.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, c]) => [nameFn(k), c]);
  }
  function renderSelection() {
    if (!selCount) { selEl.hidden = true; return; }
    let poc = 0, scored = 0, crit = 0, withEpss = 0, hot = 0, yMin = 9999, yMax = 0, ransom = 0;
    const scores = [];
    for (let i = 0; i < N; i++) {
      if (!selected[i]) continue;
      if (POC(i)) poc++;
      if (RANSOM(i)) ransom++;
      if (D.score[i] !== NO_SCORE) { scored++; scores.push(D.score[i]); if (D.score[i] >= 90) crit++; }
      if (D.epss[i] !== NO_EPSS) { withEpss++; if (D.epss[i] >= 100) hot++; }
      const y = 1999 + pubYear[i]; if (y < yMin) yMin = y; if (y > yMax) yMax = y;
    }
    scores.sort((a, b) => a - b);
    const median = scores.length ? (scores[Math.floor(scores.length / 2)] / 10).toFixed(1) : "—";
    const pct = (a, b) => (b ? `${((a / b) * 100).toFixed(1)} %` : "—");
    const list = (rows) => `<ol>${rows.map(([name, c]) => `<li><span>${escapeHtml(String(name))}</span><span>${fmt(c)}</span></li>`).join("")}</ol>`;
    selEl.innerHTML = `<div class="sel-head"><b><span>${fmt(selCount)}</span> selected</b><button type="button" class="sel-close" id="f-sel-clear">clear</button></div>`
      + `<dl><dt>of shown</dt><dd>${pct(selCount, shownCount)} of ${fmt(shownCount)}</dd>`
      + `<dt>published</dt><dd>${yMin === yMax ? yMin : `${yMin}–${yMax}`}</dd>`
      + `<dt>in KEV</dt><dd>${fmt(selKev)} · ${pct(selKev, selCount)}${ransom ? ` · ${fmt(ransom)} ransomware` : ""}</dd>`
      + `<dt>public PoC</dt><dd>${fmt(poc)} · ${pct(poc, selCount)}</dd>`
      + `<dt>scored</dt><dd>${fmt(scored)} · median ${median} · Critical ${pct(crit, scored)}</dd>`
      + `<dt>EPSS ≥ 1%</dt><dd>${fmt(hot)} · ${pct(hot, withEpss)} of ${fmt(withEpss)} scored by EPSS</dd></dl>`
      + `<h4>Assigners</h4>${list(topN((i) => D.cna[i], (k) => CNAS[k]))}`
      + `<h4>Weaknesses</h4>${list(topN((i) => D.cwe[i], (k) => cweName(k)))}`
      + `<h4>Vendors</h4>${list(topN((i) => D.vendor[i], (k) => VENDORS[k]))}`
      + `<p class="sel-note">Counts are exact over the ${fmt(selCount)} records inside the box in this view. Re-arranging or filtering clears the selection.</p>`;
    selEl.hidden = false;
    $("f-sel-clear").addEventListener("click", () => clearSelection());
  }
  function updateCounters() {
    const live = selCount > 0;
    $("f-count-k").textContent = live ? "selected" : "shown";
    $("f-count").textContent = fmt(live ? selCount : shownCount);
    $("f-kev").textContent = fmt(live ? selKev : shownKev);
    const n = live ? selCount : shownCount, k = live ? selKev : shownKev;
    $("f-share").textContent = n ? `${((k / n) * 100).toFixed(2)} %` : "—";
  }
  function setSelectMode(on) {
    state.select = on;
    $("f-select").setAttribute("aria-pressed", String(on));
    canvas.classList.toggle("selecting", on);
    if (!on && rect) { rect = null; rectEl.hidden = true; }
  }
  $("f-select").addEventListener("click", () => setSelectMode(!state.select));
  addEventListener("keydown", (e) => {
    if (e.target && /^(INPUT|SELECT|TEXTAREA)$/.test(e.target.tagName)) return;
    if (e.key === "Escape") { if (selCount) clearSelection(); else setSelectMode(false); }
    if (e.key === "s" || e.key === "S") setSelectMode(!state.select);
  });

  canvas.addEventListener("pointerdown", (e) => {
    if (state.select && e.button === 0 && !e.shiftKey) {
      const [x, y] = canvasXY(e); rect = { x0: x, y0: y, x1: x, y1: y }; drawRect();
      canvas.setPointerCapture(e.pointerId); tip.style.opacity = 0; return;
    }
    drag = { x: e.clientX, y: e.clientY, b: e.button, shift: e.shiftKey, moved: false }; canvas.setPointerCapture(e.pointerId); canvas.style.cursor = "grabbing";
  });
  canvas.addEventListener("pointerup", (e) => {
    if (rect) { const r = rect; rect = null; rectEl.hidden = true; captureRect(r); return; }
    if (drag && !drag.moved) click(e); drag = null; canvas.style.cursor = state.select ? "crosshair" : "grab";
  });
  canvas.addEventListener("pointermove", (e) => {
    if (rect) { [rect.x1, rect.y1] = canvasXY(e); drawRect(); return; }
    if (drag) {
      const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
      if (Math.abs(dx) + Math.abs(dy) > 2) drag.moved = true;
      drag.x = e.clientX; drag.y = e.clientY;
      if (drag.b === 2 || drag.shift) {
        const k = cam.r * 0.0016;
        cam.tx -= dx * Math.cos(cam.theta) * k; cam.tz += dx * Math.sin(cam.theta) * k; cam.ty += dy * k;
      } else {
        cam.theta -= dx * 0.006; cam.phi = Math.max(0.12, Math.min(1.52, cam.phi - dy * 0.006));
      }
      tip.style.opacity = 0;
    } else hover(e);
  }, { passive: true });
  canvas.addEventListener("wheel", (e) => { e.preventDefault(); cam.r = Math.max(30, Math.min(1600, cam.r * (1 + e.deltaY * 0.0012))); }, { passive: false });
  canvas.addEventListener("contextmenu", (e) => e.preventDefault());
  canvas.addEventListener("pointerleave", () => { tip.style.opacity = 0; });

  const ray = new THREE.Raycaster(); ray.params.Points.threshold = 1.6;
  const mouse = new THREE.Vector2();
  function pick(e) {
    const r = canvas.getBoundingClientRect();
    mouse.x = ((e.clientX - r.left) / r.width) * 2 - 1;
    mouse.y = -((e.clientY - r.top) / r.height) * 2 + 1;
    ray.setFromCamera(mouse, camera);
    const hits = ray.intersectObject(points);
    for (const h of hits) if (shown[h.index] && pos[h.index * 3 + 1] > -500) return h.index;
    return -1;
  }
  const lagText = (lag) => (lag < 0 ? `${fmt(-lag)} d before publication` : lag === 0 ? "the day it published" : `${fmt(lag)} d after publication`);
  function recordHtml(i) {
    const sc = D.score[i] === NO_SCORE ? "no score in record" : `CVSS ${(D.score[i] / 10).toFixed(1)} (v${D.ver[i]})`;
    const ep = D.epss[i] === NO_EPSS ? "no EPSS" : `EPSS ${(D.epss[i] / 100).toFixed(2)}%`;
    return `<b>${cveId(i)}</b>`
      + `<span>published ${dstr(D.day[i])} · ${sc} · ${ep}</span>`
      + `<span>${escapeHtml(CNAS[D.cna[i]])} · ${escapeHtml(VENDORS[D.vendor[i]])} · ${escapeHtml(cweName(D.cwe[i]))}</span>`
      + `<span>NVD: ${escapeHtml(STATUS[NVD(i)])}${POC(i) && !D.pocday[i] ? " · public PoC (undated)" : ""}</span>`
      + (D.pocday[i] ? `<span>first public PoC ${dstr(D.pocday[i])} · ${lagText(pocLag(i))}</span>` : "")
      + (KEV(i) ? `<em>KEV since ${dstr(D.kevday[i])} · ${lagText(kevLag(i))}${RANSOM(i) ? " · known ransomware use" : ""}</em>` : "")
      + `<i>click to open the record on cve.org</i>`;
  }
  function hover(e) {
    const now = performance.now();
    if (now - hoverAt < 60 || animStart) return;
    hoverAt = now;
    const i = pick(e);
    if (i < 0) { tip.style.opacity = 0; return; }
    tip.innerHTML = recordHtml(i);
    const r = canvas.getBoundingClientRect();
    tip.style.left = `${Math.min(e.clientX - r.left + 14, r.width - 330)}px`;
    tip.style.top = `${Math.min(e.clientY - r.top + 14, r.height - 140)}px`;
    tip.style.opacity = 1;
  }
  function click(e) {
    const i = pick(e);
    if (i >= 0) window.open(`https://www.cve.org/CVERecord?id=${encodeURIComponent(cveId(i))}`, "_blank", "noopener");
  }

  // ---- render loop ----------------------------------------------------------
  const v = new THREE.Vector3();
  function frame() {
    requestAnimationFrame(frame);
    if (animStart) {
      const t = REDUCE ? 1 : Math.min(1, (performance.now() - animStart) / 750);
      const e = 1 - Math.pow(1 - t, 3);
      for (let i = 0; i < N * 3; i++) pos[i] = fromPos[i] + (target[i] - fromPos[i]) * e;
      geo.attributes.position.needsUpdate = true;
      // three caches the bounding sphere on first raycast; recompute once the
      // points have settled or every later hover misses the broad-phase test.
      if (t >= 1) { animStart = 0; geo.computeBoundingSphere(); }
    }
    camera.position.set(
      cam.tx + cam.r * Math.sin(cam.phi) * Math.sin(cam.theta),
      cam.ty + cam.r * Math.cos(cam.phi),
      cam.tz + cam.r * Math.sin(cam.phi) * Math.cos(cam.theta));
    camera.lookAt(cam.tx, cam.ty, cam.tz);
    renderer.render(scene, camera);
    const w = canvas.clientWidth, h = canvas.clientHeight;
    for (const l of labels) {
      v.copy(l.p).project(camera);
      const on = v.z < 1 && Math.abs(v.x) < 1.1 && Math.abs(v.y) < 1.1;
      l.el.style.display = on ? "block" : "none";
      if (on) { l.el.style.left = `${(v.x * 0.5 + 0.5) * w}px`; l.el.style.top = `${(-v.y * 0.5 + 0.5) * h}px`; }
    }
  }

  function refresh() {
    applyFilter();
    // positions are about to move: a box drawn on the old view means nothing
    if (selCount) { selected.fill(0); selCount = 0; selKev = 0; selEl.hidden = true; }
    layout(); colour();
    updateCounters();
    if (focusIdx >= 0 && shown[focusIdx]) {
      // fly the camera to the focused record and pin its card top-right
      cam.tx = target[focusIdx * 3]; cam.ty = target[focusIdx * 3 + 1]; cam.tz = target[focusIdx * 3 + 2];
      cam.r = Math.min(cam.r, 140);
      tip.innerHTML = recordHtml(focusIdx);
      tip.style.left = `${Math.max(12, canvas.clientWidth - 336)}px`; tip.style.top = "12px"; tip.style.opacity = 1;
    }
    writeHash();
  }

  // ---- shareable state ------------------------------------------------------
  // The hash carries the view so any arrangement is a link: #a=clock&c=lat&y=2020-2026&s=7&k=1&cve=CVE-2024-3400
  let focusIdx = -1;
  function writeHash() {
    const h = new URLSearchParams();
    if (state.layout !== "time") h.set("a", state.layout);
    if (state.color !== "expl") h.set("c", state.color);
    if (state.from !== 1999 || state.to !== MAX_YEAR) h.set("y", `${state.from}-${state.to}`);
    if (state.minScore) h.set("s", String(state.minScore));
    if (state.kevOnly) h.set("k", "1");
    if (state.pocOnly) h.set("p", "1");
    if (state.ransomOnly) h.set("r", "1");
    if (state.cnaQ.trim()) h.set("q", state.cnaQ.trim());
    if (state.vendorQ.trim()) h.set("v", state.vendorQ.trim());
    if (state.sort !== "count") h.set("o", state.sort);
    if (state.size !== 1) h.set("z", String(state.size));
    if (focusIdx >= 0) h.set("cve", cveId(focusIdx));
    const s = h.toString();
    history.replaceState(null, "", s ? `#${s}` : location.pathname + location.search);
  }
  function findCve(id) {
    const m = String(id).trim().match(/^CVE-(\d{4})-(\d{4,})$/i);
    if (!m) return -1;
    const y = +m[1], q = +m[2];
    for (let i = 0; i < N; i++) if (D.year[i] === y && D.seq[i] === q) return i;
    return -1;
  }
  function readHash() {
    const h = new URLSearchParams(location.hash.slice(1));
    const qs = new URLSearchParams(location.search);
    if (ARRANGE[h.get("a")]) state.layout = h.get("a");
    if (LEGEND[h.get("c")] !== undefined) state.color = h.get("c");
    const y = (h.get("y") || "").match(/^(\d{4})-(\d{4})$/);
    if (y) { state.from = Math.max(1999, Math.min(MAX_YEAR, +y[1])); state.to = Math.max(state.from, Math.min(MAX_YEAR, +y[2])); }
    if (h.get("s")) state.minScore = Math.max(0, Math.min(10, +h.get("s") || 0));
    state.kevOnly = h.get("k") === "1"; state.pocOnly = h.get("p") === "1"; state.ransomOnly = h.get("r") === "1";
    state.cnaQ = h.get("q") || ""; state.vendorQ = h.get("v") || "";
    if (["count", "kev", "name"].includes(h.get("o"))) state.sort = h.get("o");
    if (h.get("z")) state.size = Math.max(0.5, Math.min(2.5, +h.get("z") || 1));
    focusIdx = findCve(h.get("cve") || qs.get("cve") || "");
    // reflect in the controls
    document.querySelectorAll("[data-layout]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.layout === state.layout));
    document.querySelectorAll("[data-color]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.color === state.color));
    $("f-from").value = state.from; $("f-to").value = state.to;
    $("f-min").value = state.minScore; $("f-minv").textContent = state.minScore ? `≥ ${state.minScore.toFixed(1)}` : "any";
    $("f-kevonly").checked = state.kevOnly; $("f-poconly").checked = state.pocOnly; $("f-ransom").checked = state.ransomOnly;
    $("f-cna").value = state.cnaQ; $("f-vendor").value = state.vendorQ; $("f-sort").value = state.sort; $("f-size").value = state.size;
  }

  // ---- controls -------------------------------------------------------------
  const CAMS = {
    time: { theta: 0.55, phi: 0.98, r: 600, tx: 60, ty: 6, tz: 0 }, grid: { theta: 0.2, phi: 0.95, r: 360, tx: 0, ty: 8, tz: 0 },
    cna: { theta: 0.15, phi: 0.72, r: 480, tx: 0, ty: 8, tz: 0 }, cwe: { theta: 0.15, phi: 0.72, r: 440, tx: 0, ty: 8, tz: 0 },
    status: { theta: 0.15, phi: 0.72, r: 420, tx: 0, ty: 8, tz: 0 }, vendor: { theta: 0.15, phi: 0.72, r: 480, tx: 0, ty: 8, tz: 0 },
    clock: { theta: 0.3, phi: 1.0, r: 560, tx: 0, ty: 6, tz: 0 },
  };
  function resetCamera() { Object.assign(cam, CAMS[state.layout]); }

  const fromEl = $("f-from"), toEl = $("f-to");
  fromEl.max = toEl.max = MAX_YEAR; toEl.value = MAX_YEAR;
  const showYears = () => { $("f-years").textContent = state.from === state.to ? String(state.from) : `${state.from}–${state.to}`; };
  const onYears = () => {
    let a = +fromEl.value, b = +toEl.value;
    if (a > b) [a, b] = [b, a];
    state.from = a; state.to = b; showYears(); stopPlay(); refresh();
  };
  fromEl.addEventListener("input", onYears); toEl.addEventListener("input", onYears); showYears();

  let playTimer = null;
  function stopPlay() {
    if (!state.playing) return;
    state.playing = false; clearInterval(playTimer); $("f-play").textContent = "▶ Play the years";
  }
  $("f-play").addEventListener("click", () => {
    if (state.playing) { stopPlay(); refresh(); return; }
    state.playing = true; state.playFrom = state.from; state.to = state.from;
    toEl.value = state.to; showYears(); $("f-play").textContent = "■ Stop";
    refresh();
    playTimer = setInterval(() => {
      if (state.to >= MAX_YEAR) { stopPlay(); refresh(); return; }
      state.to++; toEl.value = state.to; showYears(); refresh();
    }, REDUCE ? 1200 : 700);
  });

  $("f-min").addEventListener("input", (e) => { state.minScore = +e.target.value; $("f-minv").textContent = state.minScore ? `≥ ${state.minScore.toFixed(1)}` : "any"; refresh(); });
  $("f-kevonly").addEventListener("change", (e) => { state.kevOnly = e.target.checked; refresh(); });
  $("f-poconly").addEventListener("change", (e) => { state.pocOnly = e.target.checked; refresh(); });
  $("f-ransom").addEventListener("change", (e) => { state.ransomOnly = e.target.checked; refresh(); });
  let qt = null;
  $("f-cna").addEventListener("input", (e) => { clearTimeout(qt); qt = setTimeout(() => { state.cnaQ = e.target.value; refresh(); }, 250); });
  $("f-vendor").addEventListener("input", (e) => { clearTimeout(qt); qt = setTimeout(() => { state.vendorQ = e.target.value; refresh(); }, 250); });
  $("f-sort").addEventListener("change", (e) => { state.sort = e.target.value; refresh(); });
  $("f-size").addEventListener("input", (e) => { state.size = +e.target.value; colour(); });
  $("f-reset").addEventListener("click", resetCamera);
  document.querySelectorAll("[data-layout]").forEach((b) => b.addEventListener("click", () => {
    state.layout = b.dataset.layout;
    document.querySelectorAll("[data-layout]").forEach((x) => x.setAttribute("aria-pressed", x === b));
    resetCamera(); refresh();
  }));
  document.querySelectorAll("[data-color]").forEach((b) => b.addEventListener("click", () => {
    state.color = b.dataset.color;
    document.querySelectorAll("[data-color]").forEach((x) => x.setAttribute("aria-pressed", x === b));
    colour(); writeHash();
  }));
  // a click anywhere on the canvas releases a pinned focus
  canvas.addEventListener("pointerdown", () => { if (focusIdx >= 0) { focusIdx = -1; colour(); writeHash(); } });

  // ---- sources --------------------------------------------------------------
  const s = meta.sources || {};
  const skipped = meta.skipped || {};
  const str = (x) => escapeHtml(x == null ? "?" : String(x));
  $("f-sources").innerHTML =
    `${fmt(meta.n)} published CVEs placed · ${fmt(skipped.rejected || 0)} rejected and ${fmt(skipped.undated || 0)} undated records left out · `
    + `${fmt(meta.counts.scored)} carry a score in the record · ${fmt(meta.counts.epss)} have an EPSS score · ${fmt(meta.counts.poc_dated || 0)} have a dated public PoC.<br>`
    + `cvelistV5 ${str(s.cvelist?.release)} · CISA KEV ${str(s.kev?.catalog_version)} (${fmt(s.kev?.count || 0)} entries) · `
    + `EPSS ${str(s.epss?.model_version)} of ${str(s.epss?.score_date)} · `
    + `NVD statuses ${s.nvd?.fetched_at ? `fetched ${str(s.nvd.fetched_at)}` : "not fetched"} · `
    + `PoC corpora: ${fmt(s.poc?.cve_count || 0)} CVEs referenced.<br>`
    + `Built ${str(meta.generated_at)} by <a href="https://github.com/Devko/CyberMon/blob/main/pipeline/field_export.py">pipeline/field_export.py</a>. `
    + `The charted version of this corpus is <a href="cve.html">the CVE Ecosystem page</a>.`;

  // ---- go -------------------------------------------------------------------
  pos.fill(0); for (let i = 0; i < N; i++) pos[i * 3 + 1] = -999;
  readHash(); showYears(); resetCamera(); refresh();
  notice.hidden = true;
  requestAnimationFrame(frame);
}

async function boot() {
  if (typeof THREE === "undefined") {
    showNotice("The 3D library did not load", `<p>three.js could not be fetched from the CDN, so the field cannot be drawn. The same corpus is charted on <a href="cve.html">cve.html</a>.</p>`);
    return;
  }
  try {
    const loaded = await loadField();
    main(loaded);
  } catch (err) {
    const missing = /HTTP 404/.test(String(err.message));
    showNotice(
      missing ? "The Field has not been built here" : "The Field could not be loaded",
      missing
        ? `<p>The per-CVE record stream is a nightly build product, not a committed file. Build it with</p><p><code>python -m pipeline --out site/data --field-out site/field</code></p><p>and reload. The charted version of the corpus is on <a href="cve.html">cve.html</a>.</p>`
        : `<p>${escapeHtml(err.message)}</p><p>The charted version of the corpus is on <a href="cve.html">cve.html</a>.</p>`);
  }
}

boot();
