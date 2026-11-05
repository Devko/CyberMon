// =============================================================================
// og.js — social preview card template (og.html). Not a reader page.
//
// tools/make_og_images.py loads og.html once, reads window.__ogPages (the
// pages editorial.js knows: the landing page, every module in editorial.nav
// and every instrument in editorial.home.instruments), then for each page id
// calls `await window.__ogRender(id)` and screenshots the 1200×630 card into
// og/<id>.png. The module list comes from editorial.nav, so a module added
// there gets a card with no change here.
//
// Card copy, per page:
//   index       — home.kicker over masthead.thesis;
//   module      — carousel.coverModule ("Module 20 — Botnet C2 Servers")
//                 over the module's home-card headline;
//   instrument  — og.instrumentLine over the instrument's card headline;
//   other page  — a page the generator found with an og:image but no
//                 editorial entry (an instrument that keeps its own copy):
//                 its own og:title, "CyberMon — <name>: <summary>".
// =============================================================================
import { editorial, tpl } from "./editorial.js";
import { el, clear } from "./dom.js";

const MAX_FONT = 66; // px, the headline's size before fitting (css/og.css)
const MIN_FONT = 36;

const instruments = () => editorial.home.instruments?.items ?? [];

function pageIds() {
  const ids = ["index"];
  for (const tab of editorial.nav) if (tab.id !== "home") ids.push(tab.id);
  for (const item of instruments()) ids.push(item.id);
  return [...new Set(ids)];
}

// "CyberMon — The Alias Graph: threat groups …" -> { line, headline }.
async function copyFromPage(id) {
  const res = await fetch(`${id}.html`, { cache: "no-cache" });
  if (!res.ok) throw new Error(`${id}.html: HTTP ${res.status}`);
  const doc = new DOMParser().parseFromString(await res.text(), "text/html");
  const title = (doc.querySelector('meta[property="og:title"]')?.content ?? doc.title ?? "")
    .replace(/^CyberMon\s*[—–-]\s*/, "").trim();
  const cut = title.indexOf(": ");
  if (cut < 0) {
    return { line: title, headline: doc.querySelector('meta[property="og:description"]')?.content ?? "" };
  }
  const rest = title.slice(cut + 2);
  return { line: title.slice(0, cut), headline: rest.charAt(0).toUpperCase() + rest.slice(1) };
}

async function copyFor(id) {
  if (id === "index") return { line: editorial.home.kicker, headline: editorial.masthead.thesis };
  const mod = editorial.home.modules.find((m) => m.id === id);
  if (mod) {
    return {
      line: tpl(editorial.carousel.coverModule, { num: mod.num, label: mod.label }),
      headline: mod.headline,
    };
  }
  const item = instruments().find((m) => m.id === id);
  if (item) return { line: tpl(editorial.og.instrumentLine, { label: item.label }), headline: item.headline };
  return copyFromPage(id);
}

function wordmark() {
  const p = el("p", "og-wordmark");
  p.append("CYBER", el("span", "accent", "MON"));
  return p;
}

// Draw one card; resolve to the list of problems (empty = clean).
async function render(id) {
  const problems = [];
  const card = clear(document.getElementById("card"));
  let copy;
  try {
    copy = await copyFor(id);
  } catch (err) {
    return [`${id}: ${err?.message ?? err}`];
  }
  if (!copy.line || !copy.headline) problems.push(`${id}: no copy for the card`);

  const line = el("p", "og-line", copy.line);
  const box = el("div", "og-headline-box");
  const headline = el("h1", "og-headline", copy.headline);
  box.append(headline);
  const foot = el("p", "og-foot");
  foot.append(el("span", null, editorial.carousel.siteUrl), el("span", null, editorial.masthead.kicker));
  card.append(wordmark(), line, box, foot);

  await document.fonts.ready;
  const pad = getComputedStyle(box);
  const room = box.clientHeight - parseFloat(pad.paddingTop) - parseFloat(pad.paddingBottom);
  let size = MAX_FONT;
  headline.style.fontSize = `${size}px`;
  while (size > MIN_FONT && headline.offsetHeight > room) {
    size -= 2;
    headline.style.fontSize = `${size}px`;
  }
  if (headline.offsetHeight > room) problems.push(`${id}: headline does not fit at ${size}px`);
  for (const p of [line, foot]) {
    if (/\{\w+\}|undefined|NaN|null/.test(p.textContent)) problems.push(`${id}: bad text "${p.textContent}"`);
  }
  if (/\{\w+\}|undefined|NaN/.test(headline.textContent)) problems.push(`${id}: bad headline`);
  return problems;
}

window.__ogPages = pageIds();
window.__ogRender = render;
window.__ogReady = true;
