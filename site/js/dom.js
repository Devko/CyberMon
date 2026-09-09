// =============================================================================
// dom.js — tiny safe-DOM builders. All user-visible text is inserted via
// textContent (never markup), so editorial strings and pipeline data can't
// inject HTML.
// =============================================================================

export function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

export function frag(...children) {
  const f = document.createDocumentFragment();
  for (const c of children) if (c) f.append(c);
  return f;
}

// External links open a new tab (noopener). In-page anchors ("#footer") stay
// in-page so the smooth-scroll in shared.css applies; pass { sameTab: true }
// to force that for any href.
export function link(href, text, className, { sameTab = false } = {}) {
  const a = el("a", className, text);
  a.href = href;
  if (!sameTab && !String(href).startsWith("#")) {
    a.target = "_blank";
    a.rel = "noopener";
  }
  return a;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

// Every CVE id in a string becomes a link into the Field instrument, opened
// on that record (field.html#cve=…), the rest stays text. Same tab: it is
// the same site, and the Field's own link carries the reader back.
const CVE_ID = /CVE-\d{4}-\d{4,}/g;
export function withCveLinks(text, className = "cve-link") {
  const out = document.createDocumentFragment();
  const s = String(text);
  let last = 0;
  for (const m of s.matchAll(CVE_ID)) {
    if (m.index > last) out.append(s.slice(last, m.index));
    const a = link(`field.html#cve=${encodeURIComponent(m[0])}`, m[0], className, { sameTab: true });
    a.title = "Open this record in the Field";
    out.append(a);
    last = m.index + m[0].length;
  }
  if (last < s.length) out.append(s.slice(last));
  return out;
}
