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
