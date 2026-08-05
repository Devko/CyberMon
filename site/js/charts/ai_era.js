// Shared era selection for the AI Alibi charts.
//
// ai.html gives the reader a live selector: the hero owns it, the
// inflection board re-renders from it. The carousel generator calls the
// same renderers with `render(slots, data)` and no store at all — a
// printed slide has no controls to drive one.
//
// Rather than teach two charts to branch on that, both take an OPTIONAL
// store and fall back to `makeEraStore(data)`, which is inert: it reports
// the default era and ignores writes. One code path, two hosts.
export function makeEraStore(data, { live = false } = {}) {
  const eras = data.eras || [];
  const fallback = eras.find((e) => e.default) || eras[0] || null;
  let current = fallback ? fallback.id : null;
  const subscribers = [];
  return {
    eras,
    live,
    get id() { return current; },
    get era() { return eras.find((e) => e.id === current) || null; },
    subscribe(fn) { if (live) subscribers.push(fn); },
    set(id) {
      if (!live || id === current || !eras.some((e) => e.id === id)) return;
      current = id;
      // One bad subscriber must not strand the others mid-update.
      for (const fn of subscribers) {
        try { fn(id); } catch (err) { console.warn("[CyberMon] era subscriber failed:", err); }
      }
    },
  };
}
