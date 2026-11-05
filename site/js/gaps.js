// =============================================================================
// gaps.js — missed nights as gaps, for every chart drawn from a nightly record.
//
// CyberMon's histories have one row per night the pipeline ran. A night it
// missed has no row, and a category axis built from the rows alone would
// close up around it: two readings days apart would sit side by side and a
// line would join them. Charts build their axis from calendar() instead:
// one slot per date (or ISO week) from the first row to the last, null where
// the record has no row. A null draws no bar and breaks the line.
//
// Used by the C2, CNA roster, EPSS Volatility and NVD backlog/throughput
// charts, and by the Observatory stream.
// =============================================================================
import { C, escapeHtml } from "./theme.js";
import { editorial } from "./editorial.js";

const DAY_MS = 86400000;
const isoDay = (ms) => new Date(ms).toISOString().slice(0, 10);
const dayMs = (iso) => Date.parse(`${iso}T00:00:00Z`);

// Every ISO date from `first` to `last`, both included.
export function daysBetween(first, last) {
  const out = [];
  if (!first || !last) return out;
  const end = dayMs(last);
  for (let t = dayMs(first); t <= end; t += DAY_MS) out.push(isoDay(t));
  return out;
}

// "2026-W29" <-> the Monday that starts it.
function weekMonday(label) {
  const [, y, w] = /^(\d{4})-W(\d{2})$/.exec(label) ?? [];
  if (!y) return NaN;
  const jan4 = Date.UTC(+y, 0, 4); // ISO week 1 holds 4 January
  const monday1 = jan4 - (((new Date(jan4).getUTCDay() + 6) % 7) * DAY_MS);
  return monday1 + (+w - 1) * 7 * DAY_MS;
}
function weekLabel(ms) {
  const d = new Date(ms);
  d.setUTCDate(d.getUTCDate() + 3 - ((d.getUTCDay() + 6) % 7)); // its Thursday decides the year
  const year = d.getUTCFullYear();
  const week = 1 + Math.floor((d - weekMonday(`${year}-W01`)) / (7 * DAY_MS));
  return `${year}-W${String(week).padStart(2, "0")}`;
}

// The record laid on its calendar.
//   rows: the record, oldest first (order is not assumed; slots are sorted).
//   key:  the row's date ("2026-08-02") or, with unit "week", its ISO week
//         ("2026-W31").
// Returns { slots, rows }: `slots` the axis labels, `rows[i]` the record's
// row for slots[i] or null when the record has none.
export function calendar(rows, { key = (r) => r.date, unit = "day" } = {}) {
  const byKey = new Map(rows.map((r) => [key(r), r]));
  if (!byKey.size) return { slots: [], rows: [] };
  const keys = [...byKey.keys()].sort();
  let slots;
  if (unit === "week") {
    slots = [];
    const end = weekMonday(keys[keys.length - 1]);
    for (let t = weekMonday(keys[0]); t <= end; t += 7 * DAY_MS) slots.push(weekLabel(t));
  } else {
    slots = daysBetween(keys[0], keys[keys.length - 1]);
  }
  return { slots, rows: slots.map((s) => byKey.get(s) ?? null) };
}

// Series data from a calendar: value(row) on a reading, null on a gap.
export const gapData = (cal, value) => cal.rows.map((r) => (r ? value(r) : null));

// A reading with a gap on both sides has no line segment to draw; a chart
// that hides its symbols uses this to show such a reading as a dot.
export function loneSymbol(cal, size) {
  return (value, params) => {
    const i = params?.dataIndex ?? -1;
    const alone = cal.rows[i] && !cal.rows[i - 1] && !cal.rows[i + 1];
    return alone ? size : 0;
  };
}

// The slot of the last reading before slot i, or -1. A reading that follows
// a gap was compared with this one (a diff that spans the missed nights).
export function previousReading(cal, i) {
  for (let j = i - 1; j >= 0; j--) if (cal.rows[j]) return j;
  return -1;
}

// Tooltip for a gap slot: the date and why there is no reading.
export function gapTooltip(label, reason = editorial.ui.noReading) {
  return `<div style="color:${C.muted};">${escapeHtml(label)} · ${escapeHtml(reason)}</div>`;
}
