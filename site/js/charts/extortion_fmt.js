// Shared USD formatting for the three Extortion Ledger charts. All amounts
// in extortion_ledger.json are whole dollars at historical (day-of-transfer)
// rates — see docs/data-contracts.md.
import { fmtInt } from "../theme.js";

// "$139,502,184" — exact, for tooltips and table cells.
export const fmtUSD = (n) => `$${fmtInt(Math.round(n))}`;

// "$1.02B" / "$139.5M" / "$47k" / "$800" — compact, for axes and hero stats.
export function fmtUSDCompact(n) {
  const abs = Math.abs(n);
  if (abs >= 1e9) return `$${(n / 1e9).toFixed(2)}B`;
  if (abs >= 1e6) return `$${(n / 1e6).toFixed(1)}M`;
  if (abs >= 1e3) return `$${(n / 1e3).toFixed(0)}k`;
  return `$${fmtInt(Math.round(n))}`;
}

// "2020Q3" (+ "*" when the quarter falls in the partial generation year).
export const fmtQuarter = (r, genYear) =>
  `${r.year}Q${r.quarter}${r.year === genYear ? "*" : ""}`;
