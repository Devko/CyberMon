"""Extortion Ledger metrics (extortion_ledger.json).

Confirmed ransomware revenue from the Ransomwhere export — crowdsourced,
verified, on-chain. Everything here is a FLOOR: a payment enters the
dataset only after someone reported the address and the transfers were
verified, so the honest claim is always "at least this much", never "the
market is this big".

Definitions the site relies on:

* **USD basis** — ``amountUSD`` is upstream's conversion at the HISTORICAL
  rate of the transaction date (verified: the implied BTC/USD rate per
  transaction year tracks the price history). Sums are dollars-of-the-day.
* **Revenue** — the sum of transaction ``amountUSD`` as published. The
  export lists a transaction once per receiving tracked address, so a
  transfer that fans out across several tracked addresses contributes each
  received output; exact repeats of (address, hash, amount) — either
  duplicate outputs in one transaction or upstream double entries, not
  distinguishable without chain data — carry ~1% of total USD and are
  summed as published rather than second-guessed.
* **Payment** — one distinct on-chain transaction (unique ``hash``), its
  USD value the sum of its outputs to tracked addresses. 21.8k ledger
  entries collapse to 18.9k payments on live data. Payment counts and the
  median payment size use this collapsed view; a year's median plots only
  with at least ``min_n`` payments (a median of three is an anecdote).
* **Family** — Ransomwhere's own label, taken as-is as a neutral
  identifier. The literal ``"Unlabeled"`` bucket (verified payments nobody
  attributed — the single largest slice) is never ranked as a family: it
  is reported separately as ``families.unattributed``. The board ranks
  the top ``top_k`` labeled families by all-time confirmed USD; the rest
  pool into ``families.other``. A ranked board is emitted instead of a
  yearly-share series on purpose: family coverage is episodic (a
  campaign's wallets may be reported years after the fact), so per-year
  shares would chart reporting artifacts, not market share.

No pace projection, ever, despite yearly payment counts being a flow:
crowdsourced reports arrive with a lag, so the partial current year
structurally undercounts and the uniform-flow assumption behind the pace
math (docs/data-contracts.md, "Pace projections") does not hold.

Quarters between the first and last observed payment are gap-filled with
zero so the revenue axis never silently skips time (concentration-years
pattern); trailing empty quarters after the last payment are not invented.
"""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone

from .fetch_ransomwhere import UNATTRIBUTED_LABEL, RansomwhereData

DEFAULT_MIN_N = 10
DEFAULT_TOP_K = 8


def _quarter(ts: int) -> tuple[int, int]:
    d = datetime.fromtimestamp(ts, tz=timezone.utc)
    return d.year, (d.month - 1) // 3 + 1


def _next_quarter(year: int, quarter: int) -> tuple[int, int]:
    return (year + 1, 1) if quarter == 4 else (year, quarter + 1)


def build_extortion_ledger(data: RansomwhereData, generated_at: str, *,
                           min_n: int = DEFAULT_MIN_N,
                           top_k: int = DEFAULT_TOP_K) -> dict:
    """Assemble the extortion_ledger.json object."""
    usd_by_quarter: Counter[tuple[int, int]] = Counter()
    payments: dict[str, list] = {}  # hash -> [usd_sum, time]
    fam_usd: defaultdict[str, float] = defaultdict(float)
    fam_hashes: defaultdict[str, set[str]] = defaultdict(set)
    fam_years: dict[str, tuple[int, int]] = {}
    entry_count = 0
    total_usd = 0.0

    for rec in data.records:
        for tx in rec.transactions:
            entry_count += 1
            total_usd += tx.amount_usd
            year, quarter = _quarter(tx.time)
            usd_by_quarter[(year, quarter)] += tx.amount_usd
            p = payments.setdefault(tx.hash, [0.0, tx.time])
            p[0] += tx.amount_usd
            fam = rec.family
            fam_usd[fam] += tx.amount_usd
            fam_hashes[fam].add(tx.hash)
            lo, hi = fam_years.get(fam, (year, year))
            fam_years[fam] = (min(lo, year), max(hi, year))

    if not payments:
        raise ValueError("extortion_ledger: export carries no transactions; "
                         "refusing to emit an empty ledger")

    # ---- hero: confirmed USD per quarter, gap-filled ----------------------
    first_q = min(usd_by_quarter)
    last_q = max(usd_by_quarter)
    revenue_by_quarter = []
    q = first_q
    while True:
        revenue_by_quarter.append({"year": q[0], "quarter": q[1],
                                   "usd": round(usd_by_quarter.get(q, 0.0))})
        if q == last_q:
            break
        q = _next_quarter(*q)

    # ---- payments per year + median payment size --------------------------
    usd_by_payment_year: defaultdict[int, list[float]] = defaultdict(list)
    for usd, ts in payments.values():
        usd_by_payment_year[_quarter(ts)[0]].append(usd)
    payments_by_year = []
    for year in sorted(usd_by_payment_year):
        values = usd_by_payment_year[year]
        row = {"year": year, "payments": len(values),
               "usd": round(sum(values))}
        if len(values) >= min_n:
            # 2 decimals (documented contract exception to the 1-decimal
            # rule): early mass-campaign years have sub-dollar medians —
            # 2013's true median is $0.03, which 1-decimal rounding would
            # crush to a false (and log-axis-breaking) zero.
            row["median_usd"] = round(statistics.median(values), 2)
        payments_by_year.append(row)

    # ---- family concentration board ---------------------------------------
    def _fam_row(fam: str) -> dict:
        lo, hi = fam_years[fam]
        return {"family": fam, "usd": round(fam_usd[fam]),
                "payments": len(fam_hashes[fam]),
                "first_year": lo, "last_year": hi}

    labeled = sorted((f for f in fam_usd if f != UNATTRIBUTED_LABEL),
                     key=lambda f: (-fam_usd[f], f))
    top = [_fam_row(f) for f in labeled[:top_k]]
    rest = labeled[top_k:]
    unattributed_hashes = fam_hashes.get(UNATTRIBUTED_LABEL, set())
    families = {
        "top": top,
        "other": {"families": len(rest),
                  "usd": round(sum(fam_usd[f] for f in rest)),
                  "payments": len(set().union(*(fam_hashes[f] for f in rest))
                                  if rest else set())},
        "unattributed": {"usd": round(fam_usd.get(UNATTRIBUTED_LABEL, 0.0)),
                         "payments": len(unattributed_hashes)},
    }

    peak = max(revenue_by_quarter, key=lambda r: r["usd"])
    return {
        "generated_at": generated_at,
        "min_n": min_n,
        "revenue_by_quarter": revenue_by_quarter,
        "payments_by_year": payments_by_year,
        "families": families,
        "catalog": {
            "addresses": data.address_count,
            "families": len(labeled),
            "transactions": entry_count,
            "payments": len(payments),
            "total_usd": round(total_usd),
        },
        "headline": {
            "total_usd": round(total_usd),
            "peak_quarter": {"year": peak["year"], "quarter": peak["quarter"],
                             "usd": peak["usd"]},
            "first_year": payments_by_year[0]["year"],
            "last_year": payments_by_year[-1]["year"],
        },
    }
