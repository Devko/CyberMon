"""AI Product CVEs metrics (ai_products.json, module 27).

CVEs in AI and machine-learning software, read from the shared corpus
pass: :class:`AiProductCollector` is handed to ``Aggregator.consume`` as an
observer (the AI Credits pattern), so there is no fetch and no second
pass. Each published record is classified by ``pipeline/ai_products.py``
from the vendor and product its CNA lists first; nothing reads
descriptions. Three views:

* **years** — AI-product CVEs per publication year, split into the
  classifier's four categories, beside the year's published total and how
  many of those records name a product at all (``named``: the ceiling on
  what any vendor/product classifier can see). The site computes shares.
* **cwe** — the first-listed CWE of the AI-product CVEs published in the
  window against every other CVE published in the same years. The
  baseline is **year-matched**: each year's share among the other CVEs,
  weighted by that year's share of the AI-product CVEs, so a CWE that
  became common corpus-wide in 2026 is not read as an AI trait just
  because most AI-product CVEs are from 2026. ``ai_specific`` counts the
  records citing, anywhere in their problem types (CNA or ADP), one of
  the CWE entries written for machine-learning and generative-AI
  weaknesses.
* **exploited** — the share on CISA KEV, with public exploit code
  (Exploit-DB or a Metasploit exploit module) and with a Nuclei detection
  template, against the same year-matched baseline. KEV listings and
  exploit code accumulate with age; matching years keeps the two
  populations equally old, by publication year at least.

Plus ``products`` (the board: every product key with a record in the
window) and ``cnas`` (who assigns AI-product CVEs in the window — a
handful of CNAs issue most of them, so the counts follow their programmes
as much as the products).

What this is NOT: a measure of AI-assisted attacks (module 21, AI and PoC
Timing) or of who found a bug (module 22, AI Credits). Every count is a
lower bound on CVEs in AI software: see the classifier's recall limits.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from . import ai_products
from .cwe_top25_data import cwe_name
from .metrics import CveFacts, _pct

# CWE window and exploitation window: the last WINDOW_YEARS publication
# years ending at the edition's year (the partial current year included,
# like the Record Tags board). Recent enough to describe the products in
# use now; the per-year baseline keeps the partial year from skewing it.
WINDOW_YEARS = 4
TOP_CWES = 10
TOP_CNAS = 5
BOARD_TOP = 15
# CWE entries written for ML / generative-AI weaknesses: CWE-1039
# (adversarial input perturbations, 2018), CWE-1426 (improper validation
# of generative AI output, 2024), CWE-1427 (improper neutralization of
# input used for LLM prompting — prompt injection, 2024).
AI_CWES = ("CWE-1039", "CWE-1426", "CWE-1427")
_AI_CWE_SET = frozenset(AI_CWES)
NO_CWE = "none"
RATES = ("kev", "poc", "nuclei")


def _cwe_ids(record: dict) -> set[str]:
    """Every cweId in the record's problem types, CNA and ADP containers."""
    containers = record.get("containers") or {}
    blocks = [containers.get("cna")] + list(containers.get("adp") or [])
    out: set[str] = set()
    for block in blocks:
        if not isinstance(block, dict):
            continue
        for pt in block.get("problemTypes") or []:
            if not isinstance(pt, dict):
                continue
            for desc in pt.get("descriptions") or []:
                cwe = desc.get("cweId") if isinstance(desc, dict) else None
                if isinstance(cwe, str) and cwe.startswith("CWE-"):
                    out.add(cwe)
    return out


@dataclass
class AiRow:
    cve_id: str
    year: int
    key: str
    cwe: str              # first-listed CWE, NO_CWE when untagged
    ai_cwe: bool          # cites an AI_CWES entry anywhere
    kev: bool
    poc: bool
    nuclei: bool
    cna: str


@dataclass
class AiProductCollector:
    """Observer for ``Aggregator.consume``: one :class:`AiRow` per
    published AI-product CVE, plus per-year tallies over EVERY published
    record (the baseline: totals, named-product counts, first-listed CWEs
    and the three exploitation flags)."""

    kev_ids: Iterable[str] = ()
    poc_ids: Iterable[str] = ()
    nuclei_ids: Iterable[str] = ()
    rows: list[AiRow] = field(default_factory=list)
    published: Counter = field(default_factory=Counter)
    named: Counter = field(default_factory=Counter)
    cwes: dict = field(default_factory=lambda: defaultdict(Counter))
    flags: dict = field(default_factory=lambda: defaultdict(Counter))

    def __post_init__(self) -> None:
        self.kev_ids = frozenset(self.kev_ids)
        self.poc_ids = frozenset(self.poc_ids)
        self.nuclei_ids = frozenset(self.nuclei_ids)

    def __call__(self, facts: CveFacts, record: dict) -> None:
        if facts.state != "PUBLISHED" or not facts.date_published:
            return
        year = facts.year
        self.published[year] += 1
        cwe = facts.cwe or NO_CWE
        self.cwes[year][cwe] += 1
        kev = facts.cve_id in self.kev_ids
        poc = facts.cve_id in self.poc_ids
        nuclei = facts.cve_id in self.nuclei_ids
        flags = self.flags[year]
        flags["kev"] += kev
        flags["poc"] += poc
        flags["nuclei"] += nuclei
        key, named = ai_products.classify_record(record)
        self.named[year] += named
        if key is None:
            return
        self.rows.append(AiRow(
            cve_id=facts.cve_id, year=year, key=key, cwe=cwe,
            ai_cwe=bool(_cwe_ids(record) & _AI_CWE_SET),
            kev=kev, poc=poc, nuclei=nuclei, cna=facts.cna))


def _weights(rows: list[AiRow]) -> dict[int, float]:
    """Each year's share of the AI-product rows (the baseline weights)."""
    n = len(rows)
    by_year = Counter(r.year for r in rows)
    return {y: c / n for y, c in by_year.items()} if n else {}


def _baseline_rate(weights: dict[int, float], part: dict[int, int],
                   whole: dict[int, int]) -> float:
    """Year-matched baseline rate (0..1): sum over years of
    weight x (part / whole) among the other CVEs of that year."""
    total = 0.0
    for year, w in weights.items():
        if whole.get(year):
            total += w * part.get(year, 0) / whole[year]
    return total


def _baseline_pct(weights: dict[int, float], part: dict[int, int],
                  whole: dict[int, int]) -> float:
    return round(100.0 * _baseline_rate(weights, part, whole), 1)


def _others(collector: AiProductCollector, rows: list[AiRow],
            years: Iterable[int]) -> tuple[dict, dict, dict]:
    """Per-year (published, cwe counters, flag counters) for the records
    that are NOT AI-product CVEs."""
    ai_n = Counter(r.year for r in rows)
    ai_cwe: dict[int, Counter] = defaultdict(Counter)
    ai_flags: dict[int, Counter] = defaultdict(Counter)
    for r in rows:
        ai_cwe[r.year][r.cwe] += 1
        for k in RATES:
            ai_flags[r.year][k] += getattr(r, k)
    published, cwes, flags = {}, {}, {}
    for y in years:
        published[y] = collector.published.get(y, 0) - ai_n.get(y, 0)
        c = Counter(collector.cwes.get(y) or {})
        c.subtract(ai_cwe.get(y) or {})
        cwes[y] = c
        f = Counter(collector.flags.get(y) or {})
        f.subtract(ai_flags.get(y) or {})
        flags[y] = f
    return published, cwes, flags


def _cwe_block(rows: list[AiRow], weights: dict[int, float],
               published: dict, cwes: dict) -> dict:
    n = len(rows)
    counts = Counter(r.cwe for r in rows)
    ranked = sorted(((c, k) for k, c in counts.items() if k != NO_CWE),
                    key=lambda ck: (-ck[0], ck[1]))
    top = []
    for c, cwe in ranked[:TOP_CWES]:
        top.append({
            "cwe": cwe, "name": cwe_name(cwe), "n": c, "pct": _pct(c, n),
            "baseline_pct": _baseline_pct(
                weights, {y: cwes[y][cwe] for y in cwes}, published),
        })
    return {
        "n": n,
        "no_cwe": counts.get(NO_CWE, 0),
        "no_cwe_pct": _pct(counts.get(NO_CWE, 0), n),
        "baseline_no_cwe_pct": _baseline_pct(
            weights, {y: cwes[y][NO_CWE] for y in cwes}, published),
        "top": top,
        "top_share_pct": _pct(sum(t["n"] for t in top), n),
        "ai_specific": {"ids": list(AI_CWES),
                        "n": sum(r.ai_cwe for r in rows)},
    }


def _exploited_block(rows: list[AiRow], weights: dict[int, float],
                     published: dict, flags: dict) -> dict:
    n = len(rows)
    out: dict = {"n": n, "baseline_n": sum(published.values())}
    for k in RATES:
        hit = sum(getattr(r, k) for r in rows)
        rate = _baseline_rate(weights, {y: flags[y][k] for y in flags},
                              published)
        out[k] = hit
        out[f"{k}_pct"] = _pct(hit, n)
        out[f"{k}_baseline_pct"] = round(100.0 * rate, 1)
        # The count the AI-product CVEs would have at the baseline rate:
        # KEV shares round to 0.3% on both sides, the counts do not.
        out[f"{k}_expected"] = round(n * rate, 1)
    out["kev_cves"] = [
        {"cve": r.cve_id, "product": ai_products.PRODUCTS[r.key].label}
        for r in sorted(rows, key=lambda r: r.cve_id) if r.kev]
    return out


def _board(all_rows: list[AiRow], window_rows: list[AiRow]) -> list[dict]:
    per_all = Counter(r.key for r in all_rows)
    first = {}
    for r in all_rows:
        first[r.key] = min(first.get(r.key, r.year), r.year)
    by_key: dict[str, list[AiRow]] = defaultdict(list)
    for r in window_rows:
        by_key[r.key].append(r)
    board = []
    for key, rows in by_key.items():
        cnas = Counter(r.cna for r in rows)
        top_cna, top_n = min(cnas.items(), key=lambda kv: (-kv[1], kv[0]))
        p = ai_products.PRODUCTS[key]
        board.append({
            "key": key, "label": p.label, "category": p.category,
            "n": len(rows), "all_years": per_all[key],
            "first_year": first[key],
            "kev": sum(r.kev for r in rows), "poc": sum(r.poc for r in rows),
            "top_cna": top_cna, "top_cna_pct": _pct(top_n, len(rows)),
        })
    board.sort(key=lambda b: (-b["n"], b["label"]))
    return board


def build_ai_products(collector: AiProductCollector,
                      generated_at: str, *,
                      window_years: int = WINDOW_YEARS) -> dict:
    """Assemble ai_products.json. ``years`` is empty (and every window
    block zero-sized) when the corpus holds no AI-product CVE — the page
    then shows its no-data card."""
    current_year = int(generated_at[:4])
    rows = [r for r in collector.rows if r.year <= current_year]
    cats = ai_products.CATEGORIES

    years = []
    if rows:
        for y in range(min(r.year for r in rows), current_year + 1):
            yr = [r for r in rows if r.year == y]
            by_cat = Counter(ai_products.category_of(r.key) for r in yr)
            keys = Counter(r.key for r in yr)
            lead = min(keys.items(), key=lambda kv: (-kv[1], kv[0]),
                       default=None)
            years.append({
                "year": y,
                "published": collector.published.get(y, 0),
                "named": collector.named.get(y, 0),
                "ai": len(yr),
                "by_category": {c: by_cat.get(c, 0) for c in cats},
                # the year's largest product (tooltip and copy guard)
                "top_product": None if lead is None else {
                    "label": ai_products.PRODUCTS[lead[0]].label,
                    "n": lead[1]},
            })

    window = range(current_year - window_years + 1, current_year + 1)
    win_rows = [r for r in rows if r.year in window]
    weights = _weights(win_rows)
    published, cwes, flags = _others(collector, win_rows, window)

    cnas = Counter(r.cna for r in win_rows)
    ranked_cnas = sorted(cnas.items(), key=lambda kv: (-kv[1], kv[0]))
    board = _board(rows, win_rows)

    out = {
        "generated_at": generated_at,
        "classifier": {
            "version": ai_products.CLASSIFIER_VERSION,
            "reviewed": ai_products.REVIEWED,
            "rules": ai_products.rule_count(),
            "products": len(ai_products.PRODUCTS),
        },
        "categories": list(cats),
        "years": years,
        "window": {"from": window.start, "to": window.stop - 1,
                   "years": window_years,
                   "weights": [{"year": y, "pct": round(100.0 * w, 1)}
                               for y, w in sorted(weights.items())]},
        "cwe": _cwe_block(win_rows, weights, published, cwes),
        "exploited": _exploited_block(win_rows, weights, published, flags),
        "products": board[:BOARD_TOP],
        "product_count": len(board),
        "cnas": {
            "n": len(win_rows),
            "cna_count": len(cnas),
            "top": [{"cna": c, "n": k, "pct": _pct(k, len(win_rows))}
                    for c, k in ranked_cnas[:TOP_CNAS]],
            "top3_pct": _pct(sum(k for _, k in ranked_cnas[:3]),
                             len(win_rows)),
        },
    }
    out["headline"] = _headline(years, board, current_year)
    return out


def _headline(years: list[dict], board: list[dict],
              current_year: int) -> dict:
    """Numbers the hero stat and copy quote: the latest COMPLETE year
    beside the partial current year (labelled as partial), and the largest
    single product in the window."""
    full = [r for r in years if r["year"] < current_year]
    latest = full[-1] if full else None
    current = next((r for r in years if r["year"] == current_year), None)
    lead = board[0] if board else None
    window_n = sum(b["n"] for b in board)
    return {
        "latest_year": latest["year"] if latest else 0,
        "latest_ai": latest["ai"] if latest else 0,
        "latest_share_pct": _pct(latest["ai"], latest["published"])
        if latest else 0.0,
        "current_year": current_year,
        "current_ai": current["ai"] if current else 0,
        "current_share_pct": _pct(current["ai"], current["published"])
        if current else 0.0,
        "lead_label": lead["label"] if lead else "",
        "lead_n": lead["n"] if lead else 0,
        "lead_pct": _pct(lead["n"], window_n) if lead else 0.0,
    }
