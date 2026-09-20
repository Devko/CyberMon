"""AI-credited CVEs metrics (ai_credits.json).

Which CVE records say, in their own ``credits`` field, that an AI system or
an AI lab found the bug? This stage rides the shared corpus pass as an
``Aggregator.consume`` observer — no fetch, no second pass — and matches
every credit string against the committed registry in
``ai_credits_data.py``.

**A floor, never a census.** ``credits`` is optional and under half of
published records carry one at all (the ``coverage`` section publishes that
share per year so the page can say so). An AI-found bug whose CNA wrote no
credit, or credited only the human who filed it, is invisible here; the
series measures *crediting practice* as much as discovery. The opposite
error is guarded by the registry being narrow and hand-curated.

**Entities only.** Credit strings carry personal names and e-mail
addresses. Nothing from the raw string is emitted — the JSON holds registry
labels, counts, months, CNA short names and (for the KEV cut) CVE ids.

**Two kinds, never summed.** LLM labs and AI-security vendors get
separate headlines, lanes, severity cuts and funnels (``kinds.llm`` /
``kinds.vendor``); a CVE crediting both appears once in each.

**Tangible, not just counted.** Each kind carries a severity cut (the
record's effective CVSS score — CNA first, ADP fallback — in the site's
usual critical/high/medium/low buckets, ``unscored`` kept visible) and a
funnel: credited -> scored -> high-or-critical -> on CISA KEV. A small KEV
number is expected and is not a verdict on its own: coordinated-disclosure
bugs are patched before attackers meet them, and the cohort is months old.
``baseline`` publishes the same funnel for *every* credit-carrying CVE over
the same window so the page compares like with like.

**Claims are quoted, never measured.** ``claims`` carries each finder's own
published number (committed in ``ai_credits_data.CLAIMS`` with unit, date
and source) beside the count this pipeline measured for that finder. The
units mostly differ — "vulnerabilities found" is not "CVEs assigned" — and
``unit_kind`` exists so the page can refuse to put them on one scale.

Every matched credit is recorded with its tier (``system`` / ``org``, see
the registry docstring). What the page may *call* AI-credited — headlines,
lanes, severity, funnels, the board ranking — goes through
``ai_credits_data.counts_toward_headline`` and nothing else.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, NamedTuple

from .ai_credits_data import (CLAIMS, FINDERS, GROUPS, KINDS, classify,
                              counts_toward_headline, kind_of)
from .metrics import CveFacts, _pct, severity_bucket

COVERAGE_FROM_YEAR = 2018   # credits are near-absent from records before it
TOP_CNAS = 3
SEVERITIES = ("critical", "high", "medium", "low", "unscored")

_BY_KEY = {f.key: f for f in FINDERS}


def _credit_strings(record: dict) -> list[str]:
    """Every credit ``value`` in the record, CNA container first. ADP
    containers may carry credits too (none did as of 2026-07)."""
    containers = record.get("containers") or {}
    blocks = [containers.get("cna")] + list(containers.get("adp") or [])
    out: list[str] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        for credit in block.get("credits") or []:
            value = credit.get("value") if isinstance(credit, dict) else None
            if isinstance(value, str) and value.strip():
                out.append(value)
    return out


def _severity(facts: CveFacts) -> str:
    score = facts.effective_score
    return "unscored" if score is None else severity_bucket(score)


class CreditRow(NamedTuple):
    cve_id: str
    month: str                 # publication month "YYYY-MM"
    cna: str
    found: dict[str, str]      # finder key -> tier
    severity: str              # one of SEVERITIES
    in_kev: bool


@dataclass
class CreditCollector:
    """Observer for ``Aggregator.consume``: one :class:`CreditRow` per
    published CVE naming a registry finder, plus the denominators the
    coverage caveat and the baseline funnel need (per publication month,
    over every credit-carrying record)."""

    kev_ids: Iterable[str] = ()
    rows: list[CreditRow] = field(default_factory=list)
    published_by_year: Counter = field(default_factory=Counter)
    credited_by_year: Counter = field(default_factory=Counter)
    # (month, severity) -> n and month -> n, over ALL credit-carrying records
    credited_severity: Counter = field(default_factory=Counter)
    credited_kev: Counter = field(default_factory=Counter)

    def __post_init__(self) -> None:
        self.kev_ids = frozenset(self.kev_ids)

    def __call__(self, facts: CveFacts, record: dict) -> None:
        if facts.state != "PUBLISHED" or not facts.date_published:
            return
        self.published_by_year[facts.year] += 1
        credits = _credit_strings(record)
        if not credits:
            return
        month = facts.date_published[:7]
        severity = _severity(facts)
        in_kev = facts.cve_id in self.kev_ids
        self.credited_by_year[facts.year] += 1
        self.credited_severity[month, severity] += 1
        self.credited_kev[month] += in_kev
        found: dict[str, str] = {}
        for text in credits:
            for key, tier in classify(text).items():
                # strongest tier wins across a record's credit lines
                if found.get(key) != "system":
                    found[key] = tier
        if found:
            self.rows.append(CreditRow(facts.cve_id, month, facts.cna,
                                       found, severity, in_kev))


def _month_span(first: str, last: str) -> list[str]:
    y, m = int(first[:4]), int(first[5:7])
    out = []
    while f"{y:04d}-{m:02d}" <= last:
        out.append(f"{y:04d}-{m:02d}")
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    return out


def _counted_groups(found: dict[str, str]) -> set[str]:
    return {_BY_KEY[k].group for k, tier in found.items()
            if counts_toward_headline(_BY_KEY[k].group, tier)}


def _funnel(severity: Counter, kev: int) -> dict:
    credited = sum(severity.values())
    scored = credited - severity["unscored"]
    serious = severity["critical"] + severity["high"]
    return {"credited": credited, "scored": scored,
            "high_or_critical": serious,
            "high_or_critical_pct": _pct(serious, scored),
            "kev": kev, "kev_pct": _pct(kev, credited)}


def _severity_obj(severity: Counter) -> dict:
    return {s: severity[s] for s in SEVERITIES}


def _build_kind(kind: str, rows: list[tuple[CreditRow, set[str]]],
                this_month: str, this_year: int, board: list[dict]) -> dict:
    """One kind's headline / lanes / severity / funnel. ``rows`` pairs each
    counted CVE with the groups (of this kind) it counts for."""
    lanes_for = [g for g in GROUPS if kind_of(g) == kind]
    if not rows:
        return {"headline": None, "lanes": lanes_for, "months": [],
                "severity": _severity_obj(Counter()),
                "funnel": _funnel(Counter(), 0), "kev_cves": []}
    lanes: dict[str, Counter] = {m: Counter() for m in _month_span(
        min(r.month for r, _ in rows), this_month)}
    severity: Counter = Counter()
    for row, groups in rows:
        severity[row.severity] += 1
        lanes[row.month]["total"] += 1
        lanes[row.month].update(groups)
    months = [{"month": m, **{g: c[g] for g in lanes_for},
               "total": c["total"]} for m, c in lanes.items()]
    kev_cves = sorted(r.cve_id for r, _ in rows if r.in_kev)
    return {
        "headline": {
            "cves": len(rows),
            "this_year": this_year,
            "cves_this_year": sum(r["total"] for r in months
                                  if r["month"].startswith(str(this_year))),
            "finders": sum(1 for b in board
                           if b["kind"] == kind and b["counted"]),
            "first_month": months[0]["month"],
        },
        "lanes": lanes_for, "months": months,
        "severity": _severity_obj(severity),
        "funnel": _funnel(severity, len(kev_cves)),
        "kev_cves": kev_cves,
    }


def build_ai_credits(collector: CreditCollector, generated_at: str) -> dict:
    """Assemble ai_credits.json. A kind's ``headline`` is None (and its
    ``months`` empty) when no credit of that kind counts — the page then
    renders "not enough data yet" rather than a zero dressed up as a
    finding."""
    this_year = int(generated_at[:4])
    this_month = generated_at[:7]
    # A record post-dated past this edition (a CNA typo) is dropped whole,
    # so the lanes, the severity cut and the board can never disagree.
    credited = [r for r in collector.rows if r.month <= this_month]

    coverage = [{"year": y, "published": collector.published_by_year[y],
                 "with_credits": collector.credited_by_year[y],
                 "pct": _pct(collector.credited_by_year[y],
                             collector.published_by_year[y])}
                for y in range(COVERAGE_FROM_YEAR, this_year + 1)
                if collector.published_by_year[y]]

    # ---- board: every registry finder that appears at all ---------------
    per: dict[str, dict] = {}
    for row in credited:
        for key, tier in row.found.items():
            b = per.setdefault(key, {"system": 0, "org": 0, "counted": 0,
                                     "kev": 0, "months": [],
                                     "cnas": Counter(),
                                     "severity": Counter()})
            counts = counts_toward_headline(_BY_KEY[key].group, tier)
            b[tier] += 1
            b["counted"] += counts
            b["months"].append(row.month)
            b["cnas"][row.cna] += 1
            if counts:      # severity and KEV describe the counted CVEs only
                b["severity"][row.severity] += 1
                b["kev"] += row.in_kev
    board = [{"key": key, "label": _BY_KEY[key].label,
              "group": _BY_KEY[key].group,
              "kind": kind_of(_BY_KEY[key].group),
              "cves": b["system"] + b["org"], "counted": b["counted"],
              "system": b["system"], "org": b["org"],
              "severity": _severity_obj(b["severity"]), "kev": b["kev"],
              "first_month": min(b["months"]), "last_month": max(b["months"]),
              "top_cnas": [{"cna": c, "n": n} for c, n in
                           sorted(b["cnas"].items(),
                                  key=lambda kv: (-kv[1], kv[0]))[:TOP_CNAS]]}
             for key, b in per.items()]
    board.sort(key=lambda r: (-r["counted"], -r["cves"], r["label"]))

    # ---- the two kinds ---------------------------------------------------
    kinds = {}
    for kind in KINDS:
        rows = [(row, {g for g in _counted_groups(row.found)
                       if kind_of(g) == kind}) for row in credited]
        kinds[kind] = _build_kind(kind, [(r, g) for r, g in rows if g],
                                  this_month, this_year, board)

    # ---- baseline: every credit-carrying CVE over the same window --------
    firsts = [k["headline"]["first_month"] for k in kinds.values()
              if k["headline"]]
    baseline = None
    if firsts:
        start = min(firsts)
        severity: Counter = Counter()
        for (month, sev), n in collector.credited_severity.items():
            if start <= month <= this_month:
                severity[sev] += n
        kev = sum(n for m, n in collector.credited_kev.items()
                  if start <= m <= this_month)
        baseline = {"from_month": start, **_funnel(severity, kev),
                    "severity": _severity_obj(severity)}
    # ---- claims: the vendor's own number beside our measured one ---------
    counted_by_key = {r["key"]: r["counted"] for r in board}
    claims = [{"finder": c.finder, "label": _BY_KEY[c.finder].label,
               "kind": kind_of(_BY_KEY[c.finder].group),
               "value": c.value, "qualifier": c.qualifier, "unit": c.unit,
               "unit_kind": c.unit_kind, "date": c.date, "live": c.live,
               "source": c.source, "note": c.note,
               "credited": counted_by_key.get(c.finder, 0)}
              for c in CLAIMS]
    return {"generated_at": generated_at, "kinds": kinds,
            "baseline": baseline, "coverage": coverage, "board": board,
            "claims": claims}
