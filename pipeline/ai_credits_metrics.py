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
labels, counts, months, CNA short names, affected-product names and (for
the KEV cut) CVE ids.

**Two kinds, never summed.** LLM labs and AI-security vendors get
separate headlines, lanes, severity cuts and funnels (``kinds.llm`` /
``kinds.vendor``); a CVE crediting both appears once in each.

**Tangible, not just counted.** Each kind carries a severity cut (the
record's effective CVSS score — CNA first, ADP fallback — in the site's
usual critical/high/medium/low buckets, ``unscored`` kept visible) and a
funnel: credited -> high-or-critical -> public exploit code -> on CISA KEV.
The stages are each a share of ``credited``, not nested. Small exploit and
KEV numbers are expected and are not a verdict on their own:
coordinated-disclosure bugs are patched before attackers meet them, the
cohort is months old, and the exploit corpora lag publication.
``baseline`` publishes the same funnel for *every* credit-carrying CVE over
the same window so the page compares like with like.

**Three more cuts ride the same rows.** ``weaknesses`` buckets each CVE's
first-listed CWE into the committed families in ``ai_credits_data`` for
labs, vendors and the baseline; ``targets`` ranks the first affected
product each CNA lists (a map of where the tools were pointed — and of
which partnerships wrote the record); ``profile`` sets the three
populations side by side on median CVSS, median EPSS percentile, public
exploit code, KEV, memory-safety share and how often the CNA scored the
record itself. Small-n honesty: every share ships beside its count.

**Claims are quoted, never measured.** ``claims`` carries each finder's own
published number (committed in ``ai_credits_data.CLAIMS`` with unit, date
and source) beside the count this pipeline measured for that finder. The
units mostly differ — "vulnerabilities found" is not "CVEs assigned" — and
``unit_kind`` exists so the page can refuse to put them on one scale.

Every matched credit is recorded with its tier (``system`` / ``org``, see
the registry docstring). What the page may *call* AI-credited — headlines,
lanes, severity, funnels, the three cuts above, the board ranking — goes
through ``ai_credits_data.counts_toward_headline`` and nothing else.
"""
from __future__ import annotations

import statistics
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Mapping, NamedTuple

from .ai_credits_data import (CLAIMS, FINDERS, GROUPS, KINDS, WEAKNESS_KEYS,
                              WEAKNESS_LABELS, classify,
                              counts_toward_headline, kind_of,
                              weakness_family)
from .metrics import CveFacts, _pct, _r1, severity_bucket

COVERAGE_FROM_YEAR = 2018   # credits are near-absent from records before it
TOP_CNAS = 3
TOP_TARGETS = 10
TOP_SHARE_N = 5             # "the top five products hold X%"
SEVERITIES = ("critical", "high", "medium", "low", "unscored")
POPULATIONS = (*KINDS, "baseline")
_PLACEHOLDER = frozenset({"", "n/a", "na", "unknown", "unspecified", "-"})

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


def _clean(value) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip()
    return "" if value.lower() in _PLACEHOLDER else value


def _target(record: dict) -> str:
    """The first affected product the CNA lists, as ``"vendor / product"``
    (placeholders dropped, a vendor the product already starts with folded
    away); ``""`` when the record names none. It is the CNA's framing: a
    distro CNA lists its distro, not the upstream project."""
    cna = (record.get("containers") or {}).get("cna") or {}
    affected = cna.get("affected")
    if not isinstance(affected, list):
        return ""
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        vendor, product = _clean(entry.get("vendor")), \
            _clean(entry.get("product"))
        # "Red Hat / Red Hat Enterprise Linux" says the vendor twice
        repeats = product.lower().startswith(vendor.lower())
        if vendor and product and not repeats:
            return f"{vendor} / {product}"
        if product or vendor:
            return product or vendor
    return ""


def _severity(facts: CveFacts) -> str:
    score = facts.effective_score
    return "unscored" if score is None else severity_bucket(score)


class Traits(NamedTuple):
    """What every cut needs from one credit-carrying record."""
    month: str                 # publication month "YYYY-MM"
    severity: str              # one of SEVERITIES
    score: float | None        # effective CVSS base score
    cna_scored: bool           # the CNA (not an ADP) supplied a score
    cwe: str | None            # first-listed CWE id
    epss_pctile: float | None  # 0..1, None when EPSS has no row
    in_kev: bool
    has_poc: bool


class CreditRow(NamedTuple):
    cve_id: str
    cna: str
    found: dict[str, str]      # finder key -> tier
    target: str                # "" when the record names no product
    traits: Traits


@dataclass
class CreditCollector:
    """Observer for ``Aggregator.consume``: one :class:`CreditRow` per
    published CVE naming a registry finder, plus — as the baseline every
    cut is read against — the :class:`Traits` of *every* credit-carrying
    record (tens of thousands of small tuples), and the per-year coverage
    denominators."""

    kev_ids: Iterable[str] = ()
    poc_ids: Iterable[str] = ()
    epss_percentiles: Mapping[str, float] = field(default_factory=dict)
    rows: list[CreditRow] = field(default_factory=list)
    credited: list[Traits] = field(default_factory=list)
    published_by_year: Counter = field(default_factory=Counter)
    credited_by_year: Counter = field(default_factory=Counter)

    def __post_init__(self) -> None:
        self.kev_ids = frozenset(self.kev_ids)
        self.poc_ids = frozenset(self.poc_ids)

    def __call__(self, facts: CveFacts, record: dict) -> None:
        if facts.state != "PUBLISHED" or not facts.date_published:
            return
        self.published_by_year[facts.year] += 1
        credits = _credit_strings(record)
        if not credits:
            return
        self.credited_by_year[facts.year] += 1
        traits = Traits(
            month=facts.date_published[:7],
            severity=_severity(facts),
            score=facts.effective_score,
            cna_scored=bool(facts.cna_scores),
            cwe=facts.cwe,
            epss_pctile=self.epss_percentiles.get(facts.cve_id),
            in_kev=facts.cve_id in self.kev_ids,
            has_poc=facts.cve_id in self.poc_ids)
        self.credited.append(traits)
        found: dict[str, str] = {}
        for text in credits:
            for key, tier in classify(text).items():
                # strongest tier wins across a record's credit lines
                if found.get(key) != "system":
                    found[key] = tier
        if found:
            self.rows.append(CreditRow(facts.cve_id, facts.cna, found,
                                       _target(record), traits))


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


def _severity_obj(traits: list[Traits]) -> dict:
    counts = Counter(t.severity for t in traits)
    return {s: counts[s] for s in SEVERITIES}


def _funnel(traits: list[Traits]) -> dict:
    severity = _severity_obj(traits)
    credited = len(traits)
    scored = credited - severity["unscored"]
    serious = severity["critical"] + severity["high"]
    poc = sum(t.has_poc for t in traits)
    kev = sum(t.in_kev for t in traits)
    return {"credited": credited, "scored": scored,
            "high_or_critical": serious,
            "high_or_critical_pct": _pct(serious, scored),
            "poc": poc, "poc_pct": _pct(poc, credited),
            "kev": kev, "kev_pct": _pct(kev, credited)}


def _profile(traits: list[Traits]) -> dict:
    """One population's column in the side-by-side profile. Medians are
    None on an empty population; every share sits beside ``n``."""
    n = len(traits)
    scores = [t.score for t in traits if t.score is not None]
    pctiles = [t.epss_pctile for t in traits if t.epss_pctile is not None]
    cwes = Counter(t.cwe for t in traits if t.cwe)
    top = min(cwes.items(), key=lambda kv: (-kv[1], kv[0]), default=None)
    return {
        "n": n,
        "median_cvss": _r1(statistics.median(scores)) if scores else None,
        "median_epss_pctile":
            _r1(100.0 * statistics.median(pctiles)) if pctiles else None,
        "epss_scored": len(pctiles),
        "poc_pct": _pct(sum(t.has_poc for t in traits), n),
        "kev_pct": _pct(sum(t.in_kev for t in traits), n),
        "memory_pct": _pct(sum(weakness_family(t.cwe) == "memory"
                               for t in traits), n),
        "cna_scored_pct": _pct(sum(t.cna_scored for t in traits), n),
        "top_cwe": None if top is None else
            {"cwe": top[0], "n": top[1], "pct": _pct(top[1], n)},
    }


def _targets(rows: list[CreditRow]) -> dict:
    """Most-credited first-affected products for one kind. Grouped
    case-insensitively (the corpus carries both "MISP" and "misp"); the
    label is the commonest spelling. Shares are of the CVEs that name a
    product at all (``named``)."""
    spellings: dict[str, Counter] = {}
    for row in rows:
        if row.target:
            spellings.setdefault(row.target.lower(),
                                 Counter())[row.target] += 1
    ranked = sorted(
        ((sum(c.values()),
          min(c.items(), key=lambda kv: (-kv[1], kv[0]))[0])
         for c in spellings.values()),
        key=lambda nl: (-nl[0], nl[1].lower()))
    named = sum(n for n, _ in ranked)
    return {
        "cves": len(rows), "named": named, "distinct": len(ranked),
        "top_share_n": TOP_SHARE_N,
        "top_share_pct": _pct(sum(n for n, _ in ranked[:TOP_SHARE_N]), named),
        "projects": [{"label": label, "n": n, "pct": _pct(n, named)}
                     for n, label in ranked[:TOP_TARGETS]],
    }


def _build_kind(kind: str, rows: list[tuple[CreditRow, set[str]]],
                this_month: str, this_year: int, board: list[dict]) -> dict:
    """One kind's headline / lanes / severity / funnel. ``rows`` pairs each
    counted CVE with the groups (of this kind) it counts for."""
    lanes_for = [g for g in GROUPS if kind_of(g) == kind]
    traits = [r.traits for r, _ in rows]
    if not rows:
        return {"headline": None, "lanes": lanes_for, "months": [],
                "severity": _severity_obj([]), "funnel": _funnel([]),
                "kev_cves": []}
    lanes: dict[str, Counter] = {m: Counter() for m in _month_span(
        min(t.month for t in traits), this_month)}
    for row, groups in rows:
        lanes[row.traits.month]["total"] += 1
        lanes[row.traits.month].update(groups)
    months = [{"month": m, **{g: c[g] for g in lanes_for},
               "total": c["total"]} for m, c in lanes.items()]
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
        "severity": _severity_obj(traits),
        "funnel": _funnel(traits),
        "kev_cves": sorted(r.cve_id for r, _ in rows if r.traits.in_kev),
    }


def build_ai_credits(collector: CreditCollector, generated_at: str) -> dict:
    """Assemble ai_credits.json. A kind's ``headline`` is None (and its
    ``months`` empty) when no credit of that kind counts — the page then
    renders "not enough data yet" rather than a zero dressed up as a
    finding. ``baseline``, ``profile``, ``weaknesses`` and ``targets`` are
    None together when neither kind counts anything."""
    this_year = int(generated_at[:4])
    this_month = generated_at[:7]
    # A record post-dated past this edition (a CNA typo) is dropped whole,
    # so the lanes, the severity cut and the board can never disagree.
    credited = [r for r in collector.rows if r.traits.month <= this_month]

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
            b = per.setdefault(key, {"system": 0, "org": 0, "months": [],
                                     "cnas": Counter(), "counted": []})
            b[tier] += 1
            b["months"].append(row.traits.month)
            b["cnas"][row.cna] += 1
            # severity, exploit code and KEV describe the counted CVEs only
            if counts_toward_headline(_BY_KEY[key].group, tier):
                b["counted"].append(row.traits)
    board = [{"key": key, "label": _BY_KEY[key].label,
              "group": _BY_KEY[key].group,
              "kind": kind_of(_BY_KEY[key].group),
              "cves": b["system"] + b["org"], "counted": len(b["counted"]),
              "system": b["system"], "org": b["org"],
              "severity": _severity_obj(b["counted"]),
              "poc": sum(t.has_poc for t in b["counted"]),
              "kev": sum(t.in_kev for t in b["counted"]),
              "first_month": min(b["months"]), "last_month": max(b["months"]),
              "top_cnas": [{"cna": c, "n": n} for c, n in
                           sorted(b["cnas"].items(),
                                  key=lambda kv: (-kv[1], kv[0]))[:TOP_CNAS]]}
             for key, b in per.items()]
    board.sort(key=lambda r: (-r["counted"], -r["cves"], r["label"]))

    # ---- the two kinds ---------------------------------------------------
    kinds: dict[str, dict] = {}
    kind_rows: dict[str, list[CreditRow]] = {}
    for kind in KINDS:
        pairs = [(row, {g for g in _counted_groups(row.found)
                        if kind_of(g) == kind}) for row in credited]
        pairs = [(r, g) for r, g in pairs if g]
        kind_rows[kind] = [r for r, _ in pairs]
        kinds[kind] = _build_kind(kind, pairs, this_month, this_year, board)

    # ---- baseline + the three cuts read against it -----------------------
    firsts = [k["headline"]["first_month"] for k in kinds.values()
              if k["headline"]]
    baseline = profile = weaknesses = targets = None
    if firsts:
        start = min(firsts)
        window = [t for t in collector.credited
                  if start <= t.month <= this_month]
        baseline = {"from_month": start, **_funnel(window),
                    "severity": _severity_obj(window)}
        populations = {**{k: [r.traits for r in kind_rows[k]] for k in KINDS},
                       "baseline": window}
        profile = {name: _profile(populations[name]) for name in POPULATIONS}
        families = {name: Counter(weakness_family(t.cwe)
                                  for t in populations[name])
                    for name in POPULATIONS}
        weaknesses = {"families": [
            {"key": key, "label": WEAKNESS_LABELS[key],
             **{name: {"n": families[name][key],
                       "pct": _pct(families[name][key],
                                   len(populations[name]))}
                for name in POPULATIONS}}
            for key in WEAKNESS_KEYS]}
        targets = {kind: _targets(kind_rows[kind]) for kind in KINDS}

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
            "baseline": baseline, "profile": profile,
            "weaknesses": weaknesses, "targets": targets,
            "coverage": coverage, "board": board, "claims": claims}
