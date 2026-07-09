"""The curated buzzword watchlist for the Security Market module.

Each term carries one explicit query string per source, because the three
sources search very different corpora:

* **GDELT** sweeps general world news, so short acronyms are disambiguated
  with a security/tech context ('"SASE" (security OR network)') — a bare
  "SASE" or "MDR" in a news corpus matches airlines, EU medical-device
  regulation, and worse. Truly ambiguous acronyms are spelled out.
* **Hacker News** (Algolia) is already tech-centric; plain phrases work.
* **arXiv** queries run scoped to ``cat:cs.CR`` (cryptography & security),
  so plain phrases are unambiguous there.

Adding or removing a term here is the only edit needed — the fetch stage
backfills new terms automatically via the sync-state pending queue.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TermDef:
    """One tracked buzzword: stable id, display label, per-source queries."""

    id: str
    label: str
    gdelt_query: str
    hn_query: str
    arxiv_query: str


TERMS: list[TermDef] = [
    TermDef("zero_trust", "Zero Trust",
            gdelt_query='"zero trust" security',
            hn_query='"zero trust"',
            arxiv_query='"zero trust"'),
    TermDef("sbom", "SBOM",
            gdelt_query='"SBOM" (software OR security)',
            hn_query='"SBOM"',
            arxiv_query='"SBOM"'),
    TermDef("post_quantum", "Post-Quantum",
            gdelt_query='"post-quantum" (cryptography OR encryption OR security)',
            hn_query='"post-quantum"',
            arxiv_query='"post-quantum"'),
    TermDef("xdr", "XDR",
            gdelt_query='"XDR" (security OR "threat detection")',
            hn_query='"XDR" security',
            arxiv_query='"XDR"'),
    TermDef("sase", "SASE",
            gdelt_query='"SASE" (security OR network)',
            hn_query='"SASE"',
            arxiv_query='"SASE"'),
    TermDef("cnapp", "CNAPP",
            gdelt_query='"CNAPP" (cloud OR security)',
            hn_query='"CNAPP"',
            arxiv_query='"CNAPP"'),
    TermDef("ai_security", "AI Security",
            gdelt_query='"AI security"',
            hn_query='"AI security"',
            arxiv_query='"AI security"'),
    TermDef("agentic_ai", "Agentic AI",
            gdelt_query='"agentic AI"',
            hn_query='"agentic AI"',
            arxiv_query='"agentic AI"'),
    TermDef("ransomware", "Ransomware",
            gdelt_query='"ransomware"',
            hn_query='"ransomware"',
            arxiv_query='"ransomware"'),
    TermDef("supply_chain_security", "Supply Chain Security",
            gdelt_query='"supply chain security"',
            hn_query='"supply chain security"',
            arxiv_query='"supply chain security"'),
    TermDef("passwordless", "Passwordless",
            gdelt_query='"passwordless" (authentication OR login)',
            hn_query='"passwordless"',
            arxiv_query='"passwordless"'),
    TermDef("deepfake", "Deepfake",
            gdelt_query='"deepfake"',
            hn_query='"deepfake"',
            arxiv_query='"deepfake"'),
    TermDef("confidential_computing", "Confidential Computing",
            gdelt_query='"confidential computing"',
            hn_query='"confidential computing"',
            arxiv_query='"confidential computing"'),
    TermDef("mdr", "MDR",
            gdelt_query='"managed detection and response"',
            hn_query='"managed detection and response"',
            arxiv_query='"managed detection and response"'),
]
