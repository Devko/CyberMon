"""The curated buzzword watchlist for the Security Market module.

Each term carries one explicit query string per source, because the five
sources search very different corpora:

* **GDELT** sweeps general world news, so acronyms are disambiguated
  with a security/tech context ('"CNAPP" (cloud OR security)') — a bare
  acronym in a news corpus matches airlines, EU medical-device
  regulation, and worse. Quoted phrases under 5 characters (SBOM, XDR,
  SASE, MDR) are rejected outright by the GDELT DOC API (non-JSON error
  response), so those terms are spelled out in full instead.
* **Hacker News** (Algolia) is already tech-centric; plain phrases work.
* **arXiv** queries run scoped to ``cat:cs.CR`` (cryptography & security),
  so plain phrases are unambiguous there.
* **Wikipedia** (Pageviews REST API) counts monthly views of ONE curated
  en.wikipedia article per term — ``wiki_article`` below. The mapping is
  editorial data, reviewable like any other curation in this repo (same
  spirit as the guards classifier): the judgment calls are commented
  inline. The 2026-07-21 audit missed that three mapped titles were
  already redirects (re-checked 2026-09-23 with the MediaWiki API,
  ``action=query&redirects=1``): after a page move, the Pageviews API
  counts only the requests that still arrive through the old title, so
  the series collapsed at each move date. A moved article is mapped to
  its current title, with every earlier title in ``wiki_former``; the
  fetch sums the titles month by month (a request is counted under the
  one title it asked for, so nothing is counted twice). ``None`` means en.wikipedia
  has no on-topic article for the term (CNAPP, as of the audit); the
  term simply has no Wikipedia series — an honest gap, never a
  stand-in article that measures something else.
* **SEC EDGAR full-text search** counts filings matching a quoted
  phrase. Filings are a finance corpus, so acronym collisions are worse
  than news: XDR is the IMF's Special Drawing Rights currency code and
  MDR is the EU Medical Device Regulation — both are spelled out in
  full, mirroring the GDELT rule.

Adding or removing a term here is the only edit needed — the fetch stage
backfills new terms automatically (the HN pending queue plus the
stateless full-history passes of the other four sources).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TermDef:
    """One tracked buzzword: stable id, display label, per-source queries.

    ``wiki_article`` is an exact en.wikipedia.org article title (None =
    no on-topic article exists; the term has no Wikipedia series).
    ``wiki_former`` lists the article's earlier titles (now redirects to
    it); their monthly views are added to the current title's.
    ``edgar_query`` is the quoted phrase for SEC EDGAR full-text search
    (None = term not tracked there).
    """

    id: str
    label: str
    gdelt_query: str
    hn_query: str
    arxiv_query: str
    wiki_article: str | None = None
    edgar_query: str | None = None
    wiki_former: tuple[str, ...] = ()


TERMS: list[TermDef] = [
    TermDef("zero_trust", "Zero Trust",
            gdelt_query='"zero trust" security',
            hn_query='"zero trust"',
            arxiv_query='"zero trust"',
            # moved from Zero_trust_security_model on 2024-11-21
            wiki_article="Zero_trust_architecture",
            wiki_former=("Zero_trust_security_model",),
            edgar_query='"zero trust"'),
    TermDef("sbom", "SBOM",
            gdelt_query='"software bill of materials"',
            hn_query='"SBOM"',
            arxiv_query='"SBOM"',
            # Judgment call, flagged for review: the SBOM article was
            # moved to the broader title Software_supply_chain on
            # 2022-05-03. It is the same article under a wider name, so
            # the lane follows it rather than counting only the requests
            # still arriving through the old title (which fell from
            # ~5,500 to ~600 a month at the move).
            wiki_article="Software_supply_chain",
            wiki_former=("Software_bill_of_materials",),
            edgar_query='"software bill of materials"'),
    TermDef("post_quantum", "Post-Quantum",
            gdelt_query='"post-quantum" (cryptography OR encryption OR security)',
            hn_query='"post-quantum"',
            arxiv_query='"post-quantum"',
            wiki_article="Post-quantum_cryptography",
            edgar_query='"post-quantum"'),
    TermDef("xdr", "XDR",
            gdelt_query='"extended detection and response"',
            hn_query='"XDR" security',
            arxiv_query='"XDR"',
            wiki_article="Extended_detection_and_response",
            # spelled out: in filings "XDR" is the IMF Special Drawing
            # Rights currency code far more often than the product class
            edgar_query='"extended detection and response"'),
    TermDef("sase", "SASE",
            gdelt_query='"secure access service edge"',
            hn_query='"SASE"',
            arxiv_query='"SASE"',
            wiki_article="Secure_access_service_edge",
            edgar_query='"secure access service edge"'),
    TermDef("cnapp", "CNAPP",
            gdelt_query='"CNAPP" (cloud OR security)',
            hn_query='"CNAPP"',
            arxiv_query='"CNAPP"',
            # en.wikipedia has no CNAPP article (verified 2026-07-21:
            # both hyphenation variants 404) — honest gap, no stand-in
            wiki_article=None,
            edgar_query='"cloud native application protection"'),
    TermDef("ai_security", "AI Security",
            gdelt_query='"AI security"',
            hn_query='"AI security"',
            arxiv_query='"AI security"',
            # Judgment call, flagged for review: en.wikipedia has no
            # "AI security" article (the literal title is a near-zero-
            # traffic stub). Adversarial_machine_learning is the
            # canonical security-of-AI article; AI_safety is the
            # alignment topic (off-topic), and
            # Artificial_intelligence_in_cybersecurity covers AI *as* a
            # defense tool with negligible traffic.
            wiki_article="Adversarial_machine_learning",
            edgar_query='"AI security"'),
    TermDef("agentic_ai", "Agentic AI",
            gdelt_query='"agentic AI"',
            hn_query='"agentic AI"',
            arxiv_query='"agentic AI"',
            # article created late 2024 (its short pageview history is
            # the honest history of the term), moved to AI_agent on
            # 2025-12-18
            wiki_article="AI_agent",
            wiki_former=("Agentic_AI",),
            edgar_query='"agentic AI"'),
    TermDef("ransomware", "Ransomware",
            gdelt_query='"ransomware"',
            hn_query='"ransomware"',
            arxiv_query='"ransomware"',
            wiki_article="Ransomware",
            edgar_query='"ransomware"'),
    TermDef("supply_chain_security", "Supply Chain Security",
            gdelt_query='"supply chain security"',
            hn_query='"supply chain security"',
            arxiv_query='"supply chain security"',
            # Supply_chain_attack is the software-security article this
            # term means; the literal-title Supply_chain_security page
            # is mostly cargo/physical security (verified 2026-07-21)
            wiki_article="Supply_chain_attack",
            edgar_query='"supply chain security"'),
    TermDef("passwordless", "Passwordless",
            gdelt_query='"passwordless" (authentication OR login)',
            hn_query='"passwordless"',
            arxiv_query='"passwordless"',
            wiki_article="Passwordless_authentication",
            edgar_query='"passwordless"'),
    TermDef("deepfake", "Deepfake",
            gdelt_query='"deepfake"',
            hn_query='"deepfake"',
            arxiv_query='"deepfake"',
            wiki_article="Deepfake",
            edgar_query='"deepfake"'),
    TermDef("confidential_computing", "Confidential Computing",
            gdelt_query='"confidential computing"',
            hn_query='"confidential computing"',
            arxiv_query='"confidential computing"',
            wiki_article="Confidential_computing",
            edgar_query='"confidential computing"'),
    TermDef("mdr", "MDR",
            gdelt_query='"managed detection and response"',
            hn_query='"managed detection and response"',
            arxiv_query='"managed detection and response"',
            wiki_article="Managed_detection_and_response",
            # spelled out: in filings "MDR" is the EU Medical Device
            # Regulation (and assorted tickers), not the service class
            edgar_query='"managed detection and response"'),
]
