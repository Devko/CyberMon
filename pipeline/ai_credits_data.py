"""The committed registry behind AI-credited CVEs (ai_credits.json).

Who counts as an "AI finder" is an editorial judgment, so it lives here as
data — reviewable in a diff — and never as a clever regex. Each
:class:`Finder` is one credited entity; each of its patterns carries the
**tier** a match proves:

* ``system`` — the credit text names an AI system as (co-)finder: a model
  ("Claude", "Codex"), an autonomous agent ("Big Sleep", "XBOW"), or a
  self-described AI scanner.
* ``org`` — the credit names an AI lab or AI-native security vendor, but
  only as a person's affiliation ("Alex Gaynor (Anthropic)"). The record
  does not say a model found the bug; it says who employs the finder.

* ``fix`` — the registry entity is named, but only in a credit whose CVE
  schema role is not about finding the bug: remediation developer, reviewer
  or verifier, coordinator, sponsor. "Claude" as *remediation developer*
  says a model wrote the patch, not that it found the flaw. Recorded, shown
  on the board, never counted. (An external review on 2026-09-20 caught the
  first version ignoring roles; 31 of Anthropic's then-177 counted CVEs were
  fix credits.)

A credit's tier is the strongest tier any pattern proved, in the order
``system`` > ``org`` > ``fix``. Which tiers a page may headline as
"AI-credited" is decided once, in :func:`counts_toward_headline` below.

**What a match does and does not establish.** A ``system`` match means the
record *says* an AI system was involved in finding or reporting the bug. It
does not verify how the bug was found, and an ``org`` match says less
still. The registry can also only match names it knows: the first version
missed "Google OSS-Fuzz-Gen" (CVE-2024-9143, October 2024) and the page
claimed no AI finder before 2025 on the strength of that gap. Statements
about "the record" are statements about this registry's matches.

Patterns are matched case-insensitively against the raw credit string and
are deliberately narrow. A probe of the July 2026 corpus with a broad
``\\bai\\b|gemini|agent`` net caught "Capgemini", "2045gemini@gmail.com",
a researcher named Ai Ho and every ``*.ai`` vanity domain — so bare
"gemini", bare "ai" and bare "agent" are not patterns, and an ``.ai``
domain alone proves nothing (Horizon3.ai and GoSecure.ai credit human
researchers at pentest firms; they are excluded on purpose).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

TIERS = ("system", "org", "fix")

# CVE schema credit roles that are not about finding or reporting the bug.
# Everything else — finder, reporter, analyst, tool, other, or no role at
# all (a fifth of credit lines carry none) — is treated as discovery-side.
NON_DISCOVERY_ROLES = frozenset({
    "coordinator", "remediation developer", "remediation reviewer",
    "remediation verifier", "sponsor"})
_TIER_RANK = {tier: i for i, tier in enumerate(TIERS)}


def stronger(a: str | None, b: str) -> str:
    """The stronger of two tiers (``a`` may be None)."""
    return b if a is None or _TIER_RANK[b] < _TIER_RANK[a] else a

# Finder.group — the lanes the page draws. The three frontier labs get a
# lane each, other model makers share one, and everything else is an
# AI-native security vendor or tool. The page never mixes the two kinds:
# a lab's model is a general tool anyone can point at code, a vendor's
# product is a finding service, and their credit lines mean different
# things (see :func:`counts_toward_headline`).
GROUPS = ("anthropic", "openai", "google", "other_llm", "vendor")
KINDS = ("llm", "vendor")


def kind_of(group: str) -> str:
    return "vendor" if group == "vendor" else "llm"


@dataclass(frozen=True)
class Finder:
    key: str            # stable id used in the JSON
    label: str          # display name
    group: str          # one of GROUPS
    system: tuple[str, ...] = ()   # patterns proving the ``system`` tier
    org: tuple[str, ...] = ()      # patterns proving the ``org`` tier


FINDERS: tuple[Finder, ...] = (
    Finder("anthropic", "Anthropic (Claude)", "anthropic",
           # "Claude" is also a given name. The lookbehind drops
           # "Jean-Claude"; a bare "Claude Surname" credit would still
           # match — none exists in the corpus as of 2026-07, and
           # test_ai_credits pins the known negatives.
           system=(r"(?<!-)\bclaude\b", r"\bmythos\b"),
           org=(r"\banthropic\b",)),
    Finder("openai", "OpenAI (Codex / GPT)", "openai",
           system=(r"\bcodex\b", r"\bgpt-?\d", r"\baardvark\b"),
           org=(r"\bopenai\b",)),
    Finder("google", "Google (Big Sleep)", "google",
           # bare "gemini" is a surname fragment and a gmail handle in this
           # corpus; only a model-shaped mention ("Gemini 2.5 Pro") counts
           # OSS-Fuzz-Gen: LLM-written fuzz targets. Plain "OSS-Fuzz" is
           # classic fuzzing and must not match (it is credited since 2017).
           system=(r"\bbig ?sleep\b", r"\bcodemender\b",
                   r"\boss-?fuzz-?gen\b",
                   r"\bgemini[- ]?(\d|pro\b|ultra\b|flash\b)"),
           org=(r"\bdeepmind\b",)),
    # --- AI-native security vendors and tools ---------------------------
    Finder("aisle", "AISLE", "vendor",
           system=(r"found by aisle", r"discovered by aisle"),
           org=(r"\baisle\b",)),
    Finder("xbow", "XBOW", "vendor", system=(r"\bxbow\b",)),
    Finder("zast", "ZAST.AI", "vendor", system=(r"\bzast\.ai\b",)),
    Finder("fluid", "Fluid Attacks AI SAST", "vendor",
           system=(r"fluid attacks' ai sast",)),
    Finder("xint", "Xint Code (Theori)", "vendor",
           system=(r"\bxint code\b",), org=(r"\bxint\.io\b",)),
    Finder("depthfirst", "depthfirst", "vendor", org=(r"\bdepthfirst\b",)),
    Finder("hacktron", "Hacktron AI", "vendor", org=(r"\bhacktron\b",)),
    Finder("zeropath", "ZeroPath", "vendor", org=(r"zeropath\b",)),
    Finder("striga", "striga.ai", "vendor", org=(r"\bstriga\.ai\b",)),
    Finder("bugbunny", "bugbunny.ai", "vendor", org=(r"\bbugbunny\.ai\b",)),
    Finder("zai", "Z.ai (GLM)", "other_llm",
           system=(r"\bglm-?\d",), org=(r"\bz\.ai\b",)),
    Finder("github_taskflow", "GitHub Security Lab Taskflow Agent", "vendor",
           system=(r"taskflow agent",)),
    Finder("cantina_apex", "Cantina Apex", "vendor",
           system=(r"cantina's appsec agent",)),
    Finder("codeant", "CodeAnt AI", "vendor", system=(r"\bcodeant ai\b",)),
    Finder("kolega", "Kolega", "vendor", system=(r"\bkolega-ai-dev\b",)),
    Finder("tencent_aig", "Tencent AI-Infra-Guard", "vendor",
           system=(r"tencent/ai-infra-guard",)),
    Finder("orbis", "Orbis Security AI", "vendor",
           system=(r"orbis security ai",)),
    Finder("aether", "Aether AI", "vendor", system=(r"\baether ai\b",)),
    # Self-described agents with no vendor behind the name.
    Finder("unnamed_agent", "Self-described AI agent", "vendor",
           system=(r"code security ai agent", r"^artificial intelligence$")),
)

_COMPILED: tuple[tuple[Finder, tuple[re.Pattern[str], ...],
                       tuple[re.Pattern[str], ...]], ...] = tuple(
    (f,
     tuple(re.compile(p, re.I) for p in f.system),
     tuple(re.compile(p, re.I) for p in f.org))
    for f in FINDERS)


def classify(text: str, role: str | None = None) -> dict[str, str]:
    """``{finder key: tier}`` for every registry entity one credit line
    names. Empty for the overwhelming majority of credits. ``role`` is the
    credit's CVE-schema ``type``: a non-discovery role caps the match at
    ``fix`` whatever the text says."""
    fix_only = (role or "").strip().lower() in NON_DISCOVERY_ROLES
    found: dict[str, str] = {}
    for finder, system, org in _COMPILED:
        if any(p.search(text) for p in system):
            found[finder.key] = "fix" if fix_only else "system"
        elif any(p.search(text) for p in org):
            found[finder.key] = "fix" if fix_only else "org"
    return found


def counts_toward_headline(group: str, tier: str) -> bool:
    """Does a (group, tier) credit count as "AI-credited" in the headline
    numbers, the monthly lanes, the severity cut and the KEV funnel?

    Every tier is always *recorded* (the board shows the system/org split
    for each finder); this only decides what the page may call AI-credited
    out loud. The rule is split by kind (decided 2026-09-20):

    * **LLM labs** count only at the ``system`` tier. A lab's staff also
      find bugs by hand, so "Alex Gaynor (Anthropic)" proves an employer,
      not a model.
    * **Vendors** count at either tier. AI analysis is the product — AISLE
      credits the human who triaged the finding, and reading that as
      "not AI" would drop 98 of its 103 CVEs on a formatting habit.
    """
    if tier == "fix":       # credited for the patch, not the find
        return False
    return tier == "system" or kind_of(group) == "vendor"


# ------------------------------------------------------------------ claims

# What each finder says about itself — the funnel's first stage. Unlike
# everything else in this module these numbers are NOT measured here: they
# are the vendor's own, quoted with unit, date and source, and the page
# must draw them apart from the measured stages (hatched, and never on the
# measured bars' scale unless ``unit_kind == "cves"``).
#
# Rules for an entry: first-party source (the vendor's own page or post);
# the number was seen on the page at ``source`` on ``checked``; ``unit`` is
# the vendor's wording, not ours. ``unit_kind`` says whether the claim is
# even comparable to a CVE count:
#
#   cves             CVE ids assigned — directly comparable
#   advisories       public advisories; close to, but not, a CVE count
#   vulnerabilities  found / validated / reported bugs; no CVE count given
#   submissions      bug-bounty reports against live targets; mostly never
#                    eligible for a CVE
#
# ``live`` marks an undated running counter: ``date`` is then the day it
# was read, and the entry goes stale by design. ``checked`` is the last day
# somebody opened ``source`` and saw ``value`` on it; test_ai_credits fails
# once a live claim's reading is older than CLAIM_MAX_AGE_DAYS["live"] (or a
# dated claim's older than ["dated"]) — re-open the page, update ``value``
# and ``date`` for a counter, bump ``checked``. Never bump it unread.
#
# All nine entries below were opened and confirmed on 2026-09-20.
CLAIM_MAX_AGE_DAYS = {"live": 45, "dated": 365}
CLAIM_UNIT_KINDS = ("cves", "advisories", "vulnerabilities", "submissions")
CLAIM_QUALIFIERS = ("", "more than", "nearly")


@dataclass(frozen=True)
class Claim:
    finder: str         # Finder.key
    value: int
    qualifier: str      # one of CLAIM_QUALIFIERS
    unit: str           # the vendor's wording
    unit_kind: str      # one of CLAIM_UNIT_KINDS
    date: str           # YYYY-MM-DD of the claim (or of the reading, if live)
    source: str
    checked: str        # YYYY-MM-DD the number was last seen at ``source``
    live: bool = False
    note: str = ""


CLAIMS: tuple[Claim, ...] = (
    Claim("anthropic", 500, "more than",
          "high-severity vulnerabilities found and validated",
          "vulnerabilities", "2026-02-05",
          "https://www.anthropic.com/research/zero-days", "2026-09-20",
          note="Claude Opus 4.6, open-source code; the post gives no CVE "
               "count."),
    Claim("anthropic", 10000, "more than",
          "high- or critical-severity vulnerabilities",
          "vulnerabilities", "2026-05-22",
          "https://www.anthropic.com/research/glasswing-initial-update",
          "2026-09-20",
          note="Total for Anthropic and about 50 Project Glasswing partners, "
               "whose scans cover their own software as well as open source; "
               "some findings may never receive a public CVE."),
    Claim("anthropic", 65, "",
          "public advisories (of 530 bugs disclosed, 75 patched)",
          "advisories", "2026-05-22",
          "https://www.anthropic.com/research/glasswing-initial-update",
          "2026-09-20"),
    Claim("openai", 14, "", "CVEs assigned", "cves", "2026-03-06",
          "https://openai.com/index/codex-security-now-in-research-preview/",
          "2026-09-20", note="Codex Security; the post lists the CVE ids."),
    Claim("google", 20, "", "vulnerabilities reported", "vulnerabilities",
          "2025-08-04",
          "https://x.com/argvee/status/1952390039700431184", "2026-09-20",
          note="Big Sleep's first batch, announced by Google's VP of "
               "security engineering; the post gives no CVE count."),
    Claim("xbow", 1060, "nearly", "vulnerabilities submitted on HackerOne",
          "submissions", "2025-06-24",
          "https://xbow.com/blog/top-1-how-xbow-did-it", "2026-09-20",
          note="130 resolved and 303 triaged at the time. Bug-bounty "
               "reports against live services usually do not receive CVEs."),
    Claim("aisle", 400, "", "CVEs assigned", "cves", "2026-09-20",
          "https://aisle.com/cve-discoveries", "2026-09-20", live=True),
    Claim("zeropath", 13, "", "CVEs assigned", "cves", "2026-09-20",
          "https://zeropath.com/wall", "2026-09-20", live=True),
    Claim("depthfirst", 9, "", "CVE ids (of 21 FFmpeg zero-days)", "cves",
          "2026-06-02",
          "https://depthfirst.com/research/21-zero-days-in-ffmpeg",
          "2026-09-20"),
)


# ------------------------------------------------------- weakness families

# Coarse families for the "what AI finds" chart. A CVE's first-listed CWE
# (CNA first, ADP fallback — CveFacts.cwe) lands in the first family that
# lists it; everything else is ``other``, and a record with no CWE at all is
# ``none``. Deliberately short and flat: the chart compares three
# populations across a handful of classes, not the CWE tree. Membership is
# by exact id — MITRE's own view hierarchy is not consulted, so a parent
# pillar (CWE-664) counts only if it is listed here.
WEAKNESS_FAMILIES: tuple[tuple[str, str, frozenset[int]], ...] = (
    ("memory", "Memory safety", frozenset({
        119, 120, 121, 122, 123, 124, 125, 126, 127, 129, 131, 170, 190,
        191, 415, 416, 457, 466, 476, 590, 680, 761, 762, 763, 786, 787,
        788, 789, 805, 822, 823, 824, 825, 843, 908})),
    ("injection", "Injection (XSS, SQL, command)", frozenset({
        74, 77, 78, 79, 80, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98,
        113, 116, 643, 917, 943, 1236, 1336})),
    ("access", "Access control and auth", frozenset({
        250, 264, 266, 269, 276, 281, 284, 285, 287, 288, 290, 294, 302,
        303, 304, 305, 306, 307, 346, 352, 425, 522, 639, 640, 732, 798,
        862, 863, 1390})),
    ("path", "Files, paths and requests", frozenset({
        22, 23, 35, 36, 59, 61, 73, 434, 552, 601, 610, 611, 918})),
    ("crypto", "Crypto and certificate checks", frozenset({
        295, 296, 297, 310, 311, 319, 321, 326, 327, 328, 330, 331, 338,
        345, 347, 354, 916})),
    ("logic", "Input, state and resource handling", frozenset({
        20, 134, 185, 248, 252, 362, 367, 369, 400, 401, 404, 459, 502,
        617, 665, 667, 669, 670, 674, 682, 697, 704, 754, 755, 770, 772,
        834, 835, 1284, 1333})),
)
WEAKNESS_KEYS = tuple(k for k, _, _ in WEAKNESS_FAMILIES) + ("other", "none")
WEAKNESS_LABELS = {**{k: label for k, label, _ in WEAKNESS_FAMILIES},
                   "other": "Other CWE", "none": "No CWE listed"}


def weakness_family(cwe: str | None) -> str:
    """Family key for a ``"CWE-416"``-style id (``none`` when absent)."""
    if not cwe:
        return "none"
    try:
        number = int(cwe.rsplit("-", 1)[-1])
    except ValueError:
        return "other"
    for key, _, members in WEAKNESS_FAMILIES:
        if number in members:
            return key
    return "other"
