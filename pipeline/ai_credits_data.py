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

A credit's tier is the strongest tier any pattern proved. Which tiers a
page may headline as "AI-credited" is decided once, in
:func:`counts_toward_headline` below.

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

TIERS = ("system", "org")

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
           system=(r"\bbig ?sleep\b", r"\bcodemender\b",
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


def classify(text: str) -> dict[str, str]:
    """``{finder key: tier}`` for every registry entity one credit string
    names. Empty for the overwhelming majority of credits."""
    found: dict[str, str] = {}
    for finder, system, org in _COMPILED:
        if any(p.search(text) for p in system):
            found[finder.key] = "system"
        elif any(p.search(text) for p in org):
            found[finder.key] = "org"
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
          note="Claude Opus 4.6, open-source code. No CVE count given."),
    Claim("anthropic", 10000, "more than",
          "high- or critical-severity vulnerabilities",
          "vulnerabilities", "2026-05-22",
          "https://www.anthropic.com/research/glasswing-initial-update",
          "2026-09-20",
          note="Collective total with about 50 Project Glasswing partners; "
               "includes proprietary code that will never get a public CVE."),
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
               "security engineering. Google publishes no CVE count."),
    Claim("xbow", 1060, "nearly", "vulnerabilities submitted on HackerOne",
          "submissions", "2025-06-24",
          "https://xbow.com/blog/top-1-how-xbow-did-it", "2026-09-20",
          note="130 resolved and 303 triaged at the time; bug-bounty "
               "reports against live targets rarely receive CVEs."),
    Claim("aisle", 400, "", "CVEs assigned", "cves", "2026-09-20",
          "https://aisle.com/cve-discoveries", "2026-09-20", live=True),
    Claim("zeropath", 13, "", "CVEs assigned", "cves", "2026-09-20",
          "https://zeropath.com/wall", "2026-09-20", live=True),
    Claim("depthfirst", 9, "", "CVE ids (of 21 FFmpeg zero-days)", "cves",
          "2026-06-02",
          "https://depthfirst.com/research/21-zero-days-in-ffmpeg",
          "2026-09-20"),
)
