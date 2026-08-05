"""The AI-and-offensive-security timeline — a small, hand-committed static
table (no upstream fetch), plus the era cutoffs the inflection test uses.

This is the ONLY new "source" the AI Alibi module adds, and it is static
hand-transcribed data rather than a nightly fetch for the same reason
``cwe_top25_data.py`` is: nobody publishes a machine-readable, curated
"when did AI touch offensive security" feed, and the events are a handful
per year. A committed table with one source URL per row is both
sufficient and auditable — disagree with an entry and you can open a PR
against this file.

**Every row carries a source URL and a date precision.** ``precision`` is
``"day"`` when the event has a single unambiguous published date (a model
release, a dated vendor report) and ``"month"`` when it does not (a
leaderboard position held over weeks, a multi-day event). Month-precision
rows plot at mid-month and say so in the tooltip — the chart never
implies a day it cannot support.

**What this table is NOT.** It is not evidence of anything by itself. The
module's argument is made entirely by CyberMon's own nightly series; the
timeline is the overlay that lets a reader check whether those series
bend at any of these dates. That is why ``kind`` matters more than the
row count:

* ``capability`` — a model or tool with a security-relevant capability
  became available, or was deliberately withheld because of one;
* ``no_uplift`` — a threat-intel shop looked specifically for offensive
  capability uplift in the wild and reported finding none;
* ``offensive`` — a documented case of AI used in a real intrusion or
  extortion operation;
* ``defensive`` — AI finding or fixing bugs on the defenders' side;
* ``research`` — lab-feasibility work, not in-the-wild evidence.

**Inclusion rule.** An event earns a row when it is security-relevant —
which explicitly includes getting better at FINDING vulnerabilities, not
only at exploiting them. A frontier model release with no security claim
attached does not qualify: this is an argument, not a launch feed, and
every generic row buried here dilutes the ``no_uplift`` rows that carry
the actual reasoning. A release with a measured vulnerability-discovery
or exploit-conversion result does qualify, because that is the mechanism
by which the clock this module tracks could actually start moving.

The ``no_uplift`` rows are the load-bearing ones: they are the reason a
2018-2023 trend cannot be attributed to a 2025 capability, and they come
from the two vendors with the strongest commercial incentive to report
the opposite.

VERIFICATION STATUS: every URL below resolved at time of writing and the
day-precision dates are the publishers' own. The month-precision rows are
deliberately coarse — if you tighten one to a day, cite the primary
document in the row's ``source`` and flip ``precision``.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Milestone:
    """One dated event on the AI/offensive-security timeline.

    ``date`` is ISO ``YYYY-MM-DD`` for day precision and ``YYYY-MM`` for
    month precision — the builder expands month rows to mid-month for
    plotting and keeps the original string for display.
    """

    date: str
    precision: str  # "day" | "month"
    kind: str       # capability | no_uplift | offensive | defensive | research
    label: str
    note: str
    source: str


@dataclass(frozen=True)
class Era:
    """One candidate "the AI era started here" cutoff.

    ``cut_year`` is derived, never hand-set: it is the last calendar year
    that ends entirely BEFORE ``date``, so no charted year ever straddles
    the cutoff. See ``ai_metrics.cut_year_for``.
    """

    id: str
    label: str
    date: str
    caption: str


# The three defensible answers to "when did the AI era start", offered as a
# chart control rather than picked for the reader. The default is the
# earliest (most generous to the AI-caused thesis in terms of how much
# post-era data it admits); a reader who thinks GPT-3.5 was too weak to
# matter can move the goalpost forward and watch the answer hold.
ERAS: list[Era] = [
    Era("chatgpt", "ChatGPT", "2022-11-30",
        "The month the public narrative starts: GPT-3.5 in everyone's "
        "browser."),
    Era("gpt4", "GPT-4", "2023-03-14",
        "The stricter test — the first model widely argued to be capable "
        "enough to matter offensively."),
    Era("uplift", "First documented uplift", "2025-08-27",
        "The most generous cutoff: the first vendor report of AI running "
        "real extortion operations, not just assisting."),
]

DEFAULT_ERA = "chatgpt"

# Chronological. Keep this list SHORT — it is an overlay, not a news feed;
# an event earns a row only if it plausibly changes what a reader believes
# about AI's effect on exploitation speed.
MILESTONES: list[Milestone] = [
    Milestone(
        "2022-11-30", "day", "capability",
        "ChatGPT (GPT-3.5) released",
        "General-purpose LLMs reach the public. No offensive tooling "
        "ecosystem exists yet.",
        "https://openai.com/index/chatgpt/",
    ),
    Milestone(
        "2023-03-14", "day", "capability",
        "GPT-4 released",
        "The first model widely argued to be capable enough to matter for "
        "exploit development.",
        "https://openai.com/index/gpt-4-research/",
    ),
    Milestone(
        "2024-02-14", "day", "no_uplift",
        "Microsoft + OpenAI: no capability uplift observed",
        "A joint threat report finds state actors using LLMs for recon, "
        "scripting and translation — and concludes it saw no novel "
        "capabilities or capability uplift.",
        "https://www.microsoft.com/en-us/security/blog/2024/02/14/"
        "staying-ahead-of-threat-actors-in-the-age-of-ai/",
    ),
    Milestone(
        "2024-04", "month", "research",
        "Fang et al.: LLM agents exploit one-day vulns (lab)",
        "A UIUC benchmark reports high success on a 15-CVE set — but the "
        "agent is handed the CVE description, and the method drew "
        "substantial criticism. Lab feasibility, not an in-the-wild driver.",
        "https://arxiv.org/abs/2404.08144",
    ),
    Milestone(
        "2024-11", "month", "defensive",
        "Big Sleep finds a real-world memory-safety bug",
        "Google's LLM-assisted bug hunter reports a genuine SQLite flaw — a "
        "milestone on the DEFENDERS' side of the ledger.",
        "https://googleprojectzero.blogspot.com/2024/10/"
        "from-naptime-to-big-sleep.html",
    ),
    Milestone(
        "2025-01", "month", "no_uplift",
        "Google GTIG: productivity gains, not new capabilities",
        "A second threat-intel shop looks specifically for offensive uplift "
        "in adversarial generative-AI use and reaches the same conclusion.",
        "https://cloud.google.com/blog/topics/threat-intelligence/"
        "adversarial-misuse-generative-ai",
    ),
    Milestone(
        "2025-06", "month", "offensive",
        "XBOW tops the HackerOne US leaderboard",
        "An autonomous pentesting system out-reports human researchers on a "
        "public bounty leaderboard — bug finding at scale, on authorised "
        "targets.",
        "https://xbow.com/blog/xbow-top-1/",
    ),
    Milestone(
        "2025-08", "month", "defensive",
        "DARPA AIxCC finals",
        "Autonomous systems find and patch a large share of injected "
        "synthetic vulnerabilities — the defensive-automation proof point.",
        "https://aicyberchallenge.com/",
    ),
    Milestone(
        "2025-08", "month", "offensive",
        "Anthropic reports AI-assisted extortion",
        "The first vendor account of a model orchestrating a real extortion "
        "operation end to end, rather than assisting a human operator.",
        "https://www.anthropic.com/news/detecting-countering-misuse-aug-2025",
    ),
    Milestone(
        "2025-11", "month", "offensive",
        "Anthropic reports AI-orchestrated espionage",
        "Multi-stage intrusion workflows run with reduced human involvement "
        "— genuinely new, and three years downstream of the trend this "
        "module measures.",
        "https://www.anthropic.com/news/disrupting-AI-espionage",
    ),
    # ---- 2026: the capability turn ------------------------------------
    # These rows sit beyond the clock's last COMPLETE year, so this module
    # cannot yet test them. That is the point of carrying them: they are
    # the first events on this timeline whose stated purpose is finding
    # vulnerabilities at scale, and they are exactly what a reader should
    # watch if they expect the historical finding to stop holding.
    Milestone(
        "2026-04-07", "day", "capability",
        "Anthropic withholds Claude Mythos, citing vulnerability discovery",
        "A frontier model is kept from public release specifically because "
        "of its ability to find software vulnerabilities — the first time "
        "cyber capability, rather than any other risk, gates a launch. It "
        "goes instead to roughly 50 defensive-security organisations under "
        "Project Glasswing.",
        "https://www.anthropic.com/glasswing",
    ),
    Milestone(
        "2026-05-11", "day", "defensive",
        "OpenAI launches Daybreak",
        "A cyber programme built the same way: vulnerability-finding "
        "capability released through vetted-defender access rather than "
        "generally, alongside tooling to patch what it finds.",
        "https://openai.com/index/daybreak-securing-the-world/",
    ),
    Milestone(
        "2026-05-22", "day", "defensive",
        "Glasswing reports 10,000+ high/critical vulnerabilities in a month",
        "Partners report more than ten thousand high- or critical-severity "
        "findings in systemically important software within a month; of "
        "1,752 independently assessed, 90.6% were valid true positives. "
        "Discovery volume, not exploitation speed — which is the shift this "
        "module's own charts cannot yet see.",
        "https://www.anthropic.com/research/glasswing-initial-update",
    ),
    Milestone(
        "2026-06-22", "day", "capability",
        "GPT-5.5-Cyber: measured gain in turning bugs into exploits",
        "A model purpose-built for finding and patching vulnerabilities. "
        "OpenAI reports 85.6% on CyberGym (from 81.8%) and, more relevant "
        "here, 39.5% against 25.95% on ExploitGym — converting a known "
        "vulnerability into a working exploit. That is the one mechanism "
        "that would compress the gap this page measures.",
        "https://openai.com/index/daybreak-securing-the-world/",
    ),
]

# Vendor-reported figures that are widely cited as evidence for the
# AI-made-attackers-fast story and that CyberMon deliberately does NOT
# plot: they are not reproducible from this pipeline, so they live in the
# page's prose as attributed context only. Kept here (not in editorial.js)
# so the citation and the reason travel with the data, and so a reviewer
# can check the claim without reading the copy.
#
# House rule: nothing in this list may ever reach a chart axis. The
# contract has no field for it and the builder never emits it — it is
# documentation, deliberately inert.
EXTERNAL_CONTEXT: list[dict[str, str]] = [
    {
        "claim": "Median time-to-exploit fell from ~63 days (2018-19) to "
                 "~5 days (2023).",
        "attribution": "Mandiant / Google Cloud, Time-to-Exploit Trends",
        "why_not_plotted": "Derived from Mandiant's private incident corpus; "
                           "not reproducible from open data, and its median "
                           "is taken over observed-exploited vulns, so a "
                           "rising zero-day share pulls it toward zero by "
                           "construction.",
        "source": "https://cloud.google.com/blog/topics/threat-intelligence/"
                  "time-to-exploit-trends-2023",
    },
    {
        "claim": "Edge-device exploitation rose roughly eightfold as a share "
                 "of exploitation-related breaches (~3% to ~22%).",
        "attribution": "Verizon DBIR 2025",
        "why_not_plotted": "Survey-and-caseload methodology over a "
                           "contributor corpus; the report itself attributes "
                           "the shift to target selection and extortion "
                           "economics, not AI.",
        "source": "https://www.verizon.com/business/resources/reports/dbir/",
    },
    {
        "claim": "Median exploit development time ~22 days from vulnerability "
                 "identification.",
        "attribution": "RAND, Zero Days, Thousands of Nights (2017)",
        "why_not_plotted": "A one-off study of a private zero-day dataset — "
                           "cited as prose because it dates the trend line "
                           "well before the LLM era, not as a series.",
        "source": "https://www.rand.org/pubs/research_reports/RR1751.html",
    },
]

VALID_KINDS = frozenset(
    {"capability", "no_uplift", "offensive", "defensive", "research"})
