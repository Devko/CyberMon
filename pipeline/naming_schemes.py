"""Vendor naming schemes: which scheme's documented form a threat-group name has.

The Alias Graph (site/alias.html, data/alias_graph.json) links each MITRE
ATT&CK group to the vendor naming schemes its names follow. This module is
the rule table behind that link. It is versioned: change ``RULES_VERSION``
whenever a scheme, a pattern, the element list or an exception changes, and
add a line to the changelog below. The version ships in alias_graph.json, so
a change in the counts can always be traced to a data change or a rule
change.

How a name is classified (:func:`classify`):

* every pattern of every scheme is tested against the whole name (stripped
  of surrounding spaces; a pattern either matches the full string or not);
* exactly one scheme matches -> the name is that scheme's;
* no scheme matches -> ``no_rule``;
* two or more schemes match -> ``ambiguous``, never a guess (VOID MANTICORE
  has both Check Point's and Trend Micro's form);
* a name listed in :data:`EXCEPTIONS` is ``exception``: it has a scheme's
  form but a cited publication shows another organisation coined it.

Rules are written only where the vendor publishes its naming convention and
the form can be tested without a list of names (a word list such as
Microsoft's chemical elements counts: it is closed and documented). Every
pattern cites that documentation. A name that merely *has* a vendor's form
is counted under that vendor; the exceptions list is the only correction,
and it holds only cases with a citation.

Vendors with no rule here, and why:

* ESET, Kaspersky, Symantec/Broadcom, F-Secure, Volexity, ClearSky: their
  names are free-form words (Sednit, Crouching Yeti, Waterbug) with no
  documented, testable form.
* Talos (UAT-NNNN), CERT-UA (UAC-NNNN), Qihoo 360 (APT-C-NN), QiAnXin
  (APT-Q-NN), Tencent (T-APT-NN), Google TAG (FROZENLAKE ...), Dragos
  (minerals: ELECTRUM, XENOTIME), Accenture (fish: BELUGASTURGEON): no
  public naming documentation was found (checked 2026-11-05).
* PwC (colour + word: Blue Kitsune, Red Apollo): a colour followed by any
  word cannot be told apart from Microsoft's "Red Sandstorm" by form.
* Recorded Future's colour + NATO-alphabet names (RedDelta, PurpleBravo):
  the taxonomy paper that documents them no longer resolves; only the
  TAG-NN designator, used in its published reports, has a rule.
* Microsoft's retired tree and volcano names (ELBRUS, CHIMBORAZO): not a
  closed list, so not testable.

Changelog
  1 (2026-11-05) first table: ten schemes, three exceptions.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

RULES_VERSION = 1

# Classification outcomes (alias_graph.json ``names[].status``).
CLASSIFIED = "classified"
NO_RULE = "no_rule"
AMBIGUOUS = "ambiguous"
EXCEPTION = "exception"
STATUSES = (CLASSIFIED, NO_RULE, AMBIGUOUS, EXCEPTION)


@dataclass(frozen=True)
class Scheme:
    id: str
    label: str
    doc: str          # the vendor's naming documentation (linked on the page)
    forms: str        # the documented forms, as the page lists them
    patterns: tuple[re.Pattern[str], ...]


def _words(*words: str) -> str:
    return "(?:" + "|".join(words) + ")"


def _full(pattern: str, *, ci: bool = False) -> re.Pattern[str]:
    return re.compile(rf"^{pattern}$", re.IGNORECASE if ci else 0)


# Chemical elements (IUPAC names; US and UK spellings of the three that
# differ). Microsoft's retired nation-state names were element names.
ELEMENTS = (
    "Hydrogen Helium Lithium Beryllium Boron Carbon Nitrogen Oxygen Fluorine "
    "Neon Sodium Magnesium Aluminum Aluminium Silicon Phosphorus Sulfur Sulphur "
    "Chlorine Argon Potassium Calcium Scandium Titanium Vanadium Chromium "
    "Manganese Iron Cobalt Nickel Copper Zinc Gallium Germanium Arsenic "
    "Selenium Bromine Krypton Rubidium Strontium Yttrium Zirconium Niobium "
    "Molybdenum Technetium Ruthenium Rhodium Palladium Silver Cadmium Indium "
    "Tin Antimony Tellurium Iodine Xenon Cesium Caesium Barium Lanthanum "
    "Cerium Praseodymium Neodymium Promethium Samarium Europium Gadolinium "
    "Terbium Dysprosium Holmium Erbium Thulium Ytterbium Lutetium Hafnium "
    "Tantalum Tungsten Rhenium Osmium Iridium Platinum Gold Mercury Thallium "
    "Lead Bismuth Polonium Astatine Radon Francium Radium Actinium Thorium "
    "Protactinium Uranium Neptunium Plutonium Americium Curium Berkelium "
    "Californium Einsteinium Fermium Mendelevium Nobelium Lawrencium "
    "Rutherfordium Dubnium Seaborgium Bohrium Hassium Meitnerium Darmstadtium "
    "Roentgenium Copernicium Nihonium Flerovium Moscovium Livermorium "
    "Tennessine Oganesson"
).split()

# Microsoft family names: 23 nation-state families (one per country or
# region of origin) plus Tempest (financially motivated), Tsunami (private
# sector offensive actors) and Flood (influence operations).
MICROSOFT_FAMILIES = (
    "Waterspout Freeze Typhoon Gale Monsoon Sandstorm Heatwave Swell Sleet "
    "Rain Vortex Lightning Blizzard Squall Hail Derecho Haze Dust Frost Gust "
    "Fog Tornado Cyclone Tempest Tsunami Flood"
).split()

CROWDSTRIKE_ANIMALS = (
    "Bear Bison Buffalo Chollima Crane Hawk Jackal Kitten Leopard Lynx Ocelot "
    "Panda Saiga Sphinx Spider Tiger Wolf"
).split()

SECUREWORKS_PREFIXES = (
    "ALUMINUM BRONZE COBALT COPPER GOLD IRON LITHIUM NICKEL PLATINUM RADIUM "
    "SILVER STEEL TIN TUNGSTEN ZINC"
).split()

UNIT42_CONSTELLATIONS = (
    "Draco Lynx Pisces Serpens Taurus Ursa Libra Scorpius"
).split()

TREND_ELEMENTS = ("Earth", "Water", "Fire", "Wind", "Void")

# One word (letters, digits, hyphens, apostrophes) before a family word.
_ADJ = r"[A-Za-z0-9'\-]+"


SCHEMES: tuple[Scheme, ...] = (
    Scheme(
        id="microsoft",
        label="Microsoft",
        doc="https://learn.microsoft.com/en-us/defender-xdr/microsoft-threat-actor-naming",
        forms=("adjective + weather family (Forest Blizzard, Volt Typhoon, "
               "Octo Tempest); Storm-NNNN; retired: DEV-NNNN and chemical "
               "elements (STRONTIUM)"),
        patterns=(
            # "How Microsoft names threat actors", Microsoft Learn (updated
            # 2026-10-21): "a weather event or family name represents one of
            # the above categories ... Threat actors within the same weather
            # family are given an adjective"; the family table lists the 23
            # nation-state families plus Tempest, Tsunami and Flood.
            # https://learn.microsoft.com/en-us/defender-xdr/microsoft-threat-actor-naming
            _full(rf"{_ADJ} {_words(*MICROSOFT_FAMILIES)}", ci=True),
            # Same page: "For groups in development, a temporary designation
            # of Storm and a four-digit number is used".
            _full(r"Storm-\d{4}", ci=True),
            # "Microsoft shifts to a new threat actor naming taxonomy",
            # Microsoft Security blog, 2023-04-18: "we use a temporary
            # designation of Storm (previously DEV) and a four-digit number"
            # and "The naming approach we have used previously (Elements,
            # Trees, Volcanoes, and DEVs) has been retired." Microsoft's own
            # mapping shows the three-digit form too (DEV-500).
            # https://www.microsoft.com/en-us/security/blog/2023/04/18/microsoft-shifts-to-a-new-threat-actor-naming-taxonomy/
            _full(r"DEV-\d{3,4}", ci=True),
            # Same blog: the retired "Elements" names, one element name
            # each (STRONTIUM, NOBELIUM, PHOSPHORUS). Trees and volcanoes
            # (ELBRUS) are not a closed list and get no rule.
            _full(_words(*ELEMENTS), ci=True),
        ),
    ),
    Scheme(
        id="crowdstrike",
        label="CrowdStrike",
        doc="https://www.crowdstrike.com/en-us/adversaries/",
        forms="adjective + animal (Fancy Bear, Wicked Panda, Scattered Spider)",
        patterns=(
            # CrowdStrike 2025 Global Threat Report, Executive Summary, p. 4,
            # "Naming conventions": BEAR Russia, BUFFALO Vietnam, CHOLLIMA
            # DPRK, CRANE ROK, HAWK Syria, JACKAL hacktivist, KITTEN Iran,
            # LEOPARD Pakistan, LYNX Georgia, OCELOT Colombia, PANDA China,
            # SAIGA Kazakhstan, SPIDER eCrime, TIGER India, WOLF Turkey,
            # SPHINX Egypt. https://www.crowdstrike.com/en-us/global-threat-report/
            # BISON (Belarus) from the Adversary Universe listing (Umbral
            # Bison). https://www.crowdstrike.com/en-us/adversaries/
            # "Naming adversaries and why it matters to security teams":
            # nation-states "are identified by their country of origin's
            # national animal", cybercriminals are SPIDERs, hacktivists
            # JACKALs. https://www.crowdstrike.com/en-us/blog/naming-adversaries-and-why-it-matters-to-security-teams/
            _full(rf"{_ADJ} {_words(*CROWDSTRIKE_ANIMALS)}", ci=True),
        ),
    ),
    Scheme(
        id="mandiant",
        label="Mandiant",
        doc="https://cloud.google.com/blog/topics/threat-intelligence/how-mandiant-tracks-uncategorized-threat-actors",
        forms="APTnn, FINnn, UNCnnnn, TEMP.name",
        patterns=(
            # "DebUNCing Attribution: How Mandiant Tracks Uncategorized
            # Threat Actors" (Mandiant, now Google Threat Intelligence):
            # "UNC groups ... a cluster of cyber intrusion activity ... that
            # we are not yet ready to give a classification such as APT or
            # FIN"; clusters may be "combined under a TEMP name, such as
            # TEMP.Warlock, and/or 'graduate' into fully defined groups, such
            # as FIN11". Written exactly so; matched case-sensitively.
            # https://cloud.google.com/blog/topics/threat-intelligence/how-mandiant-tracks-uncategorized-threat-actors
            _full(r"APT\d+"),
            _full(r"FIN\d+"),
            _full(r"UNC\d+"),
            _full(r"TEMP\.[A-Za-z]+"),
        ),
    ),
    Scheme(
        id="secureworks",
        label="Secureworks",
        doc="https://docs.taegis.secureworks.com/intelligence/threat_groups/",
        forms=("metal or alloy prefix + word, in capitals (IRON TWILIGHT, "
               "BRONZE UNION, GOLD BLACKBURN); retired: TG-NNNN"),
        patterns=(
            # Secureworks Taegis documentation, "Threat Groups": "Every time
            # a new Threat Group is identified, they are assigned a name
            # selected randomly from a list. Where that Threat Group is
            # attributed to a specific country or thematic area ... it will
            # be assigned a prefix that denotes that attribution"; the
            # METAL/ALLOY table lists the fifteen prefixes above. The names
            # are written in capitals; matching is case-sensitive so a
            # title-case name such as Trend Micro's "Iron Tiger" is not one.
            # https://docs.taegis.secureworks.com/intelligence/threat_groups/
            _full(rf"{_words(*SECUREWORKS_PREFIXES)} [A-Z][A-Z'\-]+"),
            # Same page: "In November 2016, CTU researchers began to
            # transition from a numeric Threat Group identification format
            # (e.g., TG-1234)"; ATT&CK also spells the number out
            # (Threat Group-3390, Threat Group 2889).
            _full(r"TG-\d{4}"),
            _full(r"Threat Group[- ]\d{4}"),
        ),
    ),
    Scheme(
        id="unit42",
        label="Unit 42",
        doc="https://unit42.paloaltonetworks.com/threat-actor-groups-tracked-by-palo-alto-networks-unit-42/",
        forms=("adjective + constellation (Stately Taurus, Fighting Ursa, "
               "Muddled Libra); CL-STA-NNNN; TGR-STA-NNNN"),
        patterns=(
            # "Threat Actor Groups Tracked by Palo Alto Networks Unit 42":
            # Draco (Pakistan), Lynx (Belarus), Pisces (North Korea), Serpens
            # (Iran), Taurus (China), Ursa (Russia), Libra (cybercrime),
            # Scorpius (ransomware).
            # https://unit42.paloaltonetworks.com/threat-actor-groups-tracked-by-palo-alto-networks-unit-42/
            _full(rf"{_ADJ} {_words(*UNIT42_CONSTELLATIONS)}", ci=True),
            # "Unit 42 Attribution Framework": activity clusters "using the
            # prefix CL- followed by a motivation tag and a unique number"
            # (CL-STA-0001); temporary groups "using the prefix TGR-"
            # (TGR-STA-0001). Motivation tags CRI, STA, MIX, UNK.
            # https://unit42.paloaltonetworks.com/unit-42-attribution-framework/
            _full(r"(?:CL|TGR)-(?:CRI|STA|MIX|UNK)-\d+"),
        ),
    ),
    Scheme(
        id="proofpoint",
        label="Proofpoint",
        doc="https://www.proofpoint.com/us/blog/threat-insight/one-email-closer-edge-unkmasstraction-physics-exploitation",
        forms="TAnnn; UNK_name",
        patterns=(
            # Proofpoint Threat Research, "One Email Closer to the Edge"
            # (2026): "Proofpoint uses the UNK_ designator to define clusters
            # of activity that are still developing and have not been
            # observed for long enough to receive a numerical TA
            # designation."
            # https://www.proofpoint.com/us/blog/threat-insight/one-email-closer-edge-unkmasstraction-physics-exploitation
            _full(r"TA\d{3,4}"),
            _full(r"UNK_[A-Za-z0-9]+"),
        ),
    ),
    Scheme(
        id="trendmicro",
        label="Trend Micro",
        doc="https://www.trendaisecurity.com/en-us/resources-insights/research/threat-attribution-framework-how-trendai-applies-structure-over-speculation",
        forms=("motivation element + creature (Earth Preta, Water Galura); "
               "SHADOW-EARTH-NNN"),
        patterns=(
            # TrendAI (Trend Micro), "Threat Attribution Framework": a final
            # intrusion-set name combines a classical element for the
            # motivation (Earth espionage, Water financial, Fire
            # destructive, Wind hacktivism, Void mixed) with a creature name
            # ("Earth Demon"); temporary names follow "SHADOW-ELEMENT-NUMBER"
            # (SHADOW-EARTH-007), Aether being used only there.
            # https://www.trendaisecurity.com/en-us/resources-insights/research/threat-attribution-framework-how-trendai-applies-structure-over-speculation
            _full(rf"{_words(*TREND_ELEMENTS)} {_ADJ}", ci=True),
            _full(r"SHADOW-(?:EARTH|WATER|FIRE|WIND|AETHER|VOID)-\d+",
                  ci=True),
        ),
    ),
    Scheme(
        id="ibm",
        label="IBM X-Force",
        doc=("https://www-api.ibm.com/adobe/assets/urn:aaid:aem:ecf46930-e212-4eb0-a01c-27586a3e89c6/"
             "original/as/ibm-security-x-force-threat-intelligence-index-2022-full-report.pdf"),
        forms="ITGnn; Hivennnn",
        patterns=(
            # IBM Security X-Force Threat Intelligence Index 2022, p. 30:
            # "IBM tracks and names threat groups numerically, identified by
            # IBM Threat Group (ITG) followed by an assigned number. For
            # threat groups still in the research phase, we use the
            # designation Hive, as in Hive0109".
            # https://www-api.ibm.com/adobe/assets/urn:aaid:aem:ecf46930-e212-4eb0-a01c-27586a3e89c6/original/as/ibm-security-x-force-threat-intelligence-index-2022-full-report.pdf
            _full(r"ITG\d+"),
            _full(r"Hive\d{4}", ci=True),
        ),
    ),
    Scheme(
        id="recordedfuture",
        label="Recorded Future",
        doc="https://www.recordedfuture.com/research/chinese-group-tag-22-targets-nepal-philippines-taiwan",
        forms="TAG-nn",
        patterns=(
            # Recorded Future Insikt Group reports name new clusters "using
            # the temporary name Threat Activity Group 22 (TAG-22)"; "Insikt
            # Group tracks this activity under the temporary group
            # designator TAG-56".
            # https://www.recordedfuture.com/research/chinese-group-tag-22-targets-nepal-philippines-taiwan
            # https://www.recordedfuture.com/research/suspected-iran-nexus-tag-56-uses-uae-forum-lure-for-credential-theft-against-us-think-tank
            _full(r"TAG-\d+"),
        ),
    ),
    Scheme(
        id="checkpoint",
        label="Check Point",
        doc="https://research.checkpoint.com/2023/educated-manticore-iran-aligned-threat-actor-targeting-israel-via-improved-arsenal-of-tools/",
        forms="adjective + Manticore (Educated Manticore)",
        patterns=(
            # Check Point Research, "Educated Manticore" (2023): "According
            # to the new convention, labeling threats as mythical creatures,
            # Iranian-aligned threats are Manticores." No other creature is
            # documented, so only Manticore has a rule.
            # https://research.checkpoint.com/2023/educated-manticore-iran-aligned-threat-actor-targeting-israel-via-improved-arsenal-of-tools/
            _full(rf"{_ADJ} Manticore", ci=True),
        ),
    ),
)

SCHEME_IDS = tuple(s.id for s in SCHEMES)
SCHEME_BY_ID = {s.id: s for s in SCHEMES}

# Names with a scheme's form that a cited publication shows another
# organisation coined. Keyed by the casefolded name; value = (the scheme
# whose form it has, the source).
EXCEPTIONS: dict[str, tuple[str, str]] = {
    # Trend Micro, "Operation Iron Tiger: Exploring Chinese Cyber-Espionage
    # Attacks on United States Defense Contractors" (September 2015).
    # https://securityaffairs.com/40199/cyber-crime/operation-iron-tiger.html
    "iron tiger": ("crowdstrike",
                   "Trend Micro, Operation Iron Tiger (2015)"),
    # ClearSky, "Fox Kitten Campaign: Widespread Iranian Espionage-Offensive
    # Campaign" (February 2020). CrowdStrike's name is Pioneer Kitten.
    # https://www.clearskysec.com/wp-content/uploads/2020/02/ClearSky-Fox-Kitten-Campaign.pdf
    "fox kitten": ("crowdstrike",
                   "ClearSky, Fox Kitten Campaign (2020)"),
    # "Operation Bleeding Bear": Ukraine's National Cyber Security
    # Coordination Center's name for the January 2022 WhisperGate attacks,
    # used by Elastic Security Labs.
    # https://www.elastic.co/security-labs/operation-bleeding-bear
    "bleeding bear": ("crowdstrike",
                      "Ukraine NCSCC / Elastic, Operation Bleeding Bear (2022)"),
}


@dataclass(frozen=True)
class Classification:
    status: str                       # one of STATUSES
    scheme: str | None = None         # set when status == CLASSIFIED
    candidates: tuple[str, ...] = ()  # AMBIGUOUS: the schemes that match;
                                      # EXCEPTION: the scheme whose form it has


def matching_schemes(name: str) -> tuple[str, ...]:
    """Ids of every scheme with a pattern matching the whole name, in table
    order."""
    s = name.strip()
    return tuple(sc.id for sc in SCHEMES
                 if any(p.match(s) for p in sc.patterns))


def classify(name: str) -> Classification:
    """The scheme whose documented form ``name`` has, or why there is none."""
    hit = matching_schemes(name)
    exc = EXCEPTIONS.get(name.strip().casefold())
    if exc is not None and exc[0] in hit:
        return Classification(EXCEPTION, None, (exc[0],))
    if len(hit) == 1:
        return Classification(CLASSIFIED, hit[0])
    if len(hit) > 1:
        return Classification(AMBIGUOUS, None, hit)
    return Classification(NO_RULE)
