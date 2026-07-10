"""Security-product classifier for KEV vendor/product strings.

THE decision rule (also stated verbatim in the on-page methodology): a
KEV entry counts as a **security product** when the product's primary
function is security enforcement or secure access — the product exists
to protect, gate, or monitor other systems. Categories counted:

* firewalls / UTM / security gateways (Fortinet, SonicWall, Sophos,
  Check Point, WatchGuard, Palo Alto Networks, Zyxel firewalls, Cisco
  ASA/FTD, Juniper ScreenOS);
* VPN / secure-access appliances and the ADCs whose exploited
  deployments are secure-access gateways (Ivanti/Pulse Connect Secure,
  Citrix NetScaler/Gateway, F5 BIG-IP, Array Networks, Cisco AnyConnect);
* endpoint protection (Trend Micro, McAfee, Symantec, Sophos,
  Microsoft Defender / Forefront TMG);
* email/web security gateways (Barracuda ESG, Libraesva, SonicWall
  Email Security) — mail *servers* are not email *security*;
* identity / access management / PAM (Cisco ISE and ACS, BeyondTrust,
  ForgeRock AM, Micro Focus Access Manager);
* mobile device management (Omnissa Workspace ONE UEM,
  Ivanti EPMM/MobileIron, Sentry, Citrix
  XenMobile) — MDM ships as device-trust enforcement;
* security operations tooling (Netwrix Auditor, Wazuh, Aqua Security
  Trivy, Fortra Cobalt Strike);
* dedicated secure file-transfer appliances from security-portfolio
  vendors (Accellion FTA, Kiteworks, Fortra GoAnywhere, Soliton FileZen).

Judgment calls, drawn once and applied consistently (disagreements
welcome — the list below is data, reviewable in this repo; open an
issue or PR):

* **File transfer**: a secure-transfer appliance from a security vendor
  counts (Accellion, GoAnywhere, FileZen); file-transfer products of
  general software vendors do not (Progress MOVEit and WS_FTP, CrushFTP,
  Cleo, SolarWinds Serv-U). MOVEit is transfer, not security.
* **ADCs / load balancers**: F5 BIG-IP and Citrix NetScaler count —
  their KEV exploitation history is in the secure-access-gateway role;
  plain load balancing does not (Progress Kemp LoadMaster, Ivanti
  Virtual Traffic Manager).
* **Desktop/systems management is not MDM**: LANDESK-descended desktop
  management (Ivanti EPM), Quest KACE, Zoho Desktop Central and RMM
  suites (Kaseya VSA, N-able, ConnectWise ScreenConnect, SimpleHelp,
  TeamViewer) are IT operations tools, not security enforcement. Ivanti
  CSA counts: it is the internet-facing secure gateway of that estate,
  and it is exploited in that role.
* **Mail/collaboration servers** (Exchange, Zimbra, Roundcube, MDaemon,
  SmarterMail, Exim) are not security products; email *security
  gateways* are.
* **Network gear is not a guard**: routers, switches, WLAN and SD-WAN
  (Cisco IOS/SD-WAN, DrayTek/NETGEAR/D-Link VPN routers, MikroTik,
  Versa, Aviatrix, FatPipe) stay out even when they terminate VPNs —
  the gate is "sold primarily as security enforcement", not "has a
  crypto feature".
* **Physical security** (cameras, door controllers: Hikvision, Dahua,
  Nice eMerge) is out of scope — the module is about products guarding
  networks and hosts.
* **Zoho ManageEngine** is excluded wholesale: its exploited estate
  spans identity (ADSelfService Plus), UEM and ITSM, but the catalog's
  product field mostly says just "ManageEngine" — too coarse to split
  honestly, so it is left unclassified rather than guessed.
* **Backup/recovery** (Veeam, Commvault, Acronis, Arcserve, Veritas)
  is resilience, not enforcement — excluded.
* **Known coarse-label misses** (the classifier reads only
  vendor/product, never descriptions): Zyxel "Multiple Products"
  (CVE-2020-29583) is really the ZyWALL/USG firewall bug but stays
  unclassified. **Splunk Enterprise** (SIEM-adjacent, sold as a data
  platform) and **Twilio Authy** (consumer MFA) are deliberately
  excluded; **Palo Alto Expedition** (a config-migration tool) and
  **BeyondTrust Remote Support** (bundled with PRA/PAM) ride in on
  their wholesale vendors — the wholesale rule trades these edge cases
  for auditability.

Mechanics: :data:`SECURITY_VENDORS` lists vendors whose entire KEV
footprint is security products (matched on the trimmed, casefolded
``vendorProject``). :data:`PRODUCT_RULES` handles mixed vendors: the
entry counts only when the product string contains one of the vendor's
keywords (casefolded substring). Bump :data:`CLASSIFIER_VERSION` on any
change to either table so published data files carry the revision that
produced them.
"""
from __future__ import annotations

# Bump on ANY change to SECURITY_VENDORS or PRODUCT_RULES (the emitted
# kev_guards.json carries it, so a published number is traceable to the
# classifier revision that produced it).
CLASSIFIER_VERSION = 2

# Vendors whose entire KEV footprint is security products. Keys are
# trimmed + casefolded vendorProject values.
SECURITY_VENDORS = frozenset({
    # firewalls / UTM / security gateways
    "fortinet",
    "palo alto networks",
    "sonicwall",
    "sophos",
    "check point",
    "watchguard",
    # VPN / secure-access appliances (incl. ADCs in the gateway role)
    "pulse secure",
    "f5",
    "array networks",
    # endpoint protection
    "trend micro",
    "mcafee",
    # ThreatSonar Anti-Ransomware (EDR) is TeamT5's only KEV footprint
    "teamt5",
    "symantec",
    # email security gateways
    "barracuda",
    "barracuda networks",
    "libraesva",
    # identity / access management / PAM
    "beyondtrust",
    "forgerock",
    # mobile device management
    "mobileiron",
    # Workspace ONE UEM (AirWatch lineage) is Omnissa's only KEV footprint
    "omnissa",
    # security operations tooling (Fortra: GoAnywhere MFT + Cobalt Strike)
    "netwrix",
    "wazuh",
    "aquasecurity",
    "fortra",
    # dedicated secure file transfer from security-portfolio vendors
    "accellion",
    "kiteworks",
    "soliton systems k.k",
})

# Mixed vendors: the entry is a security product only when the product
# string contains one of these casefolded substrings.
PRODUCT_RULES: dict[str, tuple[str, ...]] = {
    # security products only — not IOS/routers/SD-WAN/UC/HyperFlex
    "cisco": (
        "adaptive security appliance",
        "firepower",
        "threat defense",
        "anyconnect",
        "identity services engine",
        "secure firewall",
        "secure access control system",
    ),
    # NetScaler estate + XenMobile — not ShareFile/StoreFront/Workspace
    "citrix": (
        "netscaler",
        "gateway",
        "application delivery controller",
        "xenmobile",
    ),
    # secure access + MDM — not Endpoint Manager (desktop) or the
    # Virtual Traffic Manager load balancer
    "ivanti": (
        "connect secure",
        "policy secure",
        "pulse",
        "zta",
        "epmm",
        "endpoint manager mobile",
        "mobileiron",
        "sentry",
        "cloud services appliance",
        "cloud service appliance",
    ),
    # the NetScreen firewall line — not Junos routers/switches
    "juniper": ("screenos",),
    # Defender + Forefront TMG — not Exchange/Windows/Office
    # "Malware Protection Engine" is Defender's scan engine (mpengine.dll)
    # even though the KEV label never says "Defender".
    "microsoft": ("defender", "forefront", "malware protection engine"),
    # IAM/SSO only — not vCenter/ESXi/Spring et al.
    "vmware": ("workspace one access", "identity manager"),
    # security appliances — not CPE routers/NAS
    "zyxel": ("firewall",),
    # Access Manager — not Operations Bridge Reporter
    "micro focus": ("access manager",),
}


def normalize_vendor(vendor: str) -> str:
    """Canonical grouping key for a KEV vendorProject value (the feed
    carries stray whitespace, e.g. ``"SimpleHelp "``)."""
    return " ".join(str(vendor).split())


def is_security_product(vendor: str, product: str) -> bool:
    """True when (vendor, product) classifies as a security product."""
    key = normalize_vendor(vendor).casefold()
    if key in SECURITY_VENDORS:
        return True
    keywords = PRODUCT_RULES.get(key)
    if not keywords:
        return False
    text = str(product).casefold()
    return any(kw in text for kw in keywords)


def rule_count() -> int:
    """Number of classifier rules (wholesale vendors + keyword vendors) —
    emitted alongside CLASSIFIER_VERSION for auditability."""
    return len(SECURITY_VENDORS) + len(PRODUCT_RULES)
