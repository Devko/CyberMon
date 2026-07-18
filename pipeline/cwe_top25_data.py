"""MITRE's published annual CWE Top 25 rankings — a small, hand-committed
static list (no upstream fetch).

This is the ONLY new "source" the CWE Top 25 module adds, and it is a
static hand-transcribed list rather than a nightly fetch: MITRE publishes
one Top-25 a year, as an HTML archive page, so a committed table is both
sufficient and auditable. Each year maps to the 25 CWE ids in official
rank order (rank 1 first). Regenerate by copying the next year's archive
page when MITRE publishes it.

Sources (verbatim rank order transcribed from these pages):
* 2024: https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html
* 2023: https://cwe.mitre.org/top25/archive/2023/2023_cwe_top25.html

The MITRE Top-25 methodology itself is derived from NVD CVEs joined to
CISA KEV, re-scored by a data-driven formula — so it is NOT an independent
oracle. That partial circularity is exactly why the module compares the
official *rank* against raw first-listed-CWE prevalence and KEV membership:
the DIVERGENCE from the published order is the story, not the list itself.
"""
from __future__ import annotations

# year -> the 25 CWE ids in official rank order (index 0 == rank 1).
OFFICIAL: dict[int, list[str]] = {
    2023: [
        "CWE-787", "CWE-79", "CWE-89", "CWE-416", "CWE-78", "CWE-20",
        "CWE-125", "CWE-22", "CWE-352", "CWE-434", "CWE-862", "CWE-476",
        "CWE-287", "CWE-190", "CWE-502", "CWE-77", "CWE-119", "CWE-798",
        "CWE-918", "CWE-306", "CWE-362", "CWE-269", "CWE-94", "CWE-863",
        "CWE-276",
    ],
    2024: [
        "CWE-79", "CWE-787", "CWE-89", "CWE-352", "CWE-22", "CWE-125",
        "CWE-78", "CWE-416", "CWE-862", "CWE-434", "CWE-94", "CWE-20",
        "CWE-77", "CWE-287", "CWE-269", "CWE-502", "CWE-200", "CWE-863",
        "CWE-918", "CWE-119", "CWE-476", "CWE-798", "CWE-190", "CWE-400",
        "CWE-306",
    ],
}

# Concise, chart-friendly names for every CWE that appears in any committed
# Top-25 above (the official MITRE names are far too long for an axis label).
# Ids not in this map fall back to their bare "CWE-N" — see cwe_name().
NAMES: dict[str, str] = {
    "CWE-20": "Improper input validation",
    "CWE-22": "Path traversal",
    "CWE-77": "Command injection",
    "CWE-78": "OS command injection",
    "CWE-79": "Cross-site scripting",
    "CWE-89": "SQL injection",
    "CWE-94": "Code injection",
    "CWE-119": "Memory-buffer bounds",
    "CWE-125": "Out-of-bounds read",
    "CWE-190": "Integer overflow",
    "CWE-200": "Sensitive info exposure",
    "CWE-269": "Improper privilege management",
    "CWE-276": "Incorrect default permissions",
    "CWE-287": "Improper authentication",
    "CWE-306": "Missing authentication",
    "CWE-352": "Cross-site request forgery",
    "CWE-362": "Race condition",
    "CWE-400": "Uncontrolled resource consumption",
    "CWE-416": "Use after free",
    "CWE-434": "Unrestricted file upload",
    "CWE-476": "NULL pointer dereference",
    "CWE-502": "Deserialization of untrusted data",
    "CWE-787": "Out-of-bounds write",
    "CWE-798": "Hard-coded credentials",
    "CWE-862": "Missing authorization",
    "CWE-863": "Incorrect authorization",
    "CWE-918": "Server-side request forgery (SSRF)",
}


def cwe_name(cwe_id: str) -> str:
    """Display name for a CWE id, the bare id when unmapped."""
    return NAMES.get(cwe_id, cwe_id)
