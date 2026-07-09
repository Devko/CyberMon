"""CyberMon data pipeline.

Fetches open CVE-ecosystem data (cvelistV5, EPSS, CISA KEV, NVD status
counts), computes the pre-aggregated JSON files defined in
docs/data-contracts.md, validates them against pipeline/contracts.py, and
writes them into site/data/.

Run from the repo root:

    python -m pipeline --out site/data              # full nightly run
    python -m pipeline --out site/data --skip-nvd   # skip the slow NVD paging
    python -m pipeline --offline-fixtures --out tmp # CI smoke test, no network
"""

__version__ = "1.0.0"
