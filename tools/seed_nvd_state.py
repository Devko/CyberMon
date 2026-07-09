"""Seed the NVD incremental-sync state from NVD's static yearly feeds.

The pipeline's NVD stage normally maintains ``.cache/nvd_status_state.json.gz``
incrementally via the API (see pipeline/fetch_nvd.py). The one expensive
operation is the initial full sweep — ~370k records through an API that, on
bad days, drips single pages for minutes (measured 2026-07-09: 58s per
2000-record page, with stalls that outlive any read-timeout).

This tool builds the same state file from NVD's static yearly JSON feeds
(https://nvd.nist.gov/feeds/json/cve/2.0/…), which are CDN-served flat
files: minutes instead of hours, no paging, no rate limits. Run it once
before the first real pipeline run (or any time the state is lost):

    python tools/seed_nvd_state.py [--cache-dir .cache]

The feeds regenerate nightly, so the seeded snapshot can be up to ~24h
stale; ``last_sync`` is therefore back-dated by FEED_STALENESS_H hours so
the pipeline's next incremental API pull re-covers the gap.
"""
from __future__ import annotations

import argparse
import gzip
import io
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.__main__ import _save_nvd_state  # noqa: E402

FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
FIRST_FEED_YEAR = 2002  # the 2002 feed carries 1999-2002
FEED_STALENESS_H = 25


def seed(cache_dir: Path) -> int:
    import requests

    session = requests.Session()
    session.headers["User-Agent"] = "CyberMon/1.0 (+https://github.com/Devko/CyberMon)"
    now = datetime.now(timezone.utc)
    statuses: dict[str, str] = {}

    for year in range(FIRST_FEED_YEAR, now.year + 1):
        url = FEED_URL.format(year=year)
        print(f"feed {year}: downloading ...", flush=True)
        resp = session.get(url, timeout=(10, 300))
        resp.raise_for_status()
        with gzip.open(io.BytesIO(resp.content), "rt", encoding="utf-8") as f:
            doc = json.load(f)
        n = 0
        for item in doc.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if cve_id:
                statuses[cve_id] = cve.get("vulnStatus") or "Unknown"
                n += 1
        total = doc.get("totalResults")
        if total is not None and total != n:
            print(f"  warning: feed says totalResults={total}, parsed {n}")
        print(f"  {n} records ({len(statuses)} cumulative)", flush=True)

    iso = "%Y-%m-%dT%H:%M:%SZ"
    state = {
        "version": 1,
        "last_full_sync": now.strftime(iso),
        # Back-dated: the feeds regenerate nightly, so the next incremental
        # API pull must re-cover up to a day of modifications.
        "last_sync": (now - timedelta(hours=FEED_STALENESS_H)).strftime(iso),
        "statuses": statuses,
    }
    _save_nvd_state(cache_dir, state)
    print(f"state written: {len(statuses)} CVEs -> {cache_dir}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Seed .cache NVD sync state from the static yearly feeds.")
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache"))
    sys.exit(seed(parser.parse_args().cache_dir))
