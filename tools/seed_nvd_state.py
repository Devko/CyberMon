"""Seed the NVD incremental-sync state from NVD's static yearly feeds.

The pipeline does this itself now — a missing/stale/unreadable
``.cache/nvd_status_state.json.gz`` makes pipeline/fetch_nvd.py run its
feed-based full sweep (minutes, CDN-served, no rate limits) instead of
paging the API. This tool is just that same sweep behind a CLI, for
warming or repairing the cache without running the whole pipeline:

    python tools/seed_nvd_state.py [--cache-dir .cache]

``last_sync`` in the written state is back-dated (see
``fetch_nvd.FEED_STALENESS``) because the feeds regenerate only nightly;
the pipeline's next incremental API pull re-covers the gap.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.__main__ import _save_nvd_state  # noqa: E402
from pipeline.fetch_nvd import full_sweep_state  # noqa: E402


def seed(cache_dir: Path) -> int:
    state = full_sweep_state()
    _save_nvd_state(cache_dir, state)
    print(f"state written: {len(state['statuses'])} CVEs -> {cache_dir}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Seed .cache NVD sync state from the static yearly feeds.")
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache"))
    sys.exit(seed(parser.parse_args().cache_dir))
