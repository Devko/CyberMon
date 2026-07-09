"""CLI entry point: ``python -m pipeline --out site/data [flags]``.

Stages: fetch (cvelistV5 zip, EPSS, KEV, NVD status counts) -> aggregate
(one streaming pass over the CVE corpus) -> build the six chart files +
meta.json -> validate every output against pipeline/contracts.py -> write.
Nothing is written unless *all* outputs validate.

``--offline-fixtures`` runs the identical metrics/validate/write path from
the test fixtures in pipeline/tests/fixtures — the no-network CI smoke test.

``--skip-nvd`` behavior (documented choice): the NVD stage is the only slow
one, so when skipped we carry the previous run's ``nvd_decay.json`` forward
untouched (no new history row is appended — a duplicated snapshot would
fake data the ecosystem never produced), mark it and ``meta.sources.nvd``
with ``"stale": true``, and keep ``fetched_at`` at its old value. If no
previous file exists, ``nvd_decay.json`` is omitted for this run and
``meta.json`` omits ``sources.nvd`` (contracts.py allows that).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from . import contracts, history, metrics
from .fetch_cvelist import (download_zip, iter_cve_records,
                            iter_cve_records_from_dir, latest_release)
from .fetch_epss import EpssData, fetch_epss, load_epss_file
from .fetch_kev import KevData, fetch_kev, load_kev_file

FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures"
DEFAULT_MIN_CVES = 100


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m pipeline",
        description="CyberMon data pipeline: fetch, aggregate, validate, emit.")
    parser.add_argument("--out", required=True, type=Path,
                        help="output directory (normally site/data)")
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache"),
                        help="download cache directory (default: .cache)")
    parser.add_argument("--skip-nvd", action="store_true",
                        help="skip the slow NVD paging; carry the previous "
                             "nvd_decay.json forward (marked stale)")
    parser.add_argument("--offline-fixtures", action="store_true",
                        help="run entirely from pipeline/tests/fixtures "
                             "(no network; CI smoke test)")
    parser.add_argument("--window-years", type=int, default=3,
                        help="CNA leaderboard window (default: 3)")
    parser.add_argument("--min-cves", type=int, default=None,
                        help="CNA leaderboard volume threshold (default: "
                             f"{DEFAULT_MIN_CVES}; 1 in fixture mode)")
    return parser.parse_args(argv)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _gather_records(args: argparse.Namespace) -> tuple[str, Iterator[dict]]:
    """Return (release label, streaming record iterator) for the corpus."""
    if args.offline_fixtures:
        return "fixtures", iter_cve_records_from_dir(FIXTURES_DIR / "cvelist")
    print("fetching cvelistV5 latest release ...")
    tag, url = latest_release()
    zip_path = download_zip(args.cache_dir, tag, url)
    print(f"  release {tag} -> {zip_path}")
    return tag, iter_cve_records(zip_path)


def _gather_nvd(args: argparse.Namespace) -> dict[str, int] | None:
    """Fresh NVD status counts, or None when the stage is skipped."""
    if args.skip_nvd:
        return None
    if args.offline_fixtures:
        return json.loads((FIXTURES_DIR / "nvd_statuses.json")
                          .read_text(encoding="utf-8"))
    from .fetch_nvd import fetch_status_counts

    api_key = os.environ.get("NVD_API_KEY") or None
    print(f"fetching NVD status counts ({'keyed' if api_key else 'keyless'}, "
          "this is the slow stage) ...")
    return fetch_status_counts(api_key=api_key)


def _nvd_outputs(args: argparse.Namespace, statuses: dict[str, int] | None,
                 generated_at: str
                 ) -> tuple[dict | None, dict | None, list[dict] | None]:
    """(nvd_decay.json object or None, meta.sources.nvd object or None,
    merged history rows to persist or None).

    Fresh statuses: merge today's history row in memory (last run per date
    wins) and build from the merged history — the CSV itself is only
    written by run() after every output validates. Skipped: carry forward,
    see module docstring.
    """
    if statuses is not None:
        csv_path = args.out / "history" / "nvd_backlog.csv"
        rows = history.merge_row(history.read_rows(csv_path),
                                 metrics.backlog_row(statuses, _today()))
        return (metrics.build_nvd_decay(statuses, rows, generated_at),
                {"fetched_at": generated_at}, rows)

    prior_path = args.out / "nvd_decay.json"
    if not prior_path.exists():
        print("warning: --skip-nvd with no previous nvd_decay.json; "
              "omitting nvd_decay.json and meta.sources.nvd this run")
        return None, None, None
    prior = json.loads(prior_path.read_text(encoding="utf-8"))
    fetched_at = prior.get("generated_at", generated_at)
    carried = dict(prior)
    carried["generated_at"] = generated_at
    carried["stale"] = True
    print(f"  --skip-nvd: carrying forward nvd_decay.json from {fetched_at}")
    return carried, {"fetched_at": fetched_at, "stale": True}, None


def run(args: argparse.Namespace) -> int:
    generated_at = _now_iso()

    # ---- gather ----------------------------------------------------------
    release, records = _gather_records(args)
    if args.offline_fixtures:
        epss = load_epss_file(FIXTURES_DIR / "epss_scores.csv")
        kev = load_kev_file(FIXTURES_DIR / "kev.json")
    else:
        print("fetching EPSS scores ...")
        epss = fetch_epss()
        print(f"  EPSS {epss.model_version} @ {epss.score_date}: "
              f"{epss.row_count} rows")
        print("fetching CISA KEV catalog ...")
        kev = fetch_kev()
        print(f"  KEV {kev.catalog_version}: {kev.count} entries")
    nvd_statuses = _gather_nvd(args)

    # ---- aggregate (single streaming pass over the corpus) ---------------
    print("aggregating CVE corpus ...")
    agg = metrics.Aggregator()
    agg.consume(records)
    print(f"  {agg.cve_count} CVE records aggregated")
    if agg.cve_count == 0:
        print("error: no CVE records found; refusing to emit empty charts",
              file=sys.stderr)
        return 1

    # ---- build -----------------------------------------------------------
    min_cves = args.min_cves if args.min_cves is not None else \
        (1 if args.offline_fixtures else DEFAULT_MIN_CVES)
    outputs: dict[str, dict] = {
        "severity_inflation.json":
            metrics.build_severity_inflation(agg, generated_at),
        "nine_eight_flood.json":
            metrics.build_nine_eight_flood(agg, generated_at),
        "score_vs_reality.json":
            metrics.build_score_vs_reality(agg, epss.scores, kev.cve_ids,
                                           generated_at),
        "cna_leaderboard.json":
            metrics.build_cna_leaderboard(agg, generated_at,
                                          window_years=args.window_years,
                                          min_cves=min_cves),
        "volume_curve.json": metrics.build_volume_curve(agg, generated_at),
    }
    nvd_decay, nvd_source, history_rows = _nvd_outputs(
        args, nvd_statuses, generated_at)
    if nvd_decay is not None:
        outputs["nvd_decay.json"] = nvd_decay
    outputs["meta.json"] = metrics.build_meta(
        generated_at,
        cvelist_release=release, cve_count=agg.cve_count,
        epss_model_version=epss.model_version,
        epss_score_date=epss.score_date, epss_row_count=epss.row_count,
        kev_catalog_version=kev.catalog_version, kev_count=kev.count,
        nvd_source=nvd_source)

    # ---- validate everything, then write ----------------------------------
    for name, obj in outputs.items():
        contracts.validate(name, obj)  # ContractViolation = loud failure
    args.out.mkdir(parents=True, exist_ok=True)
    if history_rows is not None:
        csv_path = args.out / "history" / "nvd_backlog.csv"
        history.write_rows(csv_path, history_rows)
        print(f"  history: {len(history_rows)} snapshot(s) in {csv_path}")
    for name, obj in outputs.items():
        path = args.out / name
        path.write_text(json.dumps(obj, indent=1) + "\n", encoding="utf-8")
        print(f"wrote {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
