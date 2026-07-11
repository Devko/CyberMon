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

from . import (attack_metrics, breach_metrics, calendar_metrics,
               concentration_metrics, contracts, epss_report_metrics,
               extortion_metrics, guards_metrics, history, hygiene_metrics,
               kev_changelog, kev_metrics, market_metrics, metrics,
               quality_metrics)
from .fetch_cvelist import (download_zip, iter_cve_records,
                            iter_cve_records_from_dir, latest_release)
from .fetch_epss import EpssData, fetch_epss, load_epss_file
from .fetch_hibp import HibpData, fetch_hibp, load_hibp_file
from .fetch_kev import KevData, fetch_kev, load_kev_file
from .fetch_ransomwhere import fetch_ransomwhere, load_ransomwhere_file

FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures"
DEFAULT_MIN_CVES = 100
DEFAULT_MIN_REJECTION_N = 50


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
    parser.add_argument("--skip-market", action="store_true",
                        help="skip the market-hype fetch stage; carry the "
                             "previous market_hype.json forward (marked stale)")
    parser.add_argument("--market-backfill-batch", type=int, default=8,
                        help="max HN backfill requests per run (default: 8; "
                             "raise for a one-off accelerated backfill)")
    parser.add_argument("--skip-attack", action="store_true",
                        help="skip the ATT&CK index fetch; carry the previous "
                             "attack_churn.json forward (marked stale)")
    parser.add_argument("--skip-epss-report", action="store_true",
                        help="skip the EPSS day-before lookups; carry the "
                             "previous epss_report.json forward (marked "
                             "stale)")
    parser.add_argument("--kev-changelog-backfill", type=int, default=0,
                        help="max Wayback KEV-capture fetches this run "
                             "(default: 0 — the archive is never contacted; "
                             "the one-time historical backfill is run "
                             "manually with a large value, e.g. 200, before "
                             "the first live diff)")
    parser.add_argument("--epss-backfill-batch", type=int, default=30,
                        help="max EPSS day-before lookups per run (default: "
                             "30 — a nightly needs a handful; the one-time "
                             "historical backfill is run manually with a "
                             "large value, e.g. 2000)")
    parser.add_argument("--window-years", type=int, default=3,
                        help="CNA leaderboard window (default: 3)")
    parser.add_argument("--min-cves", type=int, default=None,
                        help="CNA leaderboard volume threshold (default: "
                             f"{DEFAULT_MIN_CVES}; 1 in fixture mode)")
    parser.add_argument("--concentration-window-years", type=int, default=5,
                        help="CNA rejection leaderboard window (default: 5)")
    parser.add_argument("--min-rejection-n", type=int, default=None,
                        help="rejection leaderboard volume threshold "
                             f"(default: {DEFAULT_MIN_REJECTION_N}; "
                             "1 in fixture mode)")
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


def _nvd_state_path(cache_dir: Path) -> Path:
    return cache_dir / "nvd_status_state.json.gz"


def _load_nvd_state(cache_dir: Path) -> dict | None:
    """Cached NVD sync state, or None when absent/unreadable (the sync
    then falls back to a full sweep — the state is only ever a cache)."""
    import gzip

    path = _nvd_state_path(cache_dir)
    if not path.exists():
        return None
    try:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as exc:
        print(f"warning: ignoring unreadable NVD state {path}: {exc!r}")
        return None


def _save_nvd_state(cache_dir: Path, state: dict) -> None:
    import gzip

    path = _nvd_state_path(cache_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with gzip.open(tmp, "wt", encoding="utf-8") as f:
        json.dump(state, f, separators=(",", ":"))
    tmp.replace(path)


def _gather_nvd(args: argparse.Namespace) -> dict[str, int] | None:
    """Fresh NVD status counts, or None when the stage is skipped."""
    if args.skip_nvd:
        return None
    if args.offline_fixtures:
        return json.loads((FIXTURES_DIR / "nvd_statuses.json")
                          .read_text(encoding="utf-8"))
    from .fetch_nvd import status_counts, sync_status_state

    api_key = os.environ.get("NVD_API_KEY") or None
    print(f"syncing NVD status counts ({'keyed' if api_key else 'keyless'}) ...")
    state = sync_status_state(_load_nvd_state(args.cache_dir), api_key=api_key)
    _save_nvd_state(args.cache_dir, state)
    return status_counts(state)


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
        hibp = load_hibp_file(FIXTURES_DIR / "hibp_breaches.json")
        ransomwhere = load_ransomwhere_file(FIXTURES_DIR / "ransomwhere.json")
    else:
        print("fetching EPSS scores ...")
        epss = fetch_epss()
        print(f"  EPSS {epss.model_version} @ {epss.score_date}: "
              f"{epss.row_count} rows")
        print("fetching CISA KEV catalog ...")
        kev = fetch_kev()
        print(f"  KEV {kev.catalog_version}: {kev.count} entries")
        print("fetching HIBP breach catalog ...")
        hibp = fetch_hibp()
        print(f"  HIBP: {hibp.breach_count} breaches")
        print("fetching Ransomwhere export ...")
        ransomwhere = fetch_ransomwhere()
        print(f"  Ransomwhere: {ransomwhere.address_count} addresses, "
              f"{ransomwhere.tx_count} transactions")
    nvd_statuses = _gather_nvd(args)

    # ---- aggregate (single streaming pass over the corpus) ---------------
    print("aggregating CVE corpus ...")
    agg = metrics.Aggregator(kev_ids=kev.cve_ids)
    agg.consume(records)
    print(f"  {agg.cve_count} CVE records aggregated")
    if agg.cve_count == 0:
        print("error: no CVE records found; refusing to emit empty charts",
              file=sys.stderr)
        return 1

    # ---- build -----------------------------------------------------------
    min_cves = args.min_cves if args.min_cves is not None else \
        (1 if args.offline_fixtures else DEFAULT_MIN_CVES)
    # Fixture corpora are tiny; disable the hero chart's statistical filters
    # there (the real thresholds are exercised by unit tests).
    inflation_kwargs = {"min_n": 1, "min_share": 0.0} \
        if args.offline_fixtures else {}
    outputs: dict[str, dict] = {
        "severity_inflation.json":
            metrics.build_severity_inflation(agg, generated_at,
                                             **inflation_kwargs),
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
        "kev_latency.json":
            kev_metrics.build_kev_latency(
                agg, kev.entries, generated_at,
                **({"min_n": 1} if args.offline_fixtures else {})),
        "cna_concentration.json":
            concentration_metrics.build_cna_concentration(
                agg, generated_at,
                window_years=args.concentration_window_years,
                min_total=args.min_rejection_n
                if args.min_rejection_n is not None else
                (1 if args.offline_fixtures else DEFAULT_MIN_REJECTION_N)),
        "advisory_quality.json":
            quality_metrics.build_advisory_quality(
                agg, generated_at,
                **({"min_n": 1} if args.offline_fixtures else {})),
        "cwe_distribution.json":
            quality_metrics.build_cwe_distribution(
                agg, generated_at,
                **({"min_n": 1} if args.offline_fixtures else {})),
        "kev_ransomware.json":
            kev_metrics.build_kev_ransomware(
                kev.entries, generated_at,
                **({"min_n": 1} if args.offline_fixtures else {})),
        "kev_guards.json":
            guards_metrics.build_kev_guards(
                kev.entries, generated_at,
                **({"min_n": 1, "min_vendor_entries": 1}
                   if args.offline_fixtures else {})),
        "breach_ledger.json":
            breach_metrics.build_breach_ledger(
                hibp.breaches, generated_at,
                **({"min_n": 1} if args.offline_fixtures else {})),
        "extortion_ledger.json":
            extortion_metrics.build_extortion_ledger(
                ransomwhere, generated_at,
                **({"min_n": 1} if args.offline_fixtures else {})),
        "cve_calendar.json":
            calendar_metrics.build_cve_calendar(
                agg, generated_at,
                **({"min_n": 1} if args.offline_fixtures else {})),
    }
    nvd_decay, nvd_source, history_rows = _nvd_outputs(
        args, nvd_statuses, generated_at)
    if nvd_decay is not None:
        outputs["nvd_decay.json"] = nvd_decay
    market_hype, market_source = market_metrics.run_stage(
        args.out, args.cache_dir, generated_at,
        skip=args.skip_market, offline_fixtures=args.offline_fixtures,
        backfill_batch=args.market_backfill_batch)
    if market_hype is not None:
        outputs["market_hype.json"] = market_hype
    attack_churn, attack_source = attack_metrics.run_stage(
        args.out, args.cache_dir, generated_at,
        skip=args.skip_attack, offline_fixtures=args.offline_fixtures)
    if attack_churn is not None:
        outputs["attack_churn.json"] = attack_churn
    epss_report, epss_history_source = epss_report_metrics.run_stage(
        args.out, args.cache_dir, generated_at,
        kev_entries=kev.entries,
        published_dates=agg.kev_published_dates,
        current_model_version=epss.model_version,
        skip=args.skip_epss_report,
        offline_fixtures=args.offline_fixtures,
        backfill_batch=args.epss_backfill_batch)
    if epss_report is not None:
        outputs["epss_report.json"] = epss_report
    # No skip flag and no carried-forward staleness: upstream publishes
    # its full history, so this stage is a cheap stateless refetch.
    dnssec_adoption, apnic_source = hygiene_metrics.run_stage(
        generated_at, offline_fixtures=args.offline_fixtures)
    outputs["dnssec_adoption.json"] = dnssec_adoption
    # KEV changelog: diffs the fresh catalog against the committed state.
    # No skip flag (the KEV fetch it rides on has none either); its
    # history writes are deferred to after validation, like nvd_backlog.
    changelog, changelog_source, changelog_pending = \
        kev_changelog.run_stage(
            args.out, args.cache_dir, generated_at,
            kev_entries=kev.entries,
            offline_fixtures=args.offline_fixtures,
            backfill_batch=args.kev_changelog_backfill)
    outputs["kev_changelog.json"] = changelog
    outputs["meta.json"] = metrics.build_meta(
        generated_at,
        cvelist_release=release, cve_count=agg.cve_count,
        epss_model_version=epss.model_version,
        epss_score_date=epss.score_date, epss_row_count=epss.row_count,
        kev_catalog_version=kev.catalog_version, kev_count=kev.count,
        nvd_source=nvd_source)
    if market_source is not None:
        outputs["meta.json"]["sources"]["market"] = market_source
    outputs["meta.json"]["sources"]["hibp"] = {
        "fetched_at": generated_at, "breach_count": hibp.breach_count}
    outputs["meta.json"]["sources"]["ransomwhere"] = {
        "fetched_at": generated_at,
        "address_count": ransomwhere.address_count,
        "tx_count": ransomwhere.tx_count,
    }
    if attack_source is not None:
        outputs["meta.json"]["sources"]["attack"] = attack_source
    if epss_history_source is not None:
        outputs["meta.json"]["sources"]["epss_history"] = \
            epss_history_source
    outputs["meta.json"]["sources"]["apnic"] = apnic_source
    outputs["meta.json"]["sources"]["kev_changelog"] = changelog_source

    # ---- validate everything, then write ----------------------------------
    for name, obj in outputs.items():
        contracts.validate(name, obj)  # ContractViolation = loud failure
    args.out.mkdir(parents=True, exist_ok=True)
    if history_rows is not None:
        csv_path = args.out / "history" / "nvd_backlog.csv"
        history.write_rows(csv_path, history_rows)
        print(f"  history: {len(history_rows)} snapshot(s) in {csv_path}")
    # KEV changelog history (event CSV + fingerprint state): written only
    # here, after every output above validated — same discipline as the
    # NVD history; both files are irreplaceable records.
    kev_changelog.persist(args.out, changelog_pending)
    for name, obj in outputs.items():
        path = args.out / name
        path.write_text(json.dumps(obj, indent=1) + "\n", encoding="utf-8")
        print(f"wrote {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
