"""Generate synthetic sample data conforming to docs/data-contracts.md.

Lets the site be developed and demoed before the first real pipeline run.
meta.json carries "sample": true so the site shows its synthetic-data banner.
Deterministic on purpose: no randomness, just shaped curves.
"""
import csv
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "site" / "data"
GENERATED_AT = "2026-07-09T00:00:00Z"


def write(name: str, obj: dict) -> None:
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {path}")


def pub_count(year: int) -> int:
    """CVE volume: slow start, explosive recent growth."""
    base = {1999: 1579, 2005: 4931, 2010: 4639, 2015: 6480, 2017: 14645,
            2020: 18325, 2022: 25059, 2024: 40009, 2026: 52000}
    years = sorted(base)
    for lo, hi in zip(years, years[1:]):
        if lo <= year <= hi:
            f = (year - lo) / (hi - lo)
            return int(base[lo] + f * (base[hi] - base[lo]))
    return base[years[-1]]


def main() -> None:
    years = list(range(1999, 2027))

    # --- severity_inflation.json ---
    v2, v3, v4, blended = [], [], [], []
    for y in years:
        n = pub_count(y)
        scored = int(n * (0.95 if y < 2024 else 0.82))  # backlog bites recently
        if y <= 2017:
            v2.append({"year": y, "n": scored, "median": round(5.0 + (y - 1999) * 0.05, 1),
                       "p25": 4.3, "p75": round(6.8 + (y - 1999) * 0.04, 1)})
        if y >= 2016:
            med = min(7.5 + (y - 2016) * 0.05, 8.1)
            v3.append({"year": y, "n": scored if y > 2017 else scored // 2,
                       "median": round(med, 1), "p25": round(med - 1.4, 1),
                       "p75": round(med + 1.3, 1)})
        if y >= 2024:
            v4.append({"year": y, "n": int(scored * 0.15), "median": 7.3,
                       "p25": 5.9, "p75": 8.6})
        pct_hc = min(25.0 + (y - 1999) * 1.3, 60.0)
        med_b = 5.0 + (y - 1999) * 0.05 if y < 2016 else min(7.4 + (y - 2016) * 0.05, 8.0)
        blended.append({"year": y, "n": scored, "median": round(med_b, 1),
                        "pct_high_critical": round(pct_hc, 1)})
    write("severity_inflation.json", {
        "generated_at": GENERATED_AT,
        "series": {"v2": v2, "v3": v3, "v4": v4},
        "blended": blended,
        "annotations": [{"year": 2015, "label": "CVSS v3.0 released"},
                        {"year": 2023, "label": "CVSS v4.0 released"}],
        "headline": {"latest_year": 2026,
                     "pct_high_critical_latest": blended[-1]["pct_high_critical"],
                     "pct_high_critical_decade_ago": blended[-11]["pct_high_critical"]},
    })

    # --- nine_eight_flood.json ---
    flood = []
    for y in years:
        n = pub_count(y)
        crit_share = min(0.05 + (y - 1999) * 0.006, 0.21)
        high_share = min(0.20 + (y - 1999) * 0.007, 0.39)
        crit = int(n * crit_share)
        high = int(n * high_share)
        low = int(n * 0.06)
        unscored = int(n * (0.05 if y < 2024 else 0.18))
        flood.append({"year": y, "critical": crit, "high": high,
                      "medium": n - crit - high - low - unscored,
                      "low": low, "unscored": unscored})
    write("nine_eight_flood.json", {"generated_at": GENERATED_AT, "years": flood})

    # --- score_vs_reality.json ---
    cvss_buckets = ["0.1-3.9", "4.0-6.9", "7.0-8.9", "9.0-10.0"]
    epss_buckets = ["<0.1%", "0.1-1%", "1-10%", ">10%"]
    # rows: share of each cvss bucket falling in each epss bucket
    shape = {"0.1-3.9": [0.80, 0.15, 0.04, 0.01],
             "4.0-6.9": [0.68, 0.24, 0.06, 0.02],
             "7.0-8.9": [0.55, 0.30, 0.11, 0.04],
             "9.0-10.0": [0.52, 0.31, 0.11, 0.06]}
    totals = {"0.1-3.9": 14200, "4.0-6.9": 96100, "7.0-8.9": 92400, "9.0-10.0": 45210}
    grid = [{"cvss_bucket": cb, "epss_bucket": eb, "n": int(totals[cb] * share)}
            for cb in cvss_buckets for eb, share in zip(epss_buckets, shape[cb])]
    write("score_vs_reality.json", {
        "generated_at": GENERATED_AT,
        "grid": grid, "cvss_buckets": cvss_buckets, "epss_buckets": epss_buckets,
        "headline": {"pct_critical_epss_below_1pct": 83.0,
                     "n_critical_with_epss": totals["9.0-10.0"]},
        "kev": {"total": 1402, "below_high": 118, "pct_below_high": 8.4,
                "cvss_distribution": [{"bucket": b, "n": n} for b, n in
                                      zip(cvss_buckets, [21, 97, 772, 512])]},
    })

    # --- nvd_decay.json + history csv ---
    history = []
    backlog = 24000
    for m in range(1, 8):  # monthly-ish snapshots Jan..Jul 2026
        backlog += 1000 + m * 40
        history.append({"date": f"2026-{m:02d}-09", "backlog_total": backlog,
                        "awaiting_analysis": backlog - 690})
    hist_csv = OUT / "history" / "nvd_backlog.csv"
    hist_csv.parent.mkdir(parents=True, exist_ok=True)
    with hist_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["date", "backlog_total", "awaiting_analysis",
                    "undergoing_analysis", "received"])
        for h in history:
            w.writerow([h["date"], h["backlog_total"], h["awaiting_analysis"], 400, 290])
    print(f"wrote {hist_csv}")
    write("nvd_decay.json", {
        "generated_at": GENERATED_AT,
        "current": {"statuses": [
            {"status": "Awaiting Analysis", "n": history[-1]["awaiting_analysis"]},
            {"status": "Undergoing Analysis", "n": 400},
            {"status": "Received", "n": 290}],
            "backlog_total": history[-1]["backlog_total"]},
        "history": history,
    })

    # --- cna_leaderboard.json ---
    cnas = [("VendorX_S", "VendorX Security", 412, 8.9, 9.1, 48.2, 88.1),
            ("PatchCo", "PatchCo Ltd.", 233, 8.4, 8.8, 39.5, 81.0),
            ("BigCloud", "BigCloud Inc.", 1890, 7.8, 8.0, 24.6, 63.2),
            ("GitHub_M", "GitHub, Inc. (sample)", 1234, 7.9, 8.1, 22.4, 61.0),
            ("distro-sec", "Distro Security Team", 902, 6.1, 6.3, 4.1, 31.7),
            ("mitre", "MITRE Corporation", 3010, 6.6, 6.8, 9.8, 44.0)]
    write("cna_leaderboard.json", {
        "generated_at": GENERATED_AT, "window_years": 3, "min_cves": 100,
        "cnas": sorted([{"cna": c, "org": o, "n": n, "avg_cvss": a,
                         "median_cvss": m, "pct_geq_9": p9, "pct_geq_7": p7}
                        for c, o, n, a, m, p9, p7 in cnas],
                       key=lambda r: -r["pct_geq_9"]),
    })

    # --- volume_curve.json ---
    write("volume_curve.json", {
        "generated_at": GENERATED_AT,
        "years": [{"year": y, "published": pub_count(y),
                   "rejected": int(pub_count(y) * 0.015)} for y in years],
    })

    # --- meta.json ---
    write("meta.json", {
        "generated_at": GENERATED_AT,
        "sample": True,
        "sources": {
            "cvelist": {"release": "sample", "cve_count": 251342},
            "epss": {"model_version": "v4", "score_date": "2026-07-08", "row_count": 248101},
            "kev": {"catalog_version": "2026.07.08", "count": 1402},
            "nvd": {"fetched_at": GENERATED_AT},
        },
    })


if __name__ == "__main__":
    main()
