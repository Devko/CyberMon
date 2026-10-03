"""Run the claims audits against the last N committed nightly editions.

A claim that passes tonight but failed three nights ago has no headroom.
This extracts site/data from each recent data commit (cached by hash) and
runs pipeline/tests against it through CYBERMON_DATA_DIR, with the guards
and copy of the working tree. Prints one line per edition: its date and the
claims that fail on it.

    python tools/claims_history.py                  # last 14 editions
    python tools/claims_history.py --last 30 -k credits
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def editions(last: int) -> list[str]:
    out = subprocess.run(
        ["git", "log", f"-n{last}", "--format=%h", "--", "site/data/meta.json"],
        cwd=ROOT, check=True, capture_output=True, text=True).stdout
    return out.split()


def extract(commit: str, cache: Path) -> Path:
    data = cache / commit / "site" / "data"
    if (data / "meta.json").exists():
        return data
    blob = subprocess.run(["git", "archive", "--format=tar", commit,
                           "site/data"], cwd=ROOT, check=True,
                          capture_output=True).stdout
    with tarfile.open(fileobj=io.BytesIO(blob)) as tar:
        tar.extractall(cache / commit, filter="data")
    return data


def failures(data: Path, keyword: str | None) -> list[str]:
    cmd = [sys.executable, "-m", "pytest", "pipeline/tests", "-q",
           "-p", "no:cacheprovider", "-rf"]
    if keyword:
        cmd += ["-k", keyword]
    env = dict(os.environ, CYBERMON_DATA_DIR=str(data))
    out = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True,
                         text=True).stdout
    return [m.group(1) for m in re.finditer(r"^FAILED (\S+)", out, re.M)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--last", type=int, default=14)
    ap.add_argument("-k", dest="keyword", help="pytest -k expression")
    ap.add_argument("--cache-dir", type=Path, default=Path(
        tempfile.gettempdir()) / "cybermon-claims-history")
    args = ap.parse_args()
    bad = 0
    for commit in editions(args.last):
        data = extract(commit, args.cache_dir)
        stamp = json.loads((data / "meta.json").read_text("utf-8"))
        failed = failures(data, args.keyword)
        bad += bool(failed)
        print(f"{stamp['generated_at'][:10]} {commit}  "
              + ("ok" if not failed else f"{len(failed)} failing"))
        for test in failed:
            print(f"    {test.removeprefix('pipeline/tests/')}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
