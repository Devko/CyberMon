"""The package universe behind Open-Source Maintainers (module 30).

Which packages count as "the software everyone depends on" is the
module's methodological landmine, so the answer is a written, versioned
rule applied once per edition and frozen in a committed file
(``pipeline/oss_universe.json``). The nightly never re-ranks anything: it
only re-reads, for this fixed list, who can publish each package and how
its source repository scores on OpenSSF Scorecard.

Inclusion rule, version 1 (edition 2026-11)
-------------------------------------------

For each of four registries (npm, PyPI, crates.io, RubyGems):

1. Rank the registry's packages by ecosyste.ms's ``dependent_packages_count``
   (``GET packages.ecosyste.ms/api/v1/registries/<registry>/package_names
   ?sort=dependent_packages_count&order=desc``): the number of packages in
   the same registry with at least one published version that declares a
   dependency on it, of any kind (runtime, development, optional).
2. Walk that ranking from the top and keep a package only if it is also
   among the registry's :data:`DOWNLOAD_FLOOR` most-downloaded packages in
   ecosyste.ms's download ranking (``sort=downloads``). The floor exists
   because a dependent count is easy to inflate: on 2026-11-05, 598 of the
   first 848 RubyGems names by dependents were generated spam
   (``jagger_*_test`` and similar rings that depend on each other), and
   PyPI's top 260 held two such rings and a placeholder project.
3. Stop at :data:`PER_ECOSYSTEM` kept packages.

Each kept package's source repository is ecosyste.ms's ``repository_url``
at selection time, kept only when it is a GitHub repository (OpenSSF
Scorecard's public results cover GitHub); otherwise ``repo`` is null.

The list is frozen per edition. Changing the rule bumps
:data:`RULE_VERSION`; re-running it on a later date starts a new
:data:`EDITION`. Both are printed on the page. The nightly state is keyed
by the edition, so a new list starts a fresh observation cycle.

Licence: the ranking comes from ecosyste.ms, whose data is CC BY-SA 4.0
("attributing 'ecosyste.ms' as the source of data"). The committed list
is an adaptation and is shared under the same licence; README and the page
footer carry the attribution. The ecosyste.ms API is public and documents
its rate-limit pools (api page, checked 2026-11-05); selection is a
one-off of about 70 requests, never part of the nightly.

Re-select (network; review the diff before committing)::

    python -m pipeline.oss_universe --write
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

RULE_VERSION = 1
EDITION = "2026-11"
PER_ECOSYSTEM = 250
DOWNLOAD_FLOOR = 5000

# Data key -> ecosyste.ms registry name. The data key is what every output
# and the page use; display names live in editorial.js.
ECOSYSTEMS: dict[str, str] = {
    "npm": "npmjs.org",
    "pypi": "pypi.org",
    "crates": "crates.io",
    "rubygems": "rubygems.org",
}

UNIVERSE_PATH = Path(__file__).resolve().parent / "oss_universe.json"
ECOSYSTEMS_API = "https://packages.ecosyste.ms/api/v1"
SOURCE = "ecosyste.ms Packages API"
LICENSE = "CC BY-SA 4.0 (adapted from ecosyste.ms data)"

_NAMES_PAGE = 1000      # ecosyste.ms per_page ceiling for package_names
_DEPENDENTS_DEPTH = 3000  # how far down the dependents ranking to read
_BULK_BATCH = 25        # purls per bulk_lookup request (each ~180 KB)

_PURL_TYPE = {"npm": "npm", "pypi": "pypi", "crates": "cargo",
              "rubygems": "gem"}

_GITHUB_RE = re.compile(
    r"^(?:git\+)?(?:https?|git|ssh)?:?/*(?:git@)?(?:www\.)?github\.com[/:]"
    r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?(?:[#?/].*)?$")


def normalize_repo(url: object) -> str | None:
    """``github.com/<owner>/<repo>`` for a GitHub repository URL in any of
    the spellings registries carry (``git+https://…git``, ``git@github.com:
    …``, trailing ``/tree/main``), else None. Case is kept as given: GitHub
    and the Scorecard API resolve it either way."""
    if not isinstance(url, str):
        return None
    m = _GITHUB_RE.match(url.strip())
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    if owner in (".", "..") or repo in (".", ".."):
        return None
    return f"github.com/{owner}/{repo}"


@dataclass(frozen=True)
class UniversePackage:
    ecosystem: str
    name: str
    repo: str | None

    @property
    def key(self) -> str:
        return f"{self.ecosystem}/{self.name}"


@dataclass(frozen=True)
class Universe:
    edition: str
    rule_version: int
    selected_at: str
    per_ecosystem: int
    download_floor: int
    packages: tuple[UniversePackage, ...]

    def by_ecosystem(self, eco: str) -> list[UniversePackage]:
        return [p for p in self.packages if p.ecosystem == eco]


def parse_universe(obj: object) -> Universe:
    """Validate a universe document strictly: the list is the module's
    denominator, so a malformed file must fail loudly, never shrink it."""
    if not isinstance(obj, dict):
        raise ValueError("oss universe: expected an object")
    for key in ("edition", "rule_version", "selected_at", "per_ecosystem",
                "download_floor", "ecosystems"):
        if key not in obj:
            raise ValueError(f"oss universe: missing {key!r}")
    per = obj["per_ecosystem"]
    if isinstance(per, bool) or not isinstance(per, int) or per < 1:
        raise ValueError("oss universe: per_ecosystem must be a positive int")
    ecos = obj["ecosystems"]
    if not isinstance(ecos, dict) or set(ecos) != set(ECOSYSTEMS):
        raise ValueError(f"oss universe: ecosystems must be exactly "
                         f"{sorted(ECOSYSTEMS)}")
    packages: list[UniversePackage] = []
    for eco in ECOSYSTEMS:
        rows = ecos[eco]
        if not isinstance(rows, list) or len(rows) != per:
            raise ValueError(f"oss universe: {eco} must list exactly {per} "
                             f"packages")
        seen: set[str] = set()
        for i, row in enumerate(rows):
            if not isinstance(row, dict):
                raise ValueError(f"oss universe: {eco}[{i}] is not an object")
            name = row.get("name")
            repo = row.get("repo")
            if not isinstance(name, str) or not name.strip():
                raise ValueError(f"oss universe: {eco}[{i}] has no name")
            if name in seen:
                raise ValueError(f"oss universe: {eco} lists {name!r} twice")
            seen.add(name)
            if repo is not None and normalize_repo("https://" + str(repo)) \
                    != repo:
                raise ValueError(f"oss universe: {eco}/{name}: repo "
                                 f"{repo!r} is not github.com/<owner>/<repo>")
            packages.append(UniversePackage(eco, name, repo))
    return Universe(
        edition=str(obj["edition"]),
        rule_version=int(obj["rule_version"]),
        selected_at=str(obj["selected_at"]),
        per_ecosystem=per,
        download_floor=int(obj["download_floor"]),
        packages=tuple(packages),
    )


def load_universe(path: Path = UNIVERSE_PATH) -> Universe:
    return parse_universe(json.loads(Path(path).read_text(encoding="utf-8")))


# --------------------------------------------------------------- selection

def _names(session, registry: str, sort: str, depth: int, *, sleep,
           log) -> list[str]:
    from .fetch_http import get_with_retry

    names: list[str] = []
    page = 1
    while len(names) < depth:
        resp = get_with_retry(
            session, f"{ECOSYSTEMS_API}/registries/{registry}/package_names",
            label="ecosyste.ms",
            params={"sort": sort, "order": "desc", "per_page": _NAMES_PAGE,
                    "page": page},
            timeout=180, sleep=sleep, log=log)
        batch = resp.json()
        if not isinstance(batch, list) or not all(
                isinstance(n, str) for n in batch):
            raise ValueError(f"ecosyste.ms: {registry} {sort} page {page} "
                             f"is not a list of names")
        if not batch:
            break
        names.extend(batch)
        page += 1
        sleep(1.0)
    return names[:depth]


def _repos(session, eco: str, names: list[str], *, sleep, log
           ) -> dict[str, str | None]:
    from .fetch_http import USER_AGENT

    out: dict[str, str | None] = {}
    for i in range(0, len(names), _BULK_BATCH):
        chunk = names[i:i + _BULK_BATCH]
        purls = [f"pkg:{_PURL_TYPE[eco]}/{n}" for n in chunk]
        resp = session.post(f"{ECOSYSTEMS_API}/packages/bulk_lookup",
                            json={"purls": purls},
                            headers={"User-Agent": USER_AGENT}, timeout=180)
        resp.raise_for_status()
        rows = resp.json()
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and row.get("name") in chunk:
                out[row["name"]] = normalize_repo(row.get("repository_url"))
        log(f"  {eco}: repositories {min(i + _BULK_BATCH, len(names))}"
            f"/{len(names)}")
        sleep(1.0)
    return {n: out.get(n) for n in names}


def select(session=None, *, sleep=time.sleep,
           log: Callable[[str], None] = print, today: str | None = None
           ) -> dict:
    """Apply the inclusion rule against ecosyste.ms and return the universe
    document (see the module docstring). Network; never run nightly."""
    import requests

    session = session or requests.Session()
    today = today or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    ecos: dict[str, list[dict]] = {}
    dropped: dict[str, int] = {}
    for eco, registry in ECOSYSTEMS.items():
        log(f"{eco}: ranking by dependents and downloads ...")
        by_dependents = _names(session, registry, "dependent_packages_count",
                               _DEPENDENTS_DEPTH, sleep=sleep, log=log)
        by_downloads = set(_names(session, registry, "downloads",
                                  DOWNLOAD_FLOOR, sleep=sleep, log=log))
        kept: list[str] = []
        skipped = 0
        for name in by_dependents:
            if name in by_downloads and name not in kept:
                kept.append(name)
                if len(kept) == PER_ECOSYSTEM:
                    break
            else:
                skipped += 1
        if len(kept) < PER_ECOSYSTEM:
            raise ValueError(f"{eco}: only {len(kept)} packages pass the "
                             f"download floor in the first "
                             f"{_DEPENDENTS_DEPTH} by dependents")
        dropped[eco] = skipped
        repos = _repos(session, eco, kept, sleep=sleep, log=log)
        ecos[eco] = [{"name": n, "repo": repos[n]} for n in kept]
        log(f"  {eco}: kept {len(kept)}, passed over {skipped}, "
            f"{sum(1 for n in kept if repos[n])} with a GitHub repository")
    doc = {
        "edition": EDITION,
        "rule_version": RULE_VERSION,
        "selected_at": today,
        "source": SOURCE,
        "license": LICENSE,
        "rule": (
            f"Per registry, ecosyste.ms's ranking by dependent packages, "
            f"keeping only packages also among the registry's "
            f"{DOWNLOAD_FLOOR} most-downloaded; first {PER_ECOSYSTEM} kept."),
        "per_ecosystem": PER_ECOSYSTEM,
        "download_floor": DOWNLOAD_FLOOR,
        "passed_over": dropped,
        "ecosystems": ecos,
    }
    parse_universe(doc)  # the same validation the nightly applies
    return doc


def write_universe(doc: dict, path: Path = UNIVERSE_PATH) -> None:
    parse_universe(doc)
    Path(path).write_text(json.dumps(doc, indent=1, ensure_ascii=False)
                          + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m pipeline.oss_universe",
        description="Re-select the Open-Source Maintainers package universe "
                    "(network; one-off per edition).")
    parser.add_argument("--write", action="store_true",
                        help=f"write the selection to {UNIVERSE_PATH.name}")
    parser.add_argument("--path", type=Path, default=UNIVERSE_PATH)
    args = parser.parse_args(argv)
    doc = select()
    if args.write:
        write_universe(doc, args.path)
        print(f"wrote {args.path}")
    else:
        json.dump(doc, sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
