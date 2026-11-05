"""endoflife.date release-cycle catalogue (the Support Windows feed).

endoflife.date documents release dates and end-of-support dates for a few
hundred software products, operating systems, devices and services, and
serves them through a public API (v1, documented at
https://endoflife.date/docs/api/v1/). The stage reads ONE document:

    https://endoflife.date/api/v1/products/full

the API's documented bulk endpoint ("a dump of nearly all endoflife.date
data"): every product with its category and every release cycle. Checked
2026-11-05: 489 products, 9,367 release cycles, ~3 MB of JSON (~320 KB
gzipped on the wire).

Why the bulk endpoint and not one request per product. The per-product
documents (``/products/<name>``) carry the site build's ``generated_at``
at their top level, so their ETags change on every endoflife.date deploy
(several a day) and a conditional GET would not save a transfer; the
product list (``/products``) carries no per-product change stamp to
refetch selectively by. One request for the dump is ~490 times fewer
requests than a per-product sweep and fewer bytes. The API documents no
numeric rate limit; it answers 429 with an optional ``Retry-After``, which
:func:`pipeline.fetch_http.get_with_retry` honours. The request carries
``If-None-Match`` from the cached state, so a night with no new
endoflife.date build costs a 304 and reuses the cached parse.

Fields read per release cycle (schema 1.2.x): ``releaseDate`` (required),
``eolFrom`` (end of the standard support window, null when not announced)
and ``isEol``; ``eoasFrom`` / ``isEoas`` (end of active support, present
only for products that separate active support from security support).
Extended support (``eoesFrom``, usually paid) and ``isMaintained`` (which
counts any level of support, extended included) are not read. Per product:
``name``, ``label``, ``category``.

Integrity guards: a document that is not the documented shape raises;
``total`` must equal the number of products listed; fewer than
:data:`MIN_PRODUCTS` products, or fewer than :data:`FLOOR_RATIO` of the
cached count, is refused as a truncated dump. A release cycle with an
unparseable date, or an end before its release, is skipped and counted
(``malformed``); more than :data:`MAX_MALFORMED_SHARE` of them raises.

Licence: the endoflife.date data and code are MIT-licensed ("Copyright
2020 endoflife.date contributors", the repository LICENSE linked from the
API's own OpenAPI document). The site credits endoflife.date in the footer
and the README source table.
"""
from __future__ import annotations

import gzip
import json
import time
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Callable

from .fetch_http import get_with_retry

EOL_URL = "https://endoflife.date/api/v1/products/full"
STATE_NAME = "eol_state.json.gz"
STATE_VERSION = 1

MIN_PRODUCTS = 100
FLOOR_RATIO = 0.9
MAX_MALFORMED_SHARE = 0.01


@dataclass(frozen=True)
class ReleaseLine:
    """One release cycle, reduced to the dates the module reads."""

    name: str
    release: str            # YYYY-MM-DD
    eol: str | None         # end of support (announced), YYYY-MM-DD
    is_eol: bool            # upstream flag: support has ended
    has_eoas: bool          # the product separates active support here
    eoas: str | None = None
    is_eoas: bool | None = None

    def to_state(self) -> list:
        return [self.name, self.release, self.eol, self.is_eol,
                self.has_eoas, self.eoas, self.is_eoas]

    @classmethod
    def from_state(cls, row: list) -> "ReleaseLine":
        return cls(*row)


@dataclass
class Product:
    name: str
    label: str
    category: str
    lines: list[ReleaseLine] = field(default_factory=list)

    def to_state(self) -> dict:
        return {"name": self.name, "label": self.label,
                "category": self.category,
                "lines": [ln.to_state() for ln in self.lines]}

    @classmethod
    def from_state(cls, obj: dict) -> "Product":
        return cls(name=obj["name"], label=obj["label"],
                   category=obj["category"],
                   lines=[ReleaseLine.from_state(r) for r in obj["lines"]])


@dataclass
class EolSnapshot:
    """The parsed catalogue. ``malformed`` counts release cycles skipped
    for an unusable date; ``not_modified`` is True when tonight's request
    answered 304 and the cached parse was reused."""

    products: list[Product]
    upstream_generated_at: str | None = None
    schema_version: str | None = None
    malformed: int = 0
    etag: str | None = None
    last_modified: str | None = None
    not_modified: bool = False

    @property
    def product_count(self) -> int:
        return len(self.products)

    @property
    def line_count(self) -> int:
        return sum(len(p.lines) for p in self.products)


def _str(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _date(value: object) -> str | None:
    """ISO date string -> ``YYYY-MM-DD``; None for null; raises
    ``ValueError`` for anything else."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"not a date: {value!r}")
    return date.fromisoformat(value[:10]).isoformat()


def _bool(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _parse_line(rel: object) -> ReleaseLine:
    """One release cycle. Raises ``ValueError`` on an unusable record."""
    if not isinstance(rel, dict):
        raise ValueError("release is not an object")
    release = _date(rel.get("releaseDate"))
    if release is None:
        raise ValueError("missing releaseDate")
    eol = _date(rel.get("eolFrom"))
    is_eol = _bool(rel.get("isEol"))
    if is_eol is None:
        raise ValueError(f"unusable isEol {rel.get('isEol')!r}")
    if eol is not None and eol < release:
        raise ValueError(f"eolFrom {eol} before releaseDate {release}")
    has_eoas = "eoasFrom" in rel or "isEoas" in rel
    eoas = _date(rel.get("eoasFrom")) if has_eoas else None
    if eoas is not None and eoas < release:
        raise ValueError(f"eoasFrom {eoas} before releaseDate {release}")
    return ReleaseLine(
        name=_str(rel.get("name")) or "?",
        release=release, eol=eol, is_eol=is_eol, has_eoas=has_eoas,
        eoas=eoas, is_eoas=_bool(rel.get("isEoas")) if has_eoas else None)


def parse_full(obj: object, *, min_products: int = MIN_PRODUCTS
               ) -> EolSnapshot:
    """Parse the ``/products/full`` document into an :class:`EolSnapshot`.

    The document shape is checked strictly (a broken dump must never pass
    for a small catalogue); single release cycles with unusable dates are
    skipped and counted, up to :data:`MAX_MALFORMED_SHARE` of all cycles.
    ``min_products`` drops to 1 for the fixture catalogue only.
    """
    if not isinstance(obj, dict) or not isinstance(obj.get("result"), list):
        raise ValueError("endoflife.date: expected an object with a "
                         "'result' list of products")
    result = obj["result"]
    total = obj.get("total")
    if isinstance(total, int) and not isinstance(total, bool) \
            and total != len(result):
        raise ValueError(f"endoflife.date: 'total' says {total} products, "
                         f"the dump lists {len(result)}")
    products: list[Product] = []
    seen: set[str] = set()
    malformed = 0
    cycles = 0
    for i, rec in enumerate(result):
        path = f"result[{i}]"
        if not isinstance(rec, dict):
            raise ValueError(f"endoflife.date: {path} is not an object")
        name = _str(rec.get("name"))
        category = _str(rec.get("category"))
        releases = rec.get("releases")
        if not name or not category or not isinstance(releases, list):
            raise ValueError(f"endoflife.date: {path}: product without a "
                             f"name, category or releases list")
        if name in seen:
            raise ValueError(f"endoflife.date: duplicate product {name!r}")
        seen.add(name)
        lines: list[ReleaseLine] = []
        for rel in releases:
            cycles += 1
            try:
                lines.append(_parse_line(rel))
            except ValueError:
                malformed += 1
        products.append(Product(name=name,
                                label=_str(rec.get("label")) or name,
                                category=category, lines=lines))
    if len(products) < min_products:
        raise ValueError(f"endoflife.date: only {len(products)} products in "
                         f"the dump (minimum {min_products}) — refusing a "
                         f"truncated catalogue")
    if cycles and malformed > cycles * MAX_MALFORMED_SHARE:
        raise ValueError(f"endoflife.date: {malformed} of {cycles} release "
                         f"cycles unusable — above the "
                         f"{MAX_MALFORMED_SHARE:.0%} ceiling")
    gen = obj.get("generated_at")
    ver = obj.get("schema_version")
    return EolSnapshot(
        products=products,
        upstream_generated_at=gen if isinstance(gen, str) and gen else None,
        schema_version=ver if isinstance(ver, str) and ver else None,
        malformed=malformed)


def load_full_file(path: Path) -> EolSnapshot:
    """Parse a local copy of the dump (the small fixture catalogue, so
    the product floor does not apply)."""
    return parse_full(json.loads(path.read_text(encoding="utf-8")),
                      min_products=1)


# ---- cached state -------------------------------------------------------------

def load_state(cache_dir: Path, log: Callable[[str], None] = print
               ) -> EolSnapshot | None:
    """The cached parse, or None when absent or unreadable (tonight then
    downloads the dump in full; the state is only ever a cache)."""
    path = cache_dir / STATE_NAME
    if not path.exists():
        return None
    try:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            obj = json.load(f)
        if obj.get("version") != STATE_VERSION:
            return None
        return EolSnapshot(
            products=[Product.from_state(p) for p in obj["products"]],
            upstream_generated_at=obj.get("upstream_generated_at"),
            schema_version=obj.get("schema_version"),
            malformed=obj.get("malformed", 0),
            etag=obj.get("etag"), last_modified=obj.get("last_modified"))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        log(f"warning: ignoring unreadable endoflife.date state {path}: "
            f"{exc!r}")
        return None


def save_state(cache_dir: Path, snap: EolSnapshot) -> None:
    path = cache_dir / STATE_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with gzip.open(tmp, "wt", encoding="utf-8") as f:
        json.dump({"version": STATE_VERSION, "etag": snap.etag,
                   "last_modified": snap.last_modified,
                   "upstream_generated_at": snap.upstream_generated_at,
                   "schema_version": snap.schema_version,
                   "malformed": snap.malformed,
                   "products": [p.to_state() for p in snap.products]},
                  f, separators=(",", ":"))
    tmp.replace(path)


# ---- network ------------------------------------------------------------------

def _floor_check(new: EolSnapshot, reference: int | None) -> None:
    if not reference:
        return
    if new.product_count < reference * FLOOR_RATIO:
        raise ValueError(
            f"endoflife.date: dump lists {new.product_count} products, the "
            f"previous read {reference}; below the {FLOOR_RATIO:.0%} floor "
            f"— refusing a truncated catalogue")


def fetch_full(cache_dir: Path, session=None, *,
               prior_products: int | None = None, timeout: Any = 120.0,
               sleep=time.sleep, log: Callable[[str], None] = print
               ) -> EolSnapshot:
    """Tonight's catalogue: the cached parse when the server answers 304,
    else a fresh download and parse. Any failure raises (the caller
    carries the module forward); the state is saved only on success.

    The shrink floor compares against the larger of the cached parse and
    ``prior_products`` (the previous published edition's count, which CI
    always has even when the cache is cold)."""
    if session is None:
        import requests

        session = requests.Session()
    cached = load_state(cache_dir, log=log)
    headers = {"Accept": "application/json"}
    if cached is not None:
        if cached.etag:
            headers["If-None-Match"] = cached.etag
        if cached.last_modified:
            headers["If-Modified-Since"] = cached.last_modified

    def consume(resp) -> EolSnapshot:
        if resp.status_code == 304:
            if cached is None:
                raise ValueError("endoflife.date: 304 without a cached copy")
            cached.not_modified = True
            return cached
        resp.raise_for_status()
        snap = parse_full(resp.json())
        snap.etag = resp.headers.get("ETag")
        snap.last_modified = resp.headers.get("Last-Modified")
        return snap

    snap = get_with_retry(session, EOL_URL, label="endoflife.date",
                          headers=headers, timeout=timeout, sleep=sleep,
                          log=log, raise_for_status=False, consume=consume)
    if not snap.not_modified:
        _floor_check(snap, max(cached.product_count if cached else 0,
                               prior_products or 0))
        save_state(cache_dir, snap)
    how = "not modified" if snap.not_modified else "downloaded"
    log(f"  endoflife.date: {how} — {snap.product_count} products, "
        f"{snap.line_count} release cycles"
        + (f", {snap.malformed} unusable" if snap.malformed else ""))
    return snap
