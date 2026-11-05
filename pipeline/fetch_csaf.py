"""CSAF providers named by the BSI CSAF Lister (Machine-Readable Advisories).

CSAF (Common Security Advisory Framework, an OASIS standard) is the JSON
format for machine-readable security advisories. A provider publishes a
``provider-metadata.json`` that points at its documents: either a
directory (``directory_url``, with ``changes.csv`` listing every document
path and its last-change time) or ROLIE feeds (JSON feeds, one entry per
document). Aggregators and listers collect provider-metadata URLs.

The universe is fixed and named: the providers and publishers listed by the
**BSI CSAF Lister** (``wid.cert-bund.de``), the lister that the OASIS CSAF
TC's site csaf.io links as "Lister". Vendors outside that list (Microsoft,
Cisco and SUSE publish provider-metadata too) are not counted; the page
says so.

What one night fetches, and the bound on it:

1. the lister's ``aggregator.json`` (one request);
2. each listed provider-metadata.json (one each; ~15);
3. one document LIST per distribution: ``changes.csv`` for a directory,
   and for a ROLIE feed first the ``changes.csv`` beside it (BSI's feed is
   48 MB, its changes.csv 0.9 MB), else the feed itself. Only TLP:WHITE /
   TLP:CLEAR feeds are read; other TLP labels need an account;
4. the documents of a fixed **sample**: per distribution, the
   :data:`SAMPLE_K` documents whose file name has the smallest SHA-256.
   The rule is deterministic and unrelated to content, so the sample is a
   uniform draw that stays put from night to night; a new document enters
   it only when its hash ranks in the first K. A sampled document is
   fetched once and its field summary cached (``.cache/csaf_state.json.gz``);
   it is fetched again only when its change time in the list moves, at
   most :data:`REFRESH_CAP` refreshes a night. New sample members are
   capped at :data:`NEW_CAP` a night (enough to refill a lost cache in one
   night). A normal night fetches a few dozen documents.

robots.txt is honoured per host (RFC 9309: a 4xx robots file allows all, a
5xx or unreachable one disallows all; ``*`` and ``$`` wildcards; the
``Crawl-delay`` is kept between requests to that host). Huawei's document
host disallows every path, so Huawei is listed but not measured.

Failure policy: the lister being unreachable or malformed raises (the
caller carries the module forward stale). A single provider that fails
tonight (unreachable, refused, empty or newly disallowed) keeps its last
good counts for up to :data:`CARRY_DAYS` days (status ``carried``); after
that it reports its failure with no documents. Wall-clock budgets bound a
night with slow hosts (:data:`DOC_BUDGET_S`, :data:`STAGE_BUDGET_S`).
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import re
import time
from dataclasses import dataclass, field
from datetime import date as _date
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

from .fetch_http import USER_AGENT, get_with_retry

LISTER_URL = ("https://wid.cert-bund.de/.well-known/csaf-aggregator/"
              "aggregator.json")
UA_TOKEN = "cybermon"

SAMPLE_K = 30
NEW_CAP = 450
REFRESH_CAP = 40
CARRY_DAYS = 14
# Wall-clock bounds: sampled-document fetches stop after DOC_BUDGET_S, and a
# provider not yet started once the crawl has run STAGE_BUDGET_S is skipped
# (it keeps its carried counts). A host that fails HOST_FAILURES sampled
# documents in a row gets no more document requests that night.
DOC_BUDGET_S = 600.0
STAGE_BUDGET_S = 1200.0
HOST_FAILURES = 3
TIMEOUT = (10.0, 60.0)   # connect, read

STATE_NAME = "csaf_state.json.gz"
STATE_VERSION = 1

LIST_MAX_BYTES = 64 << 20
DOC_MAX_BYTES = 32 << 20
PUBLIC_TLP = {"WHITE", "CLEAR"}

# Document categories, grouped. Anything that is not VEX or a security
# advisory (csaf_base, informational advisories, incident responses, the
# CSAF 2.1 deprecated/withdrawn/superseded profiles, vendor-defined names)
# is "other".
VEX = "csaf_vex"
ADVISORY = "csaf_security_advisory"

FIELDS = ("cvss", "cwe", "product_tree", "remediation")

_YEAR_RE = re.compile(r"^(19|20)\d{2}$")


# ------------------------------------------------------------------ robots

@dataclass
class Robots:
    """One host's robots.txt rules for our user agent."""

    rules: list[tuple[bool, str]] = field(default_factory=list)
    delay: float = 0.0
    disallow_all: bool = False

    def allows(self, url: str) -> bool:
        if self.disallow_all:
            return False
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        best: tuple[int, bool] | None = None
        for allow, pattern in self.rules:
            if not pattern:
                continue
            if _robots_match(pattern, path):
                key = (len(pattern), allow)
                if best is None or key > best:
                    best = key
        return True if best is None else best[1]


def _robots_match(pattern: str, path: str) -> bool:
    anchored = pattern.endswith("$")
    if anchored:
        pattern = pattern[:-1]
    regex = "".join(".*" if c == "*" else re.escape(c) for c in pattern)
    return re.match(regex + ("$" if anchored else ""), path) is not None


def parse_robots(text: str, agent: str = UA_TOKEN) -> Robots:
    """The rules of the group naming ``agent``, else the ``*`` group."""
    groups: list[tuple[list[str], list[tuple[bool, str]], float]] = []
    agents: list[str] = []
    rules: list[tuple[bool, str]] = []
    delay = 0.0
    in_rules = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = (s.strip() for s in line.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            if in_rules:
                groups.append((agents, rules, delay))
                agents, rules, delay, in_rules = [], [], 0.0, False
            agents.append(value.lower())
        elif key in ("allow", "disallow"):
            in_rules = True
            if value or key == "allow":
                rules.append((key == "allow", value))
        elif key == "crawl-delay":
            in_rules = True
            try:
                delay = float(value)
            except ValueError:
                pass
    if agents:
        groups.append((agents, rules, delay))
    chosen = None
    for agents_, rules_, delay_ in groups:
        if any(a != "*" and a in agent for a in agents_):
            chosen = (rules_, delay_)
            break
    if chosen is None:
        for agents_, rules_, delay_ in groups:
            if "*" in agents_:
                chosen = (rules_, delay_)
                break
    if chosen is None:
        return Robots()
    return Robots(rules=list(chosen[0]), delay=min(chosen[1], 30.0))


# ------------------------------------------------------------------ fetching

class Fetcher:
    """GETs with robots.txt, crawl-delay and a request tally."""

    def __init__(self, session, *, sleep: Callable[[float], None] = time.sleep,
                 log: Callable[[str], None] = print, timeout=TIMEOUT):
        self.session = _Counting(session, self)
        self.sleep = sleep
        self.log = log
        self.timeout = timeout
        self.robots: dict[str, Robots] = {}
        self.last_hit: dict[str, float] = {}
        self.requests = 0
        self.bytes = 0

    def _robots(self, url: str) -> Robots:
        host = urlsplit(url).netloc
        if host in self.robots:
            return self.robots[host]
        robots_url = f"{urlsplit(url).scheme}://{host}/robots.txt"
        try:
            resp = self.session.get(robots_url, timeout=self.timeout,
                                    headers={"User-Agent": USER_AGENT})
            code = resp.status_code
            if code == 200:
                rules = parse_robots(resp.text)
            elif 400 <= code < 500:
                rules = Robots()  # RFC 9309 2.3.1.3: unavailable -> allow
            else:
                rules = Robots(disallow_all=True)  # unreachable
        except OSError:
            rules = Robots(disallow_all=True)
        self.robots[host] = rules
        return rules

    def allowed(self, url: str) -> bool:
        return self._robots(url).allows(url)

    def get(self, url: str, *, max_bytes: int, attempts: int = 2,
            accept_status: tuple[int, ...] = (200,)) -> tuple[int, bytes]:
        """(status, body). Raises ``PermissionError`` when robots.txt
        forbids the URL, ``OSError`` on network failure. A status outside
        ``accept_status`` returns with an empty body."""
        rules = self._robots(url)
        if not rules.allows(url):
            raise PermissionError(f"robots.txt disallows {url}")
        host = urlsplit(url).netloc
        if rules.delay and host in self.last_hit:
            wait = rules.delay - (time.monotonic() - self.last_hit[host])
            if wait > 0:
                self.sleep(wait)

        def consume(resp) -> tuple[int, bytes]:
            if resp.status_code not in accept_status:
                return resp.status_code, b""
            buf = io.BytesIO()
            for chunk in resp.iter_content(1 << 16):
                buf.write(chunk)
                if buf.tell() > max_bytes:
                    raise ValueError(f"csaf: {url} exceeds {max_bytes} bytes")
            return resp.status_code, buf.getvalue()

        try:
            status, body = get_with_retry(
                self.session, url, label="csaf", timeout=self.timeout,
                attempts=attempts, backoff=5.0, sleep=self.sleep,
                log=self.log, stream=True, raise_for_status=False,
                consume=consume)
        finally:
            self.last_hit[host] = time.monotonic()
        self.bytes += len(body)
        return status, body


class _Counting:
    """Session wrapper that tallies every request, retries included."""

    def __init__(self, session, owner: "Fetcher"):
        self._session = session
        self._owner = owner

    def get(self, url, **kwargs):
        self._owner.requests += 1
        return self._session.get(url, **kwargs)


# ------------------------------------------------------------------ parsing

@dataclass
class ListedSource:
    name: str
    category: str
    role: str
    kind: str          # "provider" | "publisher"
    metadata_url: str


def parse_lister(obj: Any) -> tuple[dict, list[ListedSource]]:
    """(lister info, listed sources). Malformed documents raise."""
    if not isinstance(obj, dict):
        raise ValueError("csaf: lister document is not an object")
    agg = obj.get("aggregator")
    if not isinstance(agg, dict) or not agg.get("name"):
        raise ValueError("csaf: lister has no aggregator block")
    sources: list[ListedSource] = []
    seen: set[str] = set()
    for key, kind in (("csaf_providers", "provider"),
                      ("csaf_publishers", "publisher")):
        entries = obj.get(key) or []
        if not isinstance(entries, list):
            raise ValueError(f"csaf: lister {key} is not a list")
        for i, entry in enumerate(entries):
            meta = entry.get("metadata") if isinstance(entry, dict) else None
            pub = meta.get("publisher") if isinstance(meta, dict) else None
            url = meta.get("url") if isinstance(meta, dict) else None
            if not isinstance(pub, dict) or not isinstance(url, str) \
                    or not pub.get("name") or not url.startswith("https://"):
                raise ValueError(f"csaf: lister {key}[{i}] is malformed")
            if url in seen:
                continue
            seen.add(url)
            sources.append(ListedSource(
                name=str(pub["name"]).strip(),
                category=str(pub.get("category") or "other"),
                role=str(meta.get("role") or ""),
                kind=kind, metadata_url=url))
    if not sources:
        raise ValueError("csaf: lister names no providers")
    info = {"name": str(agg["name"]), "url": LISTER_URL,
            "last_updated": str(obj.get("last_updated") or "")}
    return info, sources


@dataclass
class Distribution:
    kind: str           # "directory" | "rolie"
    url: str            # directory base (ends with /) or feed URL
    tlp: str | None = None


def parse_distributions(pm: Any) -> list[Distribution]:
    """Public distributions in a provider-metadata document: every
    directory_url, and ROLIE feeds labelled TLP:WHITE or TLP:CLEAR. A
    directory that is the folder of a non-public feed takes that feed's
    label and is dropped."""
    if not isinstance(pm, dict):
        raise ValueError("csaf: provider-metadata is not an object")
    dirs: list[Distribution] = []
    feeds: list[Distribution] = []
    for d in pm.get("distributions") or []:
        if not isinstance(d, dict):
            continue
        url = d.get("directory_url")
        if isinstance(url, str) and url.startswith("https://"):
            dirs.append(Distribution("directory", url.rstrip("/") + "/"))
        rolie = d.get("rolie")
        if isinstance(rolie, dict):
            for f in rolie.get("feeds") or []:
                if isinstance(f, dict) and isinstance(f.get("url"), str) \
                        and f["url"].startswith("https://"):
                    feeds.append(Distribution(
                        "rolie", f["url"],
                        str(f.get("tlp_label") or "").upper() or None))
    closed = {_folder(f.url) for f in feeds
              if f.tlp and f.tlp not in PUBLIC_TLP}
    out = [d for d in dirs if d.url not in closed]
    out += [f for f in feeds if f.tlp in PUBLIC_TLP]
    seen: set[str] = set()
    unique = []
    for d in out:
        if d.url not in seen:
            seen.add(d.url)
            unique.append(d)
    return unique


def _folder(url: str) -> str:
    return url.rsplit("/", 1)[0] + "/"


@dataclass
class DocRef:
    url: str
    year: int | None
    ts: str


def parse_changes_csv(text: str, base: str) -> list[DocRef]:
    """Rows of ``"<yyyy>/<file>.json","<timestamp>"``. The year folder is
    the year of the document's initial release (CSAF 2.0 requirement 11);
    a path without one leaves the year unknown."""
    docs: list[DocRef] = []
    bad = 0
    for row in csv.reader(io.StringIO(text)):
        if not row or not row[0].strip():
            continue
        path = row[0].strip().lstrip("/")
        ts = row[1].strip() if len(row) > 1 else ""
        if not path.lower().endswith(".json") or not ts:
            bad += 1
            continue
        first = path.split("/", 1)[0]
        year = int(first) if _YEAR_RE.match(first) else None
        docs.append(DocRef(urljoin(base, path), year, ts))
    if bad > max(5, len(docs) // 10):
        raise ValueError(f"csaf: changes.csv at {base} has {bad} malformed "
                         f"rows")
    return docs


def parse_rolie(obj: Any) -> list[DocRef]:
    """Entries of a ROLIE feed: the document URL, the year of
    ``published`` (the initial release date) and ``updated``."""
    feed = obj.get("feed") if isinstance(obj, dict) else None
    if not isinstance(feed, dict):
        raise ValueError("csaf: ROLIE document has no feed")
    docs: list[DocRef] = []
    for e in feed.get("entry") or []:
        if not isinstance(e, dict):
            continue
        url = None
        content = e.get("content")
        if isinstance(content, dict) and isinstance(content.get("src"), str):
            url = content["src"]
        if url is None:
            for link in e.get("link") or []:
                if isinstance(link, dict) and link.get("rel") == "self":
                    url = link.get("href")
                    break
        if not isinstance(url, str) or not url.startswith("https://"):
            continue
        published = str(e.get("published") or "")
        year = int(published[:4]) if _YEAR_RE.match(published[:4]) else None
        docs.append(DocRef(url, year, str(e.get("updated") or published)))
    return docs


def _walk_products(branches: Any) -> int:
    n = 0
    for b in branches or []:
        if isinstance(b, dict):
            if isinstance(b.get("product"), dict):
                n += 1
            n += _walk_products(b.get("branches"))
    return n


def _has_vector(v: dict) -> bool:
    for s in v.get("scores") or []:
        if isinstance(s, dict):
            for k in ("cvss_v2", "cvss_v3", "cvss_v4"):
                if isinstance(s.get(k), dict) and s[k].get("vectorString"):
                    return True
    for m in v.get("metrics") or []:   # CSAF 2.1
        c = m.get("content") if isinstance(m, dict) else None
        if isinstance(c, dict):
            for k in ("cvss_v2", "cvss_v3", "cvss_v4"):
                if isinstance(c.get(k), dict) and c[k].get("vectorString"):
                    return True
    return False


def summarize_document(doc: Any) -> dict:
    """The fields this module reads from one CSAF document:
    ``c`` category; ``cvss`` / ``cwe`` / ``remediation`` — every
    vulnerability entry carries a CVSS vector / a CWE / a remediation (a
    document without vulnerability entries has none of the three);
    ``product_tree`` — the product tree names at least one product."""
    if not isinstance(doc, dict) or not isinstance(doc.get("document"),
                                                   dict):
        raise ValueError("csaf: not a CSAF document")
    category = str(doc["document"].get("category") or "").strip()
    vulns = [v for v in doc.get("vulnerabilities") or []
             if isinstance(v, dict)]
    pt = doc.get("product_tree") if isinstance(doc.get("product_tree"),
                                               dict) else {}
    products = _walk_products(pt.get("branches")) + \
        len(pt.get("full_product_names") or []) + \
        len(pt.get("relationships") or [])

    def every(pred) -> bool:
        return bool(vulns) and all(pred(v) for v in vulns)

    return {
        "c": category,
        "cvss": every(_has_vector),
        "cwe": every(lambda v: bool(v.get("cwe")) or bool(v.get("cwes"))),
        "product_tree": products > 0,
        "remediation": every(lambda v: bool(v.get("remediations"))),
    }


def category_group(category: str) -> str:
    if category == VEX:
        return "vex"
    if category == ADVISORY:
        return "advisory"
    return "other"


def sample_key(url: str) -> str:
    """Sampling rank: SHA-256 of the lower-cased file name."""
    name = urlsplit(url).path.rsplit("/", 1)[-1].lower()
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ state

def load_state(cache_dir: Path, log: Callable[[str], None] = print) -> dict:
    path = cache_dir / STATE_NAME
    empty = {"version": STATE_VERSION, "docs": {}, "providers": {}}
    if not path.exists():
        return empty
    try:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            obj = json.load(f)
        if obj.get("version") != STATE_VERSION or \
                not isinstance(obj.get("docs"), dict) or \
                not isinstance(obj.get("providers"), dict):
            return empty
        return obj
    except (OSError, ValueError) as exc:
        log(f"warning: ignoring unreadable CSAF state {path}: {exc!r}")
        return empty


def save_state(cache_dir: Path, state: dict) -> None:
    path = cache_dir / STATE_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with gzip.open(tmp, "wt", encoding="utf-8") as f:
        json.dump(state, f, separators=(",", ":"), sort_keys=True)
    tmp.replace(path)


# ------------------------------------------------------------------ the crawl

@dataclass
class DistResult:
    docs: list[DocRef]
    sample: list[dict]          # [{url, ts, summary}] — summaries present


@dataclass
class SourceResult:
    source: ListedSource
    status: str                 # measured | carried | robots | denied | empty | error
    detail: str = ""
    dists: list[DistResult] = field(default_factory=list)
    carried_row: dict | None = None
    measured_on: str | None = None


@dataclass
class CsafCrawl:
    lister: dict
    results: list[SourceResult]
    requests: int = 0
    bytes: int = 0
    docs_fetched: int = 0
    docs_cached: int = 0
    k: int = SAMPLE_K


class _Budget:
    def __init__(self, new_cap: int, refresh_cap: int,
                 clock: Callable[[], float] = time.monotonic):
        self.new_left = new_cap
        self.refresh_left = refresh_cap
        self.clock = clock
        self.start = clock()
        self.host_failures: dict[str, int] = {}

    def docs_open(self, url: str) -> bool:
        """May tonight's crawl still fetch this sampled document?"""
        if self.clock() - self.start > DOC_BUDGET_S:
            return False
        return self.host_failures.get(urlsplit(url).netloc, 0) < \
            HOST_FAILURES

    def stage_open(self) -> bool:
        return self.clock() - self.start <= STAGE_BUDGET_S

    def record(self, url: str, ok: bool) -> None:
        host = urlsplit(url).netloc
        self.host_failures[host] = 0 if ok else \
            self.host_failures.get(host, 0) + 1


def _list_distribution(fx: Fetcher, dist: Distribution) -> list[DocRef]:
    """The document list of one distribution (see module docstring)."""
    if dist.kind == "directory":
        status, body = fx.get(dist.url + "changes.csv",
                              max_bytes=LIST_MAX_BYTES)
        if status != 200:
            raise _HttpStatus(status)
        return parse_changes_csv(body.decode("utf-8", "replace"), dist.url)
    folder = _folder(dist.url)
    changes = folder + "changes.csv"
    if fx.allowed(changes):
        try:
            status, body = fx.get(changes, max_bytes=LIST_MAX_BYTES,
                                  attempts=1, accept_status=(200,))
        except (OSError, ValueError):
            status, body = 0, b""   # a failed probe falls back to the feed
        if status == 200 and body.strip():
            try:
                docs = parse_changes_csv(body.decode("utf-8", "replace"),
                                         folder)
            except ValueError:
                docs = []
            if docs:
                return docs
    status, body = fx.get(dist.url, max_bytes=LIST_MAX_BYTES)
    if status != 200:
        raise _HttpStatus(status)
    return parse_rolie(json.loads(body))


class _HttpStatus(Exception):
    def __init__(self, status: int):
        super().__init__(f"HTTP {status}")
        self.status = status


def _sample(fx: Fetcher, docs: list[DocRef], state_docs: dict,
            new_state: dict, budget: _Budget, today: str, k: int,
            log: Callable[[str], None], crawl: CsafCrawl) -> list[dict]:
    picked = sorted(docs, key=lambda d: sample_key(d.url))[:k]
    out: list[dict] = []
    stale: list[tuple[str, DocRef, dict]] = []
    for ref in picked:
        cached = state_docs.get(ref.url)
        if cached and cached.get("ts") == ref.ts:
            new_state[ref.url] = cached
            out.append({"url": ref.url, "summary": cached["s"]})
            crawl.docs_cached += 1
        elif cached:
            stale.append((cached.get("at", ""), ref, cached))
        else:
            if budget.new_left <= 0:
                continue
            budget.new_left -= 1
            summary = _fetch_doc(fx, ref.url, budget, log)
            if summary is not None:
                crawl.docs_fetched += 1
                new_state[ref.url] = {"ts": ref.ts, "at": today, "s": summary}
                out.append({"url": ref.url, "summary": summary})
    # Changed documents: refresh the longest-cached first, within the cap;
    # the rest keep their earlier summary until a later night.
    for _at, ref, cached in sorted(stale, key=lambda t: t[0]):
        summary = None
        if budget.refresh_left > 0:
            budget.refresh_left -= 1
            summary = _fetch_doc(fx, ref.url, budget, log)
        if summary is not None:
            crawl.docs_fetched += 1
            new_state[ref.url] = {"ts": ref.ts, "at": today, "s": summary}
        else:
            summary = cached["s"]
            new_state[ref.url] = cached
            crawl.docs_cached += 1
        out.append({"url": ref.url, "summary": summary})
    return out


def _fetch_doc(fx: Fetcher, url: str, budget: _Budget,
               log: Callable[[str], None]) -> dict | None:
    if not budget.docs_open(url):
        return None
    summary = None
    try:
        status, body = fx.get(url, max_bytes=DOC_MAX_BYTES)
        if status != 200:
            log(f"  csaf: HTTP {status} for sampled document {url}")
        else:
            summary = summarize_document(json.loads(body))
    except Exception as exc:  # one bad document never fails the night
        log(f"  csaf: skipped sampled document {url}: {exc!r}")
    budget.record(url, summary is not None)
    return summary


def _crawl_source(fx: Fetcher, src: ListedSource, state: dict,
                  new_docs: dict, budget: _Budget, today: str, k: int,
                  log: Callable[[str], None], crawl: CsafCrawl
                  ) -> SourceResult:
    if not fx.allowed(src.metadata_url):
        return SourceResult(src, "robots", "robots.txt")
    try:
        status, body = fx.get(src.metadata_url, max_bytes=1 << 20)
    except OSError as exc:
        return SourceResult(src, "error", type(exc).__name__)
    if status in (401, 403):
        return SourceResult(src, "denied", f"HTTP {status}")
    if status != 200:
        return SourceResult(src, "error", f"HTTP {status}")
    try:
        dists = parse_distributions(json.loads(body))
    except ValueError:
        return SourceResult(src, "error", "unreadable provider-metadata")
    if not dists:
        return SourceResult(src, "empty", "no public distribution")
    results: list[DistResult] = []
    seen_urls: set[str] = set()
    outcomes: list[str] = []
    # Directories come first (parse_distributions order); a feed whose
    # folder's changes.csv was already read lists nothing new.
    listed_dirs: set[str] = set()
    for dist in dists:
        if dist.kind == "rolie" and _folder(dist.url) in listed_dirs:
            continue
        if not fx.allowed(dist.url if dist.kind == "rolie"
                          else dist.url + "changes.csv"):
            outcomes.append("robots")
            continue
        try:
            docs = _list_distribution(fx, dist)
        except _HttpStatus as exc:
            outcomes.append("denied" if exc.status in (401, 403)
                            else "error")
            continue
        except (OSError, ValueError) as exc:
            log(f"  csaf: {src.name}: {dist.url}: {exc!r}")
            outcomes.append("error")
            continue
        outcomes.append("ok")
        if dist.kind == "directory":
            listed_dirs.add(dist.url)
        # A document reachable through two distributions (a directory and
        # the ROLIE feed over it), or listed twice in one changes.csv,
        # counts once; the first listing wins (changes.csv is newest
        # first).
        unique = []
        for d in docs:
            key = d.url.lower()
            if key in seen_urls:
                continue
            seen_urls.add(key)
            unique.append(d)
        if unique:
            sample = _sample(fx, unique, state["docs"], new_docs, budget,
                             today, k, log, crawl)
            results.append(DistResult(unique, sample))
    if results:
        return SourceResult(src, "measured", "", results, measured_on=today)
    if "ok" in outcomes:
        return SourceResult(src, "empty", "no documents listed")
    for kind, detail in (("robots", "robots.txt"), ("denied", "HTTP 401/403")):
        if kind in outcomes:
            return SourceResult(src, kind, detail)
    return SourceResult(src, "error", "document lists unreachable")


def crawl(session, state_dir: Path | None, today: str, *, k: int = SAMPLE_K,
          new_cap: int = NEW_CAP, refresh_cap: int = REFRESH_CAP,
          row_builder: Callable[[SourceResult], dict] | None = None,
          sleep: Callable[[float], None] = time.sleep,
          log: Callable[[str], None] = print,
          clock: Callable[[], float] = time.monotonic) -> CsafCrawl:
    """Tonight's crawl of the lister's sources. Raises when the lister
    itself fails. ``row_builder`` turns a measured result into the output
    row that is cached for the per-provider carry-forward. ``state_dir``
    None (fixture runs) neither reads nor writes the cached state."""
    fx = Fetcher(session, sleep=sleep, log=log)
    status, body = fx.get(LISTER_URL, max_bytes=8 << 20, attempts=3)
    if status != 200:
        raise OSError(f"csaf: lister answered HTTP {status}")
    try:
        lister, sources = parse_lister(json.loads(body))
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError(f"csaf: malformed lister ({exc!r})") from exc
    state = load_state(state_dir, log=log) if state_dir is not None else \
        {"version": STATE_VERSION, "docs": {}, "providers": {}}
    new_docs: dict = {}
    new_providers: dict = {}
    budget = _Budget(new_cap, refresh_cap, clock)
    out = CsafCrawl(lister, [], k=k)
    for src in sources:
        if not budget.stage_open():
            res = SourceResult(src, "error", "time budget")
        else:
            try:
                res = _crawl_source(fx, src, state, new_docs, budget, today,
                                    k, log, out)
            except Exception as exc:  # one provider never fails the night
                log(f"  csaf: {src.name}: {exc!r}")
                res = SourceResult(src, "error", type(exc).__name__)
        prior = state["providers"].get(src.metadata_url)
        if res.status == "measured":
            if row_builder is not None:
                new_providers[src.metadata_url] = {
                    "last_ok": today, "row": row_builder(res)}
        elif prior and _days(prior.get("last_ok", ""), today) <= CARRY_DAYS:
            # Any failure (unreachable, refused, suddenly empty, newly
            # disallowed) keeps the last good counts for up to CARRY_DAYS,
            # marked; nothing is fetched for them.
            res = SourceResult(src, "carried", res.detail,
                               carried_row=prior["row"],
                               measured_on=prior["last_ok"])
            new_providers[src.metadata_url] = prior
            # Keep the cached sample of a carried provider too.
            for url, entry in state["docs"].items():
                if url in prior.get("sample_urls", ()):
                    new_docs.setdefault(url, entry)
        out.results.append(res)
        n_docs = sum(len(d.docs) for d in res.dists)
        log(f"  csaf {src.name}: {res.status}"
            + (f" ({res.detail})" if res.detail else "")
            + (f" — {n_docs} documents" if res.dists else ""))
    for src_url, entry in new_providers.items():
        if "sample_urls" not in entry:
            entry["sample_urls"] = sorted(
                s["url"] for r in out.results
                if r.source.metadata_url == src_url
                for d in r.dists for s in d.sample)
    out.requests = fx.requests
    out.bytes = fx.bytes
    if state_dir is not None:
        save_state(state_dir, {"version": STATE_VERSION, "docs": new_docs,
                               "providers": new_providers})
    return out


def _days(earlier: str, later: str) -> int:
    try:
        return (_date.fromisoformat(later) - _date.fromisoformat(earlier)).days
    except ValueError:
        return 10 ** 6


# ------------------------------------------------------------------ fixtures

class _FixtureResponse:
    def __init__(self, status_code: int, content: bytes):
        self.status_code = status_code
        self.content = content
        self.headers: dict = {}

    @property
    def text(self) -> str:
        return self.content.decode("utf-8")

    def json(self):
        return json.loads(self.content)

    def iter_content(self, size: int):
        for i in range(0, len(self.content), size):
            yield self.content[i:i + size]

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise OSError(f"HTTP {self.status_code}")


class FixtureSession:
    """Serves the offline fixture tree: ``urls.json`` maps each URL to a
    file under ``root`` or to an HTTP status code; anything else is 404."""

    def __init__(self, root: Path):
        self.root = root
        self.routes = json.loads((root / "urls.json").read_text("utf-8"))

    def get(self, url: str, **_kwargs) -> _FixtureResponse:
        target = self.routes.get(url)
        if isinstance(target, int):
            return _FixtureResponse(target, b"")
        if isinstance(target, str):
            return _FixtureResponse(200, (self.root / target).read_bytes())
        return _FixtureResponse(404, b"")
