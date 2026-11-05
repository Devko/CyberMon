"""SigmaHQ detection rules: the rule metadata behind Detection Rules (module 28).

Source: the public ``SigmaHQ/sigma`` git repository on GitHub. Its rules
are released under the Detection Rule License (DRL) 1.1, which permits
use, copy, publish and distribute; CyberMon republishes no rule — only
counts derived from four metadata fields — and credits SigmaHQ and the DRL
on the page, in the README and in the site footer.

**Transport.** GitHub's REST API and the codeload tarball endpoint answer
403 from some networks, so this fetcher speaks the git protocol over
https, which needs no API quota and no token:

* ``git ls-remote`` — one tiny request that returns the branch head;
* only when that head differs from the cached one: ``git clone --depth 1
  --bare`` (about 10 MB packed) into a temporary directory, then
  ``git ls-tree`` + one ``git cat-file --batch`` to read the rule files
  straight from the object store (no checkout). The directory is deleted
  afterwards; nothing large is kept.

A normal night therefore costs one ``ls-remote`` when SigmaHQ merged
nothing, and one shallow clone when it did. The parsed rules are cached in
``.cache/sigma_state.json`` (key ``rules``) under the head commit they came
from, so an unchanged head is never cloned again. Each git call has a
timeout and a small, bounded retry; an exhausted retry raises
:class:`SigmaFetchError` (an ``OSError``), and the stage's caller carries
the previous edition forward, marked stale.

**Which files count.** A rule is a ``.yml`` file under a top-level
``rules`` or ``rules-*`` directory (rules, rules-emerging-threats,
rules-threat-hunting, rules-placeholder, rules-compliance, …: class
``active``) or under ``deprecated/`` (class ``deprecated``). Everything
else is left out: ``unsupported/`` (rules that need features the Sigma
converters lack), ``regression_data/``, ``tests/``, ``documentation/``,
``other/`` and the CI configuration.

**What is read.** Four top-level keys of the first YAML document:
``date`` (the rule author's creation date — NOT the git commit date, so
every "added" date is approximate), ``modified`` (for a deprecated rule,
the last edit, normally the deprecation), ``status`` (informational) and
``tags`` (only ``attack.tNNNN`` / ``attack.tNNNN.NNN`` technique tags are
kept, upper-cased to ATT&CK ids). The repository's own CI lints these
fields, so a strict line reader is enough and the pipeline keeps its
stdlib-only runtime (no YAML dependency). A file whose ``date`` is missing
or unparseable is skipped and counted; when more than
:data:`MAX_SKIPPED_SHARE` of the files are skipped, or fewer than
:data:`MIN_RULES` rules parse, the snapshot is refused (ValueError) — an
upstream layout change, never something to publish.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import date as _date
from pathlib import Path
from typing import Callable, Iterable, Iterator

SIGMA_REPO = "https://github.com/SigmaHQ/sigma.git"
SIGMA_BRANCH = "master"

STATE_FILENAME = "sigma_state.json"
STATE_VERSION = 1
# Bump when the reader below changes what it extracts: a cached rule set
# parsed by an older reader is then re-fetched instead of reused.
PARSER_VERSION = 1

ACTIVE = "active"
DEPRECATED = "deprecated"

MIN_RULES = 1000            # live floor; the repository holds ~4,000
MAX_SKIPPED_SHARE = 0.02    # more unparseable files than this = layout change

_LS_REMOTE_TIMEOUT = 60.0
_CLONE_TIMEOUT = 300.0
_LOCAL_TIMEOUT = 120.0
_MAX_ATTEMPTS = 3
_BACKOFF = 10.0

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*)[ \t]*:(.*)$")
_ITEM_RE = re.compile(r"^[ \t]+-[ \t]*(.*)$")
_TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_DATE_RE = re.compile(r"^(\d{4})[-/](\d{2})[-/](\d{2})$")


class SigmaFetchError(OSError):
    """The SigmaHQ repository could not be read (network, git, timeout)."""


@dataclass(frozen=True)
class Rule:
    """One rule reduced to what the module counts. No title, id, author or
    detection logic is kept — only dates and ATT&CK technique ids."""

    cls: str                         # ACTIVE or DEPRECATED
    date: str                        # YYYY-MM-DD, the rule's own `date`
    modified: str | None             # YYYY-MM-DD or None
    techniques: tuple[str, ...]      # ATT&CK ids as tagged, e.g. "T1059.001"

    def to_row(self) -> list:
        return [self.cls, self.date, self.modified, list(self.techniques)]

    @classmethod
    def from_row(cls, row: list) -> "Rule":
        kind, day, modified, techniques = row
        if kind not in (ACTIVE, DEPRECATED):
            raise ValueError(f"bad rule class {kind!r}")
        _date.fromisoformat(day)
        if modified is not None:
            _date.fromisoformat(modified)
        return cls(kind, day, modified, tuple(str(t) for t in techniques))


# ------------------------------------------------------------ the reader

def classify(path: str) -> str | None:
    """``active`` / ``deprecated`` for a repository path, None when the file
    is not a counted rule (see the module docstring)."""
    if not path.endswith(".yml"):
        return None
    top = path.split("/", 1)[0]
    if "/" not in path:
        return None
    if top == "deprecated":
        return DEPRECATED
    if top == "rules" or top.startswith("rules-"):
        return ACTIVE
    return None


def _scalar(raw: str) -> str:
    """A YAML plain or quoted scalar as text, trailing comment removed."""
    value = raw.strip()
    if value[:1] in ("'", '"'):
        quote = value[0]
        end = value.find(quote, 1)
        return value[1:end] if end > 0 else value[1:]
    hash_at = value.find(" #")
    if hash_at >= 0:
        value = value[:hash_at]
    return value.strip()


def _iso_date(value: str | None) -> str | None:
    """``2023-01-31`` or ``2023/01/31`` -> ``2023-01-31``; None when absent
    or not a real calendar date."""
    if not value:
        return None
    m = _DATE_RE.match(value)
    if not m:
        return None
    try:
        return _date(int(m.group(1)), int(m.group(2)),
                     int(m.group(3))).isoformat()
    except ValueError:
        return None


def read_fields(text: str) -> dict:
    """The top-level ``status``/``date``/``modified`` scalars and the
    ``tags`` list of the first YAML document in ``text``. A strict line
    reader for SigmaHQ's linted layout: top-level keys start in column 0;
    ``tags`` is a block list of ``- item`` lines (a one-line ``[a, b]``
    flow list is accepted too)."""
    fields: dict = {}
    tags: list[str] = []
    in_tags = False
    started = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "---" and not line[:1].isspace():
            if started:
                break           # first document only
            continue
        if not stripped or stripped.startswith("#"):
            continue
        started = True
        if line[:1].isspace():
            if in_tags:
                m = _ITEM_RE.match(line)
                if m:
                    tags.append(_scalar(m.group(1)))
            continue
        in_tags = False
        m = _KEY_RE.match(line)
        if not m:
            continue
        key, rest = m.group(1), m.group(2)
        if key == "tags":
            rest = rest.strip()
            if rest.startswith("[") and rest.endswith("]"):
                tags.extend(_scalar(t) for t in rest[1:-1].split(",")
                            if t.strip())
            elif not rest:
                in_tags = True
        elif key in ("status", "date", "modified"):
            fields[key] = _scalar(rest)
    fields["tags"] = tags
    return fields


def technique_ids(tags: Iterable[str]) -> tuple[str, ...]:
    """ATT&CK technique ids from ``attack.tNNNN[.NNN]`` tags, upper-cased,
    de-duplicated, in sorted order. Tactic, group and software tags are
    ignored."""
    ids = set()
    for tag in tags:
        m = _TECHNIQUE_TAG_RE.match(tag.strip())
        if m:
            ids.add(m.group(1).upper())
    return tuple(sorted(ids))


def parse_rule(path: str, text: str) -> Rule | None:
    """One rule file -> :class:`Rule`, or None when the file is not a
    counted rule or has no usable ``date`` (the caller counts those)."""
    kind = classify(path)
    if kind is None:
        return None
    fields = read_fields(text)
    day = _iso_date(fields.get("date"))
    if day is None:
        return None
    return Rule(kind, day, _iso_date(fields.get("modified")),
                technique_ids(fields["tags"]))


@dataclass
class RuleSet:
    """A parsed snapshot of the repository's rules."""

    head: str            # commit sha the files came from ("fixtures" offline)
    commit_date: str     # YYYY-MM-DD of that commit
    rules: list[Rule]
    files: int           # counted .yml files seen
    skipped: int         # of those, files without a usable date


def parse_files(items: Iterable[tuple[str, str]], *, head: str,
                commit_date: str, min_rules: int = MIN_RULES) -> RuleSet:
    """Parse ``(path, text)`` pairs into a :class:`RuleSet`, enforcing the
    structural floor (module docstring)."""
    rules: list[Rule] = []
    files = skipped = 0
    for path, text in items:
        if classify(path) is None:
            continue
        files += 1
        rule = parse_rule(path, text)
        if rule is None:
            skipped += 1
            continue
        rules.append(rule)
    if len(rules) < min_rules:
        raise ValueError(f"sigma: only {len(rules)} rules parsed "
                         f"(floor {min_rules}); upstream layout changed?")
    if files and skipped / files > MAX_SKIPPED_SHARE:
        raise ValueError(f"sigma: {skipped} of {files} rule files have no "
                         f"usable date; upstream format changed?")
    return RuleSet(head=head, commit_date=commit_date, rules=rules,
                   files=files, skipped=skipped)


def read_tree(root: Path) -> Iterator[tuple[str, str]]:
    """``(path, text)`` for every counted rule file under a checked-out
    tree (the offline fixtures)."""
    for path in sorted(root.rglob("*.yml")):
        rel = path.relative_to(root).as_posix()
        if classify(rel) is not None:
            yield rel, path.read_text(encoding="utf-8")


# ------------------------------------------------------------- git access

def _git_env() -> dict:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"   # never block on a credential prompt
    env.setdefault("GIT_ASKPASS", "true")
    return env


def _git(args: list[str], *, timeout: float, input_bytes: bytes | None = None,
         run=subprocess.run) -> bytes:
    """One git invocation; any failure becomes :class:`SigmaFetchError`."""
    try:
        proc = run(["git", *args], input=input_bytes, capture_output=True,
                   timeout=timeout, env=_git_env(), check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SigmaFetchError(f"git {args[0]} failed: {exc!r}") from exc
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", "replace").strip()
        raise SigmaFetchError(f"git {args[0]} exited {proc.returncode}: "
                              f"{err[-300:]}")
    return proc.stdout


def _with_retry(action: Callable[[], object], label: str,
                log: Callable[[str], None], sleep=time.sleep,
                attempts: int = _MAX_ATTEMPTS):
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return action()
        except SigmaFetchError as exc:
            last = exc
            if attempt == attempts:
                break
            wait = _BACKOFF * attempt
            log(f"  sigma: {label} failed ({exc}); retrying in {wait:.0f}s "
                f"(attempt {attempt}/{attempts})")
            sleep(wait)
    raise SigmaFetchError(f"sigma: {label} failed after {attempts} "
                          f"attempts: {last}")


def remote_head(*, run=subprocess.run, sleep=time.sleep,
                log: Callable[[str], None] = print) -> str:
    """The upstream branch head (40-hex sha) via ``git ls-remote``."""
    ref = f"refs/heads/{SIGMA_BRANCH}"

    def _once() -> str:
        out = _git(["ls-remote", SIGMA_REPO, ref],
                   timeout=_LS_REMOTE_TIMEOUT, run=run).decode("utf-8",
                                                                "replace")
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == ref and _SHA_RE.match(parts[0]):
                return parts[0]
        raise SigmaFetchError(f"git ls-remote returned no {ref}")

    return _with_retry(_once, "ls-remote", log, sleep)


def _cat_blobs(repo: Path, entries: list[tuple[str, str]], *,
               run=subprocess.run) -> Iterator[tuple[str, str]]:
    """``(path, text)`` for each ``(path, blob sha)`` via one
    ``git cat-file --batch`` call."""
    if not entries:
        return
    payload = "".join(f"{sha}\n" for _path, sha in entries).encode("ascii")
    out = _git(["-C", str(repo), "cat-file", "--batch"],
               timeout=_LOCAL_TIMEOUT, input_bytes=payload, run=run)
    pos = 0
    for path, sha in entries:
        nl = out.index(b"\n", pos)
        header = out[pos:nl].decode("ascii", "replace").split()
        if len(header) != 3 or header[0] != sha or header[1] != "blob":
            raise SigmaFetchError(f"git cat-file: unexpected header "
                                  f"{header!r} for {path}")
        size = int(header[2])
        start = nl + 1
        yield path, out[start:start + size].decode("utf-8", "replace")
        pos = start + size + 1          # content is followed by a newline


def fetch_snapshot(*, run=subprocess.run, sleep=time.sleep,
                   log: Callable[[str], None] = print,
                   min_rules: int = MIN_RULES) -> RuleSet:
    """Shallow-clone the repository (bare, depth 1) into a temporary
    directory and parse every counted rule file at its head."""
    with tempfile.TemporaryDirectory(prefix="cybermon-sigma-") as tmp:
        repo = Path(tmp) / "sigma.git"

        def _clone() -> None:
            if repo.exists():
                import shutil

                shutil.rmtree(repo)
            _git(["clone", "--quiet", "--depth", "1", "--single-branch",
                  "--branch", SIGMA_BRANCH, "--bare", SIGMA_REPO, str(repo)],
                 timeout=_CLONE_TIMEOUT, run=run)

        _with_retry(_clone, "shallow clone", log, sleep)
        head = _git(["-C", str(repo), "rev-parse", "HEAD"],
                    timeout=_LOCAL_TIMEOUT, run=run).decode().strip()
        if not _SHA_RE.match(head):
            raise SigmaFetchError(f"git rev-parse gave {head!r}")
        commit_date = _git(["-C", str(repo), "show", "-s", "--format=%cI",
                            "HEAD"], timeout=_LOCAL_TIMEOUT,
                           run=run).decode().strip()[:10]
        if _iso_date(commit_date) is None:
            raise SigmaFetchError(f"git show gave commit date "
                                  f"{commit_date!r}")
        listing = _git(["-C", str(repo), "ls-tree", "-r", "-z", "HEAD"],
                       timeout=_LOCAL_TIMEOUT, run=run)
        entries: list[tuple[str, str]] = []
        for record in listing.split(b"\0"):
            if not record:
                continue
            meta, _tab, raw_path = record.partition(b"\t")
            parts = meta.decode("ascii", "replace").split()
            path = raw_path.decode("utf-8", "replace")
            if len(parts) == 3 and parts[1] == "blob" \
                    and classify(path) is not None:
                entries.append((path, parts[2]))
        log(f"  sigma: {len(entries)} rule files at {head[:12]} "
            f"({commit_date})")
        return parse_files(_cat_blobs(repo, entries, run=run), head=head,
                           commit_date=commit_date, min_rules=min_rules)


# ----------------------------------------------------------- cached rules

def state_path(cache_dir: Path) -> Path:
    return cache_dir / STATE_FILENAME


def load_state(cache_dir: Path, log: Callable[[str], None] = print) -> dict:
    """The whole sigma cache file (``{"rules": …, "attack": …}``), or an
    empty dict when absent or unreadable — it is only ever a cache."""
    path = state_path(cache_dir)
    if not path.exists():
        return {}
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log(f"warning: ignoring unreadable sigma state {path}: {exc!r}")
        return {}
    if not isinstance(obj, dict) or obj.get("version") != STATE_VERSION:
        return {}
    return obj


def save_state(cache_dir: Path, state: dict) -> None:
    """Write the cache atomically (temp file, then ``replace``)."""
    path = state_path(cache_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps({**state, "version": STATE_VERSION},
                              separators=(",", ":")), encoding="utf-8")
    tmp.replace(path)


def rules_to_state(rule_set: RuleSet) -> dict:
    return {"parser": PARSER_VERSION, "head": rule_set.head,
            "commit_date": rule_set.commit_date, "files": rule_set.files,
            "skipped": rule_set.skipped,
            "rules": [r.to_row() for r in rule_set.rules]}


def rules_from_state(block: object) -> RuleSet | None:
    """A cached :class:`RuleSet`, or None when the block is missing, was
    written by another reader version, or is malformed."""
    if not isinstance(block, dict) or block.get("parser") != PARSER_VERSION:
        return None
    try:
        head = str(block["head"])
        if not _SHA_RE.match(head):
            return None
        rules = [Rule.from_row(row) for row in block["rules"]]
        return RuleSet(head=head, commit_date=str(block["commit_date"]),
                       rules=rules, files=int(block["files"]),
                       skipped=int(block["skipped"]))
    except (KeyError, TypeError, ValueError):
        return None


def current_rules(state: dict, *, run=subprocess.run, sleep=time.sleep,
                  log: Callable[[str], None] = print
                  ) -> tuple[RuleSet, bool]:
    """(tonight's rule set, whether it was fetched). One ``ls-remote``;
    the shallow clone happens only when the head moved or the cache
    holds no usable rule set for it."""
    head = remote_head(run=run, sleep=sleep, log=log)
    cached = rules_from_state(state.get("rules"))
    if cached is not None and cached.head == head:
        log(f"  sigma: head {head[:12]} unchanged; using cached rules "
            f"({len(cached.rules)})")
        return cached, False
    log(f"  sigma: head {head[:12]} "
        f"{'moved' if cached else 'not cached'}; shallow-cloning")
    return fetch_snapshot(run=run, sleep=sleep, log=log), True
