"""SigmaHQ fetcher: the strict rule reader, the file classification, the
structural floors, the git transport (driven by a fake runner) and the
head-keyed rule cache."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from pipeline import fetch_sigma as fs

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "sigma" / "repo"
HEAD = "a" * 40


# ------------------------------------------------------------ the reader

def test_classify_counts_rule_folders_and_deprecated_only():
    assert fs.classify("rules/windows/x.yml") == fs.ACTIVE
    assert fs.classify("rules-emerging-threats/2024/x.yml") == fs.ACTIVE
    assert fs.classify("rules-placeholder/windows/x.yml") == fs.ACTIVE
    assert fs.classify("deprecated/windows/x.yml") == fs.DEPRECATED
    for path in ("unsupported/windows/x.yml", "regression_data/rules/x.yml",
                 "tests/x.yml", ".github/workflows/x.yml", "rules.yml",
                 "rules/windows/README.md", "deprecated/deprecated.json"):
        assert fs.classify(path) is None, path


def test_read_fields_handles_the_upstream_layouts():
    text = (
        "---\n"
        "title: x\n"
        "status: deprecated # In favour of another rule\n"
        "date: 2017/03/01\n"
        "modified: '2023-02-01'\n"
        "tags:\n"
        "    - attack.execution\n"
        "    # a comment inside the list\n"
        "  - attack.T1059.001\n"
        "logsource:\n"
        "    product: windows\n"
        "    tags:\n"
        "        - attack.t9999\n"
        "---\n"
        "date: 1999-01-01\n"
    )
    f = fs.read_fields(text)
    assert f["status"] == "deprecated"
    assert f["date"] == "2017/03/01"
    assert f["modified"] == "2023-02-01"
    assert f["tags"] == ["attack.execution", "attack.T1059.001"]


def test_flow_list_tags_and_technique_ids():
    f = fs.read_fields("date: 2020-01-01\ntags: [attack.t1003, 'attack.T1003.001', attack.g0010]\n")
    assert fs.technique_ids(f["tags"]) == ("T1003", "T1003.001")
    assert fs.technique_ids(["attack.t12345", "attack.ta0001", "car.t1059",
                             "attack.t1059.01"]) == ()


@pytest.mark.parametrize("raw,want", [
    ("2023-01-31", "2023-01-31"), ("2023/01/31", "2023-01-31"),
    ("2023-02-30", None), ("23-01-31", None), ("", None), (None, None),
])
def test_iso_date(raw, want):
    assert fs._iso_date(raw) == want


def test_parse_rule_skips_undated_and_uncounted_files():
    assert fs.parse_rule("rules/x/a.yml", "title: no date\n") is None
    assert fs.parse_rule("unsupported/x/a.yml", "date: 2020-01-01\n") is None
    rule = fs.parse_rule("deprecated/x/a.yml",
                         "date: 2020-01-01\nmodified: 2021/02/03\n"
                         "tags:\n  - attack.t1003\n")
    assert rule == fs.Rule(fs.DEPRECATED, "2020-01-01", "2021-02-03",
                           ("T1003",))


def test_fixture_tree_parses_with_its_exclusions():
    rs = fs.parse_files(fs.read_tree(FIXTURE_REPO), head=HEAD,
                        commit_date="2026-11-05", min_rules=1)
    assert (len(rs.rules), rs.files, rs.skipped) == (8, 8, 0)
    assert sum(r.cls == fs.DEPRECATED for r in rs.rules) == 2
    placeholder = [r for r in rs.rules if r.date == "2023-06-15"]
    assert placeholder and placeholder[0].techniques == ("T1059.001",)


def test_fixture_tree_matches_pyyaml():
    yaml = pytest.importorskip("yaml")
    for path, text in fs.read_tree(FIXTURE_REPO):
        doc = next(yaml.safe_load_all(text))
        rule = fs.parse_rule(path, text)
        assert rule.date == str(doc["date"]).replace("/", "-"), path
        mod = doc.get("modified")
        assert rule.modified == (str(mod).replace("/", "-") if mod else None)
        assert rule.techniques == fs.technique_ids(doc.get("tags") or [])


def test_floors_refuse_a_broken_snapshot():
    good = [(f"rules/w/{i}.yml", "date: 2020-01-01\n") for i in range(60)]
    with pytest.raises(ValueError, match="only 60 rules"):
        fs.parse_files(good, head=HEAD, commit_date="2026-01-01")
    undated = good + [("rules/w/x.yml", "title: undated\n")] * 2
    with pytest.raises(ValueError, match="no usable date"):
        fs.parse_files(undated, head=HEAD, commit_date="2026-01-01",
                       min_rules=1)
    rs = fs.parse_files(good + [("rules/w/x.yml", "title: undated\n")],
                        head=HEAD, commit_date="2026-01-01", min_rules=1)
    assert (len(rs.rules), rs.skipped) == (60, 1)


# ------------------------------------------------------------ git transport

class FakeGit:
    """Answers the git calls fetch_sigma makes from an in-memory tree."""

    def __init__(self, files: dict[str, str], head: str = HEAD,
                 fail: set[str] = frozenset()):
        self.files = files
        self.head = head
        self.fail = set(fail)
        self.calls: list[str] = []
        self.blobs = {f"{i:040x}": text
                      for i, text in enumerate(files.values(), start=1)}
        self.sha_of = dict(zip(files, self.blobs))

    def __call__(self, argv, input=None, **kwargs):
        args = argv[1:]
        if args[0] == "-C":
            args = args[2:]
        verb = args[0]
        self.calls.append(verb)
        if verb in self.fail:
            return subprocess.CompletedProcess(argv, 128, b"", b"fatal: boom")
        out = b""
        if verb == "ls-remote":
            out = f"{self.head}\trefs/heads/master\n".encode()
        elif verb == "clone":
            Path(args[-1]).mkdir(parents=True)
        elif verb == "rev-parse":
            out = f"{self.head}\n".encode()
        elif verb == "show":
            out = b"2026-11-05T12:10:50+05:45\n"
        elif verb == "ls-tree":
            out = b"".join(
                f"100644 blob {sha}\t{path}".encode() + b"\0"
                for path, sha in self.sha_of.items())
        elif verb == "cat-file":
            for sha in input.decode().split():
                body = self.blobs[sha].encode()
                out += f"{sha} blob {len(body)}\n".encode() + body + b"\n"
        return subprocess.CompletedProcess(argv, 0, out, b"")


def _tree(n: int = 1001) -> dict[str, str]:
    files = {f"rules/w/r{i}.yml": f"date: 2020-01-{1 + i % 28:02d}\n"
             f"tags:\n  - attack.t1059.001\n" for i in range(n)}
    files["unsupported/w/u.yml"] = "date: 2020-01-01\n"
    files["deprecated/w/d.yml"] = "date: 2019-01-01\nmodified: 2022-01-01\n"
    return files


def test_fetch_snapshot_reads_blobs_without_checkout():
    git = FakeGit(_tree())
    rs = fs.fetch_snapshot(run=git, sleep=lambda s: None, log=lambda m: None)
    assert rs.head == HEAD and rs.commit_date == "2026-11-05"
    assert len(rs.rules) == 1002 and rs.files == 1002
    assert git.calls == ["clone", "rev-parse", "show", "ls-tree", "cat-file"]


def test_current_rules_clones_only_when_the_head_moves():
    git = FakeGit(_tree())
    quiet = {"run": git, "sleep": lambda s: None, "log": lambda m: None}
    rs, fetched = fs.current_rules({}, **quiet)
    assert fetched
    state = {"rules": fs.rules_to_state(rs)}
    git.calls.clear()
    again, fetched = fs.current_rules(state, **quiet)
    assert not fetched and git.calls == ["ls-remote"]
    assert again.rules == rs.rules
    git.head = "b" * 40
    git.calls.clear()
    _moved, fetched = fs.current_rules(state, **quiet)
    assert fetched and "clone" in git.calls


def test_cache_from_an_older_reader_is_not_reused():
    rs = fs.parse_files(fs.read_tree(FIXTURE_REPO), head=HEAD,
                        commit_date="2026-11-05", min_rules=1)
    block = fs.rules_to_state(rs)
    assert fs.rules_from_state(block).rules == rs.rules
    assert fs.rules_from_state({**block, "parser": -1}) is None
    assert fs.rules_from_state({**block, "rules": [["bogus", "x", None,
                                                    []]]}) is None
    assert fs.rules_from_state(None) is None


def test_git_failures_retry_then_raise_oserror():
    git = FakeGit(_tree(), fail={"ls-remote"})
    sleeps = []
    with pytest.raises(OSError, match="ls-remote failed after 3"):
        fs.remote_head(run=git, sleep=sleeps.append, log=lambda m: None)
    assert git.calls.count("ls-remote") == 3 and len(sleeps) == 2


def test_missing_git_binary_is_an_oserror():
    def no_git(*args, **kwargs):
        raise FileNotFoundError("git")

    with pytest.raises(fs.SigmaFetchError):
        fs.remote_head(run=no_git, sleep=lambda s: None, log=lambda m: None)


def test_state_round_trip(tmp_path):
    assert fs.load_state(tmp_path) == {}
    fs.save_state(tmp_path, {"rules": {"head": HEAD}})
    assert fs.load_state(tmp_path)["rules"] == {"head": HEAD}
    (tmp_path / fs.STATE_FILENAME).write_text("{not json", encoding="utf-8")
    assert fs.load_state(tmp_path, log=lambda m: None) == {}
