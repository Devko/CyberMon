"""Contract for the ATT&CK Churn output (attack_churn.json).

Same philosophy as pipeline/contracts.py — hand-rolled stdlib validators
that fail loudly — kept in its own module so the ATT&CK stage lands
without touching the core contracts file. The coordinator merges
:data:`VALIDATORS` into the pipeline's dispatch; failures raise the same
:class:`pipeline.contracts.ContractViolation` type, so callers need only
one except clause.

The core module's private checking helpers are reused read-only.

Load-bearing shape guarantee (docs/data-contracts.md): the per-version
objects in ``versions[]`` must round-trip losslessly into
``fetch_attack``'s sync-state entries — the published file doubles as the
backup of the state cache. Anything this validator lets through must
therefore satisfy ``fetch_attack.reconstruct_state``.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .contracts import (DATE_RE, _check_bool, _check_generated_at,
                        _check_int, _check_list, _check_sorted, _check_str,
                        _fail, _get)

VERSION_RE = re.compile(r"^\d+(?:\.\d+)+$")
STAT_KEYS = ("techniques", "subtechniques", "groups", "software")
CHURN_KEYS = ("added", "deprecated", "revoked")


def _check_version_entry(entry: Any, path: str) -> tuple[tuple, str]:
    version = _get(entry, "version", path)
    _check_str(version, f"{path}.version", VERSION_RE)
    released = _get(entry, "released", path)
    _check_str(released, f"{path}.released", DATE_RE)
    for key in STAT_KEYS:
        _check_int(_get(entry, key, path), f"{path}.{key}")
    churn = _get(entry, "churn", path)
    if churn is not None:
        for key in CHURN_KEYS:
            _check_int(_get(churn, key, f"{path}.churn"),
                       f"{path}.churn.{key}")
    return tuple(int(p) for p in version.split(".")), released


def _check_headline(headline: Any, versions: list) -> None:
    path = "attack_churn.headline"
    if not versions:
        if headline is not None:
            _fail(path, "must be null when versions is empty")
        return
    if headline is None:
        _fail(path, "must be present when versions is non-empty")
    for key, expected in (("latest_version", versions[-1]["version"]),
                          ("first_version", versions[0]["version"])):
        value = _get(headline, key, path)
        _check_str(value, f"{path}.{key}", VERSION_RE)
        if value != expected:
            _fail(f"{path}.{key}",
                  f"{value!r} does not match versions[] ({expected!r})")
    for key in ("released_latest", "released_first"):
        _check_str(_get(headline, key, path), f"{path}.{key}", DATE_RE)
    for key in ("techniques_latest", "subtechniques_latest",
                "techniques_first", "subtechniques_first"):
        _check_int(_get(headline, key, path), f"{path}.{key}")


# ---------------------------------------------------------- attack_churn.json

def _validate_attack_churn(obj: Any) -> None:
    _check_generated_at(obj, "attack_churn")
    # Optional: present (and true) only on --skip-attack carry-forwards.
    if "stale" in obj:
        _check_bool(obj["stale"], "attack_churn.stale")

    versions = _check_list(_get(obj, "versions", "attack_churn"),
                           "attack_churn.versions")
    keys, released = [], []
    for i, entry in enumerate(versions):
        key, date = _check_version_entry(entry, f"attack_churn.versions[{i}]")
        keys.append(key)
        released.append(date)
    _check_sorted(keys, "attack_churn.versions (by version number)")
    if len(set(keys)) != len(keys):
        _fail("attack_churn.versions", "duplicate versions (one entry each)")
    # Release order and version order must agree; ties (same-day releases)
    # are tolerated, going backwards in time is not.
    _check_sorted(released, "attack_churn.versions (by release date)")

    _check_headline(_get(obj, "headline", "attack_churn"), versions)


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "attack_churn.json": _validate_attack_churn,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the ATT&CK contract for ``filename``.

    Raises :class:`pipeline.contracts.ContractViolation` on any mismatch,
    ``KeyError`` if the filename has no ATT&CK contract.
    """
    VALIDATORS[filename](obj)
