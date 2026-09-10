"""Contract for ``field.json`` — the Field's index file (pipeline/field_export.py).

Registered in :mod:`pipeline.contracts` like every other module contract.
The binary stream itself is validated by construction (a fixed struct) and
cross-checked here only by size: ``raw_bytes`` must equal ``n × record_bytes``.
"""
from __future__ import annotations

import re

from typing import Any, Callable

from .contracts import (ContractViolation, _check_generated_at, _check_int,
                        _check_list, _check_str)


def _validate_field(obj: Any) -> None:
    if not isinstance(obj, dict):
        raise ContractViolation("field.json: not an object")
    _check_generated_at(obj, "field.json")
    layout = obj.get("layout")
    if not isinstance(layout, dict):
        raise ContractViolation("field.json.layout: not an object")
    _check_int(layout.get("version"), "field.json.layout.version", minimum=1)
    _check_int(layout.get("record_bytes"), "field.json.layout.record_bytes",
               minimum=1)
    _check_str(layout.get("epoch"), "field.json.layout.epoch")
    codes = _check_list(layout.get("status_codes"),
                        "field.json.layout.status_codes")
    if len(codes) != 8:
        raise ContractViolation("field.json.layout.status_codes: 8 codes "
                                f"fit in three flag bits, got {len(codes)}")
    _check_str(obj.get("bin"), "field.json.bin")
    if layout["version"] >= 4:
        digest = obj.get("sha256", "")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ContractViolation("field.json.sha256: expected SHA-256 digest")
        if obj["bin"] != f"cves.{digest}.bin.gz":
            raise ContractViolation("field.json.bin: must name its content hash")
    n = obj.get("n")
    _check_int(n, "field.json.n", minimum=1)
    _check_int(obj.get("first_day"), "field.json.first_day")
    _check_int(obj.get("last_day"), "field.json.last_day")
    if obj["last_day"] < obj["first_day"]:
        raise ContractViolation("field.json: last_day before first_day")
    counts = obj.get("counts")
    if not isinstance(counts, dict):
        raise ContractViolation("field.json.counts: not an object")
    _check_int(obj.get("window_days"), "field.json.window_days", minimum=1)
    for key in ("kev", "poc", "poc_dated", "scored", "epss", "rescored",
                "crossed"):
        _check_int(counts.get(key), f"field.json.counts.{key}")
        if counts[key] > n:
            raise ContractViolation(f"field.json.counts.{key} exceeds n")
    cnas = _check_list(obj.get("cnas"), "field.json.cnas")
    if not cnas:
        raise ContractViolation("field.json.cnas: empty")
    vendors = _check_list(obj.get("vendors"), "field.json.vendors")
    if not vendors or vendors[0] != "other":
        raise ContractViolation('field.json.vendors[0] must be "other"')
    if len(vendors) > 65536 or len(cnas) > 65536:
        raise ContractViolation("field.json: index tables exceed u16 range")
    skipped = obj.get("skipped")
    if not isinstance(skipped, dict):
        raise ContractViolation("field.json.skipped: not an object")
    for key in ("rejected", "undated"):
        _check_int(skipped.get(key), f"field.json.skipped.{key}")
    _check_int(obj.get("raw_bytes"), "field.json.raw_bytes", minimum=1)
    _check_int(obj.get("bin_bytes"), "field.json.bin_bytes", minimum=1)
    if obj["raw_bytes"] != n * layout["record_bytes"]:
        raise ContractViolation("field.json.raw_bytes != n × record_bytes")
    if not isinstance(obj.get("sources"), dict):
        raise ContractViolation("field.json.sources: not an object")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "field.json": _validate_field,
}
