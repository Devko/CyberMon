"""Ransomwhere crowdsourced ransomware-payment export (CC0, api.ransomwhe.re).

Upstream shape relied on — ``GET /export`` returns::

    {"result": [
      {"address": "1FX4...", "balance": 112667631961, "balanceUSD": 8471774.6,
       "blockchain": "bitcoin", "family": "Maui",
       "createdAt": "2023-02-10T11:50:25.735Z", "updatedAt": "...",
       "transactions": [
         {"hash": "ae95...", "time": 1591420371,
          "amount": 62552, "amountUSD": 6.038}, ...]}, ...]}

Per address record: ``family`` is Ransomwhere's own label (the literal
string ``"Unlabeled"`` marks verified-but-unattributed addresses) and
``transactions`` lists verified inbound transfers. Per transaction:
``time`` is a unix epoch in seconds (UTC), ``amount`` the received value in
the chain's smallest unit (satoshi; the export is bitcoin-only today), and
``amountUSD`` the USD value at the HISTORICAL rate of the transaction date
— the implied BTC/USD rate per transaction year tracks the price history
($127 in 2013, ~$9.5k in 2020, ~$52k in 2021), so sums are
dollars-of-the-day, never a today's-price revaluation.

Unlike fetch_kev's tolerant filtering, malformed records here raise: every
record is money, and silently dropping one would silently understate an
already lower-bound dataset. Fail loud, fix upstream or fix the parser.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

RANSOMWHERE_URL = "https://api.ransomwhe.re/export"

USER_AGENT = "CyberMon/1.0 (+https://github.com/Devko/CyberMon)"

# Ransomwhere's literal label for verified payments nobody has attributed
# to a family. Downstream metrics must never rank it as a "family".
UNATTRIBUTED_LABEL = "Unlabeled"


@dataclass
class RansomTx:
    """One verified inbound transaction on a tracked address."""

    hash: str
    time: int          # unix epoch seconds, UTC
    amount: int        # smallest chain unit (satoshi)
    amount_usd: float  # USD at the historical (transaction-date) rate


@dataclass
class RansomAddress:
    """One tracked ransom address with its verified transactions."""

    address: str
    family: str
    blockchain: str
    transactions: list[RansomTx] = field(default_factory=list, repr=False)


@dataclass
class RansomwhereData:
    """Parsed export: counts for meta.json plus the address records."""

    address_count: int
    tx_count: int
    records: list[RansomAddress] = field(default_factory=list, repr=False)


def _parse_tx(t: object, where: str) -> RansomTx:
    if not isinstance(t, dict):
        raise ValueError(f"ransomwhere: {where}: transaction is not an object")
    h = t.get("hash")
    time = t.get("time")
    amount = t.get("amount")
    usd = t.get("amountUSD")
    if not isinstance(h, str) or not h:
        raise ValueError(f"ransomwhere: {where}: missing transaction hash")
    if isinstance(time, bool) or not isinstance(time, int) or time <= 0:
        raise ValueError(f"ransomwhere: {where}: bad transaction time {time!r}")
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
        raise ValueError(f"ransomwhere: {where}: bad amount {amount!r}")
    if isinstance(usd, bool) or not isinstance(usd, (int, float)) or usd < 0:
        raise ValueError(f"ransomwhere: {where}: bad amountUSD {usd!r}")
    return RansomTx(hash=h, time=time, amount=amount, amount_usd=float(usd))


def parse_ransomwhere(obj: object) -> RansomwhereData:
    """Parse the export document; raise ``ValueError`` on any malformed
    record — this data is money, tolerant parsing would understate it."""
    if not isinstance(obj, dict) or not isinstance(obj.get("result"), list):
        raise ValueError("ransomwhere: expected {'result': [...]} document")
    records: list[RansomAddress] = []
    tx_count = 0
    for i, r in enumerate(obj["result"]):
        where = f"result[{i}]"
        if not isinstance(r, dict):
            raise ValueError(f"ransomwhere: {where}: record is not an object")
        address = r.get("address")
        family = r.get("family")
        blockchain = r.get("blockchain")
        txs = r.get("transactions")
        if not isinstance(address, str) or not address:
            raise ValueError(f"ransomwhere: {where}: missing address")
        if not isinstance(family, str) or not family.strip():
            raise ValueError(f"ransomwhere: {where}: missing family label")
        if not isinstance(blockchain, str) or not blockchain:
            raise ValueError(f"ransomwhere: {where}: missing blockchain")
        if not isinstance(txs, list):
            raise ValueError(f"ransomwhere: {where}: transactions not a list")
        parsed = [_parse_tx(t, f"{where}.transactions[{j}]")
                  for j, t in enumerate(txs)]
        tx_count += len(parsed)
        records.append(RansomAddress(address=address, family=family.strip(),
                                     blockchain=blockchain,
                                     transactions=parsed))
    if not records:
        raise ValueError("ransomwhere: export contains no address records")
    return RansomwhereData(address_count=len(records), tx_count=tx_count,
                           records=records)


def load_ransomwhere_file(path: Path) -> RansomwhereData:
    """Load Ransomwhere data from a local JSON file (fixtures)."""
    return parse_ransomwhere(json.loads(path.read_text(encoding="utf-8")))


def fetch_ransomwhere(session=None, timeout: float = 120.0) -> RansomwhereData:
    """Download and parse the current Ransomwhere export."""
    import requests

    session = session or requests.Session()
    resp = session.get(RANSOMWHERE_URL, timeout=timeout,
                       headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    return parse_ransomwhere(resp.json())
