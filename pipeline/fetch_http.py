"""One bounded-retry GET for every fetcher.

Every upstream fetch in the pipeline follows the same discipline: a
handful of attempts, a linear backoff, retries only on the statuses that
mean "try again later" (429 and the 5xx gateway family) and on connection
errors, and a final failure that raises exactly as an unretried call
would. The retry absorbs blips; it never softens the loud-failure policy
that makes a broken nightly deploy nothing.

This module is the single copy of that ladder. Per-source knobs (attempt
count, backoff, which statuses retry, timeouts) are parameters so a
migrated fetcher keeps its own defaults; the log line format is the one
the fetchers always printed, prefixed with the caller's ``label``.

``Retry-After`` is honoured when the upstream sends one (seconds or an
HTTP-date), capped at :data:`MAX_RETRY_AFTER` so a misconfigured origin
cannot park the nightly for an hour.

The module name shadows nothing when imported as ``pipeline.fetch_http``; do
not run pipeline modules as loose scripts from inside the package
directory, where a bare ``import http`` could resolve here instead of
to the standard library.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, TypeVar

USER_AGENT = "CyberMon/1.0 (+https://github.com/Devko/CyberMon)"

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
DEFAULT_ATTEMPTS = 3
DEFAULT_BACKOFF = 15.0
MAX_RETRY_AFTER = 300.0

T = TypeVar("T")


def retry_after_seconds(resp: Any, now: datetime | None = None
                        ) -> float | None:
    """Seconds the upstream asked us to wait, or None when the response
    carries no usable ``Retry-After``. Accepts delta-seconds and HTTP-date
    forms; anything unparseable is ignored (the caller's backoff applies).
    Never negative; capped at :data:`MAX_RETRY_AFTER`."""
    headers = getattr(resp, "headers", None)
    if not headers:
        return None
    try:
        raw = headers.get("Retry-After")
    except AttributeError:
        return None
    if raw is None:
        return None
    raw = str(raw).strip()
    if not raw:
        return None
    seconds: float | None = None
    try:
        seconds = float(raw)
    except ValueError:
        try:
            when = parsedate_to_datetime(raw)
        except (TypeError, ValueError, IndexError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        now = now or datetime.now(timezone.utc)
        seconds = (when - now).total_seconds()
    if seconds is None:
        return None
    return max(0.0, min(seconds, MAX_RETRY_AFTER))


def get_with_retry(session, url: str, *, label: str,
                   params: dict | None = None,
                   headers: dict | None = None,
                   timeout: Any = 60.0,
                   attempts: int = DEFAULT_ATTEMPTS,
                   backoff: float = DEFAULT_BACKOFF,
                   retry_statuses=RETRY_STATUSES,
                   sleep: Callable[[float], None] = time.sleep,
                   log: Callable[[str], None] = print,
                   stream: bool = False,
                   raise_for_status: bool = True,
                   consume: Callable[[Any], T] | None = None):
    """GET ``url`` with a bounded retry ladder; return the response (or,
    when ``consume`` is given, whatever ``consume(response)`` returns).

    Attempt ``attempts`` times. A status in ``retry_statuses`` or an
    ``OSError`` (``requests`` exceptions subclass it) on a non-final
    attempt logs and sleeps ``backoff * attempt`` seconds — or the
    upstream's ``Retry-After`` when it sends one — then retries. On the
    final attempt, or on any other status, ``resp.raise_for_status()`` is
    called (unless ``raise_for_status`` is False, in which case the
    response is returned unchecked and the caller judges the status) and
    the response is returned.

    ``consume`` runs inside the ladder, so an ``OSError`` raised while
    reading a streamed body (a connection that dies mid-download) is
    retried like a failed connect. Any other exception from ``consume``
    propagates unchanged.

    Every request carries :data:`USER_AGENT`; ``headers`` are merged on
    top and may override it. ``params`` and ``stream`` are passed to
    ``session.get`` only when given, so the minimal fake sessions in the
    test-suite keep working.
    """
    if attempts < 1:
        raise ValueError("attempts must be at least 1")
    kwargs: dict[str, Any] = {
        "timeout": timeout,
        "headers": {"User-Agent": USER_AGENT, **(headers or {})},
    }
    if params is not None:
        kwargs["params"] = params
    if stream:
        kwargs["stream"] = True

    for attempt in range(1, attempts + 1):
        last = attempt == attempts
        wait: float | None = None
        try:
            resp = session.get(url, **kwargs)
        except OSError as exc:  # requests exceptions subclass OSError
            if last:
                raise
            message = f"request failed: {exc!r}"
        else:
            if last or resp.status_code not in retry_statuses:
                if raise_for_status:
                    resp.raise_for_status()
                if consume is None:
                    return resp
                try:
                    return consume(resp)
                except OSError as exc:
                    if last:
                        raise
                    message = f"read failed: {exc!r}"
            else:
                message = f"HTTP {resp.status_code}"
                wait = retry_after_seconds(resp)
        if wait is None:
            wait = backoff * attempt
        log(f"  {label}: {message} for {url}; retrying in {wait:.0f}s "
            f"(attempt {attempt}/{attempts})")
        sleep(wait)
    raise AssertionError("unreachable")  # pragma: no cover
