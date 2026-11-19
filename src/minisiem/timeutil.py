"""Timestamp and duration helpers. All timestamps are normalised to UTC."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

_MS_DATE = re.compile(r"/Date\((-?\d+)\)/")
_FRACTION = re.compile(r"(?<=\d{2}:\d{2}:\d{2})\.(\d+)")
_OFFSET_NO_COLON = re.compile(r"([+-]\d{2})(\d{2})$")
_DURATION = re.compile(r"^(\d+)\s*([smhd])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 timestamp (or a .NET ``/Date(ms)/`` value) into an aware UTC datetime.

    Handles the quirks seen in real exports: a trailing ``Z``, 7-digit fractional
    seconds from PowerShell's ``"o"`` format, and ``+0000`` offsets without a colon.
    """
    value = value.strip()
    match = _MS_DATE.fullmatch(value)
    if match:
        return datetime.fromtimestamp(int(match.group(1)) / 1000, tz=timezone.utc)
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    value = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), value)
    value = _OFFSET_NO_COLON.sub(r"\1:\2", value)
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_ts(value: datetime) -> str:
    """Stable, sortable string form used for storage."""
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def parse_duration(value: object) -> timedelta:
    """Parse ``30s`` / ``5m`` / ``1h`` / ``1d`` (or a number of seconds)."""
    if isinstance(value, bool):
        raise ValueError(f"invalid duration {value!r}")
    if isinstance(value, (int, float)):
        if value <= 0:
            raise ValueError(f"duration must be positive, got {value!r}")
        return timedelta(seconds=value)
    match = _DURATION.match(str(value).strip().lower())
    if not match or int(match.group(1)) == 0:
        raise ValueError(f"invalid duration {value!r} (expected e.g. 30s, 5m, 1h, 1d)")
    return timedelta(**{_UNITS[match.group(2)]: int(match.group(1))})


def format_duration(value: timedelta) -> str:
    seconds = int(value.total_seconds())
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size and seconds % size == 0:
            return f"{seconds // size}{unit}"
    if seconds >= 3600:
        return f"{seconds // 3600}h{seconds % 3600 // 60}m"
    if seconds >= 60:
        return f"{seconds // 60}m{seconds % 60}s"
    return f"{seconds}s"
