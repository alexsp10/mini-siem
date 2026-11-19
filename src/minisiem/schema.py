"""Normalised event and alert models.

Every parser turns its input into :class:`Event` objects whose ``fields`` use a
small, flat, ECS-inspired vocabulary (``event.action``, ``user.name``,
``source.ip``, ``process.command_line`` ...). Detection rules are written
against these names, so one rule can cover several log formats.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

LEVELS = ("informational", "low", "medium", "high", "critical")

KNOWN_SOURCES = (
    "linux_auth",
    "windows_security",
    "windows_system",
    "windows_powershell",
    "sysmon",
    "windows",
)


def level_rank(level: str) -> int:
    return LEVELS.index(level)


def is_present(value: Any) -> bool:
    return value is not None and str(value).strip() not in ("", "-")


@dataclass
class Event:
    timestamp: datetime
    fields: dict[str, Any]
    raw: str
    id: str = ""

    def get(self, key: str) -> Any:
        if key == "@timestamp":
            return self.timestamp.isoformat()
        return self.fields.get(key)

    @property
    def source(self) -> str:
        return str(self.fields.get("event.source", ""))

    @property
    def action(self) -> str:
        return str(self.fields.get("event.action", ""))


def assign_ids(events: list[Event]) -> None:
    """Give each event a content-derived id.

    Re-ingesting the same file yields the same ids (so it is de-duplicated),
    while genuinely repeated identical lines inside one file stay distinct.
    """
    seen: Counter[str] = Counter()
    for event in events:
        occurrence = seen[event.raw]
        seen[event.raw] += 1
        digest = hashlib.sha256(f"{event.raw}\x00{occurrence}".encode("utf-8", "replace"))
        event.id = digest.hexdigest()[:20]


_DESCRIBE_KEYS = (
    ("user.name", "user"),
    ("user.target.name", "target_user"),
    ("user.target.sid", "target_sid"),
    ("group.name", "group"),
    ("source.ip", "src"),
    ("process.parent.name", "parent"),
    ("process.name", "process"),
    ("target.process.name", "target_process"),
    ("access.granted", "access"),
    ("task.name", "task"),
    ("service.name", "service"),
    ("service.image_path", "image_path"),
    ("process.command_line", "cmd"),
)


def describe_event(event: Event, max_len: int = 180) -> str:
    """One-line, human readable summary of the interesting fields of an event."""
    parts = [event.action or "event"]
    for key, label in _DESCRIBE_KEYS:
        if event.source == "linux_auth" and key == "process.name":
            continue
        value = event.get(key)
        if is_present(value):
            parts.append(f"{label}={value}")
    text = " ".join(parts)
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


@dataclass
class Alert:
    rule_id: str
    title: str
    level: str
    description: str
    tags: list[str]
    events: list[Event]
    group: dict[str, Any] = field(default_factory=dict)
    summary: str = ""

    @property
    def timestamp(self) -> datetime:
        return self.events[0].timestamp

    @property
    def last_seen(self) -> datetime:
        return self.events[-1].timestamp

    @property
    def id(self) -> str:
        material = self.rule_id + ":" + ",".join(e.id for e in self.events)
        return hashlib.sha256(material.encode()).hexdigest()[:20]

    def context(self, key: str, limit: int = 3) -> list[str]:
        """Distinct values of ``key`` across the alert's events, in first-seen order."""
        values: list[str] = []
        for event in self.events:
            value = event.get(key)
            if is_present(value) and str(value) not in values:
                values.append(str(value))
                if len(values) >= limit:
                    break
        return values
