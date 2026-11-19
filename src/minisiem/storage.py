"""SQLite storage for events and alerts."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .schema import LEVELS, Alert, Event, level_rank
from .timeutil import format_ts, parse_iso

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id      TEXT PRIMARY KEY,
    ts      TEXT NOT NULL,
    source  TEXT,
    action  TEXT,
    host    TEXT,
    fields  TEXT NOT NULL,
    raw     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    rule_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    level       TEXT NOT NULL,
    ts          TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    description TEXT,
    tags        TEXT,
    grp         TEXT,
    summary     TEXT,
    event_ids   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.executescript(_SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ events

    def add_events(self, events: Iterable[Event]) -> int:
        """Insert events, ignoring ones already stored. Returns the number of new rows."""
        rows = [
            (
                e.id,
                format_ts(e.timestamp),
                e.source,
                e.action,
                e.get("host.name"),
                json.dumps(e.fields, default=str, ensure_ascii=False),
                e.raw,
            )
            for e in events
        ]
        before = self.conn.total_changes
        with self.conn:
            self.conn.executemany("INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
        return self.conn.total_changes - before

    @staticmethod
    def _event(row: tuple[Any, ...]) -> Event:
        event_id, ts, fields, raw = row
        return Event(timestamp=parse_iso(ts), fields=json.loads(fields), raw=raw, id=event_id)

    def load_events(self) -> list[Event]:
        cursor = self.conn.execute("SELECT id, ts, fields, raw FROM events ORDER BY ts, rowid")
        return [self._event(row) for row in cursor]

    def _events_by_id(self, ids: list[str]) -> dict[str, Event]:
        found: dict[str, Event] = {}
        unique = list(dict.fromkeys(ids))
        for start in range(0, len(unique), 500):
            chunk = unique[start : start + 500]
            # Only "?" placeholders are interpolated; the values themselves are bound parameters.
            placeholders = ",".join("?" * len(chunk))
            cursor = self.conn.execute(
                f"SELECT id, ts, fields, raw FROM events WHERE id IN ({placeholders})",  # noqa: S608
                chunk,
            )
            for row in cursor:
                found[row[0]] = self._event(row)
        return found

    # ------------------------------------------------------------------ alerts

    def replace_alerts(self, alerts: Iterable[Alert]) -> None:
        """Detection is a full re-evaluation, so the previous result set is replaced."""
        rows = [
            (
                a.id,
                a.rule_id,
                a.title,
                a.level,
                format_ts(a.timestamp),
                format_ts(a.last_seen),
                a.description,
                json.dumps(a.tags),
                json.dumps(a.group, default=str),
                a.summary,
                json.dumps([e.id for e in a.events]),
            )
            for a in alerts
        ]
        with self.conn:
            self.conn.execute("DELETE FROM alerts")
            self.conn.executemany("INSERT OR REPLACE INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)

    def load_alerts(self, min_level: str | None = None) -> list[Alert]:
        rows = self.conn.execute(
            "SELECT rule_id, title, level, description, tags, grp, summary, event_ids FROM alerts ORDER BY ts, rule_id"
        ).fetchall()
        if min_level:
            rows = [r for r in rows if level_rank(r[2]) >= level_rank(min_level)]
        all_ids = [i for r in rows for i in json.loads(r[7])]
        events = self._events_by_id(all_ids)
        alerts = []
        for rule_id, title, level, description, tags, grp, summary, event_ids in rows:
            alert_events = [events[i] for i in json.loads(event_ids) if i in events]
            if not alert_events:
                continue
            alerts.append(
                Alert(
                    rule_id=rule_id,
                    title=title,
                    level=level,
                    description=description or "",
                    tags=json.loads(tags or "[]"),
                    events=alert_events,
                    group=json.loads(grp or "{}"),
                    summary=summary or "",
                )
            )
        return alerts

    # ------------------------------------------------------------------ stats

    def stats(self) -> dict[str, Any]:
        total, first, last = self.conn.execute("SELECT COUNT(*), MIN(ts), MAX(ts) FROM events").fetchone()
        by_source = dict(
            self.conn.execute("SELECT source, COUNT(*) FROM events GROUP BY source ORDER BY 2 DESC").fetchall()
        )
        hosts = [
            r[0]
            for r in self.conn.execute(
                "SELECT DISTINCT host FROM events WHERE host IS NOT NULL ORDER BY host"
            ).fetchall()
        ]
        by_level = dict.fromkeys(LEVELS, 0)
        for level, count in self.conn.execute("SELECT level, COUNT(*) FROM alerts GROUP BY level"):
            by_level[level] = count
        return {
            "events": total,
            "first": parse_iso(first) if first else None,
            "last": parse_iso(last) if last else None,
            "by_source": by_source,
            "hosts": hosts,
            "alerts_by_level": by_level,
        }
