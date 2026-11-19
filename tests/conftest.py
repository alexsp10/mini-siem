from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from minisiem.parsers import parse_file
from minisiem.rules import load_rules
from minisiem.schema import Event, assign_ids

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"
SAMPLES = ROOT / "samples"
T0 = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


def load_sample(name: str) -> list[Event]:
    events: list[Event] = []
    for path in sorted((SAMPLES / name).iterdir()):
        events.extend(parse_file(path, year=2026).events)
    return events


@pytest.fixture(scope="session")
def rules():
    loaded, errors = load_rules(RULES_DIR)
    assert not errors, errors
    return loaded


@pytest.fixture(scope="session")
def attack_events():
    return load_sample("attack")


@pytest.fixture(scope="session")
def benign_events():
    return load_sample("benign")


def make_event(seconds: float = 0, raw: str | None = None, **fields) -> Event:
    """Build an event; the first ``_`` in a keyword becomes a dot (``process_command_line`` -> ``process.command_line``)."""
    normalised = {key.replace("_", ".", 1): value for key, value in fields.items()}
    event = Event(T0 + timedelta(seconds=seconds), normalised, raw or repr(sorted(normalised.items())))
    assign_ids([event])
    return event
