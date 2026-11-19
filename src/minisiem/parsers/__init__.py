"""Log parsers. Each turns raw text into normalised :class:`~minisiem.schema.Event` objects."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..schema import Event, assign_ids
from . import linux_auth, windows

FORMATS = ("auto", "linux_auth", "windows_json")
_JSON_SUFFIXES = {".json", ".jsonl", ".ndjson"}


@dataclass
class ParseResult:
    path: str
    format: str
    events: list[Event]
    skipped: int


def read_text(path: str | Path) -> str:
    """Read a log file, coping with UTF-16 (PowerShell 5.1 ``>`` redirection) and BOMs."""
    data = Path(path).read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    return data.decode("utf-8-sig", errors="replace")


def detect_format(path: str | Path, text: str) -> str:
    if Path(path).suffix.lower() in _JSON_SUFFIXES:
        return "windows_json"
    for line in text.splitlines():
        if line.strip():
            return "windows_json" if line.lstrip().startswith(("{", "[")) else "linux_auth"
    return "linux_auth"


def parse_text(text: str, fmt: str, year: int | None = None) -> tuple[list[Event], int]:
    if fmt == "linux_auth":
        return linux_auth.parse_lines(text.splitlines(), year=year)
    if fmt == "windows_json":
        return windows.parse_text(text)
    raise ValueError(f"unknown format {fmt!r}; expected one of {', '.join(FORMATS)}")


def parse_file(path: str | Path, fmt: str = "auto", year: int | None = None) -> ParseResult:
    text = read_text(path)
    if fmt == "auto":
        fmt = detect_format(path, text)
    events, skipped = parse_text(text, fmt, year=year)
    assign_ids(events)
    return ParseResult(str(path), fmt, events, skipped)
