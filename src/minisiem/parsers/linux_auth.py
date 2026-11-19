"""Parser for Linux ``/var/log/auth.log`` / ``/var/log/secure``.

Supports both the classic BSD syslog header (``Nov 18 13:02:11 host prog[pid]: msg``)
and the RFC 3339 header newer rsyslog defaults to. Lines from sshd, sudo, useradd,
usermod and gpasswd are mapped to specific actions; anything else that has a valid
syslog header is kept as ``event.action: other`` so it is still searchable.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from ..schema import Event
from ..timeutil import parse_iso

MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1
    )
}

_HEADER_TAIL = r"\s+(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
_BSD = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})" + _HEADER_TAIL)
_RFC3339 = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)" + _HEADER_TAIL)

_IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
_SSH_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) from " + _IP + r" port (?P<port>\d+)"
)
_SSH_ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from " + _IP + r" port (?P<port>\d+)")
_SSH_INVALID = re.compile(r"^Invalid user (?P<user>.*?) from " + _IP + r"(?: port (?P<port>\d+))?")
_SUDO = re.compile(
    r"^\s*(?P<user>\S+) : (?:(?P<reason>[^;]+?) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; "
    r"USER=(?P<target>\S+) ;(?: GROUP=\S+ ;)?(?: ENV=.*? ;)? COMMAND=(?P<cmd>.*)$"
)
_USERADD = re.compile(r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)")
_USERMOD_GROUP = re.compile(r"^add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")
_GPASSWD_GROUP = re.compile(r"^user (?P<user>\S+) added by (?P<actor>\S+) to group (?P<group>\S+)")


def _clean(fields: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in fields.items() if v not in (None, "")}


def _ssh(match: re.Match[str], outcome: str, invalid: bool = False) -> dict[str, Any]:
    return _clean(
        {
            "event.action": "ssh_login",
            "event.outcome": outcome,
            "user.name": match["user"],
            "user.invalid": True if invalid else None,
            "source.ip": match["ip"],
            "source.port": int(match["port"]),
            "auth.method": match["method"],
        }
    )


def classify(program: str, message: str) -> dict[str, Any]:
    """Map a syslog program + message to normalised fields."""
    prog = program.lower()
    if prog.startswith("sshd"):
        if m := _SSH_FAILED.match(message):
            return _ssh(m, "failure", invalid=bool(m["invalid"]))
        if m := _SSH_ACCEPTED.match(message):
            return _ssh(m, "success")
        if m := _SSH_INVALID.match(message):
            return _clean(
                {
                    "event.action": "ssh_invalid_user",
                    "event.outcome": "failure",
                    "user.name": m["user"],
                    "source.ip": m["ip"],
                    "source.port": int(m["port"]) if m["port"] else None,
                }
            )
    elif prog == "sudo":
        if m := _SUDO.match(message):
            return _clean(
                {
                    "event.action": "sudo_command",
                    "event.outcome": "failure" if m["reason"] else "success",
                    "user.name": m["user"],
                    "user.target.name": m["target"],
                    "process.command_line": m["cmd"].strip(),
                    "process.working_directory": m["pwd"],
                    "sudo.tty": m["tty"],
                    "sudo.failure_reason": m["reason"],
                }
            )
    elif prog == "useradd":
        if m := _USERADD.match(message):
            return {
                "event.action": "user_created",
                "event.outcome": "success",
                "user.target.name": m["user"],
                "user.target.id": int(m["uid"]),
            }
    elif prog in ("usermod", "gpasswd"):
        if m := _USERMOD_GROUP.match(message):
            return {
                "event.action": "group_member_added",
                "event.outcome": "success",
                "user.target.name": m["user"],
                "group.name": m["group"],
            }
        if m := _GPASSWD_GROUP.match(message):
            return {
                "event.action": "group_member_added",
                "event.outcome": "success",
                "user.name": m["actor"],
                "user.target.name": m["user"],
                "group.name": m["group"],
            }
    return {"event.action": "other"}


def parse_lines(lines: Iterable[str], year: int | None = None) -> tuple[list[Event], int]:
    """Parse auth.log lines. Returns ``(events, skipped_line_count)``.

    BSD syslog timestamps have no year, so ``year`` (default: current UTC year)
    is assumed and bumped when the month wraps from December to January.
    Timestamps are treated as UTC.
    """
    current_year = year or datetime.now(timezone.utc).year
    last_month: int | None = None
    events: list[Event] = []
    skipped = 0

    for line in lines:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        match = _RFC3339.match(line)
        if match:
            try:
                timestamp = parse_iso(match["ts"])
            except ValueError:
                skipped += 1
                continue
        else:
            match = _BSD.match(line)
            if not match or match["mon"] not in MONTHS:
                skipped += 1
                continue
            month = MONTHS[match["mon"]]
            if last_month is not None and month < last_month - 6:
                current_year += 1
            last_month = month
            try:
                timestamp = datetime.strptime(
                    f"{current_year}-{month:02d}-{int(match['day']):02d} {match['time']}",
                    "%Y-%m-%d %H:%M:%S",
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                skipped += 1
                continue

        fields: dict[str, Any] = {
            "event.source": "linux_auth",
            "host.name": match["host"],
            "process.name": match["prog"],
            "message": match["msg"],
        }
        if match["pid"]:
            fields["process.pid"] = int(match["pid"])
        fields.update(classify(match["prog"], match["msg"]))
        events.append(Event(timestamp=timestamp, fields=fields, raw=line))

    return events, skipped
