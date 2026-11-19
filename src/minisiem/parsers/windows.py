"""Parser for Windows event logs exported as JSON.

Accepted shapes (JSON lines, a JSON array, or a single object):

* the output of ``scripts/Export-WindowsEvents.ps1``::

    {"TimeCreated": "...", "Id": 4625, "Channel": "Security",
     "Computer": "DC01", "EventData": {"TargetUserName": "bob", ...}}

* Winlogbeat / Elastic style documents with ``@timestamp`` and a ``winlog`` object.

Security, System, Sysmon and PowerShell events with well-known IDs are mapped to
normalised fields. Every raw ``EventData`` value is also kept under
``winlog.event_data.<Name>`` so rules can match on anything.
"""

from __future__ import annotations

import json
import ntpath
import re
from typing import Any

from ..schema import Event, is_present
from ..timeutil import parse_iso

# event id -> (event.action, event.outcome, {normalised field: EventData name})
Mapping = tuple[str, "str | None", dict[str, str]]

_LOGON_FIELDS = {
    "user.name": "TargetUserName",
    "user.domain": "TargetDomainName",
    "source.ip": "IpAddress",
    "source.port": "IpPort",
    "source.host": "WorkstationName",
    "logon.type": "LogonType",
    "logon.process": "LogonProcessName",
    "process.executable": "ProcessName",
}
_GROUP_ADD_FIELDS = {
    "user.name": "SubjectUserName",
    "user.domain": "SubjectDomainName",
    "user.target.name": "MemberName",
    "user.target.sid": "MemberSid",
    "group.name": "TargetUserName",
    "group.domain": "TargetDomainName",
}

SECURITY: dict[int, Mapping] = {
    4624: ("logon", "success", _LOGON_FIELDS),
    4625: ("logon", "failure", {**_LOGON_FIELDS, "failure.status": "Status", "failure.sub_status": "SubStatus"}),
    4648: (
        "explicit_credential_logon",
        None,
        {"user.name": "SubjectUserName", "user.target.name": "TargetUserName", "source.ip": "IpAddress"},
    ),
    4672: ("special_privileges_assigned", None, {"user.name": "SubjectUserName", "user.domain": "SubjectDomainName"}),
    4688: (
        "process_created",
        None,
        {
            "user.name": "SubjectUserName",
            "user.domain": "SubjectDomainName",
            "process.executable": "NewProcessName",
            "process.command_line": "CommandLine",
            "process.parent.executable": "ParentProcessName",
        },
    ),
    4698: (
        "scheduled_task_created",
        None,
        {"user.name": "SubjectUserName", "task.name": "TaskName", "task.content": "TaskContent"},
    ),
    4720: (
        "user_created",
        "success",
        {"user.name": "SubjectUserName", "user.domain": "SubjectDomainName", "user.target.name": "TargetUserName"},
    ),
    4726: ("user_deleted", "success", {"user.name": "SubjectUserName", "user.target.name": "TargetUserName"}),
    4728: ("group_member_added", "success", _GROUP_ADD_FIELDS),
    4732: ("group_member_added", "success", _GROUP_ADD_FIELDS),
    4756: ("group_member_added", "success", _GROUP_ADD_FIELDS),
    4740: ("account_locked_out", None, {"user.target.name": "TargetUserName", "source.host": "TargetDomainName"}),
    1102: ("log_cleared", "success", {"user.name": "SubjectUserName", "user.domain": "SubjectDomainName"}),
}
SYSTEM: dict[int, Mapping] = {
    7045: (
        "service_installed",
        None,
        {
            "service.name": "ServiceName",
            "service.image_path": "ImagePath",
            "service.start_type": "StartType",
            "user.name": "AccountName",
        },
    ),
    104: ("log_cleared", "success", {"user.name": "SubjectUserName", "log.name": "Channel"}),
}
SYSMON: dict[int, Mapping] = {
    1: (
        "process_created",
        None,
        {
            "process.executable": "Image",
            "process.command_line": "CommandLine",
            "process.pid": "ProcessId",
            "process.working_directory": "CurrentDirectory",
            "process.parent.executable": "ParentImage",
            "process.parent.command_line": "ParentCommandLine",
            "process.hash": "Hashes",
            "user.name": "User",
        },
    ),
    3: (
        "network_connection",
        None,
        {
            "process.executable": "Image",
            "user.name": "User",
            "source.ip": "SourceIp",
            "source.port": "SourcePort",
            "destination.ip": "DestinationIp",
            "destination.port": "DestinationPort",
            "destination.domain": "DestinationHostname",
        },
    ),
    10: (
        "process_access",
        None,
        {
            "process.executable": "SourceImage",
            "target.process.executable": "TargetImage",
            "access.granted": "GrantedAccess",
            "access.call_trace": "CallTrace",
            "user.name": "SourceUser",
        },
    ),
    11: ("file_created", None, {"process.executable": "Image", "file.path": "TargetFilename", "user.name": "User"}),
    13: (
        "registry_value_set",
        None,
        {"process.executable": "Image", "registry.path": "TargetObject", "registry.value": "Details"},
    ),
    22: ("dns_query", None, {"process.executable": "Image", "dns.question.name": "QueryName"}),
}
POWERSHELL: dict[int, Mapping] = {
    4104: (
        "powershell_script_block",
        None,
        {"powershell.script_block": "ScriptBlockText", "powershell.script_path": "Path"},
    ),
}
TABLES: dict[str, dict[int, Mapping]] = {
    "windows_security": SECURITY,
    "windows_system": SYSTEM,
    "sysmon": SYSMON,
    "windows_powershell": POWERSHELL,
}

_INT_FIELDS = ("logon.type", "source.port", "destination.port", "process.pid")
_CN = re.compile(r"^CN=((?:\\,|[^,])+)", re.IGNORECASE)


def _first(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in record and record[key] is not None:
            return record[key]
    return None


def source_for_channel(channel: str) -> str:
    lowered = channel.lower()
    if "sysmon" in lowered:
        return "sysmon"
    if "powershell" in lowered:
        return "windows_powershell"
    if lowered == "security":
        return "windows_security"
    if lowered == "system":
        return "windows_system"
    return "windows"


def parse_record(record: Any) -> Event | None:
    """Turn one exported event into an :class:`Event`, or ``None`` if it is unusable."""
    if not isinstance(record, dict):
        return None
    winlog = record.get("winlog") if isinstance(record.get("winlog"), dict) else {}

    event_id = _first(record, "Id", "EventID", "EventId", "event_id")
    if event_id is None:
        event_id = winlog.get("event_id")
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        return None

    raw_ts = _first(record, "TimeCreated", "@timestamp", "timestamp", "TimeGenerated", "SystemTime")
    if raw_ts is None:
        return None
    try:
        timestamp = parse_iso(str(raw_ts))
    except ValueError:
        return None

    channel = str(_first(record, "Channel", "LogName", "channel") or winlog.get("channel") or "")
    computer = _first(record, "Computer", "MachineName", "computer_name") or winlog.get("computer_name")
    if computer is None and isinstance(record.get("host"), dict):
        computer = record["host"].get("name")
    data = record.get("EventData")
    if not isinstance(data, dict):
        data = winlog.get("event_data") if isinstance(winlog.get("event_data"), dict) else {}

    source = source_for_channel(channel)
    fields: dict[str, Any] = {
        "event.source": source,
        "event.code": event_id,
        "winlog.channel": channel,
    }
    if is_present(computer):
        fields["host.name"] = str(computer)
    for name, value in data.items():
        if value is not None:
            fields[f"winlog.event_data.{name}"] = value

    mapping = TABLES.get(source, {}).get(event_id)
    if mapping:
        action, outcome, field_map = mapping
        fields["event.action"] = action
        if outcome:
            fields["event.outcome"] = outcome
        for target, name in field_map.items():
            value = data.get(name)
            if is_present(value):
                fields[target] = value
    else:
        fields["event.action"] = f"event_{event_id}"

    _post_process(fields)
    raw = json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)
    return Event(timestamp=timestamp, fields=fields, raw=raw)


def _post_process(fields: dict[str, Any]) -> None:
    # Derive short process names from full paths (C:\Windows\System32\cmd.exe -> cmd.exe).
    for prefix in ("process", "process.parent", "target.process"):
        executable = fields.get(f"{prefix}.executable")
        if is_present(executable):
            fields[f"{prefix}.name"] = ntpath.basename(str(executable).strip('"'))
    # Split DOMAIN\user into user.domain + user.name.
    user = fields.get("user.name")
    if isinstance(user, str) and "\\" in user:
        domain, name = user.split("\\", 1)
        fields.setdefault("user.domain", domain)
        fields["user.name"] = name
    # Group membership events give the member as a distinguished name.
    target = fields.get("user.target.name")
    if isinstance(target, str) and (match := _CN.match(target)):
        fields["user.target.name"] = match.group(1).replace("\\,", ",")
    for key in _INT_FIELDS:
        value = fields.get(key)
        if isinstance(value, str) and value.isdigit():
            fields[key] = int(value)


def parse_text(text: str) -> tuple[list[Event], int]:
    """Parse JSON lines, a JSON array or a single JSON object. Returns ``(events, skipped)``."""
    records: list[Any]
    skipped = 0
    try:
        whole = json.loads(text)
    except json.JSONDecodeError:
        records = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                skipped += 1
    else:
        records = whole if isinstance(whole, list) else [whole]

    events: list[Event] = []
    for record in records:
        event = parse_record(record)
        if event is None:
            skipped += 1
        else:
            events.append(event)
    return events, skipped
