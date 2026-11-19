from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from minisiem.parsers import detect_format, parse_file
from minisiem.parsers.linux_auth import parse_lines
from minisiem.parsers.windows import parse_record, parse_text
from minisiem.timeutil import format_duration, parse_duration, parse_iso

# ----------------------------------------------------------------------------- Linux


def one(line: str, year: int = 2026):
    events, skipped = parse_lines([line], year=year)
    assert skipped == 0 and len(events) == 1
    return events[0]


def test_ssh_failed_invalid_user():
    ev = one(
        "Nov 18 13:02:12 web01 sshd[22841]: Failed password for invalid user admin from 203.0.113.45 port 51122 ssh2"
    )
    assert ev.timestamp == datetime(2026, 11, 18, 13, 2, 12, tzinfo=timezone.utc)
    assert ev.fields["event.action"] == "ssh_login"
    assert ev.fields["event.outcome"] == "failure"
    assert ev.fields["user.name"] == "admin"
    assert ev.fields["user.invalid"] is True
    assert ev.fields["source.ip"] == "203.0.113.45"
    assert ev.fields["source.port"] == 51122
    assert ev.fields["host.name"] == "web01"
    assert ev.fields["process.pid"] == 22841


def test_ssh_accepted_publickey_and_ipv6():
    ev = one(
        "Nov  3 09:00:01 web01 sshd[1]: Accepted publickey for alice from 2001:db8::5 port 2222 ssh2: RSA SHA256:x"
    )
    assert ev.fields["event.outcome"] == "success"
    assert ev.fields["auth.method"] == "publickey"
    assert ev.fields["source.ip"] == "2001:db8::5"
    assert ev.timestamp.day == 3


def test_sudo_success_and_failure():
    ok = one("Nov 18 13:06:24 web01 sudo[1]:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")
    assert ok.fields["event.action"] == "sudo_command"
    assert ok.fields["event.outcome"] == "success"
    assert ok.fields["user.name"] == "deploy"
    assert ok.fields["user.target.name"] == "root"
    assert ok.fields["process.command_line"] == "/bin/bash"

    bad = one(
        "Nov 18 12:41:07 web01 sudo[1]: www-data : user NOT in sudoers ; TTY=unknown ; PWD=/var/www ; USER=root ; COMMAND=/bin/sh"
    )
    assert bad.fields["event.outcome"] == "failure"
    assert bad.fields["sudo.failure_reason"] == "user NOT in sudoers"


def test_useradd_and_group_membership():
    created = one(
        "Nov 18 13:07:05 web01 useradd[9]: new user: name=sysupdate, UID=1002, GID=1002, home=/home/sysupdate"
    )
    assert created.fields["event.action"] == "user_created"
    assert created.fields["user.target.name"] == "sysupdate"

    added = one("Nov 18 13:07:11 web01 usermod[9]: add 'sysupdate' to shadow group 'sudo'")
    assert added.fields["event.action"] == "group_member_added"
    assert added.fields["group.name"] == "sudo"

    gpasswd = one("Nov 18 13:07:11 web01 gpasswd[9]: user eve added by root to group wheel")
    assert gpasswd.fields["user.name"] == "root"
    assert gpasswd.fields["user.target.name"] == "eve"


def test_rfc3339_header():
    ev = one("2026-11-18T13:02:12.123456+01:00 web01 sshd[5]: Failed password for root from 1.2.3.4 port 22 ssh2")
    assert ev.timestamp == datetime(2026, 11, 18, 12, 2, 12, 123456, tzinfo=timezone.utc)


def test_unknown_messages_kept_and_garbage_skipped():
    events, skipped = parse_lines(
        [
            "Nov 18 10:00:00 web01 systemd-logind[1]: New session 4 of user alice.",
            "this is not syslog",
            "",
            "Feb 30 10:00:00 web01 sshd[1]: impossible date",
        ],
        year=2026,
    )
    assert [e.fields["event.action"] for e in events] == ["other"]
    assert skipped == 2


def test_year_rollover():
    events, _ = parse_lines(["Dec 31 23:59:59 h sshd[1]: x", "Jan  1 00:00:01 h sshd[1]: y"], year=2025)
    assert [e.timestamp.year for e in events] == [2025, 2026]


# ----------------------------------------------------------------------------- Windows


def record(event_id: int, channel: str, data: dict, **extra) -> dict:
    return {
        "TimeCreated": "2026-11-18T14:10:03.1234567Z",
        "Id": event_id,
        "Channel": channel,
        "Computer": "DC01",
        "EventData": data,
        **extra,
    }


def test_failed_logon_mapping():
    ev = parse_record(
        record(
            4625, "Security", {"TargetUserName": "bob", "IpAddress": "198.51.100.23", "LogonType": "3", "IpPort": "-"}
        )
    )
    assert ev.source == "windows_security"
    assert ev.fields["event.code"] == 4625
    assert ev.fields["event.action"] == "logon"
    assert ev.fields["event.outcome"] == "failure"
    assert ev.fields["user.name"] == "bob"
    assert ev.fields["logon.type"] == 3
    assert "source.port" not in ev.fields  # "-" means empty in Windows logs
    assert ev.fields["winlog.event_data.IpPort"] == "-"  # raw data is kept
    assert ev.timestamp == datetime(2026, 11, 18, 14, 10, 3, 123456, tzinfo=timezone.utc)


def test_sysmon_process_fields_are_derived():
    ev = parse_record(
        record(
            1,
            "Microsoft-Windows-Sysmon/Operational",
            {
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                "CommandLine": "powershell -enc AAAA",
                "User": "CORP\\jsmith",
                "ProcessId": "6388",
            },
        )
    )
    assert ev.source == "sysmon"
    assert ev.fields["process.name"] == "powershell.exe"
    assert ev.fields["process.parent.name"] == "WINWORD.EXE"
    assert ev.fields["user.name"] == "jsmith"
    assert ev.fields["user.domain"] == "CORP"
    assert ev.fields["process.pid"] == 6388


def test_group_member_distinguished_name():
    ev = parse_record(
        record(
            4728,
            "Security",
            {"MemberName": "CN=Smith\\, Jo,CN=Users,DC=corp,DC=local", "TargetUserName": "Domain Admins"},
        )
    )
    assert ev.fields["user.target.name"] == "Smith, Jo"
    assert ev.fields["group.name"] == "Domain Admins"


def test_unmapped_event_and_winlogbeat_shape():
    ev = parse_record(
        {
            "@timestamp": "2026-11-18T10:00:00Z",
            "winlog": {
                "event_id": 4999,
                "channel": "Application",
                "computer_name": "SRV1",
                "event_data": {"Foo": "bar"},
            },
        }
    )
    assert ev.fields["event.action"] == "event_4999"
    assert ev.fields["host.name"] == "SRV1"
    assert ev.fields["winlog.event_data.Foo"] == "bar"
    assert ev.source == "windows"


def test_dotnet_date_and_bad_records():
    ev = parse_record({"TimeCreated": "/Date(1795000000000)/", "Id": 4624, "Channel": "Security"})
    assert ev.timestamp == datetime.fromtimestamp(1795000000, tz=timezone.utc)
    assert parse_record({"Id": 4624}) is None
    assert parse_record({"TimeCreated": "nonsense", "Id": 1}) is None
    assert parse_record(["not", "a", "dict"]) is None


def test_parse_text_accepts_array_jsonl_and_counts_garbage():
    rec = record(4624, "Security", {"TargetUserName": "a"})
    events, skipped = parse_text(json.dumps([rec, rec]))
    assert len(events) == 2 and skipped == 0
    events, skipped = parse_text(json.dumps(rec) + "\n{broken\n\n" + json.dumps(rec))
    assert len(events) == 2 and skipped == 1


def test_utf16_file_from_powershell_redirect(tmp_path):
    path = tmp_path / "events.json"
    path.write_text(json.dumps([record(4720, "Security", {"TargetUserName": "x"})]), encoding="utf-16")
    result = parse_file(path)
    assert result.format == "windows_json"
    assert result.events[0].fields["event.action"] == "user_created"


def test_format_detection_and_stable_ids(tmp_path):
    path = tmp_path / "auth"
    line = "Nov 18 10:00:00 h sshd[1]: Failed password for root from 1.1.1.1 port 1 ssh2\n"
    path.write_text(line * 2)
    assert detect_format(path, path.read_text()) == "linux_auth"
    first, second = parse_file(path, year=2026), parse_file(path, year=2026)
    assert len({e.id for e in first.events}) == 2  # identical lines stay distinct
    assert [e.id for e in first.events] == [e.id for e in second.events]  # but re-ingest is idempotent


# ----------------------------------------------------------------------------- time helpers


@pytest.mark.parametrize("text,seconds", [("30s", 30), ("5m", 300), ("1h", 3600), ("2d", 172800), (90, 90)])
def test_parse_duration(text, seconds):
    assert parse_duration(text).total_seconds() == seconds


@pytest.mark.parametrize("bad", ["0m", "5x", "", "-1m", True, -5])
def test_parse_duration_rejects(bad):
    with pytest.raises(ValueError):
        parse_duration(bad)


def test_format_duration():
    assert format_duration(parse_duration("5m")) == "5m"
    assert format_duration(parse_duration(112)) == "1m52s"


def test_parse_iso_offset_without_colon():
    assert parse_iso("2026-11-18T10:00:00+0200").hour == 8
