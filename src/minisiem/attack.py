"""Minimal MITRE ATT&CK lookup for the techniques the bundled rules use."""

from __future__ import annotations

TECHNIQUES = {
    "T1003": "OS Credential Dumping",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1027": "Obfuscated Files or Information",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1078": "Valid Accounts",
    "T1098": "Account Manipulation",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1136.001": "Create Account: Local Account",
    "T1136.002": "Create Account: Domain Account",
    "T1204.002": "User Execution: Malicious File",
    "T1218.011": "System Binary Proxy Execution: Rundll32",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "T1566.001": "Phishing: Spearphishing Attachment",
}


def technique_name(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id.upper(), technique_id.upper())


def technique_url(technique_id: str) -> str:
    return f"https://attack.mitre.org/techniques/{technique_id.upper().replace('.', '/')}/"


def tactic_label(tactic: str) -> str:
    return tactic.replace("_", " ").title().replace("And", "and")


def split_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    """Return ``(technique_ids, tactics)`` from Sigma-style ``attack.*`` tags."""
    techniques, tactics = [], []
    for tag in tags:
        if not tag.startswith("attack."):
            continue
        value = tag[len("attack.") :]
        if value[:1] == "t" and value[1:5].isdigit():
            techniques.append(value.upper())
        else:
            tactics.append(value)
    return techniques, tactics
