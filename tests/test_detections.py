"""Detection-as-code checks for the bundled rules.

* every rule must fire on the attack samples (a rule that never fires is untested),
* no rule may fire on the benign samples (false-positive regression test),
* every rule carries the metadata an analyst needs.
"""

from __future__ import annotations

from collections import Counter

import pytest
from conftest import RULES_DIR

from minisiem.engine import run_rules
from minisiem.rules import load_rules

RULES, _ = load_rules(RULES_DIR)
RULE_IDS = sorted(r.id for r in RULES)


@pytest.fixture(scope="module")
def attack_alerts(rules, attack_events):
    return run_rules(rules, attack_events)


def test_rules_directory_is_valid():
    rules, errors = load_rules(RULES_DIR)
    assert errors == []
    assert len(rules) >= 20


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_fires_on_attack_samples(rule_id, attack_alerts):
    fired = {a.rule_id for a in attack_alerts}
    assert rule_id in fired, f"{rule_id} did not fire on samples/attack; add a positive test case"


def test_no_false_positives_on_benign_samples(rules, benign_events):
    alerts = run_rules(rules, benign_events)
    assert alerts == [], "\n".join(f"{a.rule_id}: {a.summary}" for a in alerts)


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_metadata(rule):
    assert rule.description, "explain what the rule detects"
    assert rule.techniques, "map the rule to at least one ATT&CK technique"
    assert rule.tactics, "tag at least one ATT&CK tactic"
    assert rule.falsepositives, "document known false positives"
    assert rule.sources, "restrict the rule to a log source"


def test_attack_story_alert_counts(attack_alerts):
    counts = Counter(a.rule_id for a in attack_alerts)
    # Brute force activity is aggregated: one alert per attack, not one per failed login.
    assert counts["lnx-ssh-bruteforce"] == 1
    assert counts["win-logon-bruteforce"] == 1
    # Domain Admins on the DC and local Administrators on the workstation.
    assert counts["win-admin-group-add"] == 2


def test_lsass_filter_excludes_defender(attack_alerts, attack_events):
    defender_access = [e for e in attack_events if e.get("process.name") == "MsMpEng.exe"]
    assert defender_access, "sample data should contain benign Defender LSASS access"
    lsass_alerts = [a for a in attack_alerts if a.rule_id == "win-lsass-access"]
    assert len(lsass_alerts) == 1
    assert lsass_alerts[0].events[0].get("process.name") == "a.exe"
