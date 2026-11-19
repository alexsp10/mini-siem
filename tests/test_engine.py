"""Behaviour of single, threshold and sequence rules."""

from __future__ import annotations

from conftest import make_event

from minisiem.engine import run_rules
from minisiem.rules import parse_rule


def failure(seconds, ip="1.2.3.4", user="root"):
    return make_event(
        seconds,
        event_action="ssh_login",
        event_outcome="failure",
        source_ip=ip,
        user_name=user,
        raw=f"fail {seconds} {ip} {user}",
    )


def success(seconds, ip="1.2.3.4", user="root"):
    return make_event(
        seconds,
        event_action="ssh_login",
        event_outcome="success",
        source_ip=ip,
        user_name=user,
        raw=f"ok {seconds} {ip} {user}",
    )


SELECT_FAILURES = {"sel": {"event.action": "ssh_login", "event.outcome": "failure"}, "condition": "sel"}


def threshold_rule(**threshold):
    return parse_rule(
        {"id": "t", "title": "T", "level": "medium", "detection": SELECT_FAILURES, "threshold": threshold}
    )


def sequence_rule(count=3, timeframe="10m"):
    return parse_rule(
        {
            "id": "s",
            "title": "S",
            "level": "critical",
            "detection": {
                "failed": {"event.action": "ssh_login", "event.outcome": "failure"},
                "ok": {"event.action": "ssh_login", "event.outcome": "success"},
            },
            "sequence": {
                "group_by": ["source.ip"],
                "timeframe": timeframe,
                "steps": [{"selection": "failed", "count": count}, {"selection": "ok"}],
            },
        }
    )


def test_single_rule_alerts_per_event_and_respects_logsource():
    rule = parse_rule(
        {"id": "x", "title": "X", "level": "low", "logsource": {"source": "linux_auth"}, "detection": SELECT_FAILURES}
    )
    linux = make_event(0, event_source="linux_auth", event_action="ssh_login", event_outcome="failure")
    windows = make_event(1, event_source="sysmon", event_action="ssh_login", event_outcome="failure")
    alerts = run_rules([rule], [windows, linux])
    assert [a.events for a in alerts] == [[linux]]


def test_threshold_fires_once_count_is_reached():
    rule = threshold_rule(count=3, timeframe="1m", group_by=["source.ip"])
    assert run_rules([rule], [failure(0), failure(10)]) == []
    alerts = run_rules([rule], [failure(0), failure(10), failure(20)])
    assert len(alerts) == 1
    assert alerts[0].group == {"source.ip": "1.2.3.4"}
    assert "3 matching events" in alerts[0].summary


def test_threshold_window_slides():
    rule = threshold_rule(count=3, timeframe="1m", group_by=["source.ip"])
    spread_out = [failure(0), failure(50), failure(120)]  # never three within 60s
    assert run_rules([rule], spread_out) == []


def test_threshold_groups_are_independent():
    rule = threshold_rule(count=2, timeframe="1m", group_by=["source.ip"])
    events = [failure(0, ip="1.1.1.1"), failure(1, ip="2.2.2.2"), failure(2, ip="3.3.3.3")]
    assert run_rules([rule], events) == []


def test_continuing_attack_is_folded_into_one_alert():
    rule = threshold_rule(count=3, timeframe="1m", group_by=["source.ip"])
    events = [failure(s) for s in range(0, 300, 5)]  # 60 failures over 5 minutes
    alerts = run_rules([rule], events)
    assert len(alerts) == 1
    assert len(alerts[0].events) == 60


def test_new_alert_after_quiet_period():
    rule = threshold_rule(count=3, timeframe="1m", group_by=["source.ip"])
    burst = [failure(s) for s in (0, 1, 2)]
    later = [failure(s) for s in (600, 601, 602)]
    assert len(run_rules([rule], burst + later)) == 2


def test_distinct_threshold_detects_spraying_not_hammering():
    rule = threshold_rule(count=3, timeframe="5m", group_by=["source.ip"], distinct="user.name")
    hammering = [failure(i, user="root") for i in range(10)]
    assert run_rules([rule], hammering) == []
    spraying = [failure(i, user=u) for i, u in enumerate(["root", "admin", "Admin", "oracle"])]
    alerts = run_rules([rule], spraying)
    assert len(alerts) == 1  # admin/Admin count once (case-insensitive)
    assert "3 distinct user.name" in alerts[0].summary


def test_sequence_requires_order():
    rule = sequence_rule(count=3)
    assert run_rules([rule], [success(0), failure(1), failure(2), failure(3)]) == []
    alerts = run_rules([rule], [failure(1), failure(2), failure(3), success(4)])
    assert len(alerts) == 1
    assert [e.fields["event.outcome"] for e in alerts[0].events] == ["failure"] * 3 + ["success"]
    assert "3x failed -> 1x ok" in alerts[0].summary


def test_sequence_needs_enough_failures_inside_timeframe():
    rule = sequence_rule(count=3, timeframe="1m")
    assert run_rules([rule], [failure(0), failure(30), failure(100), success(110)]) == []


def test_sequence_is_grouped():
    rule = sequence_rule(count=2)
    events = [failure(0, ip="1.1.1.1"), failure(1, ip="1.1.1.1"), success(2, ip="9.9.9.9")]
    assert run_rules([rule], events) == []


def test_sequence_resets_after_alert():
    rule = sequence_rule(count=2)
    events = [failure(0), failure(1), success(2), success(3)]
    assert len(run_rules([rule], events)) == 1


def test_alerts_are_sorted_and_ids_are_stable():
    rule = parse_rule({"id": "x", "title": "X", "level": "low", "detection": SELECT_FAILURES})
    events = [failure(30), failure(10), failure(20)]
    first = run_rules([rule], events)
    second = run_rules([rule], list(reversed(events)))
    assert [a.timestamp for a in first] == sorted(a.timestamp for a in first)
    assert [a.id for a in first] == [a.id for a in second]
