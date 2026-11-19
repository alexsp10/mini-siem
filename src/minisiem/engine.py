"""Detection engine: runs compiled rules over a time-ordered stream of events.

Three rule kinds are supported:

* **single** - every matching event raises an alert.
* **threshold** - matching events are grouped (e.g. by ``source.ip``) and an
  alert fires when ``count`` events (or ``count`` distinct values of a field)
  fall inside a sliding ``timeframe``. Further matches from the same group
  while the attack continues are folded into the same alert instead of
  creating a flood of duplicates.
* **sequence** - ordered steps per group, e.g. "5 failed logins *then* a
  successful one from the same IP within 15 minutes".
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from typing import Any

from .rules import Rule, Threshold
from .schema import Alert, Event, describe_event, is_present, level_rank
from .timeutil import format_duration


def run_rules(rules: Iterable[Rule], events: Iterable[Event]) -> list[Alert]:
    ordered = sorted(events, key=lambda e: e.timestamp)
    alerts: list[Alert] = []
    for rule in rules:
        alerts.extend(evaluate_rule(rule, ordered))
    alerts.sort(key=lambda a: (a.timestamp, -level_rank(a.level), a.rule_id))
    return alerts


def evaluate_rule(rule: Rule, events: list[Event]) -> list[Alert]:
    """Evaluate one rule. ``events`` must already be sorted by timestamp."""
    if rule.sequence:
        return _evaluate_sequence(rule, events)
    if rule.threshold:
        return _evaluate_threshold(rule, events)
    return [_alert(rule, [e], summary=describe_event(e)) for e in events if rule.matches(e)]


def _alert(rule: Rule, events: list[Event], group: dict[str, Any] | None = None, summary: str = "") -> Alert:
    return Alert(
        rule_id=rule.id,
        title=rule.title,
        level=rule.level,
        description=rule.description,
        tags=list(rule.tags),
        events=events,
        group=dict(group or {}),
        summary=summary,
    )


def _norm(value: Any) -> str | None:
    return None if value is None else str(value).lower()


def _group_key(event: Event, fields: tuple[str, ...]) -> tuple[str | None, ...]:
    return tuple(_norm(event.get(f)) for f in fields)


def _group_text(group: dict[str, Any]) -> str:
    return ", ".join(f"{k}={v}" for k, v in group.items())


def _distinct(events: Iterable[Event], field: str) -> int:
    return len({_norm(e.get(field)) for e in events if is_present(e.get(field))})


def _measure(window: Iterable[Event], threshold: Threshold) -> int:
    if threshold.distinct:
        return _distinct(window, threshold.distinct)
    return sum(1 for _ in window)


def _evaluate_threshold(rule: Rule, events: list[Event]) -> list[Alert]:
    threshold = rule.threshold
    assert threshold is not None
    windows: dict[tuple, deque[Event]] = defaultdict(deque)
    open_alerts: dict[tuple, tuple[Alert, Any]] = {}
    alerts: list[Alert] = []

    for event in events:
        if not rule.matches(event):
            continue
        key = _group_key(event, threshold.group_by)

        # Activity continuing inside an open alert's window is folded into it.
        if key in open_alerts:
            alert, until = open_alerts[key]
            if event.timestamp <= until:
                alert.events.append(event)
                open_alerts[key] = (alert, event.timestamp + threshold.timeframe)
                continue
            del open_alerts[key]

        window = windows[key]
        window.append(event)
        cutoff = event.timestamp - threshold.timeframe
        while window and window[0].timestamp < cutoff:
            window.popleft()

        if _measure(window, threshold) >= threshold.count:
            group = {f: event.get(f) for f in threshold.group_by}
            alert = _alert(rule, list(window), group=group)
            alerts.append(alert)
            open_alerts[key] = (alert, event.timestamp + threshold.timeframe)
            window.clear()

    for alert in alerts:
        alert.summary = _threshold_summary(threshold, alert)
    return alerts


def _threshold_summary(threshold: Threshold, alert: Alert) -> str:
    text = f"{len(alert.events)} matching events"
    if threshold.distinct:
        text += f" with {_distinct(alert.events, threshold.distinct)} distinct {threshold.distinct}"
    span = alert.last_seen - alert.timestamp
    text += f" over {format_duration(span) if span.total_seconds() >= 1 else '<1s'}"
    rule_text = f"{threshold.count}{' distinct ' + threshold.distinct if threshold.distinct else ''}"
    text += f" (threshold {rule_text} in {format_duration(threshold.timeframe)})"
    if alert.group:
        text += f" for {_group_text(alert.group)}"
    return text


def _evaluate_sequence(rule: Rule, events: list[Event]) -> list[Alert]:
    sequence = rule.sequence
    assert sequence is not None
    steps = sequence.steps
    state: dict[tuple, list[deque[Event]]] = {}
    alerts: list[Alert] = []

    for event in events:
        if not rule.applies_to(event):
            continue
        hits = [i for i, step in enumerate(steps) if rule.selections[step.selection](event)]
        if not hits:
            continue
        key = _group_key(event, sequence.group_by)
        buckets = state.setdefault(key, [deque() for _ in steps])

        cutoff = event.timestamp - sequence.timeframe
        for bucket in buckets:
            while bucket and bucket[0].timestamp < cutoff:
                bucket.popleft()

        # Credit the event to the furthest step whose predecessors are complete.
        for index in reversed(hits):
            if all(len(buckets[j]) >= steps[j].count for j in range(index)):
                buckets[index].append(event)
                break

        if all(len(bucket) >= step.count for bucket, step in zip(buckets, steps, strict=True)):
            matched = sorted((e for bucket in buckets for e in bucket), key=lambda e: e.timestamp)
            chain = " -> ".join(f"{len(b)}x {s.selection}" for b, s in zip(buckets, steps, strict=True))
            group = {f: event.get(f) for f in sequence.group_by}
            summary = f"sequence {chain} within {format_duration(sequence.timeframe)}"
            if group:
                summary += f" for {_group_text(group)}"
            alerts.append(_alert(rule, matched, group=group, summary=summary))
            del state[key]

    return alerts
