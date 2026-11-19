"""Self-contained HTML dashboard (no external assets, works offline).

All log-derived text is HTML-escaped: log lines are attacker-controlled input,
and a SIEM report must not become an XSS vector.
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .attack import split_tags, tactic_label, technique_name, technique_url
from .schema import LEVELS, Alert, describe_event

MAX_EVENTS_PER_ALERT = 25

_CSS = """
:root {
  --bg: #f6f7f9; --panel: #ffffff; --text: #1b1f24; --muted: #5d6673; --border: #dde1e6;
  --accent: #2f5bd3; --code-bg: #f0f2f5;
  --critical: #b3261e; --high: #d3541f; --medium: #b98900; --low: #2f7d4f; --informational: #5d6673;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #111418; --panel: #1a1f25; --text: #e6e9ed; --muted: #9aa4b1; --border: #2b323b;
    --accent: #7ea2ff; --code-bg: #232a32;
    --critical: #ff6b61; --high: #ff8c4a; --medium: #e8bf3a; --low: #5cc98a; --informational: #9aa4b1;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 1180px; margin: 0 auto; padding: 28px 16px 64px; }
h1 { font-size: 26px; margin: 0 0 4px; }
h2 { font-size: 17px; margin: 0 0 14px; }
a { color: var(--accent); }
.muted { color: var(--muted); }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 22px 0; }
.card, .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; }
.card { padding: 14px 16px; }
.card .value { font-size: 26px; font-weight: 650; font-variant-numeric: tabular-nums; }
.card .label { color: var(--muted); font-size: 13px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-bottom: 16px; }
.panel { padding: 18px; min-width: 0; }
.bar-row { display: grid; grid-template-columns: minmax(90px, 38%) 1fr 36px; gap: 10px; align-items: center; margin: 7px 0; font-size: 14px; }
.bar-row .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bar { height: 10px; border-radius: 5px; background: var(--accent); min-width: 2px; }
.bar-row .num { text-align: right; font-variant-numeric: tabular-nums; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
.events-table td:first-child { white-space: nowrap; }
th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .03em; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 650;
  color: #fff; background: var(--informational); text-transform: uppercase; letter-spacing: .03em; }
.badge.critical { background: var(--critical); } .badge.high { background: var(--high); }
.badge.medium { background: var(--medium); } .badge.low { background: var(--low); }
.bar.critical { background: var(--critical); } .bar.high { background: var(--high); }
.bar.medium { background: var(--medium); } .bar.low { background: var(--low); }
.bar.informational { background: var(--informational); }
.toolbar { display: flex; flex-wrap: wrap; gap: 10px 16px; align-items: center; margin-bottom: 12px; }
.toolbar input[type=search] { flex: 1 1 240px; padding: 8px 10px; border-radius: 8px; border: 1px solid var(--border);
  background: var(--bg); color: var(--text); font: inherit; }
.toolbar label { font-size: 14px; white-space: nowrap; }
details.alert { border: 1px solid var(--border); border-radius: 8px; margin: 8px 0; background: var(--panel); }
details.alert > summary { cursor: pointer; padding: 10px 12px; display: grid; gap: 4px 12px;
  grid-template-columns: 150px 86px 1fr; align-items: baseline; list-style: none; }
details.alert > summary::-webkit-details-marker { display: none; }
details.alert > summary .title { font-weight: 600; }
details.alert > summary .sub { grid-column: 3; color: var(--muted); font-size: 13px; overflow-wrap: anywhere; }
details.alert[open] > summary { border-bottom: 1px solid var(--border); }
.alert-body { padding: 12px 14px; overflow-x: auto; }
.alert-body p { margin: 0 0 10px; }
.tags a, .tags span { display: inline-block; margin: 0 6px 6px 0; padding: 1px 8px; border-radius: 6px;
  background: var(--code-bg); font-size: 12px; text-decoration: none; }
code, pre { font-family: ui-monospace, "Cascadia Code", Consolas, monospace; font-size: 12.5px; }
pre { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; background: var(--code-bg); padding: 6px 8px; border-radius: 6px; }
.empty { padding: 28px; text-align: center; color: var(--muted); }
footer { margin-top: 36px; color: var(--muted); font-size: 13px; }
@media (max-width: 640px) {
  details.alert > summary { grid-template-columns: 1fr auto; }
  details.alert > summary .time { grid-column: 1; }
  details.alert > summary .title, details.alert > summary .sub { grid-column: 1 / -1; }
  .events-table th:nth-child(2), .events-table td:nth-child(2) { display: none; }
}
"""

_JS = """
(function () {
  var q = document.getElementById('q');
  var boxes = Array.prototype.slice.call(document.querySelectorAll('input[data-level]'));
  var shown = document.getElementById('shown');
  function apply() {
    var text = q.value.trim().toLowerCase();
    var levels = {};
    boxes.forEach(function (b) { levels[b.value] = b.checked; });
    var n = 0;
    document.querySelectorAll('details.alert').forEach(function (a) {
      var ok = levels[a.dataset.level] && a.dataset.search.indexOf(text) !== -1;
      a.hidden = !ok;
      if (ok) n++;
    });
    shown.textContent = n;
  }
  q.addEventListener('input', apply);
  boxes.forEach(function (b) { b.addEventListener('change', apply); });
})();
"""


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _fmt(ts: datetime | None) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "-"


def _bars(items: list[tuple[str, int, str]], empty: str) -> str:
    if not items:
        return f'<p class="muted">{_e(empty)}</p>'
    top = max(count for _, count, _ in items) or 1
    rows = []
    for label, count, css in items:
        width = max(2.0, 100.0 * count / top)
        rows.append(
            f'<div class="bar-row"><span class="name" title="{_e(label)}">{_e(label)}</span>'
            f'<span><span class="bar {css}" style="display:block;width:{width:.1f}%"></span></span>'
            f'<span class="num">{count}</span></div>'
        )
    return "".join(rows)


def _alert_html(alert: Alert) -> str:
    techniques, tactics = split_tags(alert.tags)
    hosts = alert.context("host.name")
    users = alert.context("user.name") + alert.context("user.target.name")
    sources = alert.context("source.ip")
    sub_bits = [alert.summary]
    if hosts:
        sub_bits.append("host " + ", ".join(hosts))
    search = " ".join([alert.title, alert.rule_id, alert.summary, *hosts, *users, *sources, *techniques]).lower()

    tag_html = "".join(
        f'<a href="{_e(technique_url(t))}" target="_blank" rel="noopener noreferrer">'
        f"{_e(t)} {_e(technique_name(t))}</a>"
        for t in techniques
    ) + "".join(f"<span>{_e(tactic_label(t))}</span>" for t in tactics)

    rows = []
    for event in alert.events[:MAX_EVENTS_PER_ALERT]:
        rows.append(
            f"<tr><td><code>{_e(_fmt(event.timestamp))}</code></td><td>{_e(event.source)}</td>"
            f"<td>{_e(describe_event(event))}<pre>{_e(event.raw[:600])}</pre></td></tr>"
        )
    more = len(alert.events) - MAX_EVENTS_PER_ALERT
    if more > 0:
        rows.append(f'<tr><td colspan="3" class="muted">... and {more} more events</td></tr>')

    group = ", ".join(f"{k} = {v}" for k, v in alert.group.items())
    return (
        f'<details class="alert" data-level="{_e(alert.level)}" data-search="{_e(search)}">'
        f'<summary><span class="time"><code>{_e(_fmt(alert.timestamp))}</code></span>'
        f'<span><span class="badge {_e(alert.level)}">{_e(alert.level)}</span></span>'
        f'<span class="title">{_e(alert.title)}</span>'
        f'<span class="sub">{_e(" · ".join(sub_bits))}</span></summary>'
        f'<div class="alert-body">'
        f"<p>{_e(alert.description)}</p>"
        f'<p class="tags">{tag_html}</p>'
        f'<p class="muted">Rule <code>{_e(alert.rule_id)}</code>'
        f"{' · grouped by ' + _e(group) if group else ''}"
        f" · {len(alert.events)} event(s) · {_e(_fmt(alert.timestamp))} to {_e(_fmt(alert.last_seen))} UTC</p>"
        f'<table class="events-table"><thead><tr><th>Time (UTC)</th><th>Source</th><th>Event</th></tr></thead>'
        f"<tbody>{''.join(rows)}</tbody></table></div></details>"
    )


def render_report(stats: dict[str, Any], alerts: list[Alert], generated_at: datetime | None = None) -> str:
    generated_at = generated_at or datetime.now(timezone.utc)
    by_level = Counter(a.level for a in alerts)
    by_rule = Counter(a.title for a in alerts)
    rule_level = {a.title: a.level for a in alerts}
    technique_counts: Counter[str] = Counter()
    technique_tactics: dict[str, set[str]] = {}
    for alert in alerts:
        techniques, tactics = split_tags(alert.tags)
        for technique in techniques:
            technique_counts[technique] += 1
            technique_tactics.setdefault(technique, set()).update(tactics)
    affected_hosts = sorted({h for a in alerts for h in a.context("host.name", limit=50)})

    cards = [
        (f"{stats.get('events', 0):,}", "events ingested"),
        (f"{len(stats.get('hosts', [])):,}", "hosts seen"),
        (f"{len(alerts):,}", "alerts"),
        (str(by_level.get("critical", 0)), "critical"),
        (str(by_level.get("high", 0)), "high"),
        (str(len(technique_counts)), "ATT&CK techniques"),
    ]
    card_html = "".join(
        f'<div class="card"><div class="value">{_e(v)}</div><div class="label">{_e(label)}</div></div>'
        for v, label in cards
    )

    severity = _bars(
        [(level, by_level[level], level) for level in reversed(LEVELS) if by_level.get(level)],
        "No alerts.",
    )
    sources = _bars([(s or "unknown", n, "") for s, n in stats.get("by_source", {}).items()], "No events.")
    top_rules = _bars([(title, n, rule_level[title]) for title, n in by_rule.most_common(10)], "No alerts.")

    if technique_counts:
        technique_rows = "".join(
            f'<tr><td><a href="{_e(technique_url(t))}" target="_blank" rel="noopener noreferrer">{_e(t)}</a></td>'
            f"<td>{_e(technique_name(t))}</td>"
            f"<td>{_e(', '.join(sorted(tactic_label(x) for x in technique_tactics[t])))}</td>"
            f'<td style="text-align:right">{n}</td></tr>'
            for t, n in sorted(technique_counts.items(), key=lambda kv: (-kv[1], kv[0]))
        )
        techniques_html = (
            "<table><thead><tr><th>ID</th><th>Technique</th><th>Tactics</th>"
            f'<th style="text-align:right">Alerts</th></tr></thead><tbody>{technique_rows}</tbody></table>'
        )
    else:
        techniques_html = '<p class="muted">No techniques observed.</p>'

    level_filters = "".join(
        f'<label><input type="checkbox" data-level value="{level}" checked> {level}</label>'
        for level in reversed(LEVELS)
    )
    alert_list = "".join(_alert_html(a) for a in sorted(alerts, key=lambda a: a.timestamp, reverse=True))
    if not alerts:
        alert_list = '<div class="empty">No alerts. Either the logs are clean or the rules missed something.</div>'

    span = f"{_fmt(stats.get('first'))} to {_fmt(stats.get('last'))} UTC" if stats.get("first") else "no events"
    hosts_line = ", ".join(affected_hosts) if affected_hosts else "none"

    return "".join(
        [
            '<!doctype html><html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            "<title>Mini SIEM Report</title><style>",
            _CSS,
            "</style></head><body><main>",
            "<h1>Mini SIEM report</h1>",
            f'<div class="muted">Log window {_e(span)} · generated {_e(_fmt(generated_at))} UTC</div>',
            f'<div class="cards">{card_html}</div>',
            '<div class="grid">',
            f'<section class="panel"><h2>Alerts by severity</h2>{severity}</section>',
            f'<section class="panel"><h2>Events by log source</h2>{sources}</section>',
            "</div>",
            '<div class="grid">',
            f'<section class="panel"><h2>Top detections</h2>{top_rules}</section>',
            f'<section class="panel"><h2>MITRE ATT&amp;CK coverage</h2>{techniques_html}</section>',
            "</div>",
            '<section class="panel"><h2>Alerts</h2>',
            f'<p class="muted">Hosts with alerts: {_e(hosts_line)}</p>',
            '<div class="toolbar"><input id="q" type="search" placeholder="Filter by rule, host, user, IP, technique..." '
            f'aria-label="Filter alerts">{level_filters}'
            f'<span class="muted"><span id="shown">{len(alerts)}</span> shown</span></div>',
            alert_list,
            "</section>",
            f"<footer>mini-siem {_e(__version__)}</footer>",
            "</main><script>",
            _JS,
            "</script></body></html>",
        ]
    )
