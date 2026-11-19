from __future__ import annotations

import json

from conftest import RULES_DIR, SAMPLES, make_event

from minisiem.cli import main
from minisiem.report import render_report
from minisiem.schema import Alert
from minisiem.storage import Store


def test_end_to_end_run(tmp_path, capsys):
    db, out = tmp_path / "siem.db", tmp_path / "report.html"
    code = main(
        ["run", str(SAMPLES / "attack"), "--year", "2026", "--rules", str(RULES_DIR), "--db", str(db), "-o", str(out)]
    )
    assert code == 0
    printed = capsys.readouterr().out
    assert "Successful SSH login after brute force" in printed
    html = out.read_text(encoding="utf-8")
    assert "Mini SIEM report" in html and "T1003.001" in html

    # Re-ingesting the same files adds nothing.
    assert main(["ingest", str(SAMPLES / "attack"), "--year", "2026", "--db", str(db)]) == 0
    assert "Ingested 0 new events" in capsys.readouterr().out

    assert main(["alerts", "--level", "critical", "--db", str(db)]) == 0
    listed = capsys.readouterr().out
    assert "CRITICAL" in listed and "MEDIUM" not in listed


def test_fail_on_exit_code(tmp_path):
    db = tmp_path / "siem.db"
    assert main(["ingest", str(SAMPLES / "attack"), "--year", "2026", "--db", str(db)]) == 0
    assert main(["detect", "--rules", str(RULES_DIR), "--db", str(db), "--fail-on", "critical"]) == 2


def test_validate_command(tmp_path, capsys):
    assert main(["validate", "--rules", str(RULES_DIR)]) == 0
    bad = tmp_path / "bad.yml"
    bad.write_text("id: x\ntitle: X\nlevel: nope\ndetection: {s: {a: 1}, condition: s}\n")
    assert main(["validate", "--rules", str(bad)]) == 1
    assert "level must be one of" in capsys.readouterr().err


def test_missing_input_is_a_clean_error(tmp_path, capsys):
    assert main(["ingest", str(tmp_path / "nope.log"), "--db", str(tmp_path / "x.db")]) == 1
    assert "does not exist" in capsys.readouterr().err


def test_store_round_trip(tmp_path):
    event = make_event(0, event_action="logon", host_name="DC01", raw="raw-1")
    alert = Alert("r", "Rule", "high", "desc", ["attack.t1078"], [event], {"source.ip": "1.2.3.4"}, "summary")
    with Store(tmp_path / "s.db") as store:
        assert store.add_events([event]) == 1
        assert store.add_events([event]) == 0
        store.replace_alerts([alert])
        loaded = store.load_alerts()
        stats = store.stats()
    assert loaded[0].id == alert.id
    assert loaded[0].group == {"source.ip": "1.2.3.4"}
    assert loaded[0].events[0].fields == event.fields
    assert stats["events"] == 1 and stats["hosts"] == ["DC01"] and stats["alerts_by_level"]["high"] == 1


def test_report_escapes_attacker_controlled_text():
    payload = '<script>alert("x")</script>'
    event = make_event(
        0, event_action="ssh_login", user_name=payload, host_name="web01", raw=json.dumps({"msg": payload})
    )
    alert = Alert("r", "Rule <b>", "high", "desc", ["attack.t1110"], [event], {}, f"user={payload}")
    html = render_report({"events": 1, "hosts": ["web01"], "by_source": {}}, [alert])
    assert payload not in html
    assert "&lt;script&gt;" in html
    assert "Rule &lt;b&gt;" in html


def test_report_without_alerts():
    html = render_report({"events": 0, "hosts": [], "by_source": {}}, [])
    assert "No alerts" in html
