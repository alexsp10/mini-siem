"""Unit tests for the rule language: conditions, field modifiers and rule validation."""

from __future__ import annotations

import pytest
import yaml
from conftest import make_event

from minisiem.condition import ConditionError, compile_condition
from minisiem.rules import RuleError, compile_field, compile_selection, load_rules, parse_rule

# ----------------------------------------------------------------------------- conditions


def evaluate(text: str, truth: dict[str, bool]) -> bool:
    compiled, _ = compile_condition(text, list(truth))
    return compiled(lambda name: truth[name])


@pytest.mark.parametrize(
    "text,truth,expected",
    [
        ("a and b or c", {"a": False, "b": True, "c": True}, True),
        ("a and (b or c)", {"a": False, "b": True, "c": True}, False),
        ("not a and b", {"a": False, "b": True}, True),
        ("not (a and b)", {"a": True, "b": True}, False),
        ("a AND NOT b", {"a": True, "b": False}, True),
        ("1 of sel_*", {"sel_x": False, "sel_y": True, "other": False}, True),
        ("all of sel_*", {"sel_x": True, "sel_y": False}, False),
        ("all of them", {"a": True, "b": True}, True),
        ("any of them", {"a": False, "b": False}, False),
        ("selection and not 1 of filter_*", {"selection": True, "filter_a": False, "filter_b": True}, False),
    ],
)
def test_condition_semantics(text, truth, expected):
    assert evaluate(text, truth) is expected


@pytest.mark.parametrize(
    "text,error",
    [
        ("", "empty"),
        ("a and", "end of condition"),
        ("(a", "parenthesis"),
        ("a b", "unexpected token"),
        ("missing", "unknown selection"),
        ("1 of nope_*", "matches no selection"),
        ("a | b", "unexpected character"),
        ("and a", "unexpected keyword"),
    ],
)
def test_condition_errors(text, error):
    with pytest.raises(ConditionError, match=error):
        compile_condition(text, ["a", "b"])


def test_condition_reports_referenced_names():
    _, used = compile_condition("a and 1 of f_*", ["a", "b", "f_1", "f_2"])
    assert used == {"a", "f_1", "f_2"}


# ----------------------------------------------------------------------------- field modifiers


EV = make_event(
    process_command_line="C:\\Windows\\System32\\rundll32.exe comsvcs.dll, MiniDump 704 out.dmp full",
    process_name="RunDLL32.exe",
    source_ip="10.20.30.40",
    logon_type=3,
    user_name="-",
)


@pytest.mark.parametrize(
    "spec,value,expected",
    [
        ("process.name", "rundll32.exe", True),  # equality is case-insensitive
        ("process.name", ["cmd.exe", "rundll32.exe"], True),  # list = any of
        ("process.name", "rundll32", False),
        ("process.command_line|contains", "MINIDUMP", True),
        ("process.command_line|contains|all", ["comsvcs", "minidump"], True),
        ("process.command_line|contains|all", ["comsvcs", "procdump"], False),
        ("process.command_line|startswith", "c:\\windows\\", True),
        ("process.command_line|endswith", " full", True),
        ("process.command_line|re", r"minidump\s+\d+", True),
        ("source.ip|cidr", "10.0.0.0/8", True),
        ("source.ip|cidr", ["192.168.0.0/16", "2001:db8::/32"], False),
        ("logon.type", 3, True),
        ("logon.type", "3", True),
        ("logon.type|gte", 3, True),
        ("logon.type|lt", 3, False),
        ("user.name", None, True),  # "-" counts as empty
        ("missing.field", None, True),
        ("missing.field|contains", "x", False),
        ("user.name|exists", False, True),
        ("source.ip|exists", True, True),
    ],
)
def test_field_modifiers(spec, value, expected):
    assert compile_field(spec, value)(EV) is expected


@pytest.mark.parametrize(
    "spec,value,error",
    [
        ("f|bogus", "x", "unknown modifier"),
        ("f|contains|startswith", "x", "only one comparison"),
        ("f|re", "(", "invalid regular expression"),
        ("f|cidr", "10.0.0.0/33", "invalid CIDR"),
        ("f|gt", "abc", "needs a number"),
        ("f|exists", "yes", "true/false"),
        ("f", [], "empty list"),
        ("f|contains", None, "null"),
    ],
)
def test_field_modifier_errors(spec, value, error):
    with pytest.raises(ValueError, match=error):
        compile_field(spec, value)


def test_selection_shapes():
    either = compile_selection("s", [{"process.name": "cmd.exe"}, {"source.ip|cidr": "10.0.0.0/8"}])
    assert either(EV)
    keywords = compile_selection("s", ["MiniDump", "nothing"])
    event = make_event(raw="... MiniDump ...")
    assert keywords(event)
    with pytest.raises(ValueError):
        compile_selection("s", {})
    with pytest.raises(ValueError):
        compile_selection("s", "just a string")


# ----------------------------------------------------------------------------- rule validation


BASE = {
    "id": "test-rule",
    "title": "Test",
    "level": "low",
    "tags": ["attack.t1110", "attack.credential_access"],
    "detection": {"sel": {"event.action": "x"}, "condition": "sel"},
}


def rule_with(**changes):
    doc = {**BASE, **changes}
    return {k: v for k, v in doc.items() if v is not None}


def test_valid_rule_parses():
    rule = parse_rule(rule_with())
    assert rule.kind == "single"
    assert rule.techniques == ["T1110"]
    assert rule.tactics == ["credential_access"]


@pytest.mark.parametrize(
    "changes,error",
    [
        ({"level": "severe"}, "level must be one of"),
        ({"title": None}, "missing required key 'title'"),
        ({"id": "bad id!"}, "id must be"),
        ({"tags": ["attack.t99"]}, "unrecognised ATT&CK tag"),
        ({"logsource": {"source": "splunk"}}, "unknown log source"),
        ({"logsource": {"product": "windows"}}, "single 'source' key"),
        ({"detection": {"sel": {"a": 1}}}, "condition is required"),
        ({"detection": {"condition": "sel"}}, "at least one selection"),
        ({"detection": {"sel": {"a": 1}, "condition": "nope"}}, "unknown selection"),
        ({"threshold": {"count": 0, "timeframe": "5m"}}, "positive integer"),
        ({"threshold": {"count": 2}}, "count and timeframe"),
        ({"threshold": {"count": 2, "timeframe": "soon"}}, "invalid duration"),
        ({"sequence": {"steps": [{"selection": "sel"}], "timeframe": "1m"}}, "at least two steps"),
        (
            {"sequence": {"steps": [{"selection": "sel"}, {"selection": "zzz"}], "timeframe": "1m"}},
            "unknown selection 'zzz'",
        ),
        ({"severity": "high"}, "unknown top-level key"),
    ],
)
def test_invalid_rules_are_rejected(changes, error):
    with pytest.raises(RuleError, match=error):
        parse_rule(rule_with(**changes), "test.yml")


def test_threshold_and_sequence_are_exclusive():
    doc = rule_with(
        threshold={"count": 2, "timeframe": "1m"},
        sequence={"steps": [{"selection": "sel"}, {"selection": "sel"}], "timeframe": "1m"},
    )
    with pytest.raises(RuleError, match="not both"):
        parse_rule(doc)


def test_load_rules_reports_duplicates_and_bad_yaml(tmp_path):
    (tmp_path / "a.yml").write_text(yaml.safe_dump(BASE))
    (tmp_path / "b.yml").write_text(yaml.safe_dump(BASE))
    (tmp_path / "c.yaml").write_text("id: [unclosed")
    rules, errors = load_rules(tmp_path)
    assert len(rules) == 1
    messages = " ".join(str(e) for e in errors)
    assert "duplicate rule id" in messages and "invalid YAML" in messages


def test_load_rules_missing_path(tmp_path):
    rules, errors = load_rules(tmp_path / "nope")
    assert not rules and "does not exist" in str(errors[0])
