"""Loading, validating and compiling YAML detection rules.

A rule looks like this (see ``rules/`` for real examples)::

    id: lnx-ssh-bruteforce
    title: SSH brute force from a single source
    level: medium                       # informational|low|medium|high|critical
    tags: [attack.credential_access, attack.t1110.001]
    logsource:
      source: linux_auth                # optional; string or list
    detection:
      selection:
        event.action: ssh_login
        event.outcome: failure
      condition: selection
    threshold:                          # optional: aggregate matching events
      count: 5
      timeframe: 5m
      group_by: [source.ip]

Field modifiers (``field|modifier: value``): ``contains``, ``startswith``,
``endswith``, ``re``, ``cidr``, ``gt``/``gte``/``lt``/``lte``, ``exists`` and
``all`` (every listed value must match instead of any). String comparisons are
case-insensitive. A list of values means "any of", a list of mappings means
"any of these groups", and a list of plain strings is a keyword search over the
raw log line.
"""

from __future__ import annotations

import ipaddress
import operator
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from .condition import ConditionError, compile_condition
from .schema import KNOWN_SOURCES, LEVELS, Event, is_present
from .timeutil import parse_duration

Predicate = Callable[[Event], bool]

MODIFIERS = {"contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte", "exists", "all"}
TACTICS = {
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
}
ALLOWED_KEYS = {
    "id",
    "title",
    "description",
    "level",
    "status",
    "author",
    "date",
    "tags",
    "references",
    "falsepositives",
    "logsource",
    "detection",
    "threshold",
    "sequence",
}
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_TECHNIQUE_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
_NUMERIC_OPS = {"gt": operator.gt, "gte": operator.ge, "lt": operator.lt, "lte": operator.le}


class RuleError(Exception):
    def __init__(self, path: str, message: str):
        super().__init__(f"{path}: {message}")
        self.path = path
        self.message = message


# --------------------------------------------------------------------------- matching


def _as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).lower()


def _value_predicate(op: str, expected: Any, spec: str) -> Callable[[Any], bool]:
    if isinstance(expected, (dict, list)):
        raise ValueError(f"nested values are not supported in {spec!r}")
    if expected is None:
        if op != "eq":
            raise ValueError(f"null can only be used without a modifier in {spec!r}")
        return lambda actual: not is_present(actual)
    if op == "re":
        try:
            pattern = re.compile(str(expected), re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"invalid regular expression in {spec!r}: {exc}") from None
        return lambda actual: actual is not None and pattern.search(str(actual)) is not None
    if op == "cidr":
        try:
            network = ipaddress.ip_network(str(expected), strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR in {spec!r}: {exc}") from None

        def in_network(actual: Any) -> bool:
            if not is_present(actual):
                return False
            try:
                return ipaddress.ip_address(str(actual).strip()) in network
            except ValueError:
                return False

        return in_network
    if op in _NUMERIC_OPS:
        try:
            limit = float(expected)
        except (TypeError, ValueError):
            raise ValueError(f"{op} needs a number in {spec!r}") from None
        compare = _NUMERIC_OPS[op]

        def numeric(actual: Any) -> bool:
            try:
                return compare(float(actual), limit)
            except (TypeError, ValueError):
                return False

        return numeric

    wanted = _as_text(expected)
    if op == "eq":
        return lambda actual: actual is not None and _as_text(actual) == wanted
    if op == "contains":
        return lambda actual: actual is not None and wanted in _as_text(actual)
    if op == "startswith":
        return lambda actual: actual is not None and _as_text(actual).startswith(wanted)
    if op == "endswith":
        return lambda actual: actual is not None and _as_text(actual).endswith(wanted)
    raise ValueError(f"unsupported modifier {op!r} in {spec!r}")  # pragma: no cover


def compile_field(spec: str, expected: Any) -> Predicate:
    """Compile one ``field|modifiers: value(s)`` entry of a selection."""
    name, *modifiers = str(spec).split("|")
    if not name:
        raise ValueError(f"empty field name in {spec!r}")
    unknown = set(modifiers) - MODIFIERS
    if unknown:
        raise ValueError(f"unknown modifier(s) {', '.join(sorted(unknown))} in {spec!r}")
    values = expected if isinstance(expected, list) else [expected]
    if not values:
        raise ValueError(f"{spec!r} has an empty list of values")

    if "exists" in modifiers:
        if len(modifiers) != 1 or len(values) != 1 or not isinstance(values[0], bool):
            raise ValueError(f"'exists' takes a single true/false value and no other modifiers in {spec!r}")
        wanted = values[0]
        return lambda event: is_present(event.get(name)) == wanted

    comparisons = [m for m in modifiers if m != "all"]
    if len(comparisons) > 1:
        raise ValueError(f"only one comparison modifier is allowed in {spec!r}")
    op = comparisons[0] if comparisons else "eq"
    predicates = [_value_predicate(op, value, spec) for value in values]
    combine = all if "all" in modifiers else any

    def check(event: Event) -> bool:
        actual = event.get(name)
        return combine(predicate(actual) for predicate in predicates)

    return check


def compile_selection(name: str, spec: Any) -> Predicate:
    if isinstance(spec, dict):
        if not spec:
            raise ValueError(f"selection {name!r} is empty")
        predicates = [compile_field(str(key), value) for key, value in spec.items()]
        return lambda event: all(p(event) for p in predicates)
    if isinstance(spec, list) and spec:
        if all(isinstance(item, dict) for item in spec):
            groups = [compile_selection(name, item) for item in spec]
            return lambda event: any(g(event) for g in groups)
        if all(isinstance(item, (str, int)) and not isinstance(item, bool) for item in spec):
            keywords = [str(item).lower() for item in spec]
            return lambda event: any(k in event.raw.lower() for k in keywords)
    raise ValueError(f"selection {name!r} must be a mapping, a list of mappings or a list of keywords")


# --------------------------------------------------------------------------- model


@dataclass(frozen=True)
class Threshold:
    count: int
    timeframe: timedelta
    group_by: tuple[str, ...] = ()
    distinct: str | None = None


@dataclass(frozen=True)
class SequenceStep:
    selection: str
    count: int = 1


@dataclass(frozen=True)
class Sequence:
    steps: tuple[SequenceStep, ...]
    timeframe: timedelta
    group_by: tuple[str, ...] = ()


@dataclass
class Rule:
    id: str
    title: str
    level: str
    path: str
    selections: dict[str, Predicate]
    condition: Callable[[Callable[[str], bool]], bool] | None
    condition_text: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)
    sources: tuple[str, ...] | None = None
    threshold: Threshold | None = None
    sequence: Sequence | None = None
    status: str = "experimental"
    author: str = ""
    falsepositives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @property
    def kind(self) -> str:
        if self.sequence:
            return "sequence"
        if self.threshold:
            return "threshold"
        return "single"

    @property
    def techniques(self) -> list[str]:
        return [t[len("attack.") :].upper() for t in self.tags if _TECHNIQUE_TAG.match(t)]

    @property
    def tactics(self) -> list[str]:
        return [t[len("attack.") :] for t in self.tags if t[len("attack.") :] in TACTICS]

    def applies_to(self, event: Event) -> bool:
        return self.sources is None or event.source in self.sources

    def matches(self, event: Event) -> bool:
        if self.condition is None or not self.applies_to(event):
            return False
        cache: dict[str, bool] = {}

        def resolve(name: str) -> bool:
            if name not in cache:
                cache[name] = self.selections[name](event)
            return cache[name]

        return self.condition(resolve)


# --------------------------------------------------------------------------- parsing


def _string_list(value: Any, what: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return list(value)
    raise ValueError(f"{what} must be a string or a list of strings")


def _positive_int(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{what} must be a positive integer")
    return value


def parse_rule(doc: Any, path: str = "<rule>") -> Rule:
    try:
        return _parse_rule(doc)
    except (ValueError, ConditionError) as exc:
        rule_id = doc.get("id") if isinstance(doc, dict) else None
        prefix = f"rule {rule_id!r}: " if rule_id else ""
        raise RuleError(path, prefix + str(exc)) from None


def _parse_rule(doc: Any) -> Rule:
    if not isinstance(doc, dict):
        raise ValueError("a rule must be a YAML mapping")
    unknown = set(doc) - ALLOWED_KEYS
    if unknown:
        raise ValueError(f"unknown top-level key(s): {', '.join(sorted(map(str, unknown)))}")
    for key in ("id", "title", "level", "detection"):
        if key not in doc:
            raise ValueError(f"missing required key {key!r}")

    rule_id = doc["id"]
    if not isinstance(rule_id, str) or not _ID.match(rule_id):
        raise ValueError("id must be a string of letters, digits, '.', '_' or '-'")
    if not isinstance(doc["title"], str) or not doc["title"].strip():
        raise ValueError("title must be a non-empty string")
    level = doc["level"]
    if level not in LEVELS:
        raise ValueError(f"level must be one of {', '.join(LEVELS)}")

    tags = [t.lower() for t in _string_list(doc.get("tags"), "tags")]
    for tag in tags:
        if tag.startswith("attack.") and not (_TECHNIQUE_TAG.match(tag) or tag[7:] in TACTICS):
            raise ValueError(f"unrecognised ATT&CK tag {tag!r}")

    sources: tuple[str, ...] | None = None
    logsource = doc.get("logsource")
    if logsource is not None:
        if not isinstance(logsource, dict) or set(logsource) - {"source"}:
            raise ValueError("logsource must be a mapping with a single 'source' key")
        sources = tuple(_string_list(logsource.get("source"), "logsource.source"))
        bad = [s for s in sources if s not in KNOWN_SOURCES]
        if bad:
            raise ValueError(f"unknown log source(s) {bad}; known: {', '.join(KNOWN_SOURCES)}")
        sources = sources or None

    detection = doc["detection"]
    if not isinstance(detection, dict):
        raise ValueError("detection must be a mapping")
    detection = dict(detection)
    condition_text = detection.pop("condition", None)
    if not detection:
        raise ValueError("detection needs at least one selection")
    selections = {str(name): compile_selection(str(name), spec) for name, spec in detection.items()}

    if "threshold" in doc and "sequence" in doc:
        raise ValueError("a rule can have a threshold or a sequence, not both")

    condition = None
    if condition_text is not None:
        if not isinstance(condition_text, str):
            raise ValueError("condition must be a string")
        condition, _ = compile_condition(condition_text, list(selections))
    elif "sequence" not in doc:
        raise ValueError("detection.condition is required")

    threshold = _parse_threshold(doc["threshold"]) if "threshold" in doc else None
    sequence = _parse_sequence(doc["sequence"], selections) if "sequence" in doc else None

    return Rule(
        id=rule_id,
        title=doc["title"].strip(),
        level=level,
        path="",
        selections=selections,
        condition=condition,
        condition_text=condition_text or "",
        description=str(doc.get("description") or "").strip(),
        tags=tags,
        sources=sources,
        threshold=threshold,
        sequence=sequence,
        status=str(doc.get("status") or "experimental"),
        author=str(doc.get("author") or ""),
        falsepositives=_string_list(doc.get("falsepositives"), "falsepositives"),
        references=_string_list(doc.get("references"), "references"),
    )


def _parse_threshold(spec: Any) -> Threshold:
    if not isinstance(spec, dict) or set(spec) - {"count", "timeframe", "group_by", "distinct"}:
        raise ValueError("threshold must be a mapping with count, timeframe, group_by and optional distinct")
    if "count" not in spec or "timeframe" not in spec:
        raise ValueError("threshold needs both count and timeframe")
    distinct = spec.get("distinct")
    if distinct is not None and not isinstance(distinct, str):
        raise ValueError("threshold.distinct must be a field name")
    return Threshold(
        count=_positive_int(spec["count"], "threshold.count"),
        timeframe=parse_duration(spec["timeframe"]),
        group_by=tuple(_string_list(spec.get("group_by"), "threshold.group_by")),
        distinct=distinct,
    )


def _parse_sequence(spec: Any, selections: dict[str, Predicate]) -> Sequence:
    if not isinstance(spec, dict) or set(spec) - {"steps", "timeframe", "group_by"}:
        raise ValueError("sequence must be a mapping with steps, timeframe and group_by")
    if "steps" not in spec or "timeframe" not in spec:
        raise ValueError("sequence needs steps and a timeframe")
    raw_steps = spec["steps"]
    if not isinstance(raw_steps, list) or len(raw_steps) < 2:
        raise ValueError("sequence.steps must list at least two steps")
    steps = []
    for index, step in enumerate(raw_steps, start=1):
        if not isinstance(step, dict) or "selection" not in step or set(step) - {"selection", "count"}:
            raise ValueError(f"sequence step {index} must be a mapping with 'selection' and optional 'count'")
        if step["selection"] not in selections:
            raise ValueError(f"sequence step {index} references unknown selection {step['selection']!r}")
        steps.append(SequenceStep(step["selection"], _positive_int(step.get("count", 1), f"step {index} count")))
    return Sequence(
        steps=tuple(steps),
        timeframe=parse_duration(spec["timeframe"]),
        group_by=tuple(_string_list(spec.get("group_by"), "sequence.group_by")),
    )


def load_rules(path: str | Path) -> tuple[list[Rule], list[RuleError]]:
    """Load every ``*.yml``/``*.yaml`` rule under ``path``. Returns ``(rules, errors)``."""
    root = Path(path)
    if root.is_file():
        files = [root]
    elif root.is_dir():
        files = sorted(p for p in root.rglob("*") if p.suffix.lower() in (".yml", ".yaml") and p.is_file())
    else:
        return [], [RuleError(str(root), "rules path does not exist")]

    rules: list[Rule] = []
    errors: list[RuleError] = []
    seen: dict[str, str] = {}
    for file in files:
        try:
            documents = [d for d in yaml.safe_load_all(file.read_text(encoding="utf-8")) if d is not None]
        except yaml.YAMLError as exc:
            errors.append(RuleError(str(file), f"invalid YAML: {exc}"))
            continue
        for document in documents:
            try:
                rule = parse_rule(document, str(file))
            except RuleError as exc:
                errors.append(exc)
                continue
            if rule.id in seen:
                errors.append(RuleError(str(file), f"duplicate rule id {rule.id!r} (also in {seen[rule.id]})"))
                continue
            rule.path = str(file)
            seen[rule.id] = str(file)
            rules.append(rule)
    return rules, errors
