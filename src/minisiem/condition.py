"""Parser for Sigma-style rule conditions.

Grammar (case-insensitive keywords, usual precedence ``not`` > ``and`` > ``or``)::

    expr    := and_expr ("or" and_expr)*
    and_expr:= not_expr ("and" not_expr)*
    not_expr:= "not" not_expr | primary
    primary := "(" expr ")"
             | ("1" | "any" | "all") "of" (PATTERN | "them")
             | NAME

``PATTERN`` may contain ``*`` wildcards, e.g. ``1 of filter_*``.

The condition is compiled into a function that takes a resolver
(``name -> bool``) so selections are only evaluated when needed.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Sequence

Resolver = Callable[[str], bool]
Compiled = Callable[[Resolver], bool]

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")
_KEYWORDS = {"and", "or", "not", "of", "them", "all", "any", "1"}


class ConditionError(ValueError):
    pass


def tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    position = 0
    text = text.rstrip()
    while position < len(text):
        match = _TOKEN.match(text, position)
        if not match:
            raise ConditionError(f"unexpected character {text[position:].strip()[:1]!r} in condition {text!r}")
        tokens.append(match.group(1))
        position = match.end()
    return tokens


class _Parser:
    def __init__(self, tokens: list[str], names: Sequence[str]):
        self.tokens = tokens
        self.names = list(names)
        self.position = 0
        self.referenced: set[str] = set()

    def peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def advance(self) -> str:
        token = self.peek()
        if token is None:
            raise ConditionError("unexpected end of condition")
        self.position += 1
        return token

    def parse(self) -> Compiled:
        if not self.tokens:
            raise ConditionError("condition is empty")
        node = self.or_expr()
        if self.peek() is not None:
            raise ConditionError(f"unexpected token {self.peek()!r}")
        return node

    def or_expr(self) -> Compiled:
        left = self.and_expr()
        while (token := self.peek()) is not None and token.lower() == "or":
            self.advance()
            right = self.and_expr()
            left = (lambda a, b: lambda r: a(r) or b(r))(left, right)
        return left

    def and_expr(self) -> Compiled:
        left = self.not_expr()
        while (token := self.peek()) is not None and token.lower() == "and":
            self.advance()
            right = self.not_expr()
            left = (lambda a, b: lambda r: a(r) and b(r))(left, right)
        return left

    def not_expr(self) -> Compiled:
        token = self.peek()
        if token is not None and token.lower() == "not":
            self.advance()
            inner = self.not_expr()
            return lambda r: not inner(r)
        return self.primary()

    def primary(self) -> Compiled:
        word = self.advance()
        lowered = word.lower()
        if word == "(":
            node = self.or_expr()
            if self.peek() != ")":
                raise ConditionError("missing closing parenthesis")
            self.advance()
            return node
        if word == ")":
            raise ConditionError("unexpected ')'")
        nxt = self.peek()
        if lowered in ("1", "any", "all") and nxt is not None and nxt.lower() == "of":
            self.advance()
            pattern = self.advance()
            names = self._expand(pattern)
            self.referenced.update(names)
            if lowered == "all":
                return lambda r: all(r(n) for n in names)
            return lambda r: any(r(n) for n in names)
        if lowered in _KEYWORDS:
            raise ConditionError(f"unexpected keyword {word!r}")
        if word not in self.names:
            raise ConditionError(f"condition references unknown selection {word!r}")
        self.referenced.add(word)
        return lambda r: r(word)

    def _expand(self, pattern: str) -> list[str]:
        if pattern.lower() == "them":
            return list(self.names)
        if pattern.lower() in _KEYWORDS or pattern in "()":
            raise ConditionError(f"expected a selection name or pattern after 'of', got {pattern!r}")
        matches = [n for n in self.names if fnmatch.fnmatchcase(n, pattern)]
        if not matches:
            raise ConditionError(f"pattern {pattern!r} matches no selection")
        return matches


def compile_condition(text: str, names: Sequence[str]) -> tuple[Compiled, set[str]]:
    """Compile ``text``; returns the evaluator and the set of selection names it uses."""
    parser = _Parser(tokenize(text), names)
    compiled = parser.parse()
    return compiled, parser.referenced
