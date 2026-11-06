#!/usr/bin/env python3
"""core.py - shared primitives for the V1 and V2 permission engines.

This module has no engine-specific policy: no base policies, parsing, audit
messages or rendering. It is the single matcher and rule model used by both
engines, so V1 and V2 cannot drift apart.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

import platforms

EFFECTS = ("allow", "ask", "deny")

# The default action follows the engine. `shell`/`subagent` are V2 names;
# `bash`/`task` are V1 names.
DEFAULT_ACTION = {"v1": "bash", "v2": "shell"}

# V1 tool names that changed in V2. The engine evaluates canonical names, but
# reports keep the name that was written in the file.
ACTION_ALIASES = {
    "bash": "shell",
    "task": "subagent",
    "write": "edit",
    "patch": "edit",
}

# Characters escaped before a pattern becomes a regular expression. `*` and
# `?` are intentionally absent: they are the wildcards.
_REGEX_SPECIAL = set(".+^${}()|[]\\")

# Separators used by the shell scanner to split compound commands.
_SHELL_SEPARATORS = ("&&", "||", ";", "|", "&", "\n")

# Actions whose resources are home-expanded when the configuration loads.
HOME_ACTIONS = ("read", "edit", "external_directory")


class ConfigError(Exception):
    """A configuration file or command could not be read or understood."""


@dataclass
class Rule:
    action: str
    resource: str
    effect: str
    source: str = "config"
    match_resource: Optional[str] = None
    display_action: str = ""

    @property
    def pattern(self) -> str:
        return self.match_resource if self.match_resource is not None else self.resource

    @property
    def shown_action(self) -> str:
        return self.display_action or self.action


@dataclass
class LoadedConfig:
    rules: List[Rule]
    description: str
    sources: List[Tuple[str, str]]
    defaults: bool
    engine: str = "v2"
    documents: Optional[List[Tuple[str, str, dict]]] = None


def canonical_action(name: str) -> str:
    """Map a V1 tool name onto the canonical action used by the engine."""
    return ACTION_ALIASES.get(name, name)


def match(value: str, pattern: str) -> bool:
    """Whole-value wildcard match, identical to the OpenCode engine.

    `*` matches any run of characters (including `/`), `?` matches exactly one
    character, and backslashes are normalised to slashes. A pattern ending in
    " *" also matches the value without arguments (`git status *` matches both
    `git status` and `git status --short`). Matching is case-sensitive.
    """
    value = value.replace("\\", "/")
    pattern = pattern.replace("\\", "/")

    regex = "".join("\\" + ch if ch in _REGEX_SPECIAL else ch for ch in pattern)
    regex = regex.replace("*", ".*").replace("?", ".")
    if regex.endswith(" .*"):
        regex = regex[:-3] + "( .*)?"

    # `^` is implicit in re.match; `$` follows the same rules as the engine's
    # JavaScript regex (it also matches before a final newline).
    return re.match(regex + "$", value, flags=re.S) is not None


def expand_home(value: str) -> str:
    """Expand `~`, `$HOME` and Windows environment tokens like the engine."""
    return platforms.expand_user(value)


def _pattern_variants(pattern: str) -> List[str]:
    """Patterns accepted by `match`; a trailing ` *` also accepts no arguments."""
    pattern = pattern.replace("\\", "/")
    variants = [pattern]
    if pattern.endswith(" *"):
        variants.append(pattern[:-2])
    return variants


def _tokens(pattern: str) -> List[Tuple[str, str]]:
    tokens: List[Tuple[str, str]] = []
    for char in pattern:
        if char == "*":
            tokens.append(("star", ""))
        elif char == "?":
            tokens.append(("any", ""))
        else:
            tokens.append(("lit", char))
    return tokens


def _nfa_intersection(first: str, second: str) -> Optional[str]:
    """Shortest witness shared by two already-normalised patterns, if any.

    The patterns use only literals, `?` (one character) and `*` (any run),
    which is exactly the language `match` implements. This is a product
    automaton, so it has no sample-list blind spots.
    """
    left = _tokens(first)
    right = _tokens(second)
    stack: List[Tuple[int, int, str]] = [(0, 0, "")]
    seen = set()

    while stack:
        left_index, right_index, witness = stack.pop()
        if left_index == len(left) and right_index == len(right):
            return witness
        state = (left_index, right_index)
        if state in seen:
            continue
        seen.add(state)

        if left_index < len(left) and left[left_index][0] == "star":
            stack.append((left_index + 1, right_index, witness))
        if right_index < len(right) and right[right_index][0] == "star":
            stack.append((left_index, right_index + 1, witness))

        if left_index >= len(left) or right_index >= len(right):
            continue

        left_kind, left_char = left[left_index]
        right_kind, right_char = right[right_index]

        if left_kind == "star" and right_kind == "star":
            # Consuming one character keeps both in place; epsilon steps above
            # already cover every way a star can end, so this adds nothing.
            continue
        if left_kind == "star":
            next_char = "x" if right_kind == "any" else right_char
            stack.append((left_index, right_index + 1, witness + next_char))
            continue
        if right_kind == "star":
            next_char = "x" if left_kind == "any" else left_char
            stack.append((left_index + 1, right_index, witness + next_char))
            continue
        if left_kind == "any" and right_kind == "any":
            stack.append((left_index + 1, right_index + 1, witness + "x"))
        elif left_kind == "any":
            stack.append((left_index + 1, right_index + 1, witness + right_char))
        elif right_kind == "any":
            stack.append((left_index + 1, right_index + 1, witness + left_char))
        elif left_char == right_char:
            stack.append((left_index + 1, right_index + 1, witness + left_char))

    return None


def pattern_intersection(first: str, second: str) -> Optional[str]:
    """Return a concrete value matched by both patterns, or None.

    Used by conflict detection. A finite sample list would miss overlaps such
    as `*.pem` and `secrets/**`; this check is exact for the matcher above.
    """
    for left in _pattern_variants(first):
        for right in _pattern_variants(second):
            witness = _nfa_intersection(left, right)
            if witness is None:
                continue
            # Guard against a bug in the automaton: never return a witness the
            # public matcher rejects.
            if not (match(witness, first) and match(witness, second)):
                continue
            # The automaton often finds the shortest witness, which can look
            # artificial (`secrets//secrets/`). Prefer a cleaned equivalent
            # when it still matches both patterns.
            collapsed = re.sub(r"/{2,}", "/", witness)
            for cleaned in (collapsed.rstrip("/"), collapsed):
                if cleaned and match(cleaned, first) and match(cleaned, second):
                    return cleaned
            return witness
    return None


def make_rule(raw_action: str, resource: str, effect: str, source: str) -> Rule:
    action = canonical_action(raw_action)
    match_resource = expand_home(resource) if action in HOME_ACTIONS else None
    return Rule(
        action=action,
        resource=resource,
        effect=effect,
        source=source,
        match_resource=match_resource,
        display_action=raw_action,
    )


def find_rule(action: str, resource: str, rules: Sequence[Rule]) -> Optional[Rule]:
    """Return the last rule matching both action and resource, if any."""
    if action in HOME_ACTIONS:
        resource = expand_home(resource)

    for rule in reversed(rules):
        if match(action, rule.action) and match(resource, rule.pattern):
            return rule
    return None


def decide(action: str, resource: str, rules: Sequence[Rule]) -> str:
    """Effect for a single canonical action/resource pair."""
    rule = find_rule(action, resource, rules)
    return rule.effect if rule else "ask"


def split_shell(command: str) -> List[str]:
    """Split a compound shell command into the segments the scanner reports.

    This is a deliberately small approximation of the real tree-sitter
    scanner: it understands quotes, backslash escapes and the separators
    `&&`, `||`, `;`, `|`, `&` and newlines. It does not model subshells,
    command substitution, heredocs or redirections such as `2>&1`, which are
    kept inside the segment. Use `--no-split` to evaluate the raw string.
    """
    segments: List[str] = []
    buffer: List[str] = []
    quote: Optional[str] = None
    i = 0

    while i < len(command):
        char = command[i]

        if quote:
            buffer.append(char)
            if char == "\\" and quote == '"' and i + 1 < len(command):
                buffer.append(command[i + 1])
                i += 2
                continue
            if char == quote:
                quote = None
            i += 1
            continue

        if char in "'\"":
            quote = char
            buffer.append(char)
            i += 1
            continue

        if char == "\\" and i + 1 < len(command):
            buffer.append(char)
            buffer.append(command[i + 1])
            i += 2
            continue

        pair = command[i : i + 2]
        if pair in ("&&", "||"):
            segments.append("".join(buffer))
            buffer = []
            i += 2
            continue

        if char in _SHELL_SEPARATORS:
            # `2>&1`, `&>log` and `>&2` are redirections, not separators.
            previous = command[i - 1] if i > 0 else ""
            following = command[i + 1] if i + 1 < len(command) else ""
            if char == "&" and (previous in "<>" or following == ">"):
                buffer.append(char)
                i += 1
                continue
            segments.append("".join(buffer))
            buffer = []
            i += 1
            continue

        buffer.append(char)
        i += 1

    segments.append("".join(buffer))
    cleaned = [segment.strip() for segment in segments if segment.strip()]
    return cleaned or [command.strip()]


def decide_shell(command: str, rules: Sequence[Rule], split: bool) -> Tuple[str, List[str]]:
    """Overall effect for a shell command; deny wins over ask, ask over allow."""
    segments = split_shell(command) if split else [command]
    effects = [decide("shell", segment, rules) for segment in segments]

    if "deny" in effects:
        return "deny", segments
    if "ask" in effects:
        return "ask", segments
    return "allow", segments


def _strip_comments(text: str) -> str:
    """Remove // and /* */ comments without touching string contents."""
    output: List[str] = []
    i, length, in_string = 0, len(text), False

    while i < length:
        char = text[i]

        if in_string:
            output.append(char)
            if char == "\\" and i + 1 < length:
                output.append(text[i + 1])
                i += 2
                continue
            if char == '"':
                in_string = False
            i += 1
            continue

        if char == '"':
            in_string = True
            output.append(char)
            i += 1
            continue

        if char == "/" and i + 1 < length and text[i + 1] == "/":
            newline = text.find("\n", i)
            i = length if newline == -1 else newline
            continue

        if char == "/" and i + 1 < length and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            stop = length if end == -1 else end + 2
            # Keep newlines so JSON error line numbers still point at the
            # original file.
            output.append("\n" * text.count("\n", i, stop))
            i = stop
            continue

        output.append(char)
        i += 1

    return "".join(output)


def _strip_trailing_commas(text: str) -> str:
    """Remove commas that appear directly before `}` or `]`."""
    output: List[str] = []
    i, length, in_string = 0, len(text), False

    while i < length:
        char = text[i]

        if in_string:
            output.append(char)
            if char == "\\" and i + 1 < length:
                output.append(text[i + 1])
                i += 2
                continue
            if char == '"':
                in_string = False
            i += 1
            continue

        if char == '"':
            in_string = True
            output.append(char)
            i += 1
            continue

        if char == ",":
            lookahead = i + 1
            while lookahead < length and text[lookahead] in " \t\r\n":
                lookahead += 1
            if lookahead < length and text[lookahead] in "}]":
                i += 1
                continue

        output.append(char)
        i += 1

    return "".join(output)


def read_jsonc(path: str) -> object:
    try:
        with open(path, encoding="utf-8-sig") as handle:
            raw = handle.read()
    except OSError as exc:
        raise ConfigError("cannot read %s: %s" % (path, exc)) from exc

    cleaned = _strip_trailing_commas(_strip_comments(raw))
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            "%s is not valid JSONC (line %d, column %d): %s"
            % (path, exc.lineno, exc.colno, exc.msg)
        ) from exc


def config_home() -> str:
    """Canonical OpenCode config directory, delegated to platforms."""
    return platforms.config_home()
