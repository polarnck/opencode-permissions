#!/usr/bin/env python3
"""V1 engine: the `permission` map, `bash`/`task`, and V1 rendering."""

from __future__ import annotations

from typing import Dict, List

import core

BASE_POLICY = (("*", "*", "allow"),)
SHELL_ACTION = "bash"
SHAPE_KEY = "permission"
KNOWN_ACTIONS = ["bash", "read", "edit", "glob", "grep", "external_directory", "task"]
LABEL = "V1 (`permission` map; actions bash/task)"
TOOL_ORDER = ("read", "edit", "bash", "external_directory")


def native_action(action: str) -> str:
    """Map a canonical action back to the V1 name."""
    if action == "shell":
        return "bash"
    if action == "subagent":
        return "task"
    return action


def parse(document: dict, source: str) -> List[core.Rule]:
    """Convert a V1 `permission` object into ordered rules."""
    raw = document.get("permission")
    if raw is None:
        return []
    if not isinstance(raw, dict):
        raise core.ConfigError("%s: `permission` must be an object" % source)

    rules: List[core.Rule] = []
    for tool, value in raw.items():
        if not isinstance(tool, str) or not tool:
            raise core.ConfigError(
                "%s: permission tool names must be non-empty strings" % source
            )
        if isinstance(value, str):
            if value == "***":
                raise core.ConfigError(
                    "%s: permission.%s has effect '***'. V1 `opencode debug config` "
                    "redacts values for secret-looking keys; inspect the on-disk "
                    "file with --config FILE instead." % (source, tool)
                )
            if value not in core.EFFECTS:
                raise core.ConfigError(
                    "%s: permission.%s has effect %r; expected one of %s"
                    % (source, tool, value, ", ".join(core.EFFECTS))
                )
            rules.append(core.make_rule(tool, "*", value, source))
            continue
        if not isinstance(value, dict):
            raise core.ConfigError(
                "%s: permission.%s must be a string or an object of "
                "pattern -> effect" % (source, tool)
            )
        for pattern, effect in value.items():
            if not isinstance(pattern, str) or not pattern:
                raise core.ConfigError(
                    "%s: permission.%s pattern names must be non-empty strings"
                    % (source, tool)
                )
            if not isinstance(effect, str) or effect not in core.EFFECTS:
                if effect == "***":
                    raise core.ConfigError(
                        "%s: permission.%s[%r] has effect '***'. V1 "
                        "`opencode debug config` redacts values for "
                        "secret-looking keys; inspect the on-disk file with "
                        "--config FILE instead." % (source, tool, pattern)
                    )
                raise core.ConfigError(
                    "%s: permission.%s[%r] has effect %r; expected one of %s"
                    % (source, tool, pattern, effect, ", ".join(core.EFFECTS))
                )
            rules.append(core.make_rule(tool, pattern, effect, source))
    return rules


def audit(document: dict, source: str, engine: str) -> List[str]:
    """Engine-specific warnings for one V1 document."""
    warnings: List[str] = []
    if "external_directory" in document:
        warnings.append(
            "%s has a top-level `external_directory`; V1 only reads "
            "`permission.external_directory`, so this key is ignored" % source
        )

    raw = document.get("permission")
    if isinstance(raw, dict):
        for tool in raw:
            if tool == "shell":
                warnings.append(
                    "%s: permission.shell is an OpenCode 2.x name; V1 uses `bash`"
                    % source
                )
            elif tool == "subagent":
                warnings.append(
                    "%s: permission.subagent is an OpenCode 2.x name; V1 uses `task`"
                    % source
                )
    return warnings


def render(rules, full: bool) -> Dict[str, object]:
    """Render canonical rule dicts into a V1 `permission` object."""
    permission: Dict[str, Dict[str, str]] = {}
    tools: List[str] = []
    for rule in rules:
        tool = rule.get("display_action") or (
            "bash" if rule["action"] == "shell" else rule["action"]
        )
        if tool not in tools:
            tools.append(tool)

    ordered = [tool for tool in TOOL_ORDER if tool in tools]
    ordered.extend(tool for tool in tools if tool not in TOOL_ORDER)
    for tool in ordered:
        tool_rules = [
            rule
            for rule in rules
            if (
                rule.get("display_action")
                or ("bash" if rule["action"] == "shell" else rule["action"])
            )
            == tool
        ]
        if not tool_rules:
            continue
        permission[tool] = {
            rule["resource"]: rule["effect"] for rule in tool_rules
        }

    body: Dict[str, object] = {"permission": permission}
    if full:
        body = {"$schema": "https://opencode.ai/config.json", **body}
    return body
