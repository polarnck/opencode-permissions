#!/usr/bin/env python3
"""V2 engine: the `permissions` list, `shell`/`subagent`, and V2 rendering."""

from __future__ import annotations

from typing import Dict, List

import core

BASE_POLICY = (
    ("*", "*", "allow"),
    ("read", "*.env", "ask"),
    ("read", "*.env.*", "ask"),
    ("read", "*.env.example", "allow"),
)
SHELL_ACTION = "shell"
SHAPE_KEY = "permissions"
KNOWN_ACTIONS = ["shell", "read", "edit", "glob", "grep", "external_directory", "subagent"]
LABEL = "V2 (`permissions` list; actions shell/subagent)"


def native_action(action: str) -> str:
    """V2 uses the canonical names."""
    return action


def parse(document: dict, source: str) -> List[core.Rule]:
    """Validate and convert the V2 `permissions` list of one document."""
    raw_rules = document.get("permissions")
    if raw_rules is None:
        return []
    if not isinstance(raw_rules, list):
        raise core.ConfigError("%s: `permissions` must be a list" % source)

    rules: List[core.Rule] = []
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            raise core.ConfigError(
                "%s: permissions[%d] must be an object" % (source, index)
            )
        action = raw.get("action")
        resource = raw.get("resource")
        effect = raw.get("effect")
        if not all(isinstance(value, str) for value in (action, resource, effect)):
            raise core.ConfigError(
                "%s: permissions[%d] needs string `action`, `resource`, `effect`"
                % (source, index)
            )
        if not action or not resource:
            raise core.ConfigError(
                "%s: permissions[%d] action and resource cannot be empty"
                % (source, index)
            )
        if effect not in core.EFFECTS:
            if effect == "***":
                raise core.ConfigError(
                    "%s: permissions[%d] has effect '***'. The resolved config "
                    "redacted this value; inspect the on-disk file with "
                    "--config FILE instead." % (source, index)
                )
            raise core.ConfigError(
                "%s: permissions[%d] has effect %r; expected one of %s"
                % (source, index, effect, ", ".join(core.EFFECTS))
            )
        rules.append(core.make_rule(action, resource, effect, source))
    return rules


def audit(document: dict, source: str, engine: str) -> List[str]:
    """Engine-specific warnings for one V2 document."""
    warnings: List[str] = []
    raw_rules = document.get("permissions")
    if isinstance(raw_rules, list):
        for index, raw in enumerate(raw_rules):
            if not isinstance(raw, dict):
                continue
            action = raw.get("action")
            if action == "bash":
                warnings.append(
                    "%s: permissions[%d] action `bash` is an OpenCode 1.x name; "
                    "V2 uses `shell`" % (source, index)
                )
            elif action == "task":
                warnings.append(
                    "%s: permissions[%d] action `task` is an OpenCode 1.x name; "
                    "V2 uses `subagent`" % (source, index)
                )
    return warnings


def render(rules, full: bool) -> Dict[str, object]:
    """Render canonical rule dicts into a V2 `permissions` list."""
    body: Dict[str, object] = {
        "permissions": [
            {
                "action": rule["action"],
                "resource": rule["resource"],
                "effect": rule["effect"],
            }
            for rule in rules
        ]
    }
    if full:
        body = {"$schema": "https://opencode.ai/config.json", **body}
    return body
