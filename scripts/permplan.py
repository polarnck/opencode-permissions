#!/usr/bin/env python3
"""permplan.py - plan, generate and verify OpenCode permission rules.

The workflow:

  1. engine: V1 (`permission` map) or V2 (`permissions` list),
  2. scope: project file or global file,
  3. paths and effects,
  4. existing rules and conflicts (keep-existing, use-new or skip-path),
  5. generate rules, verify them, then apply with a backup.

This script never writes the target configuration. `generate` prints or saves a
snippet; the skill (or the user) applies it after taking a backup.

Commands:

  python3 scripts/permplan.py doctor
  python3 scripts/permplan.py init
  python3 scripts/permplan.py show --plan examples/permissions.plan.json
  python3 scripts/permplan.py conflicts --plan permissions.plan.json
  python3 scripts/permplan.py resolve --plan permissions.plan.json --id 1 --decision keep-existing
  python3 scripts/permplan.py generate --plan examples/permissions.plan.json
  python3 scripts/permplan.py verify --plan permissions.plan.json

Exit codes: 0 ok, 1 failed verification, 2 usage/config error, 3 conflicts
need a decision (compare also uses 3 for changed decisions).
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 9):
    sys.stderr.write(
        "permplan.py requires Python 3.9 or newer; this is %s.%s.\n"
        % (sys.version_info[0], sys.version_info[1])
    )
    sys.exit(2)

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
from typing import Dict, List, Optional, Sequence, Tuple

# Import the checker from the same directory. One matcher, no copy of the
# evaluation rules in this script.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import core  # noqa: E402
import engines  # noqa: E402
import permcheck  # noqa: E402
import platforms  # noqa: E402

ConfigError = core.ConfigError

VERSION = "2.0.0"
SCHEMA = 1
SELF = os.path.join(SCRIPT_DIR, "permplan.py")

EFFECTS = ("block", "ask", "read-only", "read-write")
SHELLS = ("auto", "none", "ask", "deny", "allow")

# Presets from the documentation. `shell` is the default for project paths;
# external paths default to `none` because external_directory handles them.
EFFECT_PRESETS: Dict[str, Dict[str, str]] = {
    "block": {"read": "deny", "edit": "deny", "shell": "deny", "external": "deny"},
    "ask": {"read": "ask", "edit": "ask", "shell": "ask", "external": "ask"},
    "read-only": {"read": "allow", "edit": "deny", "shell": "ask", "external": "ask"},
    "read-write": {"read": "allow", "edit": "allow", "shell": "none", "external": "allow"},
}

EFFECT_ORDER = {"allow": 0, "ask": 1, "deny": 2}


# --------------------------------------------------------------------------
# Plan loading and path classification
# --------------------------------------------------------------------------


def _require_string(value: object, name: str, source: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError("%s: `%s` must be a non-empty string" % (source, name))
    return value


def _same_path(first: str, second: str) -> bool:
    """True for the same file, including symlinks and hard links."""
    try:
        if os.path.exists(first) and os.path.exists(second):
            if os.path.samefile(first, second):
                return True
    except OSError:
        pass
    left = os.path.normcase(os.path.realpath(os.path.abspath(first)))
    right = os.path.normcase(os.path.realpath(os.path.abspath(second)))
    return left == right


def _write_text_atomic(path: str, text: str) -> None:
    """Write a text file next to its destination, then replace atomically."""
    parent = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(parent):
        raise ConfigError("output directory does not exist: %s" % parent)
    handle, temporary = tempfile.mkstemp(
        prefix=".permplan-", suffix=".tmp", dir=parent, text=True
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(temporary, path)
    except OSError as exc:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise ConfigError("cannot write %s: %s" % (path, exc)) from exc


def _has_home_token(value: str) -> bool:
    upper = value.upper()
    if value in ("~", "$HOME") or upper == "%USERPROFILE%":
        return True
    for prefix in ("~/", "$HOME/", "%USERPROFILE%/"):
        if value[: len(prefix)].upper() == prefix.upper():
            return True
    return False


def _home_remainder(value: str) -> str:
    upper = value.upper()
    if value in ("~", "$HOME") or upper == "%USERPROFILE%":
        return ""
    for prefix in ("~/", "$HOME/", "%USERPROFILE%/"):
        if value[: len(prefix)].upper() == prefix.upper():
            return value[len(prefix) :]
    return value


def _validate_plan_path(item: dict, index: int, source: str) -> None:
    """Reject paths that would generate rules the engine can never match."""
    value = platforms.to_pattern_path(item["input"].strip())
    if not value:
        raise ConfigError("%s: paths[%d].input cannot be empty" % (source, index))

    kind = item["kind"]
    location = item["location"]
    is_pattern = "*" in value or "?" in value

    if is_pattern and kind != "pattern":
        raise ConfigError(
            "%s: paths[%d].kind must be `pattern` when input contains `*` or `?`"
            % (source, index)
        )
    if kind == "pattern" and not is_pattern:
        raise ConfigError(
            "%s: paths[%d].kind is `pattern` but input has no wildcard"
            % (source, index)
        )

    segments = value.split("/")
    if any(segment == ".." for segment in segments):
        raise ConfigError(
            "%s: paths[%d].input contains `..`; re-run init so the path is "
            "normalised relative to its scope" % (source, index)
        )

    if location == "project":
        upper = value.upper()
        if (
            platforms.is_absolute(value)
            or value.startswith("/")
            or _has_home_token(value)
            or upper in ("%APPDATA%", "%LOCALAPPDATA%")
            or upper.startswith("%APPDATA%/")
            or upper.startswith("%LOCALAPPDATA%/")
        ):
            raise ConfigError(
                "%s: paths[%d].input is absolute or home-based but location "
                "is project" % (source, index)
            )
        if len(value) >= 2 and value[1] == ":":
            raise ConfigError(
                "%s: paths[%d].input is a drive-relative Windows path; use "
                "`C:/...` or a project-relative path" % (source, index)
            )
        if value.startswith("./"):
            raise ConfigError(
                "%s: paths[%d].input starts with `./`; read/edit resources "
                "never contain that prefix" % (source, index)
            )
        if not is_pattern:
            normalised = platforms.to_pattern_path(os.path.normpath(value))
            if normalised in (".", ""):
                raise ConfigError(
                    "%s: paths[%d].input points at the project root" % (source, index)
                )
            value = normalised
    elif location == "home":
        if not _has_home_token(value):
            raise ConfigError(
                "%s: paths[%d].location is home but input does not start with "
                "`~`, `$HOME` or `%%USERPROFILE%%`" % (source, index)
            )
        remainder = _home_remainder(value)
        if remainder == "" and kind == "file":
            raise ConfigError(
                "%s: paths[%d] names the home directory as a file" % (source, index)
            )
    else:
        upper = value.upper()
        appdata = upper in ("%APPDATA%", "%LOCALAPPDATA%") or upper.startswith(
            "%APPDATA%/"
        ) or upper.startswith("%LOCALAPPDATA%/")
        if not platforms.is_absolute(value) and not appdata:
            raise ConfigError(
                "%s: paths[%d].location is absolute but input is not an "
                "absolute path" % (source, index)
            )

    item["input"] = value


def load_plan(path: str) -> dict:
    try:
        with open(path, encoding="utf-8-sig") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise ConfigError("cannot read plan %s: %s" % (path, exc)) from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(
            "%s is not valid JSON (line %d, column %d): %s"
            % (path, exc.lineno, exc.colno, exc.msg)
        ) from exc

    if not isinstance(data, dict):
        raise ConfigError("%s: a plan must be a JSON object" % path)
    schema = data.get("schema")
    if isinstance(schema, bool) or schema != SCHEMA:
        raise ConfigError(
            "%s: unsupported plan schema %r; expected %d" % (path, schema, SCHEMA)
        )

    engine = data.get("engine")
    if engine not in ("v1", "v2"):
        raise ConfigError("%s: `engine` must be `v1` or `v2`" % path)
    scope = data.get("scope")
    if scope not in ("local", "global"):
        raise ConfigError("%s: `scope` must be `local` or `global`" % path)

    for key in ("project", "config"):
        value = _require_string(data.get(key), key, path).strip()
        if not platforms.is_absolute(value):
            raise ConfigError("%s: `%s` must be an absolute path" % (path, key))
        data[key] = value
    if os.path.isdir(data["config"]):
        raise ConfigError("%s: `config` must name a file, not a directory" % path)

    raw_paths = data.get("paths")
    if not isinstance(raw_paths, list) or not raw_paths:
        raise ConfigError("%s: `paths` must be a non-empty list" % path)

    paths: List[dict] = []
    for index, raw in enumerate(raw_paths):
        if not isinstance(raw, dict):
            raise ConfigError("%s: paths[%d] must be an object" % (path, index))
        item = {}
        for key in ("input", "kind", "location", "effect", "shell"):
            item[key] = _require_string(raw.get(key), key, path)
        if item["kind"] not in ("directory", "file", "pattern"):
            raise ConfigError(
                "%s: paths[%d].kind must be directory, file or pattern" % (path, index)
            )
        if item["location"] not in ("project", "home", "absolute"):
            raise ConfigError(
                "%s: paths[%d].location must be project, home or absolute" % (path, index)
            )
        if item["effect"] not in EFFECTS:
            raise ConfigError(
                "%s: paths[%d].effect must be one of %s"
                % (path, index, ", ".join(EFFECTS))
            )
        if item["shell"] not in ("none", "ask", "deny", "allow"):
            raise ConfigError(
                "%s: paths[%d].shell must be none, ask, deny or allow" % (path, index)
            )
        _validate_plan_path(item, index, path)
        paths.append(item)

    data["paths"] = paths
    raw_resolutions = data.get("resolutions", [])
    if not isinstance(raw_resolutions, list):
        raise ConfigError("%s: `resolutions` must be a list" % path)
    resolutions: List[dict] = []
    for index, raw in enumerate(raw_resolutions):
        if not isinstance(raw, dict):
            raise ConfigError("%s: resolutions[%d] must be an object" % (path, index))
        item = {}
        for key in ("action", "resource", "new_effect", "existing_effect", "decision", "path"):
            item[key] = _require_string(raw.get(key), key, path).strip()
        existing_resource = raw.get("existing_resource", "")
        if not isinstance(existing_resource, str):
            raise ConfigError(
                "%s: resolutions[%d].existing_resource must be a string"
                % (path, index)
            )
        item["existing_resource"] = platforms.to_pattern_path(
            existing_resource.strip()
        )
        if item["decision"] not in ("keep-existing", "use-new", "skip-path"):
            raise ConfigError(
                "%s: resolutions[%d].decision must be keep-existing, use-new or "
                "skip-path" % (path, index)
            )
        for key in ("new_effect", "existing_effect"):
            if item[key] not in core.EFFECTS:
                raise ConfigError(
                    "%s: resolutions[%d].%s must be one of %s"
                    % (path, index, key, ", ".join(core.EFFECTS))
                )
        item["resource"] = platforms.to_pattern_path(item["resource"])
        item["path"] = platforms.to_pattern_path(item["path"])
        item["action"] = core.canonical_action(item["action"])
        resolutions.append(item)
    data["resolutions"] = resolutions
    return data


def _inside_project(path: str, project: str) -> bool:
    try:
        checked = os.path.normcase(os.path.abspath(path))
        root = os.path.normcase(os.path.abspath(project))
        return os.path.commonpath([checked, root]) == root
    except ValueError:
        # Different drives, or a Windows path on a non-Windows host.
        return False


def _is_windows_absolute(path: str) -> bool:
    return (
        len(path) >= 3
        and path[0].isalpha()
        and path[1] == ":"
        and path[2] == "/"
    ) or path.startswith("//")


def _expand_with_home(text: str, home: str) -> str:
    upper = text.upper()
    if text in ("~", "$HOME") or upper == "%USERPROFILE%":
        return home
    for prefix in ("~/", "$HOME/", "%USERPROFILE%/"):
        if text[: len(prefix)].upper() == prefix.upper():
            return home + text[len(prefix) - 1 :]
    return platforms.expand_user(text)


def _normalise_home_path(text: str, home: str) -> str:
    expanded = _expand_with_home(text, home)
    normalised = os.path.normpath(expanded)
    if normalised == home:
        return "~"
    prefix = home if home.endswith(os.sep) else home + os.sep
    if normalised.startswith(prefix):
        return platforms.to_pattern_path(
            "~/" + os.path.relpath(normalised, home)
        )
    return platforms.to_pattern_path(normalised)


def classify_path(
    raw: str,
    project: str,
    home: Optional[str] = None,
) -> Tuple[dict, List[str]]:
    """Classify one plan input into input/kind/location plus warnings."""
    warnings: List[str] = []
    project = os.path.abspath(os.path.expanduser(platforms.expand_user(project)))
    home = os.path.abspath(os.path.expanduser(platforms.expand_user(home or platforms.home_dir())))

    if not isinstance(raw, str) or not raw.strip():
        raise ConfigError("path cannot be empty")

    text = platforms.to_pattern_path(raw.strip())
    while text.startswith("./"):
        warnings.append("stripped leading `./` from %r" % text)
        text = text[2:]
    if not text:
        raise ConfigError("path cannot be empty")

    is_pattern = "*" in text or "?" in text
    upper = text.upper()
    home_token = (
        text in ("~", "$HOME")
        or upper == "%USERPROFILE%"
        or text.startswith("~/")
        or text.startswith("$HOME/")
        or upper.startswith("%USERPROFILE%/")
    )
    absolute_token = upper in ("%APPDATA%", "%LOCALAPPDATA%") or upper.startswith(
        "%APPDATA%/"
    ) or upper.startswith("%LOCALAPPDATA%/")

    if home_token:
        location = "home"
        expanded_home = os.path.normpath(_expand_with_home(text, home))
        try:
            inside_home = os.path.commonpath([expanded_home, home]) == home
        except ValueError:
            inside_home = False
        if not inside_home:
            raise ConfigError(
                "home path %r escapes the home directory; use an absolute path "
                "for external locations" % raw
            )
        normalised_home = _normalise_home_path(text, home)
        if normalised_home != text:
            warnings.append("normalised %r to %r" % (text, normalised_home))
        text = normalised_home
    elif platforms.is_absolute(text) or absolute_token:
        location = "absolute"
    else:
        location = "project"

    windows_absolute_on_other = (
        location == "absolute"
        and not platforms.is_windows()
        and _is_windows_absolute(text)
    )
    network_absolute = location == "absolute" and text.startswith("//")

    if location == "project":
        if len(text) >= 2 and text[0].isalpha() and text[1] == ":":
            raise ConfigError(
                "%r is a drive-relative Windows path; use `C:/...` or a "
                "project-relative path" % raw
            )
        if is_pattern and ".." in text.split("/"):
            raise ConfigError(
                "pattern %r contains `..`; refusing to guess whether it escapes "
                "the project" % text
            )
        normalised = platforms.to_pattern_path(os.path.normpath(text))
        if normalised in (".", ""):
            raise ConfigError(
                "%r points at the project root; choose a folder or file inside it"
                % raw
            )
        if normalised == ".." or normalised.startswith("../"):
            raise ConfigError(
                "path %r escapes the project; use an absolute path for external "
                "locations" % text
            )
        if normalised != text:
            warnings.append("normalised %r to %r" % (text, normalised))
            text = normalised
    else:
        expanded = _expand_with_home(text, home)
        normalised = os.path.normpath(expanded)
        if normalised != expanded:
            warnings.append("normalised %r to %r" % (expanded, normalised))
        if location == "home":
            text = _normalise_home_path(text, home)
        else:
            text = platforms.to_pattern_path(normalised)

        if (
            not windows_absolute_on_other
            and not network_absolute
            and _inside_project(normalised, project)
        ):
            if os.path.normcase(os.path.abspath(normalised)) == os.path.normcase(project):
                raise ConfigError(
                    "%r is the project root; choose a folder or file inside it" % raw
                )
            relative = platforms.to_pattern_path(os.path.relpath(normalised, project))
            warnings.append(
                "converted %r to project-relative %r (it is inside the project)"
                % (raw, relative)
            )
            text = relative
            location = "project"
            is_pattern = "*" in text or "?" in text
            windows_absolute_on_other = False
            network_absolute = False

    if is_pattern:
        kind = "pattern"
    elif windows_absolute_on_other:
        basename = os.path.basename(text.rstrip("/"))
        kind = "file" if "." in basename else "directory"
        warnings.append(
            "%r is a Windows path on this OS; inferred a %s and treated it as "
            "external" % (text, kind)
        )
    elif network_absolute:
        basename = os.path.basename(text.rstrip("/"))
        kind = "file" if "." in basename else "directory"
        warnings.append(
            "%r is a UNC path; inferred a %s without a network lookup"
            % (text, kind)
        )
    else:
        if location == "project":
            filesystem_path = os.path.join(project, text)
        elif location == "home":
            filesystem_path = _expand_with_home(text, home)
        else:
            filesystem_path = text

        if os.path.isdir(filesystem_path):
            kind = "directory"
        elif os.path.isfile(filesystem_path):
            kind = "file"
        else:
            basename = os.path.basename(text.rstrip("/"))
            kind = "file" if "." in basename else "directory"
            warnings.append(
                "%r does not exist; inferred a %s from its name" % (text, kind)
            )

    return {"input": text, "kind": kind, "location": location}, warnings


def resolve_shell(effect: str, location: str, override: str) -> str:
    """Pick the shell guard; external paths default to no shell rule."""
    if effect not in EFFECT_PRESETS:
        raise ConfigError(
            "unknown effect %r; expected one of %s" % (effect, ", ".join(EFFECTS))
        )
    if override not in SHELLS:
        raise ConfigError(
            "unknown shell guard %r; expected one of %s"
            % (override, ", ".join(SHELLS))
        )
    if override != "auto":
        return override
    if location != "project":
        return "none"
    return EFFECT_PRESETS[effect]["shell"]


def parse_path_argument(value: str) -> Tuple[str, str, str]:
    """Parse `PATH=EFFECT[:SHELL]` from --path."""
    if "=" not in value:
        raise ConfigError(
            "--path expects PATH=EFFECT[:SHELL], for example secrets=block or "
            "~/reference=read-only:none"
        )
    path, rest = value.split("=", 1)
    effect, separator, shell = rest.partition(":")
    effect = effect.strip()
    shell = shell.strip() if separator else "auto"
    if not path.strip():
        raise ConfigError("--path needs a path before `=`")
    if effect not in EFFECTS:
        raise ConfigError(
            "unknown effect %r in --path; expected one of %s"
            % (effect, ", ".join(EFFECTS))
        )
    if shell not in SHELLS:
        raise ConfigError(
            "unknown shell guard %r in --path; expected one of %s"
            % (shell, ", ".join(SHELLS))
        )
    return path, effect, shell


def build_plan(
    engine: str,
    scope: str,
    project: str,
    config: Optional[str],
    entries: Sequence[str],
) -> Tuple[dict, List[str]]:
    """Build a schema-1 plan from engine, scope and `PATH=EFFECT[:SHELL]` entries."""
    project = os.path.abspath(os.path.expanduser(platforms.expand_user(project)))
    if not os.path.isdir(project):
        raise ConfigError("project directory not found: %s" % project)

    warnings: List[str] = []
    if config:
        config = os.path.abspath(os.path.expanduser(platforms.expand_user(config)))
    elif scope == "local":
        found = platforms.find_project_config(project)
        config = found or os.path.join(project, "opencode.jsonc")
        if found and os.path.normcase(os.path.dirname(found)) != os.path.normcase(project):
            warnings.append("using project config found up the tree: %s" % found)
    else:
        existing = [
            (label, path)
            for label, path in platforms.global_config_candidates()
            if label not in platforms.MANAGED_LABELS and os.path.isfile(path)
        ]
        if len(existing) > 1:
            warnings.append(
                "multiple global configs found; using the first: %s"
                % ", ".join("%s=%s" % item for item in existing)
            )
        config = existing[0][1] if existing else platforms.find_global_config()

    paths: List[dict] = []
    for value in entries:
        path, effect, shell = parse_path_argument(value)
        item, path_warnings = classify_path(path, project)
        warnings.extend(path_warnings)
        item["effect"] = effect
        item["shell"] = resolve_shell(effect, item["location"], shell)
        paths.append(item)

    if not paths:
        raise ConfigError("a plan needs at least one path")

    plan = {
        "schema": SCHEMA,
        "engine": engine,
        "scope": scope,
        "project": project,
        "config": config,
        "paths": paths,
        "resolutions": [],
    }
    return plan, warnings


# --------------------------------------------------------------------------
# Rule generation
# --------------------------------------------------------------------------


def path_effects(item: dict) -> Dict[str, str]:
    """Expand one plan path into read/edit/shell/external effects."""
    preset = EFFECT_PRESETS[item["effect"]]
    external = preset["external"] if item["location"] != "project" else "none"
    return {
        "read": preset["read"],
        "edit": preset["edit"],
        "shell": item["shell"],
        "external": external,
    }


def _directory_pattern(base: str) -> str:
    if base == "/":
        return "/*"
    return base.rstrip("/") + "/*"


def _pattern_forms(pattern: str) -> List[str]:
    forms = [pattern]
    if pattern.startswith("**/"):
        forms.append(pattern[3:])
    return forms


def _shell_from_pattern(pattern: str) -> str:
    stripped = pattern[3:] if pattern.startswith("**/") else pattern
    if "/" in stripped:
        core = "*" + stripped
    else:
        core = stripped
    if not core.startswith("*"):
        core = "*" + core
    if not core.endswith("*"):
        core += "*"
    return core


def _strip_root(value: str) -> str:
    if value == "~" or value == "$HOME":
        return ""
    if value.startswith("~/") or value.startswith("$HOME/"):
        return value[2:]
    if value.startswith("/"):
        return value[1:]
    return value


def _external_parent(value: str) -> str:
    if "/" not in value:
        return value
    parent = value.rsplit("/", 1)[0]
    if parent in ("~", "$HOME", ""):
        if value.startswith("$HOME"):
            return _directory_pattern("$HOME")
        if value.startswith("~"):
            return _directory_pattern("~")
        return _directory_pattern("/")
    return _directory_pattern(parent)


def path_rules(item: dict) -> Tuple[List[dict], List[str]]:
    """Generate read/edit/shell/external rules for one plan path."""
    effects = path_effects(item)
    location = item["location"]
    kind = item["kind"]
    value = item["input"]
    warnings: List[str] = []
    rules: List[dict] = []

    def add(action: str, resource: str) -> None:
        effect = effects[action]
        if effect != "none":
            rule_action = "external_directory" if action == "external" else action
            rules.append(
                {
                    "action": rule_action,
                    "resource": resource,
                    "effect": effect,
                    "path": value,
                }
            )

    if location == "project":
        if kind == "directory":
            resources = [value + "/**", "**/" + value + "/**"]
        elif kind == "file":
            resources = [value, "**/" + value]
        else:
            resources = _pattern_forms(value)
        for resource in resources:
            add("read", resource)
            add("edit", resource)

        if effects["shell"] != "none":
            if kind == "directory":
                add("shell", "*" + value + "/*")
            elif kind == "file":
                add("shell", "*" + value + "*")
            else:
                add("shell", _shell_from_pattern(value))
        return rules, warnings

    # Outside the project: read/edit and external_directory are separate checks.
    if kind == "directory":
        resources = [_directory_pattern(value)]
        external = resources[0]
    elif kind == "file":
        resources = [value]
        external = _external_parent(value)
        warnings.append(
            "external_directory is directory-level; %s is broader than the file %s"
            % (external, value)
        )
    else:
        resources = _pattern_forms(value)
        external = _external_parent(value)
        warnings.append(
            "external_directory is directory-level; %s is broader than the pattern %s"
            % (external, value)
        )

    for resource in resources:
        add("read", resource)
        add("edit", resource)
    add("external", external)

    if effects["shell"] != "none":
        if kind == "pattern":
            add("shell", _shell_from_pattern(value))
        elif kind == "directory":
            add("shell", "*" + _strip_root(value) + "/*")
        else:
            add("shell", "*" + _strip_root(value) + "*")

    return rules, warnings


def build_rules(plan: dict) -> Tuple[List[dict], List[str]]:
    """Generate all rules, ordered allows -> asks -> denies, user order kept."""
    items: List[Tuple[int, int, dict]] = []
    warnings: List[str] = []
    for index, item in enumerate(plan["paths"]):
        generated, path_warnings = path_rules(item)
        warnings.extend(path_warnings)
        for rule in generated:
            items.append((EFFECT_ORDER[rule["effect"]], index, rule))
    items.sort(key=lambda entry: (entry[0], entry[1]))
    return [rule for _, _, rule in items], warnings


# --------------------------------------------------------------------------
# Existing rules and conflicts
# --------------------------------------------------------------------------


DECISIONS = ("keep-existing", "use-new", "skip-path")


def load_existing(
    plan: dict,
    config: Optional[str] = None,
    resolved: bool = False,
    binary: str = "opencode",
) -> core.LoadedConfig:
    """Load existing rules with defaults off; missing files mean no conflicts."""
    if resolved:
        try:
            return permcheck.load_engine(
                plan["project"], False, None, plan["engine"], binary
            )
        except ConfigError as exc:
            print(
                "warning: live resolved config unavailable (%s); falling back to %s"
                % (exc, plan["config"]),
                file=sys.stderr,
            )

    target = config or plan["config"]
    if os.path.exists(target) and not os.path.isfile(target):
        raise ConfigError("existing config is not a file: %s" % target)
    if not os.path.isfile(target):
        return core.LoadedConfig(
            rules=[],
            description="existing: %s (missing)" % target,
            sources=[],
            defaults=False,
            engine=plan["engine"],
            documents=[],
        )
    try:
        return permcheck.load_file(target, False, None, plan["engine"])
    except ConfigError as exc:
        raise ConfigError(
            "cannot load existing config %s: %s" % (target, exc)
        ) from exc


def print_existing_summary(config: core.LoadedConfig) -> None:
    """Print path, engine, rule count and per-action counts."""
    print("Existing config: %s" % config.description)
    print("Existing engine: %s" % config.engine.upper())
    print("Existing rules: %d" % len(config.rules))
    counts: Dict[str, int] = {}
    for rule in config.rules:
        counts[rule.action] = counts.get(rule.action, 0) + 1
    module = engines.get(config.engine)
    for action in sorted(counts):
        print("  %-20s %d" % (module.native_action(action), counts[action]))


def print_existing_rules(config: core.LoadedConfig) -> None:
    for index, rule in enumerate(config.rules):
        print(
            "  [%3d] %-5s %-18s %s"
            % (index, rule.effect, rule.shown_action, rule.resource)
        )


def _match_resource(action: str, resource: str) -> str:
    """Normalise a resource exactly as the engine does before matching."""
    text = platforms.to_pattern_path(resource)
    if action in core.HOME_ACTIONS:
        return core.expand_home(text)
    return text


def _same_resource(action: str, first: str, second: str) -> bool:
    return _match_resource(action, first) == _match_resource(action, second)


# User-facing examples first. The NFA witness is exact, but these read like
# real project paths and commands.
REALISTIC_SAMPLES = {
    "read": [
        "secrets/prod.env",
        "src/secrets/prod.env",
        "secrets/secrets/prod.env",
        "src/secrets/secrets/prod.env",
        "secrets/foo/prod.env",
        "secrets/foo/secrets/prod.env",
        "secrets/key.pem",
        "src/secrets/key.pem",
        "secrets/foo/key.pem",
        "config/prod.json",
        "src/config/prod.json",
        "key.pem",
        "a/b/key.pem",
        ".env",
        "src/.env",
        "docs/guide.md",
        "~/reference/notes.md",
        "~/reference/secrets/notes.md",
        "/srv/data/file.txt",
        "/srv/data/secrets/file.txt",
    ],
    "edit": [
        "secrets/prod.env",
        "src/secrets/prod.env",
        "secrets/secrets/prod.env",
        "src/secrets/secrets/prod.env",
        "secrets/foo/prod.env",
        "secrets/foo/secrets/prod.env",
        "secrets/key.pem",
        "src/secrets/key.pem",
        "secrets/foo/key.pem",
        "config/prod.json",
        "src/config/prod.json",
        "key.pem",
        "a/b/key.pem",
        ".env",
        "src/.env",
        "docs/guide.md",
        "~/reference/notes.md",
        "~/reference/secrets/notes.md",
        "/srv/data/file.txt",
        "/srv/data/secrets/file.txt",
    ],
    "shell": [
        "cat secrets/prod.env",
        "cat src/secrets/prod.env",
        "cat secrets/secrets/prod.env",
        "cat src/secrets/secrets/prod.env",
        "cat secrets/foo/prod.env",
        "cat secrets/foo/secrets/prod.env",
        "cat secrets/key.pem",
        "cat key.pem",
        "cat .env",
        "git status",
        "git status --short",
        "cat ~/reference/notes.md",
        "cat /srv/data/file.txt",
    ],
    "external_directory": [
        "~/reference/notes.md",
        "~/reference/secrets/notes.md",
        "/srv/data/file.txt",
        "/srv/data/secrets/file.txt",
    ],
}


def _overlap_sample(action: str, first: str, second: str) -> Optional[str]:
    """A realistic shared sample for two overlapping patterns, or None."""
    left = _match_resource(action, first)
    right = _match_resource(action, second)
    for sample in REALISTIC_SAMPLES.get(action, []):
        if core.match(sample, left) and core.match(sample, right):
            return sample
    return core.pattern_intersection(left, right)


def _action_applies(new_action: str, existing: core.Rule) -> bool:
    return existing.action == new_action or core.match(
        new_action, existing.action
    )


def _resolution_key(resolution: dict) -> Tuple[str, str, str, str, str, str]:
    return (
        resolution["action"],
        platforms.to_pattern_path(resolution["resource"]),
        resolution["new_effect"],
        resolution["existing_effect"],
        platforms.to_pattern_path(resolution.get("existing_resource", "")),
        platforms.to_pattern_path(resolution["path"]),
    )


def _find_resolution(conflict: dict, resolutions: Sequence[dict]):
    for index, resolution in enumerate(resolutions):
        if resolution["decision"] == "skip-path":
            if platforms.to_pattern_path(resolution["path"]) == platforms.to_pattern_path(
                conflict["path"]
            ):
                return index, resolution
            continue
        if (
            resolution["action"] == conflict["action"]
            and platforms.to_pattern_path(resolution["resource"])
            == platforms.to_pattern_path(conflict["resource"])
            and resolution["new_effect"] == conflict["new_effect"]
            and resolution["existing_effect"] == conflict["existing_effect"]
            and platforms.to_pattern_path(resolution.get("existing_resource", ""))
            == platforms.to_pattern_path(conflict["existing_resource"])
        ):
            return index, resolution
    return None, None


def detect_conflicts(plan: dict, existing: core.LoadedConfig) -> dict:
    """Compare generated rules with existing ones and apply stored resolutions."""
    new_rules, warnings = build_rules(plan)
    resolutions = plan.get("resolutions", [])
    used_resolutions = set()
    conflicts: List[dict] = []
    infos: List[str] = []

    def rule_key(action: str, resource: str, effect: str) -> Tuple[str, str, str]:
        return (action, _match_resource(action, resource), effect)

    # Rules the plan itself will add are not pre-existing guards. Without this,
    # re-running `conflicts` after applying the plan reports artificial
    # conflicts between the generated rules themselves.
    generated_keys = {
        rule_key(rule["action"], rule["resource"], rule["effect"])
        for rule in new_rules
    }

    for new_index, rule in enumerate(new_rules):
        for old in existing.rules:
            if not _action_applies(rule["action"], old):
                continue
            same_effect = old.effect == rule["effect"]
            exact = _same_resource(rule["action"], old.resource, rule["resource"])
            if rule_key(old.action, old.resource, old.effect) in generated_keys:
                if same_effect and exact:
                    infos.append(
                        "duplicate (same effect): %s %s <-> %s"
                        % (
                            rule["action"],
                            platforms.to_pattern_path(old.resource),
                            platforms.to_pattern_path(rule["resource"]),
                        )
                    )
                continue
            left = _match_resource(rule["action"], old.resource)
            right = _match_resource(rule["action"], rule["resource"])
            sample = _overlap_sample(rule["action"], old.resource, rule["resource"])
            if sample is None and exact:
                candidate = _concrete(right)
                if core.match(candidate, left) and core.match(candidate, right):
                    sample = candidate
            if sample is None:
                continue

            if same_effect:
                kind = "duplicate" if exact else "overlap"
                infos.append(
                    "%s (same effect): %s %s <-> %s"
                    % (
                        kind,
                        rule["action"],
                        platforms.to_pattern_path(old.resource),
                        platforms.to_pattern_path(rule["resource"]),
                    )
                )
                continue

            conflict = {
                "id": len(conflicts) + 1,
                "new_index": new_index,
                "action": rule["action"],
                "existing_effect": old.effect,
                "new_effect": rule["effect"],
                "resource": rule["resource"],
                "existing_resource": old.resource,
                "path": rule["path"],
                "sample": sample,
                "kind": "exact" if exact else "overlap",
                "status": "unresolved",
            }
            resolution_index, resolution = _find_resolution(conflict, resolutions)
            if resolution is not None:
                conflict["status"] = resolution["decision"]
                used_resolutions.add(resolution_index)
            conflicts.append(conflict)

    stale = [
        resolution
        for index, resolution in enumerate(resolutions)
        if index not in used_resolutions
    ]
    return {
        "conflicts": conflicts,
        "infos": list(dict.fromkeys(infos)),
        "stale": stale,
        "new_rules": new_rules,
        "warnings": warnings,
    }


def _decide_sample(action: str, sample: str, rules: Sequence[core.Rule]) -> str:
    if action == "shell":
        return core.decide_shell(sample, rules, True)[0]
    return core.decide(action, sample, rules)


def apply_resolutions(
    plan: dict,
    conflict_result: dict,
    existing_rules: Optional[Sequence[core.Rule]] = None,
):
    """Drop or keep new rules according to resolved conflicts.

    Decisions are per generated rule, not per conflicting pair: one new rule
    can overlap several existing rules, and contradictory answers would make
    the result depend on dictionary order. If `existing_rules` is supplied,
    the kept rules are also checked against the effect every decision promised.
    """
    conflicts = conflict_result["conflicts"]
    applied = [conflict for conflict in conflicts if conflict["status"] != "unresolved"]
    skip_paths = {
        platforms.to_pattern_path(conflict["path"])
        for conflict in applied
        if conflict["status"] == "skip-path"
    }

    decisions: Dict[int, str] = {}
    for conflict in applied:
        index = conflict["new_index"]
        decision = conflict["status"]
        if decision == "skip-path":
            continue
        previous = decisions.get(index)
        if previous is not None and previous != decision:
            raise ConfigError(
                "conflicts for generated rule #%d disagree: one says %s, another "
                "says %s. Review every conflict for the same path and choose "
                "one answer, or use skip-path." % (index, previous, decision)
            )
        decisions[index] = decision

    kept: List[dict] = []
    for index, rule in enumerate(conflict_result["new_rules"]):
        if platforms.to_pattern_path(rule["path"]) in skip_paths:
            continue
        if decisions.get(index) == "keep-existing":
            continue
        kept.append(rule)

    stats = {
        "existing_kept": sum(1 for decision in decisions.values() if decision == "keep-existing"),
        "new_overriding": sum(1 for decision in decisions.values() if decision == "use-new"),
        "paths_skipped": sorted(skip_paths),
    }

    if existing_rules is not None:
        proposed = list(existing_rules) + [
            core.make_rule(rule["action"], rule["resource"], rule["effect"], "plan")
            for rule in kept
        ]
        failures = []
        for conflict in applied:
            if conflict["status"] == "skip-path":
                continue
            path = platforms.to_pattern_path(conflict["path"])
            if path in skip_paths:
                continue
            if conflict["status"] == "keep-existing":
                expected = _decide_sample(
                    conflict["action"], conflict["sample"], existing_rules
                )
            else:
                expected = conflict["new_effect"]
            actual = _decide_sample(conflict["action"], conflict["sample"], proposed)
            if actual != expected:
                failures.append((conflict, expected, actual))
        if failures:
            first, expected, actual = failures[0]
            raise ConfigError(
                "conflict #%d (%s %s) was resolved as %s, but the kept rules "
                "decide %s instead of %s for %r. Another generated rule or "
                "resolution overrides it; choose a consistent decision or "
                "skip the path."
                % (
                    first["id"],
                    first["action"],
                    first["resource"],
                    first["status"],
                    actual,
                    expected,
                    first["sample"],
                )
            )

    return kept, stats


def unresolved(conflict_result: dict) -> List[dict]:
    return [
        conflict
        for conflict in conflict_result["conflicts"]
        if conflict["status"] == "unresolved"
    ]


def group_conflicts(conflict_result: dict) -> List[dict]:
    """Group pair conflicts into one decision per path/action/new effect.

    `secrets/**` and `**/secrets/**` are two syntax forms of the same folder
    rule. They must be accepted or rejected together; otherwise the user is
    asked the same question twice. Pair-level data stays in `pairs`.
    """
    groups: List[dict] = []
    by_key: Dict[Tuple[str, str, str], dict] = {}
    for pair in conflict_result["conflicts"]:
        key = (
            platforms.to_pattern_path(pair["path"]),
            pair["action"],
            pair["new_effect"],
        )
        group = by_key.get(key)
        if group is None:
            group = {
                "id": 0,
                "new_index": pair["new_index"],
                "new_indices": [],
                "action": pair["action"],
                "new_effect": pair["new_effect"],
                "resource": pair["resource"],
                "new_resources": [],
                "path": pair["path"],
                "pairs": [],
                "pair_ids": [],
                "existing": [],
                "sample": pair["sample"],
                "kind": "overlap",
                "status": "unresolved",
            }
            by_key[key] = group
            groups.append(group)
        group["pairs"].append(pair)
        if pair["new_index"] not in group["new_indices"]:
            group["new_indices"].append(pair["new_index"])
        if pair["resource"] not in group["new_resources"]:
            group["new_resources"].append(pair["resource"])
        group["pair_ids"].append(pair["id"])

    for number, group in enumerate(groups, start=1):
        group["id"] = number
        existing: List[dict] = []
        existing_by_key: Dict[Tuple[str, str], dict] = {}
        for pair in group["pairs"]:
            key = (
                pair["existing_effect"],
                platforms.to_pattern_path(pair["existing_resource"]),
            )
            item = existing_by_key.get(key)
            if item is None:
                item = {
                    "effect": pair["existing_effect"],
                    "resource": pair["existing_resource"],
                    "kind": pair["kind"],
                    "sample": pair["sample"],
                    "pair_ids": [],
                }
                existing_by_key[key] = item
                existing.append(item)
            elif pair["kind"] == "exact":
                # Show the exact match and its cleaner sample when available.
                item["kind"] = "exact"
                item["sample"] = pair["sample"]
            item["pair_ids"].append(pair["id"])
        group["existing"] = existing
        statuses = {pair["status"] for pair in group["pairs"]}
        if len(statuses) == 1:
            group["status"] = statuses.pop()
        elif "unresolved" in statuses:
            group["status"] = "unresolved"
        else:
            # e.g. old mixed per-pair decisions: ask once and overwrite them.
            group["status"] = "mixed"
        kinds = {pair["kind"] for pair in group["pairs"]}
        if len(kinds) == 1:
            group["kind"] = kinds.pop()
        else:
            group["kind"] = "exact+overlap"

        # Prefer a sample that illustrates as many existing overlaps as
        # possible, then the shortest one.
        existing_patterns = [
            _match_resource(group["action"], item["resource"])
            for item in existing
        ]
        candidates = list(dict.fromkeys(pair["sample"] for pair in group["pairs"]))
        scored = []
        for candidate in candidates:
            value = _match_resource(group["action"], candidate)
            score = sum(
                1 for pattern in existing_patterns if core.match(value, pattern)
            )
            scored.append((score, len(candidate), candidate))
        if scored:
            group["sample"] = max(scored, key=lambda item: (item[0], -item[1]))[2]
    return groups


def unresolved_groups(conflict_result: dict) -> List[dict]:
    return [
        group
        for group in group_conflicts(conflict_result)
        if group["status"] in ("unresolved", "mixed")
    ]


def _pairs_in_group(conflict_result: dict, group: dict) -> List[dict]:
    indices = set(group["new_indices"])
    return [
        conflict
        for conflict in conflict_result["conflicts"]
        if conflict["new_index"] in indices
    ]


def _resolution_from_conflict(conflict: dict, decision: str) -> dict:
    return {
        "action": conflict["action"],
        "resource": conflict["resource"],
        "new_effect": conflict["new_effect"],
        "existing_effect": conflict["existing_effect"],
        "existing_resource": conflict["existing_resource"],
        "decision": decision,
        "path": conflict["path"],
    }


def print_conflicts(
    conflict_result: dict,
    verbose: bool = False,
    plan_path: Optional[str] = None,
) -> None:
    groups = group_conflicts(conflict_result)
    unresolved_count = len(unresolved_groups(conflict_result))
    print(
        "Conflicts: %d group(s), %d unresolved"
        % (len(groups), unresolved_count)
    )
    for group in groups:
        print(
            "[%d] %-18s existing overlaps -> new %-5s %-32s path=%s"
            % (
                group["id"],
                group["action"],
                group["new_effect"],
                group["resource"],
                group["path"],
            )
        )
        if len(group["new_resources"]) > 1:
            print("    new rules: %s" % ", ".join(group["new_resources"]))
        for item in group["existing"]:
            print(
                "    existing %-5s %-32s kind=%-7s sample=%s"
                % (
                    item["effect"],
                    item["resource"],
                    item["kind"],
                    item["sample"],
                )
            )
        print(
            "    sample=%s kind=%s status=%s"
            % (group["sample"], group["kind"], group["status"])
        )
    if conflict_result["infos"]:
        print("Informational overlaps (same effect, no decision needed):")
        for info in conflict_result["infos"]:
            print("  - %s" % info)
    if conflict_result["stale"]:
        print("Stale resolutions (kept unresolved; the config changed):")
        for resolution in conflict_result["stale"]:
            print(
                "  - %s %s -> %s (%s, path=%s)"
                % (
                    resolution["action"],
                    resolution["resource"],
                    resolution["decision"],
                    resolution["new_effect"],
                    resolution["path"],
                )
            )
    if verbose and plan_path:
        absolute = os.path.abspath(plan_path)
        print("Resolve commands:")
        for group in groups:
            if group["status"] in ("unresolved", "mixed"):
                print(
                    '  %s --plan "%s" --id %d --decision keep-existing'
                    % (_self_command("resolve"), absolute, group["id"])
                )
        if conflict_result["stale"]:
            print(
                '  %s --plan "%s" --clear-stale'
                % (_self_command("resolve"), absolute)
            )


def _self_command(subcommand: str) -> str:
    return '"%s" "%s" %s' % (sys.executable, SELF, subcommand)


def _conflict_commands(plan_path: str, groups: Sequence[dict]) -> List[str]:
    lines = []
    absolute = os.path.abspath(plan_path)
    for group in groups:
        lines.append(
            '%s --plan "%s" --id %d --decision keep-existing'
            % (_self_command("resolve"), absolute, group["id"])
        )
    return lines


def _comment_header(plan_path: str, plan: dict, target: str) -> str:
    return (
        "// Generated by permplan.py from %s\n"
        "// Engine: %s, scope: %s\n"
        "// Target config: %s (not modified by generate)\n"
        % (plan_path, plan["engine"].upper(), plan["scope"], target)
    )


def render(
    plan: dict,
    rules: Sequence[dict],
    plan_path: str,
    full: bool,
    json_mode: bool,
) -> str:
    """Render a V1 or V2 config (full) or rule snippet (not full)."""
    body = engines.get(plan["engine"]).render(rules, full)
    text = json.dumps(body, indent=2, ensure_ascii=False) + "\n"
    if json_mode:
        return text
    return _comment_header(plan_path, plan, plan["config"]) + text


# --------------------------------------------------------------------------
# Verification samples
# --------------------------------------------------------------------------


def _concrete(pattern: str) -> str:
    return pattern.replace("**", "key").replace("*", "key").replace("?", "x")


def pattern_samples(pattern: str) -> List[str]:
    """Concrete paths for a pattern, including the root and nested forms."""
    prefix = ""
    rest = pattern
    if rest.startswith("~/"):
        prefix, rest = "~/", rest[2:]
    elif rest.startswith("/"):
        prefix, rest = "/", rest[1:]

    nested = rest.startswith("**/")
    if nested:
        rest = rest[3:]

    samples = [prefix + _concrete(rest)]
    if nested or rest.startswith("*"):
        samples.append(prefix + "a/b/" + _concrete(rest))
    return samples


def samples_for_path(item: dict) -> List[dict]:
    """Build concrete verification checks for one plan path."""
    effects = path_effects(item)
    kind = item["kind"]
    value = item["input"]
    checks: List[dict] = []

    def add(action: str, sample: str, expected: str) -> None:
        checks.append(
            {
                "path": value,
                "action": action,
                "sample": sample,
                "expected": expected,
                "control": False,
            }
        )

    if kind == "pattern":
        path_samples = pattern_samples(value)
    elif kind == "directory":
        if item["location"] == "project":
            path_samples = [
                value.rstrip("/") + "/prod.env",
                "src/" + value.rstrip("/") + "/prod.env",
            ]
        elif item["location"] == "home":
            path_samples = ["~/reference/notes.md"] if value == "~/reference" else [
                value.rstrip("/") + "/notes.md"
            ]
        else:
            path_samples = ["/srv/data/file.txt"] if value == "/srv/data" else [
                value.rstrip("/") + "/file.txt"
            ]
    else:
        if item["location"] == "project":
            path_samples = [value, "src/" + value]
        else:
            path_samples = [value]

    for sample in path_samples:
        add("read", sample, effects["read"])
        add("edit", sample, effects["edit"])

    if effects["external"] != "none":
        add("external_directory", path_samples[0], effects["external"])

    if effects["shell"] != "none":
        add("shell", "cat " + path_samples[0], effects["shell"])

    return checks


def _winner(action: str, sample: str, config: core.LoadedConfig) -> str:
    rule = core.find_rule(action, sample, config.rules)
    if rule is None:
        return "fallback ask"
    index = next(
        (position for position, candidate in enumerate(config.rules) if candidate is rule),
        0,
    )
    return "#%d %s %s (%s)" % (
        index,
        rule.effect,
        "%s: %s" % (rule.shown_action, rule.resource),
        rule.source,
    )


def _print_plan_header(plan: dict, plan_path: str) -> None:
    print("Plan: %s (schema %d)" % (plan_path, plan["schema"]))
    print("Engine: %s | Scope: %s" % (plan["engine"].upper(), plan["scope"]))
    print("Project: %s" % platforms.display_path(plan["project"]))
    print("Config: %s" % platforms.display_path(plan["config"]))


def show_plan(plan: dict, plan_path: str) -> None:
    _print_plan_header(plan, plan_path)
    print()
    print("%-24s %-10s %-9s %-6s %-6s %-6s %-8s" % (
        "Path", "Kind", "Location", "read", "edit", "shell", "external"
    ))
    for item in plan["paths"]:
        effects = path_effects(item)
        print("%-24s %-10s %-9s %-6s %-6s %-6s %-8s" % (
            item["input"],
            item["kind"],
            item["location"],
            effects["read"],
            effects["edit"],
            effects["shell"] if effects["shell"] != "none" else "-",
            effects["external"] if effects["external"] != "none" else "-",
        ))


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError as exc:
        raise ConfigError(
            "input ended before the plan was complete; use flags for non-interactive mode"
        ) from exc


def _ask_choice(prompt: str, choices: Sequence[str], default: str = "") -> str:
    suffix = " [%s]" % "/".join(choices)
    if default:
        suffix += " (default %s)" % default
    while True:
        answer = _ask(prompt + suffix + ": ")
        if not answer and default:
            return default
        if answer in choices:
            return answer
        print("  choose one of: %s" % ", ".join(choices))


def _interactive_input(project: str, scope_default: str) -> Tuple[str, str, List[str]]:
    print("Step 1/3 - Engine")
    print("  1) V1: `permission` map, actions bash/task")
    print("  2) V2: `permissions` list, actions shell/subagent")
    engine = _ask_choice("Engine", ("1", "2"))
    engine = "v1" if engine == "1" else "v2"

    print()
    print("Step 2/3 - Scope")
    print("  1) local: a project file (opencode.jsonc in the project)")
    print("  2) global: the global opencode.jsonc")
    scope = _ask_choice("Scope", ("1", "2"), "1" if scope_default == "local" else "2")
    scope = "local" if scope == "1" else "global"

    print()
    print("Step 3/3 - Paths")
    print("  Format: PATH=EFFECT[:SHELL]")
    print("  Effects: block, ask, read-only, read-write")
    print("  Shell:   auto (default), none, ask, deny, allow")
    print("  Examples: secrets=block")
    print("            config/prod.json=block")
    print("            **/*.pem=block")
    print("            ~/reference=read-only:none")
    print("            /srv/data=read-only")
    print("  The shell default for project paths comes from the effect preset;")
    print("  external paths default to no shell rule.")

    entries: List[str] = []
    while True:
        raw = _ask("Path (empty to finish): ")
        if not raw:
            break
        if "=" in raw:
            try:
                parse_path_argument(raw)
            except ConfigError as exc:
                print("  %s" % exc)
                continue
            entries.append(raw)
            continue

        effect = _ask_choice("  Effect", EFFECTS)
        shell = _ask_choice("  Shell", SHELLS, "auto")
        entries.append("%s=%s:%s" % (raw, effect, shell))

    if not entries:
        raise ConfigError("no paths entered; the plan would be empty")
    return engine, scope, entries


def command_doctor(project: str) -> int:
    return permcheck.run_doctor(project)


def _write_plan_file(plan: dict, output: str) -> None:
    parent = os.path.dirname(os.path.abspath(output))
    if not os.path.isdir(parent):
        raise ConfigError("output directory does not exist: %s" % parent)
    handle, temporary = tempfile.mkstemp(
        prefix=".permplan-", suffix=".json", dir=parent, text=True
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(plan, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, output)
    except OSError as exc:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise ConfigError("cannot write %s: %s" % (output, exc)) from exc


def _write_plan(plan: dict, output: str, force: bool) -> None:
    if _same_path(output, plan["config"]):
        raise ConfigError(
            "refusing to write the plan over the target config; choose another "
            "--output path (target: %s)" % plan["config"]
        )
    if os.path.exists(output) and not force:
        raise ConfigError(
            "%s already exists; pass --force to replace it" % output
        )
    _write_plan_file(plan, output)


def _ask_conflict(group: dict) -> str:
    while True:
        print(
            "[%d] %s: new %s %s (path %s)"
            % (
                group["id"],
                group["action"],
                group["new_effect"],
                group["resource"],
                group["path"],
            )
        )
        for item in group["existing"]:
            print(
                "    existing %s %s (sample=%s)"
                % (item["effect"], item["resource"], item["sample"])
            )
        answer = _ask_choice(
            "Conflict #%d" % group["id"],
            ("1", "2", "3", "4"),
            "1",
        )
        if answer == "1":
            return "keep-existing"
        if answer == "2":
            return "use-new"
        if answer == "3":
            return "skip-path"
        print(
            "  sample=%s; kind=%s; new effect=%s"
            % (group["sample"], group["kind"], group["new_effect"])
        )


def _interactive_conflict_resolutions(
    existing: core.LoadedConfig,
    conflict_result: dict,
) -> List[dict]:
    groups = group_conflicts(conflict_result)
    if not groups:
        return []

    while True:
        answer = _ask_choice(
            "Keep all existing rules?",
            ("yes", "show", "review"),
            "review",
        )
        if answer == "yes":
            decisions = {group["id"]: "keep-existing" for group in groups}
            break
        if answer == "show":
            print_existing_rules(existing)
            continue
        decisions = {
            group["id"]: _ask_conflict(group) for group in groups
        }
        break

    resolutions = []
    for group in groups:
        for pair in _pairs_in_group(conflict_result, group):
            resolutions.append(
                _resolution_from_conflict(pair, decisions[group["id"]])
            )
    return resolutions


def command_conflicts(args: argparse.Namespace) -> int:
    plan = load_plan(args.plan)
    if args.config and args.resolved:
        raise ConfigError("choose either --config or --resolved, not both")
    existing = load_existing(plan, args.config, args.resolved, args.binary)
    print_existing_summary(existing)
    print()
    conflict_result = detect_conflicts(plan, existing)
    print_conflicts(conflict_result, args.verbose, args.plan)
    if conflict_result["stale"]:
        print(
            "warning: %d stale resolutions need review"
            % len(conflict_result["stale"]),
            file=sys.stderr,
        )
    pending = unresolved_groups(conflict_result)
    if pending or conflict_result["stale"]:
        return 3
    return 0


def command_resolve(args: argparse.Namespace) -> int:
    plan = load_plan(args.plan)
    if _same_path(args.plan, plan["config"]):
        raise ConfigError(
            "refusing to write resolutions over the target config; the plan "
            "file must be separate from %s" % plan["config"]
        )
    if getattr(args, "config", None) and getattr(args, "resolved", False):
        raise ConfigError("choose either --config or --resolved, not both")
    existing = load_existing(
        plan,
        getattr(args, "config", None),
        getattr(args, "resolved", False),
        getattr(args, "binary", "opencode"),
    )
    conflict_result = detect_conflicts(plan, existing)

    if getattr(args, "clear_stale", False):
        if args.id is not None or args.decision:
            raise ConfigError("--clear-stale cannot be combined with --id or --decision")
        stale = conflict_result["stale"]
        if not stale:
            print("No stale resolutions.")
            return 0
        stale_ids = {id(resolution) for resolution in stale}
        plan["resolutions"] = [
            resolution
            for resolution in plan["resolutions"]
            if id(resolution) not in stale_ids
        ]
        _write_plan_file(plan, args.plan)
        print("Removed %d stale resolution(s)." % len(stale))
        print("Plan written: %s" % os.path.abspath(args.plan))
        return 0

    if args.id is None or not args.decision:
        raise ConfigError("resolve needs --id and --decision, or --clear-stale")

    group = None
    for candidate in group_conflicts(conflict_result):
        if candidate["id"] == args.id:
            group = candidate
            break
    if group is None:
        raise ConfigError(
            "conflict group id %d not found; run `%s --plan %s`"
            % (args.id, _self_command("conflicts"), args.plan)
        )

    pairs = _pairs_in_group(conflict_result, group)
    resolutions = list(plan["resolutions"])
    conflict_path = platforms.to_pattern_path(group["path"])

    if args.decision == "skip-path":
        # skip-path is path-wide: it replaces every earlier decision for this
        # path, so a stale keep-existing cannot silently resurrect a rule.
        resolutions = [
            current
            for current in resolutions
            if platforms.to_pattern_path(current["path"]) != conflict_path
        ]
        resolutions.append(
            _resolution_from_conflict(pairs[0], "skip-path")
        )
        written = 1
    else:
        # A non-skip decision for this path replaces a previous path-wide skip.
        resolutions = [
            current
            for current in resolutions
            if not (
                current["decision"] == "skip-path"
                and platforms.to_pattern_path(current["path"]) == conflict_path
            )
        ]
        written = 0
        for pair in pairs:
            resolution = _resolution_from_conflict(pair, args.decision)
            key = _resolution_key(resolution)
            replaced = False
            for index, current in enumerate(resolutions):
                if _resolution_key(current) == key:
                    resolutions[index] = resolution
                    replaced = True
                    break
            if not replaced:
                resolutions.append(resolution)
            written += 1

    plan["resolutions"] = resolutions
    _write_plan_file(plan, args.plan)
    print(
        "Conflict group #%d: %s %s -> %s; decision=%s; %d pair(s) written"
        % (
            group["id"],
            group["action"],
            ", ".join(group["new_resources"]),
            group["new_effect"],
            args.decision,
            written,
        )
    )
    print("Plan written: %s" % os.path.abspath(args.plan))
    return 0


def command_init(args: argparse.Namespace) -> int:
    project = os.path.abspath(os.path.expanduser(platforms.expand_user(args.project)))
    summary = permcheck.doctor_summary(project)
    print("Preflight: %s" % summary)
    if "opencode: not found" in summary and "opencode2: not found" in summary:
        print("OpenCode not found; offline mode still works with --config FILE.")

    interactive = (
        sys.stdin.isatty()
        and args.engine is None
        and args.scope is None
        and not args.path
    )

    if interactive:
        engine, scope, entries = _interactive_input(project, "local")
    else:
        if not args.engine:
            raise ConfigError(
                "non-interactive init needs --engine v1 or --engine v2"
            )
        if not args.scope:
            raise ConfigError(
                "non-interactive init needs --scope local or --scope global"
            )
        if not args.path:
            raise ConfigError(
                "non-interactive init needs at least one --path PATH=EFFECT[:SHELL]"
            )
        engine, scope, entries = args.engine, args.scope, args.path

    config_choice = args.config
    if not config_choice and scope == "global":
        existing_globals = [
            (label, path)
            for label, path in platforms.global_config_candidates()
            if label not in platforms.MANAGED_LABELS and os.path.isfile(path)
        ]
        if len(existing_globals) > 1 and interactive:
            print()
            print("Multiple global config files found:")
            for index, (label, path) in enumerate(existing_globals, start=1):
                print(
                    "  %d) %-16s %s"
                    % (index, label, platforms.display_path(path))
                )
            answer = _ask_choice(
                "Global config",
                tuple(str(index) for index in range(1, len(existing_globals) + 1)),
                "1",
            )
            config_choice = existing_globals[int(answer) - 1][1]

    plan, warnings = build_plan(engine, scope, project, config_choice, entries)
    _read_target_document(plan)
    for warning in warnings:
        print("warning: %s" % warning, file=sys.stderr)

    existing = load_existing(
        plan,
        None,
        getattr(args, "resolved", False),
        getattr(args, "binary", "opencode"),
    )
    print()
    print_existing_summary(existing)
    conflict_result = detect_conflicts(plan, existing)
    if conflict_result["conflicts"]:
        if not interactive and args.on_conflict in ("keep-existing", "use-new"):
            plan["resolutions"].extend(
                _resolution_from_conflict(conflict, args.on_conflict)
                for conflict in conflict_result["conflicts"]
            )
            conflict_result = detect_conflicts(plan, existing)
            print(
                "Applied --on-conflict %s to %d conflict group(s)."
                % (args.on_conflict, len(group_conflicts(conflict_result)))
            )
        print()
        print_conflicts(conflict_result)
        if interactive:
            plan["resolutions"].extend(
                _interactive_conflict_resolutions(existing, conflict_result)
            )
    else:
        for info in conflict_result["infos"]:
            print("info: %s" % info)

    print()
    show_plan(plan, "(not written yet)")

    if interactive:
        answer = _ask("Write this plan? [y/N]: ")
        if answer.lower() not in ("y", "yes"):
            print("Plan not written.")
            return 2

    _write_plan(plan, args.output, args.force)
    print()
    print("Plan written: %s" % os.path.abspath(args.output))

    final = detect_conflicts(plan, existing)
    pending = unresolved_groups(final)
    if pending:
        print(
            "Conflicts: %d unresolved group(s). Review them with:"
            % len(pending)
        )
        print(
            '  %s --plan "%s"' % (_self_command("conflicts"), args.output)
        )
        print("Then resolve each id, for example:")
        for command in _conflict_commands(args.output, pending)[:3]:
            print("  " + command)
    else:
        print(
            'Next: %s --plan "%s"'
            % (_self_command("generate"), args.output)
        )
    return 0


def _read_target_document(plan: dict) -> Optional[dict]:
    """Read the target and reject a wrong/mixed engine before generating."""
    target = plan["config"]
    if os.path.exists(target) and not os.path.isfile(target):
        raise ConfigError("target config is not a file: %s" % target)
    if not os.path.isfile(target):
        return None
    document = core.read_jsonc(target)
    if not isinstance(document, dict):
        raise ConfigError(
            "%s: a target config must be a JSON object, not a list" % target
        )
    found = engines.shape(document, target)
    if found is not None and found != plan["engine"]:
        raise ConfigError(
            "%s is a %s config but the plan uses %s; choose the matching "
            "engine or convert the file"
            % (target, found.upper(), plan["engine"].upper())
        )
    return document


def _merge_full_document(
    engine: str,
    document: dict,
    rules: Sequence[dict],
    use_new_ids: Sequence[int],
) -> dict:
    """Merge generated rules into a full target document, preserving settings."""
    body = dict(document)
    if "$schema" not in body:
        body["$schema"] = "https://opencode.ai/config.json"

    if engine == "v2":
        existing = body.get("permissions")
        if existing is None:
            existing = []
        if not isinstance(existing, list):
            raise ConfigError("the target `permissions` value is not a list")
        merged = list(existing)
        existing_keys = {
            (
                item.get("action"),
                item.get("resource"),
                item.get("effect"),
            )
            for item in existing
            if isinstance(item, dict)
        }
        for rule in rules:
            key = (rule["action"], rule["resource"], rule["effect"])
            if key in existing_keys and id(rule) not in use_new_ids:
                # Already present in the same position; appending a duplicate
                # would only change precedence relative to later rules.
                continue
            merged.append(
                {
                    "action": rule["action"],
                    "resource": rule["resource"],
                    "effect": rule["effect"],
                }
            )
        body["permissions"] = merged
        return body

    permission = body.get("permission")
    if permission is None:
        permission = {}
    if not isinstance(permission, dict):
        raise ConfigError("the target `permission` value is not an object")
    permission = {
        tool: dict(value) if isinstance(value, dict) else value
        for tool, value in permission.items()
    }
    for rule in rules:
        tool = rule.get("display_action") or engines.v1.native_action(rule["action"])
        value = permission.get(tool)
        if isinstance(value, str):
            value = {"*": value}
            permission[tool] = value
        elif value is None:
            value = {}
            permission[tool] = value
        if not isinstance(value, dict):
            raise ConfigError(
                "the target `permission.%s` value is not a string or object" % tool
            )

        resource = rule["resource"]
        effect = rule["effect"]
        if resource in value:
            if value[resource] == effect and id(rule) not in use_new_ids:
                # Same rule already in the same position: appending it would
                # change precedence relative to the rules that follow it.
                continue
            # A use-new decision must win; JSON objects keep insertion order,
            # so delete and re-add the key at the end of this tool's map.
            del value[resource]
        value[resource] = effect
    body["permission"] = permission
    return body


def _render_full_existing(
    plan: dict,
    rules: Sequence[dict],
    plan_path: str,
    json_mode: bool,
    use_new_ids: Sequence[int],
    document: Optional[dict] = None,
) -> str:
    target = plan["config"]
    if document is None:
        document = _read_target_document(plan)
    if document is None:
        raise ConfigError("target config not found: %s" % target)
    body = _merge_full_document(plan["engine"], document, rules, use_new_ids)
    text = json.dumps(body, indent=2, ensure_ascii=False) + "\n"
    if json_mode:
        return text
    return _comment_header(plan_path, plan, target) + text


def command_generate(args: argparse.Namespace) -> int:
    plan = load_plan(args.plan)
    target = plan["config"]
    if args.full and args.snippet:
        raise ConfigError("choose either --full or --snippet, not both")
    if getattr(args, "config", None) and getattr(args, "resolved", False):
        raise ConfigError("choose either --config or --resolved, not both")
    if os.path.exists(target) and not os.path.isfile(target):
        raise ConfigError("target config is not a file: %s" % target)
    target_document = _read_target_document(plan)
    full = args.full or (not args.snippet and not os.path.exists(target))

    existing = load_existing(
        plan,
        getattr(args, "config", None),
        getattr(args, "resolved", False),
        getattr(args, "binary", "opencode"),
    )
    conflict_result = detect_conflicts(plan, existing)
    for warning in conflict_result["warnings"]:
        print("warning: %s" % warning, file=sys.stderr)
    for info in conflict_result["infos"]:
        print("info: %s" % info, file=sys.stderr)

    pending = unresolved_groups(conflict_result)
    if pending:
        commands = _conflict_commands(args.plan, pending)
        raise ConfigError(
            "unresolved conflicts (groups): %s\nReview them with:\n  "
            "%s --plan %s\n"
            "Resolve them first:\n  %s"
            % (
                ", ".join("#%d" % group["id"] for group in pending),
                _self_command("conflicts"),
                args.plan,
                "\n  ".join(commands),
            )
        )

    stale = conflict_result["stale"]
    if stale:
        raise ConfigError(
            "stale resolutions: %d. The existing config changed, so these "
            "decisions no longer match it. Review them with\n  %s "
            "--plan %s\nthen resolve them again, or drop the stale entries "
            "with\n  %s --plan %s --clear-stale"
            % (
                len(stale),
                _self_command("conflicts"),
                args.plan,
                _self_command("resolve"),
                args.plan,
            )
        )

    rules, stats = apply_resolutions(plan, conflict_result, existing.rules)
    print(
        "existing rules kept: %d; new rules overriding: %d; paths skipped: %d"
        % (
            stats["existing_kept"],
            stats["new_overriding"],
            len(stats["paths_skipped"]),
        ),
        file=sys.stderr,
    )

    use_new_ids = [
        id(conflict_result["new_rules"][conflict["new_index"]])
        for conflict in conflict_result["conflicts"]
        if conflict["status"] == "use-new"
    ]

    if not full:
        existing_keys = {
            (rule.action, _match_resource(rule.action, rule.resource), rule.effect)
            for rule in existing.rules
        }
        already = [
            rule
            for rule in rules
            if (
                rule["action"],
                _match_resource(rule["action"], rule["resource"]),
                rule["effect"],
            )
            in existing_keys
        ]
        if already:
            print(
                "warning: %d generated rule(s) already exist in the target; a "
                "snippet would duplicate them. Use --full to merge, or remove "
                "those paths from the plan." % len(already),
                file=sys.stderr,
            )

    if full and os.path.isfile(target):
        print(
            "warning: --full rewrites the target JSON; comments and formatting "
            "are not preserved. Use a snippet to keep the file's layout.",
            file=sys.stderr,
        )
        print(
            "warning: --full includes all existing settings from the target, "
            "including any secrets or tokens; review the output before sharing "
            "or committing.",
            file=sys.stderr,
        )
        text = _render_full_existing(
            plan, rules, args.plan, args.json, use_new_ids, target_document
        )
    else:
        if not full and plan["engine"] == "v1":
            exact = [
                conflict
                for conflict in conflict_result["conflicts"]
                if conflict["status"] == "use-new" and conflict["kind"] == "exact"
            ]
            if exact:
                print(
                    "warning: V1 stores rules in a JSON object. For the "
                    "use-new decisions, delete the existing key and re-add the "
                    "new value at the end of its tool map, or use --full.",
                    file=sys.stderr,
                )
        text = render(plan, rules, args.plan, full, args.json)

    if args.output:
        if _same_path(args.output, target):
            raise ConfigError(
                "refusing to write the target config directly; write the snippet "
                "to another file and apply it with a backup"
            )
        if _same_path(args.output, args.plan):
            raise ConfigError(
                "refusing to overwrite the plan file; choose another --output path"
            )
        _write_text_atomic(args.output, text)
        print("Generated %s config: %s" % ("full" if full else "snippet", args.output))
    else:
        sys.stdout.write(text)
    return 0


def command_show(args: argparse.Namespace) -> int:
    plan = load_plan(args.plan)
    if getattr(args, "config", None) and getattr(args, "resolved", False):
        raise ConfigError("choose either --config or --resolved, not both")
    existing = load_existing(
        plan,
        getattr(args, "config", None),
        getattr(args, "resolved", False),
        getattr(args, "binary", "opencode"),
    )
    conflict_result = detect_conflicts(plan, existing)
    print_existing_summary(existing)
    print()
    print_conflicts(conflict_result)
    print()
    show_plan(plan, args.plan)
    print()
    print(
        "Matrix shows requested effects; existing-rule conflicts are listed "
        "above. Run `conflicts` for the winning-rule details."
    )
    pending = unresolved_groups(conflict_result)
    if pending:
        print(
            "Unresolved conflicts: %d (%s)"
            % (
                len(pending),
                ", ".join("#%d" % group["id"] for group in pending),
            )
        )
    return 0


def command_verify(args: argparse.Namespace) -> int:
    plan = load_plan(args.plan)
    if args.config and args.resolved:
        raise ConfigError("choose either --config or --resolved, not both")
    config_path = args.config or plan["config"]

    if args.resolved:
        config = permcheck.load_engine(
            plan["project"],
            True,
            None,
            plan["engine"],
            getattr(args, "binary", "opencode"),
        )
        existing = core.LoadedConfig(
            rules=[rule for rule in config.rules if rule.source != "default"],
            description=config.description,
            sources=config.sources,
            defaults=False,
            engine=config.engine,
            documents=config.documents,
        )
    else:
        if not os.path.exists(config_path):
            raise ConfigError(
                "target config not found: %s\n"
                "Generate the rules, apply them with a backup, then verify again."
                % config_path
            )
        config = permcheck.load_file(config_path, True, None, plan["engine"])
        existing = permcheck.load_file(config_path, False, None, plan["engine"])

    conflict_result = detect_conflicts(plan, existing)
    for resolution in conflict_result["stale"]:
        print(
            "warning: stale resolution ignored: %s %s -> %s"
            % (
                resolution["action"],
                resolution["resource"],
                resolution["decision"],
            ),
            file=sys.stderr,
        )
    pending = unresolved(conflict_result)
    if pending:
        print(
            "warning: %d unresolved conflict group(s); verifying the plan effects"
            % len(unresolved_groups(conflict_result)),
            file=sys.stderr,
        )

    rules, stats = apply_resolutions(plan, conflict_result, existing.rules)
    module = engines.get(plan["engine"])
    proposed = [
        core.make_rule(action, resource, effect, "default")
        for action, resource, effect in module.BASE_POLICY
    ]
    proposed.extend(existing.rules)
    for rule in rules:
        proposed.append(
            core.make_rule(
                rule["action"], rule["resource"], rule["effect"], "plan"
            )
        )
    skipped_paths = set(stats["paths_skipped"])

    if args.verbose:
        permcheck.print_header(config)
        print()
        print_existing_summary(existing)
        print(
            "Proposed order: %d existing + %d new rules; skipped paths: %d"
            % (len(existing.rules), len(rules), len(skipped_paths))
        )
        print()
    else:
        print(
            "Existing rules: %d; conflicts: %d unresolved"
            % (len(existing.rules), len(pending))
        )

    checks: List[dict] = []
    for item in plan["paths"]:
        if platforms.to_pattern_path(item["input"]) in skipped_paths:
            continue
        checks.extend(samples_for_path(item))
    checks.append(
        {
            "path": "(control)",
            "action": "shell",
            "sample": "git status",
            "expected": None,
            "control": True,
        }
    )

    rows: List[Tuple[str, str, str, str, str, str]] = []
    failures = 0
    for check in checks:
        action = check["action"]
        sample = check["sample"]
        if action == "shell":
            actual, _ = core.decide_shell(sample, config.rules, True)
        else:
            actual = core.decide(action, sample, config.rules)

        if check["control"]:
            expected = "info"
            winner = _winner(action, sample, config)
            rows.append((check["path"], action, sample, expected, actual, winner))
            continue

        expected = core.decide(action, sample, proposed)
        winner = _winner(action, sample, config)
        if actual != expected:
            failures += 1
        rows.append((check["path"], action, sample, expected, actual, winner))

    widths = [4, 6, 7, 8, 6, 6]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))

    print(
        "%-*s  %-*s  %-*s  %-*s  %-*s  %s"
        % (
            widths[0], "Path",
            widths[1], "Action",
            widths[2], "Sample",
            widths[3], "Expected",
            widths[4], "Actual",
            "Winner",
        )
    )
    for row in rows:
        print(
            "%-*s  %-*s  %-*s  %-*s  %-*s  %s"
            % (
                widths[0], row[0],
                widths[1], row[1],
                widths[2], row[2],
                widths[3], row[3],
                widths[4], row[4],
                row[5],
            )
        )

    print()
    if failures:
        print("FAILED: %d of %d checks" % (failures, len(rows) - 1))
        if args.resolved:
            hint = "python3 scripts/permcheck.py --project %s --explain" % plan["project"]
        else:
            hint = (
                "python3 scripts/permcheck.py --config %s --explain"
                % config_path
            )
        print("Inspect the winning rule with: %s \"<sample>\"" % hint)
        return 1

    print("%d checks passed" % (len(rows) - 1))
    return 0


# --------------------------------------------------------------------------
# Optional config-level sandbox
# --------------------------------------------------------------------------


SANDBOX_PREFIX = "opencode-permissions-sandbox-"
PERMPLAN_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "permplan.py")


def _sandbox_path(root: str, relative: str, label: str) -> str:
    """Join a plan path under the sandbox, refusing any escape."""
    if os.path.isabs(relative):
        raise ConfigError("sandbox path is absolute: %s" % label)
    candidate = os.path.abspath(os.path.join(root, relative))
    if candidate != root and not candidate.startswith(root + os.sep):
        raise ConfigError("sandbox path escapes its root: %s" % label)
    return candidate


def _write_fixture(path: str) -> None:
    parent = os.path.dirname(path)
    try:
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("sandbox fixture\n")
    except OSError as exc:
        raise ConfigError("cannot create sandbox fixture %s: %s" % (path, exc)) from exc


def _pattern_extension(pattern: str) -> str:
    base = pattern.rsplit("/", 1)[-1]
    extension = os.path.splitext(base)[1]
    if extension and "*" not in extension and "?" not in extension:
        return extension
    return ""


def _home_relative(value: str) -> str:
    return _home_remainder(value)


def create_fixtures(plan: dict, root: str) -> List[str]:
    """Create harmless fake files for project and home paths in the sandbox."""
    notes: List[str] = []
    project = os.path.join(root, "project")
    home = os.path.join(root, "home")

    for item in plan["paths"]:
        location = item["location"]
        kind = item["kind"]
        value = item["input"]
        if location == "absolute":
            notes.append(
                "%s is an absolute external path; checked textually, not created"
                % value
            )
            continue

        base = project if location == "project" else home
        relative = value if location == "project" else _home_relative(value)

        if kind == "pattern":
            if not _pattern_extension(relative):
                notes.append(
                    "%s has no literal extension; no fixture created" % value
                )
                continue
            sample_pattern = value if location == "project" else "~/" + relative
            for sample in pattern_samples(sample_pattern):
                sample_relative = sample
                if location == "home":
                    sample_relative = _home_relative(sample)
                _write_fixture(_sandbox_path(base, sample_relative, value))
            continue

        if kind == "directory":
            if location == "project":
                _write_fixture(_sandbox_path(base, os.path.join(relative, "prod.env"), value))
                _write_fixture(_sandbox_path(base, os.path.join(relative, "notes.txt"), value))
            else:
                _write_fixture(_sandbox_path(base, os.path.join(relative, "notes.md"), value))
            continue

        _write_fixture(_sandbox_path(base, relative, value))

    return notes


def _sandbox_config_path(plan: dict, root: str) -> str:
    if plan["scope"] == "global":
        return os.path.join(root, "home", ".config", "opencode", "opencode.jsonc")
    return os.path.join(root, "project", "opencode.jsonc")


def _copy_target_config(plan: dict, root: str) -> str:
    source = plan["config"]
    if not os.path.isfile(source):
        raise ConfigError(
            "target config not found: %s\n"
            "Apply the rules or run `permplan.py generate` first." % source
        )
    destination = _sandbox_config_path(plan, root)
    parent = os.path.dirname(destination)
    try:
        if not os.path.isdir(parent):
            os.makedirs(parent)
        shutil.copyfile(source, destination)
    except OSError as exc:
        raise ConfigError(
            "cannot copy the target config into the sandbox: %s" % exc
        ) from exc
    return destination


def _run_command(command, cwd, env, timeout):
    command = list(command)
    if (
        platforms.is_windows()
        and command
        and str(command[0]).lower().endswith(".py")
    ):
        # A Python stub is useful in tests; Windows cannot execute it directly.
        command = [sys.executable] + command
    command = platforms.prepare_command(command)
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _find_binary(explicit: Optional[str]) -> Optional[str]:
    if explicit:
        expanded = os.path.expanduser(platforms.expand_user(explicit))
        found = shutil.which(expanded)
        if found:
            return found
        if os.path.isfile(expanded):
            return os.path.abspath(expanded)
        return None
    return shutil.which("opencode") or shutil.which("opencode2")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _configure_v2_service(binary: str, root: str, env: Dict[str, str], timeout: int):
    """Give the sandboxed V2 service its own port; return (ok, message)."""
    port = _free_port()
    process = _run_command(
        [binary, "service", "set", "port", str(port)],
        os.path.join(root, "project"),
        env,
        timeout,
    )
    if process is None:
        return False, "could not start sandbox service (command failed to run)"
    if process.returncode != 0:
        detail = (process.stderr or process.stdout).strip().splitlines()
        return False, "could not set sandbox service port: %s" % (
            detail[0] if detail else "exit %s" % process.returncode
        )
    return True, "port %d" % port


def _verify_in_sandbox(plan_path: str, config_path: str, root: str, env, timeout):
    return _run_command(
        [
            sys.executable,
            PERMPLAN_SCRIPT,
            "verify",
            "--plan",
            plan_path,
            "--config",
            config_path,
        ],
        root,
        env,
        timeout,
    )


def _parse_verify_result(process) -> Tuple[int, int]:
    text = (process.stdout or "") + "\n" + (process.stderr or "")
    passed = re.search(r"(\d+) checks passed", text)
    if passed:
        return int(passed.group(1)), 0
    failed = re.search(r"FAILED: (\d+) of (\d+) checks", text)
    if failed:
        return int(failed.group(2)) - int(failed.group(1)), int(failed.group(1))
    return 0, 0


def run_sandbox(
    plan_path: str,
    binary: Optional[str] = None,
    no_engine: bool = False,
    keep: bool = False,
    clean: bool = False,
    timeout: int = 120,
) -> dict:
    """Run the config-level sandbox and return a result dictionary."""
    if timeout <= 0:
        raise ConfigError("--timeout must be a positive number of seconds")
    plan_path = os.path.abspath(plan_path)
    plan = load_plan(plan_path)
    # Check the exact target first: a missing file should not leave a sandbox.
    if not os.path.isfile(plan["config"]):
        raise ConfigError(
            "target config not found: %s\n"
            "Apply the rules or run `permplan.py generate` first."
            % plan["config"]
        )

    sandbox_parent = platforms.temp_root()
    try:
        root = tempfile.mkdtemp(prefix=SANDBOX_PREFIX, dir=sandbox_parent)
    except OSError as exc:
        raise ConfigError("cannot create the sandbox in %s: %s" % (sandbox_parent, exc)) from exc
    result = {
        "root": root,
        "config_path": "",
        "config_passed": 0,
        "config_failed": 0,
        "config_ok": False,
        "engine_status": "",
        "engine_ok": False,
        "engine_partial": False,
        "notes": [],
        "kept": False,
        "exit_code": 1,
        "config_output": "",
        "engine_output": "",
        "remove_on_error": False,
    }
    env: Dict[str, str] = {}
    engine_binary = None if no_engine else _find_binary(binary)
    service_configured = False

    try:
        env = platforms.sandbox_env(root)
        os.makedirs(os.path.join(root, "home", ".config", "opencode"), exist_ok=True)
        os.makedirs(os.path.join(root, "project"), exist_ok=True)
        result["notes"] = create_fixtures(plan, root)

        # Point OpenCode at the copied target explicitly, so it cannot fall
        # back to a real global/managed config outside the sandbox.
        config_path = _copy_target_config(plan, root)
        result["config_path"] = config_path
        env["OPENCODE_CONFIG"] = config_path

        service_error = ""
        if not no_engine and engine_binary and plan["engine"] == "v2":
            service_ok, service_message = _configure_v2_service(
                engine_binary, root, env, timeout
            )
            service_configured = service_ok
            if not service_ok:
                service_error = service_message

        config_process = _verify_in_sandbox(plan_path, config_path, root, env, timeout)
        if config_process is None:
            result["engine_status"] = "config check failed to run"
            result["exit_code"] = 1
        else:
            result["config_output"] = (config_process.stdout or "") + (
                config_process.stderr or ""
            )
            passed, failed = _parse_verify_result(config_process)
            if config_process.returncode != 0 and passed == 0 and failed == 0:
                # The verifier failed before printing a check table.
                failed = 1
            result["config_passed"] = passed
            result["config_failed"] = failed
            if config_process.returncode != 0:
                result["exit_code"] = 1
                result["config_ok"] = False
            else:
                result["exit_code"] = 0
                result["config_ok"] = True

        if no_engine:
            result["engine_status"] = "skipped (--no-engine)"
        elif engine_binary is None:
            if binary:
                result["engine_status"] = "failed: binary not found: %s" % binary
            else:
                result["engine_status"] = (
                    "failed: no OpenCode binary found; pass --binary PATH or "
                    "use --no-engine for a config-only run"
                )
            result["exit_code"] = 1
        elif service_error:
            result["engine_status"] = "failed: %s" % service_error
            result["exit_code"] = 1
        elif result["exit_code"] != 0:
            result["engine_status"] = "skipped: config check failed"
        else:
            resolved_path = os.path.join(root, "resolved.json")
            process = _run_command(
                [engine_binary, "debug", "config"],
                os.path.join(root, "project"),
                env,
                timeout,
            )
            if process is None:
                result["engine_status"] = "failed: `debug config` did not run"
                result["exit_code"] = 1
            else:
                with open(resolved_path, "w", encoding="utf-8") as handle:
                    handle.write(process.stdout or "")
                if process.returncode != 0:
                    detail = (process.stderr or process.stdout).strip().splitlines()
                    result["engine_status"] = "failed: debug config: %s" % (
                        detail[0] if detail else "exit %s" % process.returncode
                    )
                    result["exit_code"] = 1
                else:
                    try:
                        json.loads(process.stdout or "")
                    except json.JSONDecodeError:
                        result["engine_status"] = "failed: debug config did not return JSON"
                        result["exit_code"] = 1
                    else:
                        engine_process = _verify_in_sandbox(
                            plan_path, resolved_path, root, env, timeout
                        )
                        if engine_process is None:
                            result["engine_status"] = "failed: resolved verify did not run"
                            result["exit_code"] = 1
                        else:
                            result["engine_output"] = (engine_process.stdout or "") + (
                                engine_process.stderr or ""
                            )
                            if engine_process.returncode == 0:
                                result["engine_status"] = "passed (resolved.json)"
                                result["engine_ok"] = True
                            else:
                                output = (engine_process.stdout or "") + (
                                    engine_process.stderr or ""
                                )
                                if plan["engine"] == "v1" and (
                                    "***" in output or "redacts" in output
                                ):
                                    # V1 debug config redacts values for
                                    # secret-looking keys; the exact target was
                                    # already checked at config level above.
                                    result["engine_status"] = (
                                        "partial: V1 debug config redacted "
                                        "sensitive-looking keys; config check "
                                        "verified the exact target"
                                    )
                                    result["engine_partial"] = True
                                else:
                                    result["engine_status"] = (
                                        "failed: resolved verify failed"
                                    )
                                    result["exit_code"] = 1

    except ConfigError:
        result["remove_on_error"] = True
        raise
    except OSError as exc:
        result["remove_on_error"] = True
        raise ConfigError("sandbox failed: %s" % exc) from exc
    finally:
        if service_configured and engine_binary is not None:
            _run_command(
                [engine_binary, "service", "stop"],
                os.path.join(root, "project"),
                env,
                timeout,
            )
        remove = (
            result.get("remove_on_error", False)
            or clean
            or (result["exit_code"] == 0 and not keep)
        )
        if remove:
            shutil.rmtree(root, ignore_errors=True)
            result["kept"] = False
        else:
            result["kept"] = True

    return result


def print_sandbox_report(result: dict) -> None:
    print("Config checked: %s" % platforms.display_path(result["config_path"]))
    print(
        "Config check: %d passed, %d failed"
        % (result["config_passed"], result["config_failed"])
    )
    print("Engine check: %s" % result["engine_status"])
    for note in result["notes"]:
        print("note: %s" % note)
    if not result["config_ok"] and result["config_output"].strip():
        print()
        print("Failing config checks:")
        print(result["config_output"].rstrip())
    if (
        result["engine_output"].strip()
        and not result["engine_ok"]
        and not result.get("engine_partial")
    ):
        print()
        print("Failing engine checks:")
        print(result["engine_output"].rstrip())
    if result["kept"]:
        print("Sandbox kept: %s" % result["root"])
    else:
        print("Sandbox removed.")
    if result["exit_code"] == 0 and result.get("engine_partial"):
        print("Result: PASS (config only; engine check partial)")
    else:
        print("Result: %s" % ("PASS" if result["exit_code"] == 0 else "FAIL"))


def command_sandbox(args: argparse.Namespace) -> int:
    result = run_sandbox(
        args.plan,
        binary=args.binary,
        no_engine=args.no_engine,
        keep=args.keep,
        clean=args.clean,
        timeout=args.timeout,
    )
    print_sandbox_report(result)
    return result["exit_code"]


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="permplan",
        description="Plan, generate and verify OpenCode V1/V2 permission rules.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  permplan.py doctor
  permplan.py init
  permplan.py init --engine v2 --scope local --project ~/project \\
      --path secrets=block --path '~/reference=read-only:none'
  permplan.py show --plan permissions.plan.json
  permplan.py generate --plan permissions.plan.json --snippet
  permplan.py verify --plan permissions.plan.json --resolved
  permplan.py conflicts --plan permissions.plan.json
  permplan.py resolve --plan permissions.plan.json --id 1 --decision keep-existing
  permplan.py sandbox --plan permissions.plan.json --no-engine
""",
    )
    parser.add_argument("--version", action="version", version="permplan " + VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="check Python, OpenCode and config paths")
    doctor.add_argument("--project", default=".", help="project directory to inspect (default: .)")
    doctor.set_defaults(func=lambda args: command_doctor(args.project))

    init = subparsers.add_parser("init", help="build a permissions plan")
    init.add_argument("--engine", choices=("v1", "v2"), help="permission engine")
    init.add_argument("--scope", choices=("local", "global"), help="config scope")
    init.add_argument("--project", default=".", help="project directory (default: .)")
    init.add_argument("--config", help="target config path (default depends on scope)")
    init.add_argument(
        "--path",
        action="append",
        default=None,
        metavar="PATH=EFFECT[:SHELL]",
        help="repeatable path rule, for example secrets=block",
    )
    init.add_argument("--output", default="permissions.plan.json", help="plan output file")
    init.add_argument("--force", action="store_true", help="replace an existing plan file")
    init.add_argument(
        "--resolved",
        action="store_true",
        help="also include global/merged rules via `opencode debug config`",
    )
    init.add_argument(
        "--binary",
        default="opencode",
        metavar="NAME",
        help="OpenCode binary for --resolved (default: opencode)",
    )
    init.add_argument(
        "--on-conflict",
        choices=("abort", "keep-existing", "use-new"),
        default="abort",
        help="non-interactive conflict policy (default: abort)",
    )
    init.set_defaults(func=command_init)

    generate = subparsers.add_parser("generate", help="render rules from a plan")
    generate.add_argument("--plan", required=True, help="plan JSON file")
    generate.add_argument(
        "--config",
        help="existing config to compare against (default: the plan target)",
    )
    generate.add_argument(
        "--resolved",
        action="store_true",
        help="compare against `opencode debug config` in the plan project",
    )
    generate.add_argument(
        "--binary",
        default="opencode",
        metavar="NAME",
        help="OpenCode binary for --resolved (default: opencode)",
    )
    shape = generate.add_mutually_exclusive_group()
    shape.add_argument("--full", action="store_true", help="force a complete config")
    shape.add_argument("--snippet", action="store_true", help="force only the rule block")
    generate.add_argument("--json", action="store_true", help="omit JSONC comments")
    generate.add_argument("-o", "--output", help="write to a file instead of stdout")
    generate.set_defaults(func=command_generate)

    verify = subparsers.add_parser("verify", help="check planned paths against a config")
    verify.add_argument("--plan", required=True, help="plan JSON file")
    verify.add_argument("--config", help="config file (default: the plan target)")
    verify.add_argument(
        "--resolved",
        action="store_true",
        help="use `opencode debug config` in the plan project",
    )
    verify.add_argument(
        "--binary",
        default="opencode",
        metavar="NAME",
        help="OpenCode binary for --resolved (default: opencode)",
    )
    verify.add_argument("--verbose", action="store_true", help="print loaded sources and defaults")
    verify.set_defaults(func=command_verify)

    show = subparsers.add_parser("show", help="print the path x action x effect matrix")
    show.add_argument("--plan", required=True, help="plan JSON file")
    show.add_argument("--config", help="existing config file")
    show.add_argument(
        "--resolved",
        action="store_true",
        help="use `opencode debug config`; fall back to the target file",
    )
    show.add_argument(
        "--binary",
        default="opencode",
        metavar="NAME",
        help="OpenCode binary for --resolved (default: opencode)",
    )
    show.set_defaults(func=command_show)

    conflicts = subparsers.add_parser(
        "conflicts", help="compare planned rules with the existing config"
    )
    conflicts.add_argument("--plan", required=True, help="plan JSON file")
    conflicts.add_argument("--config", help="existing config file")
    conflicts.add_argument(
        "--resolved",
        action="store_true",
        help="use `opencode debug config`; fall back to the target file",
    )
    conflicts.add_argument(
        "--binary",
        default="opencode",
        metavar="NAME",
        help="OpenCode binary for --resolved (default: opencode)",
    )
    conflicts.add_argument("--verbose", action="store_true", help="print resolve commands")
    conflicts.set_defaults(func=command_conflicts)

    resolve = subparsers.add_parser(
        "resolve", help="record the winning rule for one conflict"
    )
    resolve.add_argument("--plan", required=True, help="plan JSON file")
    resolve.add_argument("--id", type=int, help="conflict id from `conflicts`")
    resolve.add_argument(
        "--decision",
        choices=("keep-existing", "use-new", "skip-path"),
        help="which side wins",
    )
    resolve.add_argument(
        "--clear-stale",
        action="store_true",
        help="drop resolutions that no longer match the existing config",
    )
    resolve.add_argument("--config", help="existing config file")
    resolve.add_argument(
        "--resolved",
        action="store_true",
        help="use `opencode debug config`; fall back to the target file",
    )
    resolve.add_argument(
        "--binary",
        default="opencode",
        metavar="NAME",
        help="OpenCode binary for --resolved (default: opencode)",
    )
    resolve.set_defaults(func=command_resolve)

    sandbox = subparsers.add_parser(
        "sandbox", help="test the applied rules in a disposable temporary sandbox"
    )
    sandbox.add_argument("--plan", required=True, help="plan JSON file")
    cleanup = sandbox.add_mutually_exclusive_group()
    cleanup.add_argument("--keep", action="store_true", help="keep the sandbox for inspection")
    cleanup.add_argument(
        "--clean",
        action="store_true",
        help="remove the sandbox even when a check fails",
    )
    sandbox.add_argument("--binary", help="OpenCode binary for the engine check")
    sandbox.add_argument(
        "--no-engine",
        action="store_true",
        help="run only the config-level check; do not call OpenCode",
    )
    sandbox.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="seconds per subprocess (default: 120)",
    )
    sandbox.set_defaults(func=command_sandbox)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
