#!/usr/bin/env python3
"""permcheck.py - deterministic permission checks for OpenCode V1 and V2.

This is the public CLI. It owns configuration loading and the output modes;
matching and rule evaluation live in `core.py`, while V1/V2 parsing, audit
messages and rendering live in `engines/`.

OpenCode evaluates permission rules the same way in both engines:

  * a rule applies when both its action and resource patterns match,
  * the LAST matching rule wins,
  * when nothing matches, the effect is `ask`.

The formats differ:

  * V1: a `permission` object, one entry per tool, pattern -> effect.
  * V2: an ordered `permissions` list of {action, resource, effect}.

This script reproduces both formats offline. It never calls a model and never
writes configuration.

Examples (run from the skill directory):

  python3 scripts/permcheck.py --doctor
  python3 scripts/permcheck.py --audit
  python3 scripts/permcheck.py --explain "cat .env" "git push origin main"
  python3 scripts/permcheck.py --check examples/expectations.txt
  python3 scripts/permcheck.py --compare old.jsonc opencode.jsonc \\
      --resources examples/resources.txt
  python3 scripts/permcheck.py --selftest

Exit codes: 0 ok, 1 failed check, 2 usage/config error, 3 changed decisions.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 9):
    sys.stderr.write(
        "permcheck.py requires Python 3.9 or newer; this is %s.%s.\n"
        % (sys.version_info[0], sys.version_info[1])
    )
    sys.exit(2)

import argparse
import json
import os
import shutil
import subprocess
from typing import Dict, List, Optional, Sequence, Tuple

import core
import engines
import platforms

VERSION = "2.1.0"

# Kept as re-exports for callers that imported them from the CLI.
ConfigError = core.ConfigError
EFFECTS = core.EFFECTS


# --------------------------------------------------------------------------
# Configuration loading
# --------------------------------------------------------------------------


def classify_source(path: str) -> str:
    """Label a document as `global` or `project` by its location."""
    if not path:
        return "config"
    resolved = os.path.normcase(
        os.path.realpath(os.path.abspath(os.path.expanduser(path)))
    )
    for _, candidate in platforms.global_config_candidates():
        checked = os.path.normcase(
            os.path.realpath(os.path.abspath(os.path.expanduser(candidate)))
        )
        if checked == resolved:
            return "global"
    return "project"


def unpack_documents(data: object, fallback_path: str) -> List[Tuple[str, str, dict]]:
    """Accept a plain config object or `opencode debug config` output.

    Returns a list of (label, path, config) in load order. The V2 debug
    command prints a list of sources; directory entries carry no `info` and
    are skipped.
    """
    if isinstance(data, dict):
        return [("config", fallback_path, data)]

    if isinstance(data, list):
        documents: List[Tuple[str, str, dict]] = []
        source_list = True
        for entry in data:
            if not isinstance(entry, dict):
                source_list = False
                continue
            info = entry.get("info")
            if isinstance(info, dict):
                path = entry.get("path") or fallback_path
                documents.append(("", path, info))
            elif "info" in entry or not ("type" in entry or "path" in entry):
                source_list = False
        if documents:
            return documents
        if source_list:
            # A fresh install has no config documents. `debug config` still
            # lists scanned directories, so an empty rule set is valid.
            return []
        raise ConfigError(
            "%s does not contain any configuration documents" % fallback_path
        )

    raise ConfigError("%s does not contain a JSON object or list" % fallback_path)


def parse_agent_rules(spec: dict, source: str) -> List[core.Rule]:
    """Parse an agent's rules, accepting either shape for migration work."""
    found = engines.shape(spec, source)
    if found is None:
        return []
    return engines.get(found).parse(spec, source)


def config_documents(path: str) -> List[Tuple[str, str, dict]]:
    return unpack_documents(core.read_jsonc(path), path)


def build_config(
    documents: Sequence[Tuple[str, str, dict]],
    defaults: bool,
    agent: Optional[str],
    description: str,
    engine: str = "auto",
) -> core.LoadedConfig:
    if engine not in ("auto", "v1", "v2"):
        raise ConfigError("unknown engine %r; expected auto, v1 or v2" % engine)

    selected = engines.detect(documents) if engine == "auto" else engine
    if engine != "auto":
        engines.validate(selected, documents)

    module = engines.get(selected)
    rules: List[core.Rule] = []
    if defaults:
        rules = [
            core.make_rule(action, resource, effect, "default")
            for action, resource, effect in module.BASE_POLICY
        ]

    sources: List[Tuple[str, str]] = []
    for label, path, document in documents:
        label = label or classify_source(path)
        rules.extend(module.parse(document, label))
        sources.append((label, path))

    if agent:
        found = False
        for _, _, document in documents:
            for key in ("agents", "agent"):
                section = document.get(key)
                if not isinstance(section, dict):
                    continue
                spec = section.get(agent)
                if not isinstance(spec, dict):
                    continue
                found = True
                rules.extend(parse_agent_rules(spec, "agent:" + agent))
        if not found:
            print(
                "warning: agent %r is not defined in the loaded configuration; "
                "built-in agents are not resolved by this tool" % agent,
                file=sys.stderr,
            )

    return core.LoadedConfig(
        rules=rules,
        description=description,
        sources=sources,
        defaults=defaults,
        engine=selected,
        documents=list(documents),
    )


def load_file(
    path: str,
    defaults: bool,
    agent: Optional[str],
    engine: str = "auto",
) -> core.LoadedConfig:
    documents = config_documents(path)
    return build_config(documents, defaults, agent, "file: " + path, engine)


def load_engine(
    project: str,
    defaults: bool,
    agent: Optional[str],
    engine: str = "auto",
    binary: str = "opencode",
) -> core.LoadedConfig:
    project = os.path.abspath(os.path.expanduser(platforms.expand_user(project)))
    if not os.path.isdir(project):
        raise ConfigError("project directory not found: %s" % project)

    try:
        process = subprocess.run(
            platforms.prepare_command([binary, "debug", "config"]),
            cwd=project,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError as exc:
        raise ConfigError(
            "`%s` was not found in PATH. Install OpenCode or pass "
            "`--config FILE` (offline mode works without OpenCode)." % binary
        ) from exc
    except OSError as exc:
        raise ConfigError(
            "`%s` could not be executed: %s. Install OpenCode or pass "
            "`--config FILE` (offline mode works without OpenCode)."
            % (binary, exc)
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ConfigError("`%s debug config` timed out" % binary) from exc

    if process.returncode != 0:
        detail = (process.stderr or process.stdout).strip()
        first_lines = "\n".join(detail.splitlines()[:4])
        raise ConfigError(
            "`%s debug config` failed in %s:\n%s\n"
            "Check that the OpenCode service is running, or use `--config FILE`."
            % (binary, project, first_lines)
        )

    try:
        data = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            "`%s debug config` did not return JSON: %s" % (binary, exc.msg)
        ) from exc

    documents = unpack_documents(data, project)
    return build_config(
        documents,
        defaults,
        agent,
        "%s debug config in %s" % (binary, project),
        engine,
    )


# --------------------------------------------------------------------------
# Doctor
# --------------------------------------------------------------------------


def _binary_version(path: str) -> str:
    try:
        process = subprocess.run(
            platforms.prepare_command([path, "--version"]),
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "found, version check failed"
    text = (process.stdout or process.stderr).strip().splitlines()
    if process.returncode != 0:
        return "found, version check failed"
    return text[0] if text else "found, no version output"


def doctor_report(project: str) -> Dict[str, object]:
    """Collect preflight facts without reading any configuration contents."""
    project = os.path.abspath(os.path.expanduser(platforms.expand_user(project)))
    binaries: Dict[str, Dict[str, str]] = {}
    for name in ("opencode", "opencode2"):
        found = shutil.which(name)
        binaries[name] = {
            "path": found or "",
            "version": _binary_version(found) if found else "",
        }

    project_configs = [
        (name, path, os.path.isfile(path))
        for name, path in platforms.project_config_candidates(project)
    ]
    global_candidates = [
        (label, path, os.path.isfile(path), label in platforms.MANAGED_LABELS)
        for label, path in platforms.global_config_candidates()
    ]
    return {
        "python": "%d.%d.%d" % sys.version_info[:3],
        "system": platforms.system(),
        "binaries": binaries,
        "global_candidates": global_candidates,
        "active_global": platforms.find_global_config(),
        "project": project,
        "project_configs": project_configs,
        "project_found": platforms.find_project_config(project),
        "opencode_config": os.environ.get("OPENCODE_CONFIG", ""),
        "opencode_config_dir": os.environ.get("OPENCODE_CONFIG_DIR", ""),
    }


def doctor_summary(project: str) -> str:
    report = doctor_report(project)
    parts = ["%s" % report["system"], "Python %s" % report["python"]]
    for name in ("opencode", "opencode2"):
        item = report["binaries"][name]  # type: ignore[index]
        if item["path"]:
            parts.append("%s: %s (%s)" % (name, item["path"], item["version"]))
        else:
            parts.append("%s: not found" % name)
    parts.append("global: %s" % platforms.display_path(report["active_global"]))
    return "; ".join(parts)


def run_doctor(project: str) -> int:
    report = doctor_report(project)
    print("OS: %s" % report["system"])
    print("Python: %s (ok, 3.9+ required)" % report["python"])
    for name in ("opencode", "opencode2"):
        item = report["binaries"][name]  # type: ignore[index]
        if item["path"]:
            print("%s: %s -> %s" % (name, item["path"], item["version"]))
        else:
            print("%s: not found on PATH" % name)

    print("Global config candidates (priority order):")
    for label, path, exists, managed in report["global_candidates"]:  # type: ignore[index]
        suffix = " (read-only, reporting only)" if managed else ""
        print(
            "  %-20s %s (%s)%s"
            % (label, platforms.display_path(path), "exists" if exists else "missing", suffix)
        )
    print(
        "Active global config: %s"
        % platforms.display_path(report["active_global"])
    )
    if report["opencode_config"]:
        print("OPENCODE_CONFIG: %s" % platforms.display_path(report["opencode_config"]))
    if report["opencode_config_dir"]:
        print(
            "OPENCODE_CONFIG_DIR: %s"
            % platforms.display_path(report["opencode_config_dir"])
        )

    print("Project config candidates in %s:" % platforms.display_path(report["project"]))
    for name, path, exists in report["project_configs"]:  # type: ignore[index]
        print(
            "  %-32s %s"
            % (name, "exists" if exists else "missing")
        )
    if report["project_found"]:
        print(
            "Project config found up the tree: %s"
            % platforms.display_path(report["project_found"])
        )
    else:
        print("Project config found up the tree: none")

    if not report["binaries"]["opencode"]["path"] and not report["binaries"]["opencode2"]["path"]:
        print()
        print(
            "OpenCode was not found. Offline mode still works: pass "
            "`--config FILE` to inspect a copied or backed-up configuration."
        )
    return 0


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------


def engine_label(engine: str) -> str:
    return engines.get(engine).LABEL


def print_header(config: core.LoadedConfig) -> None:
    document_word = "document" if len(config.sources) == 1 else "documents"
    print("Engine: %s" % engine_label(config.engine))
    print("Source: %s (%d %s)" % (config.description, len(config.sources), document_word))
    for label, path in config.sources:
        print("  %-8s %s" % (label, path))
    print("Defaults: %s" % ("on (built-in base policy)" if config.defaults else "off"))
    print("Rules: %d" % len(config.rules))


def format_rule(index: int, rule: core.Rule) -> str:
    return "[%3d] %-6s %-42s %s" % (
        index,
        rule.effect,
        "%s: %s" % (rule.shown_action, rule.resource),
        rule.source,
    )


def print_matches(action: str, resource: str, rules: Sequence[core.Rule], indent: str = "  ") -> str:
    value = core.expand_home(resource) if action in core.HOME_ACTIONS else resource
    hits = [
        (index, rule)
        for index, rule in enumerate(rules)
        if core.match(action, rule.action) and core.match(value, rule.pattern)
    ]

    if not hits:
        print(indent + "(no matching rule)")
        print(indent + "=> ASK (fallback)")
        return "ask"

    for index, rule in hits:
        winner = "  <- wins" if (index, rule) == hits[-1] else ""
        print(indent + format_rule(index, rule) + winner)

    winner_index, winner_rule = hits[-1]
    print(
        indent
        + "=> %s (rule #%d, %s)"
        % (winner_rule.effect.upper(), winner_index, winner_rule.source)
    )
    return winner_rule.effect


def explain(action: str, resource: str, config: core.LoadedConfig, split: bool) -> None:
    label = engines.get(config.engine).native_action(action)
    print()
    print("=== %s: %s" % (label, resource))

    segments = core.split_shell(resource) if split and action == "shell" else [resource]

    if len(segments) == 1:
        print_matches(action, resource, config.rules)
        return

    print("  segments: %d" % len(segments))
    effects = []
    for number, segment in enumerate(segments, start=1):
        print("  -- %d/%d: %s" % (number, len(segments), segment))
        effects.append(print_matches(action, segment, config.rules, indent="    "))

    if "deny" in effects:
        print("  => DENY (at least one segment is denied)")
    elif "ask" in effects:
        print("  => ASK (at least one segment asks)")
    else:
        print("  => ALLOW (all segments allowed)")


# --------------------------------------------------------------------------
# Modes
# --------------------------------------------------------------------------


def run_list(config: core.LoadedConfig, action: str) -> int:
    print_header(config)
    print()
    applicable = [
        (index, rule)
        for index, rule in enumerate(config.rules)
        if core.match(action, rule.action)
    ]
    print(
        "Action: %s (%d applicable rules)"
        % (engines.get(config.engine).native_action(action), len(applicable))
    )
    for index, rule in applicable:
        print("  " + format_rule(index, rule))
    if not applicable:
        print("  (no rules apply to this action)")
    elif applicable[-1][1].resource == "*" and applicable[-1][1].effect == "deny":
        print(
            "\nNote: the last rule for this action is `* -> deny`, "
            "so the tool is hidden from the model."
        )
    return 0


def run_dump(config: core.LoadedConfig) -> int:
    print_header(config)
    print()
    for index, rule in enumerate(config.rules):
        print(
            "[%3d] %-6s %-12s %-42s %s"
            % (index, rule.effect, rule.shown_action, rule.resource, rule.source)
        )
    return 0


def _audit_actions(config: core.LoadedConfig) -> List[str]:
    module = engines.get(config.engine)
    known = list(module.KNOWN_ACTIONS)
    present_native = {
        module.native_action(rule.action)
        for rule in config.rules
        if rule.action != "*"
    }
    actions = list(known)
    for action in sorted(present_native - set(known)):
        actions.append(action)
    return actions


def run_audit(config: core.LoadedConfig) -> int:
    print_header(config)
    print()

    module = engines.get(config.engine)
    actions = _audit_actions(config)
    print("Action               Rules  Allow  Ask  Deny  Last applicable rule")
    for native in actions:
        canonical = core.canonical_action(native)
        applicable = [
            (index, rule)
            for index, rule in enumerate(config.rules)
            if core.match(canonical, rule.action)
        ]
        if not applicable and canonical not in ("shell", "read", "edit"):
            continue
        counts = {"allow": 0, "ask": 0, "deny": 0}
        for _, rule in applicable:
            counts[rule.effect] += 1
        last = applicable[-1][1] if applicable else None
        last_text = "-" if last is None else "%s (%s)" % (last.resource, last.effect)
        print(
            "%-20s %5d %6d %4d %5d  %s"
            % (native, len(applicable), counts["allow"], counts["ask"], counts["deny"], last_text)
        )
    print()
    if config.defaults:
        print("Counts include the built-in base policy.")

    disabled: List[str] = []
    for native in actions:
        canonical = core.canonical_action(native)
        applicable = [
            rule for rule in config.rules if core.match(canonical, rule.action)
        ]
        if applicable and applicable[-1].resource == "*" and applicable[-1].effect == "deny":
            disabled.append(native)
    if disabled:
        print()
        print("Disabled tools (last rule is `* -> deny`): " + ", ".join(disabled))

    warnings: List[str] = []
    seen: Dict[Tuple[str, str], int] = {}

    for label, path, document in config.documents or []:
        source = label or path
        if "permission" in document and "permissions" in document:
            warnings.append(
                "%s contains both `permission` and `permissions`; remove the "
                "unused key so the format is unambiguous" % source
            )
        warnings.extend(module.audit(document, source, config.engine))

    for index, rule in enumerate(config.rules):
        if rule.source == "default":
            continue
        if rule.resource.startswith("./") and rule.action in (
            "read",
            "edit",
            "external_directory",
        ):
            warnings.append(
                "[%d] path pattern starts with `./`; read/edit resources never contain that prefix"
                % index
            )
        key = (rule.action, rule.resource)
        if key in seen:
            warnings.append(
                "[%d] duplicate of rule #%d (%s); the later rule wins"
                % (index, seen[key], rule.resource)
            )
        seen[key] = index
        if rule.action == "*" and rule.resource == "*" and rule.effect == "deny":
            warnings.append("[%d] `* -> deny` disables every tool" % index)

    for native in actions:
        canonical = core.canonical_action(native)
        deny_seen = False
        for index, rule in enumerate(config.rules):
            if not core.match(canonical, rule.action):
                continue
            if rule.effect == "deny":
                deny_seen = True
            elif rule.effect == "allow" and rule.resource == "*" and deny_seen:
                warnings.append(
                    "[%d] broad `* -> allow` for %s comes after a deny and overrides it"
                    % (index, native)
                )

    path_like_glob = [
        rule
        for rule in config.rules
        if rule.action in ("glob", "grep")
        and rule.effect in ("deny", "ask")
        and "/" in rule.resource
    ]
    if path_like_glob:
        warnings.append(
            "`glob` matches the requested glob pattern and `grep` the requested "
            "regular expression, not file paths; path-style rules there are weak "
            "guards. Use `shell` and `read` rules for folders."
        )

    print()
    if warnings:
        print("Warnings:")
        for warning in dict.fromkeys(warnings):
            print("  - " + warning)
    else:
        print("Warnings: none")
    return 0


def read_lines(path: str) -> List[str]:
    if path == "-":
        return [line.rstrip("\n") for line in sys.stdin]
    try:
        with open(path, encoding="utf-8-sig") as handle:
            return [line.rstrip("\n") for line in handle]
    except OSError as exc:
        raise ConfigError("cannot read %s: %s" % (path, exc)) from exc


def parse_expectations(path: str) -> List[Tuple[int, str, str, str]]:
    """Parse `effect | action | resource` lines; resource may contain `|`."""
    expectations: List[Tuple[int, str, str, str]] = []
    for number, line in enumerate(read_lines(path), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = [part.strip() for part in stripped.split("|", 2)]
        if len(parts) != 3:
            raise ConfigError(
                "%s:%d: expected `effect | action | resource`" % (path, number)
            )
        effect, action, resource = parts
        if effect not in EFFECTS:
            raise ConfigError(
                "%s:%d: unknown effect %r; expected one of %s"
                % (path, number, effect, ", ".join(EFFECTS))
            )
        if not action or not resource:
            raise ConfigError("%s:%d: action and resource cannot be empty" % (path, number))
        expectations.append((number, effect, action, resource))
    return expectations


def run_check(config: core.LoadedConfig, path: str, split: bool) -> int:
    expectations = parse_expectations(path)
    if not expectations:
        raise ConfigError("no expectations found in %s" % path)

    print_header(config)
    print()
    failures = 0
    total = 0
    module = engines.get(config.engine)

    for _, expected, action_name, resource in expectations:
        total += 1
        action = core.canonical_action(action_name)
        label = module.native_action(action)
        if action == "shell":
            actual, _ = core.decide_shell(resource, config.rules, split)
        else:
            actual = core.decide(action, resource, config.rules)

        if actual == expected:
            print("ok    %-5s %-8s %s" % (expected, label, resource))
        else:
            failures += 1
            print(
                "FAIL  %-5s %-8s %s   (expected %s, got %s)"
                % (expected, label, resource, expected, actual)
            )

    print()
    if failures:
        print("%d of %d expectations failed" % (failures, total))
        return 1
    print("%d expectations passed" % total)
    return 0


def run_compare(
    old: core.LoadedConfig,
    new: core.LoadedConfig,
    path: str,
    action: str,
    split: bool,
    show_all: bool,
) -> int:
    resources = [
        line.strip()
        for line in read_lines(path)
        if line.strip() and not line.strip().startswith("#")
    ]
    if not resources:
        raise ConfigError("no resources found in %s" % path)

    old_module = engines.get(old.engine)
    new_module = engines.get(new.engine)
    label = old_module.native_action(action) if old.engine == new.engine else action
    print("OLD: %s (%s, %d rules)" % (old.description, old.engine.upper(), len(old.rules)))
    print("NEW: %s (%s, %d rules)" % (new.description, new.engine.upper(), len(new.rules)))
    print(
        "Action: %s (canonical; OLD uses `%s`, NEW uses `%s`)"
        % (label, old_module.native_action(action), new_module.native_action(action))
    )
    print("Resources: %d" % len(resources))
    print()

    changed = 0
    for resource in resources:
        if action == "shell":
            before, _ = core.decide_shell(resource, old.rules, split)
            after, _ = core.decide_shell(resource, new.rules, split)
        else:
            before = core.decide(action, resource, old.rules)
            after = core.decide(action, resource, new.rules)

        if before == after:
            if show_all:
                print("same     %-6s -> %-6s %s" % (before, after, resource))
            continue

        changed += 1
        print("changed  %-6s -> %-6s %s" % (before, after, resource))

    print()
    if changed:
        print("%d of %d decisions changed" % (changed, len(resources)))
        return 3
    print("no decision changed (%d resources)" % len(resources))
    return 0


def run_selftest() -> int:
    cases: List[Tuple[str, bool]] = []

    def check(name: str, condition: bool) -> None:
        cases.append((name, condition))

    # Wildcard matching and documented path behaviour.
    check("literal match", core.match("git status", "git status"))
    check("literal mismatch", not core.match("git status", "git stat"))
    check("star crosses slashes", core.match("docs/guide/intro.md", "docs/*"))
    check("star matches empty", core.match("", "*"))
    check("question mark", core.match("a.md", "?.md") and not core.match("ab.md", "?.md"))
    check("case sensitive", not core.match("Git status", "git status"))
    check("backslash normalised", core.match("src\\main.py", "src/*"))
    check("optional arguments", core.match("git status", "git status *"))
    check("optional arguments with args", core.match("git status --short", "git status *"))
    check("optional arguments do not overreach", not core.match("git statuses", "git status *"))
    check(
        "double star still needs a segment",
        core.match("a/b/c", "**/c") and not core.match("c", "**/c"),
    )
    check(
        "one pattern covers root and nested",
        core.match("secrets/key.txt", "*secrets/*")
        and core.match("src/secrets/key.txt", "*secrets/*"),
    )
    check("root directory pattern", core.match("secrets/key.txt", "secrets/**"))
    check(
        "root directory pattern does not match nested",
        not core.match("src/secrets/key.txt", "secrets/**"),
    )
    check(
        "nested directory pattern does not match root",
        not core.match("secrets/key.txt", "**/secrets/**"),
    )
    check("extension pattern crosses depth", core.match("a/b/key.pem", "*.pem"))
    check("double star extension misses root", not core.match("key.pem", "**/*.pem"))
    check(
        "literal glob class",
        core.match("[abc].md", "[abc].md") and not core.match("a.md", "[abc].md"),
    )
    check(
        "literal braces",
        core.match("{a,b}.txt", "{a,b}.txt") and not core.match("a.txt", "{a,b}.txt"),
    )
    check("dot slash never matches a path", not core.match("secrets/key.txt", "./secrets/**"))
    check("trailing slash is literal", not core.match("secrets/key.txt", "secrets/"))
    check("suffix trap", not core.match(".env.production.example", "*.env.example"))
    check("general suffix exception", core.match(".env.production.example", "*.env*.example"))

    # Conflict detection needs exact pattern overlap, not a fixed sample list.
    witness = core.pattern_intersection("*.pem", "secrets/**")
    check(
        "pattern intersection finds a hidden overlap",
        witness is not None
        and core.match(witness, "*.pem")
        and core.match(witness, "secrets/**"),
    )
    check(
        "pattern intersection handles nested stars",
        core.pattern_intersection("secrets/**", "**/secrets/**") is not None,
    )
    check(
        "pattern intersection rejects disjoint roots",
        core.pattern_intersection("docs/**", "secrets/**") is None,
    )
    check(
        "pattern intersection respects optional arguments",
        core.pattern_intersection("git status *", "git status") == "git status",
    )

    # Evaluation order.
    broad_then_guard = [
        core.make_rule("*", "*", "allow", "test"),
        core.make_rule("shell", "*.env", "deny", "test"),
    ]
    check("last match wins", core.decide("shell", "cat .env", broad_then_guard) == "deny")
    check("other resources still allowed", core.decide("shell", "ls", broad_then_guard) == "allow")
    guard_then_allow = [
        core.make_rule("shell", "*.env", "deny", "test"),
        core.make_rule("shell", "*.env.example", "allow", "test"),
    ]
    check(
        "allow after deny wins",
        core.decide("shell", "cat .env.example", guard_then_allow) == "allow",
    )
    check("fallback is ask", core.decide("shell", "ls", []) == "ask")

    # V2 defaults.
    defaults_v2 = [
        core.make_rule(a, r, e, "default") for a, r, e in engines.v2.BASE_POLICY
    ]
    check("V2 default allows normal reads", core.decide("read", "src/app.ts", defaults_v2) == "allow")
    check("V2 default asks for .env", core.decide("read", ".env", defaults_v2) == "ask")
    check("V2 default asks for .env.local", core.decide("read", ".env.local", defaults_v2) == "ask")
    check("V2 default allows .env.example", core.decide("read", ".env.example", defaults_v2) == "allow")

    # V1 defaults are the primary-agent baseline.
    defaults_v1 = [
        core.make_rule(a, r, e, "default") for a, r, e in engines.v1.BASE_POLICY
    ]
    check("V1 default allows .env", core.decide("read", ".env", defaults_v1) == "allow")
    check("V1 default allows shell", core.decide("shell", "rm -rf build", defaults_v1) == "allow")

    # V1 parsing: string value, map value, order, aliases.
    v1_string = engines.v1.parse({"permission": {"bash": "deny"}}, "test")
    check(
        "V1 string value means star",
        len(v1_string) == 1
        and v1_string[0].action == "shell"
        and v1_string[0].resource == "*"
        and v1_string[0].shown_action == "bash",
    )
    v1_map = engines.v1.parse(
        {"permission": {"read": {"secrets/**": "deny", "secrets/*.example": "allow"}}},
        "test",
    )
    check(
        "V1 map order preserved",
        [rule.resource for rule in v1_map] == ["secrets/**", "secrets/*.example"],
    )
    v1_aliases = engines.v1.parse(
        {"permission": {"bash": "allow", "task": "deny", "write": "deny", "patch": "allow"}},
        "test",
    )
    check(
        "V1 aliases canonicalised",
        [rule.action for rule in v1_aliases] == ["shell", "subagent", "edit", "edit"],
    )
    check(
        "V1 aliases keep their written name",
        [rule.shown_action for rule in v1_aliases] == ["bash", "task", "write", "patch"],
    )

    # V2 parsing.
    v2_rules = engines.v2.parse(
        {
            "permissions": [
                {"action": "shell", "resource": "*", "effect": "ask"},
                {"action": "bash", "resource": "git push *", "effect": "deny"},
            ]
        },
        "test",
    )
    check("V2 list parses", len(v2_rules) == 2)
    check("V2 aliases canonicalised", v2_rules[1].action == "shell")

    # V1 and V2 with equivalent rules must decide the same way.
    v1_equiv = engines.v1.parse(
        {
            "permission": {
                "bash": {
                    "*": "ask",
                    "git status *": "allow",
                    "*envs/*": "deny",
                    "*envs/*.example*": "allow",
                }
            }
        },
        "test",
    )
    v2_equiv = engines.v2.parse(
        {
            "permissions": [
                {"action": "shell", "resource": "*", "effect": "ask"},
                {"action": "shell", "resource": "git status *", "effect": "allow"},
                {"action": "shell", "resource": "*envs/*", "effect": "deny"},
                {"action": "shell", "resource": "*envs/*.example*", "effect": "allow"},
            ]
        },
        "test",
    )
    check(
        "V1 and V2 equivalent rules agree",
        all(
            core.decide("shell", command, v1_equiv)
            == core.decide("shell", command, v2_equiv)
            for command in (
                "git status",
                "rm -rf build",
                "cat envs/.env.production",
                "cat envs/.env.example",
            )
        ),
    )

    # Mixed shapes are a hard error.
    try:
        engines.shape(
            {
                "permission": {"bash": "allow"},
                "permissions": [{"action": "shell", "resource": "*", "effect": "ask"}],
            },
            "mixed",
        )
        check("mixed shapes rejected", False)
    except ConfigError:
        check("mixed shapes rejected", True)

    # Engine detection and forced engine.
    check(
        "engine detected as V1",
        engines.detect([("", "x", {"permission": {"bash": "allow"}})]) == "v1",
    )
    check(
        "engine detected as V2",
        engines.detect([("", "x", {"permissions": []})]) == "v2",
    )
    try:
        engines.validate("v2", [("", "x", {"permission": {"bash": "allow"}})])
        check("forced engine mismatch rejected", False)
    except ConfigError:
        check("forced engine mismatch rejected", True)

    # Home expansion for read/edit/external_directory.
    home_rules = engines.v2.parse(
        {
            "permissions": [
                {"action": "external_directory", "resource": "~/reference/*", "effect": "ask"},
                {"action": "read", "resource": "~/reference/*", "effect": "allow"},
            ]
        },
        "test",
    )
    check(
        "home expansion in read rules",
        core.decide("read", "~/reference/notes.md", home_rules) == "allow",
    )
    check(
        "home expansion in external rules",
        core.decide("external_directory", "~/reference/notes.md", home_rules) == "ask",
    )
    check(
        "home is not expanded in shell rules",
        core.decide("shell", "cat ~/reference/notes.md", home_rules) == "ask",
    )

    # Shell segmentation.
    check(
        "split &&",
        core.split_shell("git status && git push") == ["git status", "git push"],
    )
    check(
        "quotes protect separators",
        core.split_shell('git commit -m "a && b"') == ['git commit -m "a && b"'],
    )
    check("pipe splits", core.split_shell("git log | head") == ["git log", "head"])
    check(
        "redirection stays",
        core.split_shell("cmd 2>&1 | tee log") == ["cmd 2>&1", "tee log"],
    )
    check(
        "deny wins across segments",
        core.decide_shell(
            "git status && git push",
            [core.make_rule("shell", "git push *", "deny", "test")],
            True,
        )[0]
        == "deny",
    )
    check(
        "ask wins over allow",
        core.decide_shell(
            "ls && git push",
            [core.make_rule("shell", "git push *", "ask", "test")],
            True,
        )[0]
        == "ask",
    )

    # JSONC parsing.
    sample = """
    {
      // comment with a URL: https://example.com
      "permissions": [
        { "action": "shell", "resource": "*", "effect": "ask" }, /* inline */
      ],
    }
    """
    try:
        parsed = json.loads(core._strip_trailing_commas(core._strip_comments(sample)))
        check("jsonc comments and trailing commas", parsed["permissions"][0]["effect"] == "ask")
    except json.JSONDecodeError:
        check("jsonc comments and trailing commas", False)

    check(
        "url inside string survives",
        "https://example.com"
        in core._strip_comments('{\n  "url": "https://example.com" // note\n}'),
    )

    failures = [name for name, ok in cases if not ok]
    for name, ok in cases:
        print("%s  %s" % ("ok  " if ok else "FAIL", name))
    print()
    print("selftest: %d passed, %d failed" % (len(cases) - len(failures), len(failures)))
    return 1 if failures else 0


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="permcheck",
        description="Deterministic permission checker for OpenCode V1 and V2.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  permcheck.py --doctor
  permcheck.py --audit
  permcheck.py --list
  permcheck.py --action read --list
  permcheck.py --explain "cat .env" "git push origin main"
  permcheck.py --action read --explain src/.env
  permcheck.py --check examples/expectations.txt
  permcheck.py --compare old.jsonc opencode.jsonc \\
      --resources examples/resources.txt
  permcheck.py --dump
  permcheck.py --selftest
""",
    )
    parser.add_argument("--version", action="version", version="permcheck " + VERSION)

    source = parser.add_argument_group("configuration source")
    source.add_argument("--config", metavar="FILE", help="read a JSONC file instead of `opencode debug config`")
    source.add_argument("--project", metavar="DIR", default=".", help="directory for `opencode debug config` (default: .)")
    source.add_argument(
        "--binary",
        default="opencode",
        metavar="NAME",
        help="OpenCode binary for live mode (default: opencode)",
    )
    source.add_argument("--agent", metavar="ID", help="append `agents.<ID>` rules from the loaded config")
    source.add_argument(
        "--engine",
        choices=("auto", "v1", "v2"),
        default="auto",
        help="permission engine: auto (default), v1 or v2",
    )
    source.add_argument("--no-defaults", action="store_true", help="ignore the built-in base policy")

    modes = parser.add_argument_group("modes")
    modes.add_argument("--doctor", action="store_true", help="check Python, OpenCode binaries and config paths")
    modes.add_argument("--audit", action="store_true", help="summarise rules per action and flag common mistakes")
    modes.add_argument("--list", action="store_true", help="list rules in evaluation order")
    modes.add_argument("--dump", action="store_true", help="print every rule with index, action, resource and source")
    modes.add_argument("--explain", nargs="+", metavar="RESOURCE", help="show every matching rule and the winner")
    modes.add_argument("--explain-file", metavar="FILE", help="like --explain, but read resources from a file ('-' = stdin)")
    modes.add_argument("--check", metavar="FILE", help="run an expectations file (effect | action | resource)")
    modes.add_argument("--compare", nargs=2, metavar=("OLD", "NEW"), help="compare decisions between two configs")
    modes.add_argument("--resources", metavar="FILE", help="resources for --compare ('-' = stdin)")
    modes.add_argument("--selftest", action="store_true", help="run the checker's own test suite")

    options = parser.add_argument_group("options")
    options.add_argument(
        "--action",
        default=None,
        help="action to inspect (default: bash for V1, shell for V2)",
    )
    options.add_argument("--no-split", action="store_true", help="do not split compound shell commands")
    options.add_argument("--all", action="store_true", help="with --compare, also print unchanged decisions")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.selftest:
        return run_selftest()

    if args.doctor:
        return run_doctor(args.project)

    selected_modes = (
        args.audit,
        args.list,
        args.dump,
        args.explain,
        args.explain_file,
        args.check,
        args.compare,
    )
    if not any(selected_modes):
        parser.print_help()
        return 0

    try:
        if args.compare:
            if not args.resources:
                raise ConfigError(
                    "--compare needs --resources FILE with one resource per line"
                )
            old = load_file(args.compare[0], not args.no_defaults, args.agent, args.engine)
            new = load_file(args.compare[1], not args.no_defaults, args.agent, args.engine)
            if args.action:
                action = core.canonical_action(args.action)
            elif old.engine == new.engine:
                action = core.canonical_action(core.DEFAULT_ACTION[old.engine])
            else:
                action = "shell"
            return run_compare(
                old,
                new,
                args.resources,
                action,
                not args.no_split,
                args.all,
            )

        if args.config:
            config = load_file(args.config, not args.no_defaults, args.agent, args.engine)
        else:
            config = load_engine(
                args.project,
                not args.no_defaults,
                args.agent,
                args.engine,
                args.binary,
            )

        action = (
            core.canonical_action(args.action)
            if args.action
            else core.canonical_action(core.DEFAULT_ACTION[config.engine])
        )

        if args.check:
            return run_check(config, args.check, not args.no_split)

        if args.audit:
            return run_audit(config)

        if args.dump:
            return run_dump(config)

        if args.explain or args.explain_file:
            resources = list(args.explain or [])
            if args.explain_file:
                resources.extend(
                    line.strip()
                    for line in read_lines(args.explain_file)
                    if line.strip() and not line.strip().startswith("#")
                )
            print_header(config)
            for resource in resources:
                explain(action, resource, config, not args.no_split)
            return 0

        return run_list(config, action)

    except ConfigError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
