# V1 semantics

V1 is the historical OpenCode format. It is still supported by both scripts
because existing installations and backups use it.

## Shape

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "permission": {
    "read": {
      "secrets/**": "deny",
      "secrets/*.example": "allow"
    },
    "edit": {
      "secrets/**": "deny"
    },
    "bash": {
      "*": "ask",
      "git status *": "allow",
      "*secrets/*": "deny"
    },
    "external_directory": {
      "~/reference/*": "ask"
    }
  }
}
```

A tool value may be a string, which means "every resource for this tool":

```jsonc
"permission": {
  "bash": "allow"
}
```

That is exactly equivalent to `"bash": { "*": "allow" }`.

## Actions

| V1 name | Canonical name used by the checker | Resource |
|---|---|---|
| `bash` | `shell` | command text |
| `task` | `subagent` | agent ID |
| `read` | `read` | workspace-relative path |
| `edit` | `edit` | target path for edit, write and patch |
| `glob` | `glob` | requested glob pattern, not files |
| `grep` | `grep` | requested regular expression, not files |
| `external_directory` | `external_directory` | external directory boundary |

`write` and `patch` are accepted aliases for `edit` when they appear in a
loaded rule. The display keeps the name that was written, so an audit can point
at it.

## Evaluation

1. Collect every rule whose tool name and pattern both match.
2. The last matching rule wins.
3. If nothing matches, the engine falls back to `ask`.
4. `--auto` auto-approves `ask`, never `deny`.

The checker models the common primary-agent baseline as a single `*: allow`
rule before the file's rules. Built-in agents can add their own policies at
runtime; inspect them with `opencode debug agents` / `opencode agent list`. Use
`--no-defaults` to see only the file.

Consequences of the V1 baseline: with no rules, `.env` is **allowed** for the
primary agent, unlike the V2 base policy which asks. Write explicit V1 guards
when you need parity with V2.

## Ordering and merge

- V1 rules are stored in a JSON object. Python preserves insertion order, and
  the checker evaluates in that order.
- Broad allows first, guards later, exceptions after the guards.
- Global and project configs are merged. An existing key is overwritten in
  place; a new key is appended at the end. A new local `allow` can therefore
  override a global guard. Verify the resolved order with
  `opencode debug config`.

## external_directory

`external_directory` works only inside the `permission` object:

```jsonc
"permission": {
  "external_directory": {
    "~/reference/*": "ask",
    "/srv/data/*": "allow"
  }
}
```

A top-level `external_directory` key is ignored. The audit warns about it.
The check runs before `read`/`edit`; the resource is a directory boundary,
normally ending in `/*`.

## Reload

V1 loads configuration at process start. After an edit, restart OpenCode and
start a new session before testing. `opencode reload` is a V2 command.

## Audit warnings

`permcheck.py --audit --engine v1` (or auto-detected V1) warns about:

- V2 names in a V1 file (`shell`, `subagent`);
- a top-level `external_directory`;
- `./` path patterns;
- duplicate rules;
- a broad `* -> allow` after a deny;
- a final `* -> deny` that disables a tool;
- path-style `glob`/`grep` rules, which are weak guards.

## Platform notes

Global config candidates are shared by the platform layer: `OPENCODE_CONFIG`,
`OPENCODE_CONFIG_DIR`, `XDG_CONFIG_HOME`, `~/.config/opencode`, Windows
`APPDATA`/`LOCALAPPDATA`, and read-only managed locations. The canonical
default is `~/.config/opencode/opencode.jsonc` on every OS (or XDG when set).
Project search walks up to the nearest `.git` root.

Windows paths may be written as `C:\...`, `C:/...`, `\\server\share\...` or
`%USERPROFILE%\...`; generated patterns always use `/`. See
`../common/platforms.md`.

## Limits

V1 models tool names and patterns, not built-in agent policies. A saved
"always allow" approval can turn an `ask` into an `allow`. Permissions are
guardrails, not a sandbox; see `../common/patterns.md`.

`opencode debug config` in V1 1.18.x redacts values whose key looks sensitive
(for example `secrets/**` or `credentials/**`) to `***`. The checker stops with
a clear error instead of guessing. Inspect the on-disk file with `--config
FILE` for those keys; the resolved output is only complete for non-sensitive
names. The sandbox reports a **partial** engine check when this happens: the
config-level check still verifies the exact target, but redacted rules cannot
be confirmed from the resolved output.
