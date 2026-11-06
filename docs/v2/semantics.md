# V2 semantics

V2 is the current OpenCode format. It is one ordered list of rules.

## Shape

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "permissions": [
    { "action": "shell", "resource": "git status *", "effect": "allow" },
    { "action": "read",  "resource": "*.env",         "effect": "deny" }
  ]
}
```

| Field | Meaning |
|---|---|
| `action` | `read`, `edit`, `glob`, `grep`, `shell`, `subagent`, `skill`, `webfetch`, `websearch`, `external_directory`, `question`, `execute`, MCP tools |
| `resource` | The value being checked: a path, command string, URL, agent ID, pattern, regex, … |
| `effect` | `allow`, `ask` or `deny` |

V1 names are accepted by the checker as aliases (`bash` → `shell`, `task` →
`subagent`, `write`/`patch` → `edit`), but a V2 file should use the V2 names.
The audit warns about V1 names in a V2 file.

## Evaluation

1. Collect every rule whose `action` pattern matches the action and whose
   `resource` pattern matches the resource.
2. The **last** matching rule wins.
3. If nothing matches, the effect is `ask`.
4. `--auto` auto-approves `ask`, never `deny`. A hard block must be `deny`.

Rule sources are appended in load order: built-in defaults first, then
configuration sources, then agent rules. Later rules have higher priority.

**Saved approvals:** "always allow" replies are stored per project and appended
after configuration. They can turn an `ask` into `allow`, but they never
override a configured `deny`.

## Built-in base policy

The checker models this ordered policy before any user configuration:

```jsonc
[
  { "action": "*",    "resource": "*",             "effect": "allow" },
  { "action": "read", "resource": "*.env",         "effect": "ask" },
  { "action": "read", "resource": "*.env.*",       "effect": "ask" },
  { "action": "read", "resource": "*.env.example", "effect": "allow" }
]
```

Consequences:

- with no rules at all, normal reads and shell commands are allowed;
- reading `.env`, `.env.local` and similar asks even without configuration;
- `.env.example` is allowed.

`permcheck.py` includes these rules by default. `--no-defaults` shows only the
rules from the loaded configuration.

## Matching

Patterns match the **whole value**, anchored at both ends. `*` crosses `/`;
`?` is one character. `**` has no extra power because one `*` already crosses
`/`; `**/x` still needs a segment before `x`.

- `secrets/**` covers the root-level folder.
- `**/secrets/**` covers nested copies, not the root-level folder.
- `*.pem` matches at any depth; `**/*.pem` does not match root-level `c.pem`.
- `./` never appears in a read/edit resource.
- A trailing ` *` makes arguments optional: `git status *` matches both
  `git status` and `git status --short`.
- Backslashes are normalised to `/`.
- Matching is case-sensitive in the checked builds. Verify on Windows.

The full verified catalogue is `../common/patterns.md`.

## Actions and resources

| Action | Resource |
|---|---|
| `read` | Path relative to the workspace, or a canonical absolute path outside it |
| `edit` | Target path for `edit`, `write` and `patch` |
| `glob` | The **requested glob pattern** — not the files it would find |
| `grep` | The **requested regular expression** — not the search path |
| `shell` | Command string produced by the shell scanner |
| `subagent` | Target agent ID |
| `skill` | Skill ID |
| `webfetch` / `websearch` | URL / search query |
| `external_directory` | Directory boundary, normally ending in `/*` |
| MCP tools | `<server>_<tool>` with resource `*` |

Because `glob` and `grep` match a requested pattern or regex, path-style rules
there are weak guards. Use `read`, `edit` and `shell` rules to protect folders.

## Shell

- `&&`, `||`, `;`, `|`, `&` and newlines split a compound command into
  segments. Each segment is evaluated separately. Any `deny` denies the whole
  command; otherwise any `ask` asks; otherwise it is allowed.
- Patterns match command text, not filesystem paths.
- `git status *` matches `git status` and `git status --short`, not
  `git statuses`.
- Shell commands run with the host user's filesystem, process and network
  authority. Directory inference from command text is best effort.

The checker's splitter understands quotes, backslash escapes and the
separators above. It does not model subshells, command substitution or heredocs.
Use `--no-split` to evaluate the raw string.

## External directories

- A path outside the project is checked against `external_directory`
  **before** its `read` or `edit` rules.
- The default policy allows external access; add an `external_directory` rule
  to ask or deny.
- The resource is a directory boundary, normally `~/reference/*` or
  `/srv/data/*`.
- For shell commands, the scanner infers external directories from the command
  text and checks them before the shell rules.

Example:

```jsonc
{ "action": "external_directory", "resource": "~/reference/*", "effect": "ask" },
{ "action": "read",               "resource": "~/reference/*", "effect": "allow" },
{ "action": "edit",               "resource": "~/reference/*", "effect": "deny" }
```

`read: allow` does not cancel the `external_directory` ask: they are separate
checks with separate effects.

## Configuration sources and order

| Scope | Files |
|---|---|
| Project | `opencode.jsonc`, `opencode.json`, `.opencode/opencode.jsonc`, `.opencode/opencode.json` |
| Global | `~/.config/opencode/opencode.jsonc` (or `.json`) |

- Only those names are loaded.
- `opencode debug config` prints the **sources**, not a merged object. Read the
  documents in the order shown; later documents win.
- Agent rules live under `agents.<id>.permissions` and are appended after the
  top-level rules.
- Policies managed outside the local files (organisation/Console policies) can
  override local configuration.

`permcheck.py` models the base policy, the loaded documents and (with
`--agent`) that agent's rules from the same files. Built-in agent policies —
such as `plan` denying edits outside its plan folder, or `general` denying
subagents — are added by OpenCode at runtime and are not modelled. Inspect them
with `opencode debug agents`.

## Disabled tools

A tool is removed from the model's tool list only when the **last rule matching
that action** has resource `*` and effect `deny`.

```jsonc
{ "action": "glob", "resource": "*", "effect": "deny" }
```

A specific deny such as `{ "action": "glob", "resource": "**/secrets/**" }`
blocks matching requests but does not disable the tool.

## Reload and diagnostics

| Command | Use |
|---|---|
| `opencode debug config` | Configuration sources and their order |
| `opencode debug agents` | Resolved agents, including their permissions |
| `opencode debug paths` | Global data/config/cache/state paths |
| `opencode reload` | Reload service configuration; a client may still need a restart |

Configuration is not hot-reloaded into a running session. After an edit, run
`opencode reload` and start a new session before concluding that a rule does
not work.

## Platform notes

Global config candidates are shared by the platform layer: `OPENCODE_CONFIG`,
`OPENCODE_CONFIG_DIR`, `XDG_CONFIG_HOME`, `~/.config/opencode`, Windows
`APPDATA`/`LOCALAPPDATA`, and read-only managed locations. The canonical
default is `~/.config/opencode/opencode.jsonc` on every OS (or XDG when set).
Project search walks up to the nearest `.git` root.

Windows paths may be written as `C:\...`, `C:/...`, `\\server\share\...` or
`%USERPROFILE%\...`; patterns always use `/`. See `../common/platforms.md`.

## Limits

- Rules match **text**. A determined process can avoid literal patterns with
  indirection, encoding, interpreters, redirections, `cp`/`mv`, or a different
  spelling of the same path.
- Permissions are guardrails, not a sandbox.
- Permissions do not hide files from `git status`, `git log` or `git ls-files`.
  That is `.gitignore`'s job.
- Shell rules cannot express "read-only": a denied `edit` does not stop
  `echo x > file` in a shell command.

## Fidelity

The wildcard matcher and the last-match-wins evaluation mirror the engine
implementation used by OpenCode 2.1.x. The checker's tests cover matching and
ordering (`--selftest`). Shell segmentation is an approximation, and policies
pushed from outside the local files are not visible offline.

After an OpenCode upgrade, re-run `--selftest` and confirm a few decisions with
`--explain` before trusting a large rule change.
