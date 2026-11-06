---
name: opencode-permissions
description: "Audit, design and verify OpenCode V1 and V2 permission rules for files, folders and shell commands on Windows, macOS and Linux. Use when: set up permissions, configure permissions, audit permissions, check my permissions, protect a folder, block access to a folder, allow a read-only folder, external directory access, deny .env or secrets, shell allowlist, per-agent permissions, existing rules conflict, keep existing rule, use new rule, skip path, rule does not work, permission denied, opencode.jsonc permissions, permission regression test, permission denied after reload, Windows paths. Includes scripts/permcheck.py (doctor, audit, list, dump, explain, check, compare, selftest), scripts/permplan.py (doctor, init, conflicts, resolve, generate, verify, show, sandbox) and scripts/platforms.py."
---

# OpenCode Permissions

Use the guided flow. Do not write rules before the engine, scope, path matrix
and existing conflicts are confirmed. Works on Windows, macOS and Linux.

- **V1**: `permission` object; actions `bash` and `task`.
- **V2**: `permissions` list; actions `shell` and `subagent`.

The matcher is shared: last match wins, `*` crosses `/`, `?` is one character,
backslashes normalise to `/`, and home paths are expanded for `read`, `edit` and
`external_directory`.

## Non-negotiables

1. **Read-only until the user agrees.** An audit never edits a config.
2. **Back up before writing:** `cp <config> <config>.$(date +%F_%H-%M).bak`.
3. **Verify before claiming success.** "Looks right" is not a result.
4. **Order is behaviour.** The last matching rule wins.
5. **Actions are independent.** `read`, `edit`, `glob`, `grep`, `shell` and
   `external_directory` do not inherit from each other.
6. **Guardrails, not a sandbox.** Rules match text; interpreters and
   indirection can bypass literal patterns.
7. **Never edit the target config from `permplan.py generate`.** Generate a
   snippet, review it, back up, then apply.
8. **Existing rules are preserved.** Every conflict is shown and confirmed by
   the user before generation; never silently replace a rule.

Use the `question` tool if it is available; otherwise ask in chat. Ask one
compact round per step and do not guess.

## Step 0: preflight

Run these from the skill directory (or prefix them with `$SKILL_DIR`):

```bash
python3 scripts/permcheck.py --doctor
python3 scripts/permplan.py doctor
```

Check the operating system, Python version, `opencode` / `opencode2`, every
global config candidate and the project config search. If OpenCode is missing,
continue in offline mode with `--config FILE`. On Windows use `py -3`; on
macOS/Linux use `python3`. If live mode should use the other binary, pass
`--binary opencode2` to `permcheck.py` or `permplan.py`; the sandbox uses
`--binary PATH`.

Then run:

```bash
opencode debug config
```

Read the sources in the printed order; later documents win. If live mode fails
(no service, port conflict), ask which file is authoritative and use
`--config`.

Define paths once:

```bash
SKILL_DIR="$HOME/.config/opencode/skills/opencode-permissions"   # adapt if needed
PROJECT="/path/to/the/user/project"
```

## Step 1: engine

Use the `question` tool if available; otherwise ask in chat. Offer:

1. **V1** — `permission` map, `bash`/`task`.
2. **V2** — `permissions` list, `shell`/`subagent`.
3. **Not sure** — detect and confirm.

Detection:

```bash
opencode --version
opencode debug config
```

A `permission` object means V1; a `permissions` list means V2. If a file has
both non-empty shapes, stop and report the error from `permcheck.py`. Do not
guess. Confirm the engine with the user before writing rules.

## Step 2: scope

Ask: **local project or global?**

| Scope | File |
|---|---|
| Local | The nearest `opencode.jsonc`, `opencode.json`, `.opencode/opencode.jsonc` or `.opencode/opencode.json`, walking up to the nearest `.git` root |
| Global | The first existing editable platform candidate (`OPENCODE_CONFIG`, `OPENCODE_CONFIG_DIR`, `XDG_CONFIG_HOME`, `~/.config/opencode`, Windows APPDATA/LOCALAPPDATA; managed entries are reporting-only) |

Global config candidates, in priority order:

| Priority | Windows | macOS / Linux |
|---|---|---|
| 1 | `OPENCODE_CONFIG` file | `OPENCODE_CONFIG` file |
| 2 | `OPENCODE_CONFIG_DIR/opencode.jsonc` / `.json` | `OPENCODE_CONFIG_DIR/opencode.jsonc` / `.json` |
| 3 | `XDG_CONFIG_HOME/opencode/...` | `XDG_CONFIG_HOME/opencode/...` |
| 4 | `%USERPROFILE%\.config\opencode\...` | `~/.config/opencode/...` |
| 5 | `%APPDATA%\opencode\...`, then `%LOCALAPPDATA%\opencode\...` | — |
| 6 | `%ProgramData%\opencode\...` (managed, read-only) | macOS `/Library/Application Support/opencode/...`; Linux `/etc/opencode/...` (managed, read-only) |

The canonical default is `$XDG_CONFIG_HOME/opencode/opencode.jsonc` when XDG is
set, otherwise `~/.config/opencode/opencode.jsonc` on every platform. Managed
entries are reporting-only. Full details: `docs/common/platforms.md`.

Show the detected candidates. If more than one global file exists, ask which
one to use; do not pick silently. Say the exact path out loud. Project rules
normally win, but V1 can overwrite an existing global key in place and append
new keys, so a new local `allow` can override a global guard. Verify the
resolved order with `opencode debug config`. See `docs/common/platforms.md`.

## Step 3: paths, formats and intent

Ask for each path:

- the path or pattern,
- effect: `block`, `ask`, `read-only`, `read-write`,
- shell guard: `auto`, `none`, `ask`, `deny`, `allow`,
- whether it is inside or outside the project.

Path formats:

- project-relative is the default;
- `~/...` is a home path; absolute paths are external;
- `*` / `?` make it a pattern;
- existing directory → directory, existing file → file;
- a missing path is inferred and flagged;
- `./` and trailing `/` are stripped; `..` is rejected if it escapes the
  project or home scope;
- an absolute/home path inside the project is converted to a relative path with
  a warning.

Show the matrix and ask for corrections **before** generating JSON:

| Path | read | edit | shell | external_directory |
|---|---|---|---|---|
| `secrets` | deny | deny | deny | — |
| `config/prod.json` | deny | deny | deny | — |
| `**/*.pem` | deny | deny | deny | — |
| `~/reference` | allow | deny | — | ask |
| `/srv/data` | allow | deny | — | ask |

Effects:

| Preset | read | edit | shell default | external |
|---|---|---|---|---|
| `block` | deny | deny | deny | deny |
| `ask` | ask | ask | ask | ask |
| `read-only` | allow | deny | ask | ask |
| `read-write` | allow | allow | none | allow |

For home and absolute paths the default shell guard is `none`, because
`external_directory` handles them. An explicit shell override wins.

Before writing any pattern, consult `docs/common/patterns.md`. The important
traps:

- `secrets/**` covers the root folder; `**/secrets/**` covers nested copies but
  not the root.
- `*secrets/*` is the shell equivalent and also matches `mysecrets/`.
- `*.pem` matches any depth; `**/*.pem` does not match root-level `c.pem`.
- `*.env.example` does not allow `.env.production.example`; use
  `*.env*.example`.
- `./` never matches a read/edit path; shell text can start with `./`.
- `[abc]`, `{a,b}` and `(x)` are literal characters.
- Windows paths (`C:\...`, `C:/...`, `\\server\share\...`,
  `%USERPROFILE%\...`) are accepted; generated patterns always use `/`.

## Step 3b: existing rules and conflicts

Load the existing target first; rules are **added**, never silently replaced.
Show the existing summary and ask:

> Keep all existing rules? [yes / show rules / review conflicts]

Conflict pairs are grouped into one decision per path, action and new effect;
for example `secrets/**` and `**/secrets/**` are one group. Ask once per group:

1. keep existing rules
2. use the new rule group
3. skip this path
4. show details

Record each answer with:

```bash
python3 "$SKILL_DIR/scripts/permplan.py" conflicts --plan permissions.plan.json
python3 "$SKILL_DIR/scripts/permplan.py" resolve --plan permissions.plan.json \
    --id 1 --decision keep-existing
# only when `conflicts` reports stale resolutions:
python3 "$SKILL_DIR/scripts/permplan.py" resolve --plan permissions.plan.json --clear-stale
```

`conflicts` exits `3` while unresolved groups or stale resolutions remain.
A stale resolution means the existing config changed; review it and resolve it
again, or drop it with `--clear-stale`. `generate` refuses to run while any
group is unresolved or stale. Add `--resolved` to `init`, `conflicts`,
`resolve`, `generate` and `show` to include global and merged rules; use the
same flag at every step. Add `--binary NAME` when live mode should use
`opencode2`. Non-interactive `init` accepts
`--on-conflict abort|keep-existing|use-new`; `skip-path` is always a
per-conflict decision. Never generate around an unresolved conflict.

## Step 4: generate, verify, apply

### 4a. Build the plan

Interactive:

```bash
python3 "$SKILL_DIR/scripts/permplan.py" init --project "$PROJECT"
```

Non-interactive:

```bash
python3 "$SKILL_DIR/scripts/permplan.py" init \
  --engine v2 --scope local --project "$PROJECT" \
  --path secrets=block \
  --path config/prod.json=block \
  --path '**/*.pem=block' \
  --path '~/reference=read-only:none' \
  --path '/srv/data=read-only'
```

Show the matrix:

```bash
python3 "$SKILL_DIR/scripts/permplan.py" show --plan permissions.plan.json
```

### 4b. Generate a snippet

```bash
python3 "$SKILL_DIR/scripts/permplan.py" generate --plan permissions.plan.json
```

The default is a full file when the target does not exist and a snippet when it
does. Use `--full` or `--snippet` to force either shape.

`--full` keeps existing rules and unrelated settings when the target exists, so
it can include secrets or tokens already in that file. Review the output before
sharing or committing. It rewrites the JSON and drops comments and formatting.

The command never writes the target config. `-o` writes the generated text to a
separate file.

For V1, a `use-new` rule for an existing key must move to the end of its tool
map; the command warns when a snippet cannot do that.

### 4c. Verify before applying

```bash
# Before applying, verify the proposed full file or a backup copy.
python3 "$SKILL_DIR/scripts/permplan.py" verify --plan permissions.plan.json \
    --config <proposed-file>
python3 "$SKILL_DIR/scripts/permcheck.py" --config <proposed-file> \
    --check <expectations-file>
```

Write 6–12 expectations, one per line as `effect | action | resource`:

```text
deny  | shell | cat secrets/prod.env
allow | shell | git status
ask   | read  | .env
ask   | external_directory | ~/reference/notes.md
```

`bash`/`shell` and `task`/`subagent` are accepted as aliases. Exit `1` means a
check failed; use `--explain` on the failing sample.

If the config already existed:

```bash
python3 "$SKILL_DIR/scripts/permcheck.py" --compare <backup> <new> \
    --resources <resources-file>
```

Exit `3` means decisions changed; review every line.

### 4d. Apply

1. Back up: `cp <config> <config>.$(date +%F_%H-%M).bak`.
2. Insert the verified block at the agreed position; keep unrelated rules.
3. Verify again with the real file and, where possible, `--resolved`:
   `permplan.py verify --plan permissions.plan.json --resolved`.
4. Reload: `opencode reload` (V2) or restart (V1). Start a **new session**.
5. Test one real allowed case and one real denied case with harmless files.
6. Record the backup path and the rollback command.

## Step 5: optional sandbox test

After the real allow/deny test, ask with the `question` tool if available
(otherwise ask in chat):

> Do you want to test the applied rules in a disposable sandbox now?

Offer:

1. **Yes, run the sandbox** — config-level, no model, no cost, a fresh
   temporary tree (`tempfile.gettempdir()`):
   `python3 "$SKILL_DIR/scripts/permplan.py" sandbox --plan permissions.plan.json`
2. **No, finish** — the file was already verified with
   `permplan.py verify`.
3. **Show the command only** — print the command and let the user run it later.

If the user chooses yes, run it and report the result. If it fails, keep the
sandbox path, show the failing checks, and do not claim success. Add
`--no-engine` for a config-only run, or `--binary PATH` to choose the OpenCode
binary. Without a binary and without `--no-engine`, the engine check fails and
the run reports FAIL; that is not a permission failure. For V1, a redacted
`debug config` result is reported as **partial**: the config check still
verified the exact target, but redacted rules cannot be confirmed from the
resolved output.

The sandbox proves that the real OpenCode binary reads the config and that the
checker reproduces the decisions. It does **not** prove that a model will never
find an indirect path; permissions are guardrails, not a sandbox.

## Mode A: audit (read-only)

```bash
python3 "$SKILL_DIR/scripts/permcheck.py" --project "$PROJECT" --audit
python3 "$SKILL_DIR/scripts/permcheck.py" --project "$PROJECT" --list --action shell
python3 "$SKILL_DIR/scripts/permcheck.py" --project "$PROJECT" --list --action read
```

The audit flags:

- V1 names in V2 (`bash`, `task`) and V2 names in V1 (`shell`, `subagent`);
- mixed `permission` / `permissions` shapes;
- a top-level `external_directory` in V1;
- `./` path patterns;
- duplicate rules;
- a broad `* -> allow` after a deny;
- a final `* -> deny` that disables a tool;
- path-style `glob`/`grep` rules.

Report a short table: **finding · severity · evidence · suggested fix**. Use the
winning rule from `--explain` as evidence. Propose a patch, but do not apply it
during an audit.

## Mode B: debug a rule that does not work

Work in this order:

1. Is the rule in a loaded source? `opencode debug config`.
2. Is the action right? `read` ≠ `edit`; V2 `shell` ≠ V1 `bash`;
   `glob`/`grep` take patterns, not paths.
3. Does the pattern match the whole resource? `--explain`.
4. Is the winner the intended rule? The last match wins.
5. Is it the right layer — global vs project, top-level vs agent?
6. Was the config reloaded, and is the test in a new session?
7. Is `external_directory` involved for a path outside the project?
8. Did a saved "always allow" approval turn an `ask` into an `allow`?

Report the winning rule and the exact reason.

## Definition of done

- [ ] Engine and scope recorded.
- [ ] Path matrix confirmed by the user.
- [ ] Existing rules shown; every conflict has a recorded decision.
- [ ] `permplan.py show` matches the agreed matrix.
- [ ] `permplan.py verify` passes; `permcheck.py --check` passes.
- [ ] Backup exists; the changed file and rollback path are known.
- [ ] Reload/restart done; new session used.
- [ ] One real allowed and one real blocked case tested.
- [ ] The optional sandbox was offered; if skipped, that is recorded.
- [ ] The user knows which file changed and how to roll back.

## CLI contract

Exit codes: `0` OK, `1` failed check, `2` usage or config error, `3` changed
decisions or unresolved/stale conflicts.

`permcheck.py`: `--doctor`, `--audit`, `--list`, `--dump`, `--explain`,
`--check`, `--compare`, `--selftest`.
`permplan.py`: `doctor`, `init`, `conflicts`, `resolve`, `generate`, `verify`,
`show`, `sandbox`.

Bundled examples:

```bash
python3 "$SKILL_DIR/scripts/permcheck.py" --config "$SKILL_DIR/examples/v1/opencode.jsonc" --check "$SKILL_DIR/examples/expectations.txt"
python3 "$SKILL_DIR/scripts/permcheck.py" --config "$SKILL_DIR/examples/v2/opencode.jsonc" --check "$SKILL_DIR/examples/expectations.txt"
python3 "$SKILL_DIR/scripts/permcheck.py" --compare "$SKILL_DIR/examples/v1/opencode.jsonc" "$SKILL_DIR/examples/v2/opencode.jsonc" --resources "$SKILL_DIR/examples/resources.txt" --action shell
python3 "$SKILL_DIR/scripts/permplan.py" show --plan "$SKILL_DIR/examples/permissions.plan.json"
```

`examples/README.md` explains what each demo file is.

## Limits

- The checker models the matcher and ordering, not every built-in agent or
  organisation policy.
- Shell splitting is an approximation of the real scanner; use `--no-split` to
  test the raw string.
- V1 and V2 defaults differ; use `--no-defaults` to compare explicit rules only.
- V1 `opencode debug config` redacts sensitive-looking keys to `***`; inspect
  those with `--config FILE`.
- The generator never edits the target config; the skill applies the block with
  a backup.

## Resources

- `scripts/permcheck.py --help` — all modes and flags.
- `scripts/permplan.py --help` — planner and sandbox commands.
- `scripts/core.py` — shared matcher, rule model and JSONC readers.
- `scripts/engines/v1.py`, `scripts/engines/v2.py` — engine-specific parsing,
  audit and rendering.
- `scripts/platforms.py` — OS paths, Windows path normalization and sandbox env.
- `docs/common/process.md` — the guided process and exact checklist.
- `docs/common/patterns.md` — verified path and shell pattern catalogue.
- `docs/common/platforms.md` — OS config paths and Windows examples.
- `docs/v1/` — V1 semantics, recipes, checklist.
- `docs/v2/` — V2 semantics, recipes, checklist.
- `examples/README.md` — what each demo config, plan and expectations file is.
