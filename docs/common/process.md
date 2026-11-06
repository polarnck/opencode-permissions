# The guided process

Permission work is a configuration change with a real effect on what an agent
can read, edit and run. Use the same flow for V1 and V2. The order is not
cosmetic: each step removes a class of mistakes before the next one.

## Step 0: preflight

```bash
python3 scripts/permcheck.py --doctor
python3 scripts/permplan.py doctor
```

The doctor prints the OS, the Python version, the `opencode` and `opencode2`
binaries, every global config candidate and the project config search. If
OpenCode is missing, offline work still works with `--config FILE`.

## Step 1: engine

Ask: **V1 or V2?**

| Engine | Config shape | Action names |
|---|---|---|
| V1 | `permission` object, one map per tool | `bash`, `task`, `read`, `edit`, `external_directory` |
| V2 | `permissions` ordered list of rules | `shell`, `subagent`, `read`, `edit`, `external_directory` |

If the user does not know, detect it:

```bash
opencode --version
opencode debug config
```

A V1 file has a `permission` object; a V2 file has a `permissions` list. Do not
guess when both are present: the checker raises a clear error. Confirm the
engine with the user before writing rules.

## Step 2: scope

Ask: **local project or global config?**

| Scope | File |
|---|---|
| Local | The nearest `opencode.jsonc`, `opencode.json`, `.opencode/opencode.jsonc` or `.opencode/opencode.json`, walking up to the nearest `.git` root |
| Global | The first existing editable platform candidate (`OPENCODE_CONFIG`, `OPENCODE_CONFIG_DIR`, `XDG_CONFIG_HOME`, `~/.config/opencode`, Windows APPDATA/LOCALAPPDATA; managed entries are reporting-only) |

Say the exact path out loud. If more than one global candidate exists, show
all of them and ask which file to use. Editing the wrong layer is the most
common reason a rule "does not work". Project rules normally win, but V1 merge
has a caveat: an existing key is overwritten in place and a new key is
appended, so a new local `allow` can override a global guard. Verify the
resolved order with `opencode debug config`; see `../v1/semantics.md` and
`platforms.md`.

## Step 3: paths, formats and intent

Ask for each path:

- path or pattern,
- **effect**: `block`, `ask`, `read-only`, `read-write`,
- shell guard: `auto`, `none`, `ask`, `deny`, `allow`,
- whether it is inside or outside the project.

Show the resulting matrix before generating JSON:

| Path | read | edit | shell | external_directory |
|---|---|---|---|---|
| `secrets` | deny | deny | deny | — |
| `config/prod.json` | deny | deny | deny | — |
| `**/*.pem` | deny | deny | deny | — |
| `~/reference` | allow | deny | — | ask |
| `/srv/data` | allow | deny | — | ask |

Path format rules:

- project-relative paths are the default;
- `~/...` is a home path; absolute paths are external;
- `*` and `?` make it a pattern;
- an existing directory is a directory; an existing file is a file;
- a missing path is inferred from its name and flagged;
- `./` and trailing `/` are stripped; `..` is rejected if it escapes the
  project or home scope;
- an absolute path inside the project is converted to a project-relative path
  with a warning.

The matrix is the requested preset. `show` also prints conflict groups, the
note that existing rules may win, and unresolved group ids; use `conflicts`
for winner details.

Effects:

| Preset | read | edit | shell default | external |
|---|---|---|---|---|
| `block` | deny | deny | deny | deny |
| `ask` | ask | ask | ask | ask |
| `read-only` | allow | deny | ask | ask |
| `read-write` | allow | allow | none | allow |

For home and absolute paths the default shell guard is `none`, because
`external_directory` is the separate check for those paths. An explicit shell
override wins.

## Step 3b: existing rules and conflicts

Never replace an existing rule silently. `init` loads the target with defaults
off, prints its summary and shows conflicts; it records decisions interactively
or with `--on-conflict`, otherwise they stay unresolved for `resolve`.

```bash
python3 scripts/permplan.py conflicts --plan permissions.plan.json
python3 scripts/permplan.py resolve --plan permissions.plan.json \
    --id 1 --decision keep-existing
# only when `conflicts` reports stale resolutions:
python3 scripts/permplan.py resolve --plan permissions.plan.json --clear-stale
```

For every conflict group (one path, action and new effect; `secrets/**` and
`**/secrets/**` are one group) choose **keep existing**, **use new**, or
**skip this path**. `conflicts` exits `3` while unresolved groups or stale
resolutions remain; `generate` refuses to run while any group is unresolved or
stale. A stale resolution means the config changed; review it and resolve it
again, or drop it with `--clear-stale`. Add `--resolved` to include
global/merged rules and use it consistently; add `--binary NAME` for
`opencode2`. Non-interactive `init` supports
`--on-conflict abort|keep-existing|use-new` (default `abort`); `skip-path` is
chosen per conflict.

## Step 4: generate, verify, apply

```bash
python3 scripts/permplan.py init ...
python3 scripts/permplan.py show --plan permissions.plan.json
python3 scripts/permplan.py generate --plan permissions.plan.json
# after applying:
python3 scripts/permplan.py verify --plan permissions.plan.json
```

`generate` prints or saves a snippet. It never edits the target config. An
explicit `--full` keeps existing rules and unrelated settings, so it can carry
secrets or tokens from the target into the generated file; review it before
sharing or committing. It rewrites the JSON and drops comments/formatting.
Verify a proposed file or backup with
`verify --config FILE` before applying. For V1, a `use-new` rule that replaces
an existing key must move to the end of its tool map; the command warns when a
snippet cannot do that for you.

Then:

1. **Back up** the target:
   `cp <config> <config>.$(date +%F_%H-%M).bak`
2. **Apply** the generated block at the agreed position. Do not append a broad
   `allow` after existing guards.
3. **Verify again** with the real file and, where possible, `--resolved`:
   `python3 scripts/permplan.py verify --plan permissions.plan.json --resolved`
4. **Reload**: V2 uses `opencode reload`; V1 needs a restart. Start a **new
   session** either way.
5. **Test for real**: one allowed case and one denied case, with harmless
   files. A model answer is not evidence; the tool result is.
6. **Offer the sandbox**: ask whether to run
   `python3 scripts/permplan.py sandbox --plan permissions.plan.json`.
   If the user says no, record that it was skipped.
7. **Record rollback**: the backup path and the exact file that changed.

The optional sandbox copies only the plan's target config into a fresh
temporary tree (`tempfile.gettempdir()`), creates harmless fixtures, and checks
the sandbox copy. With an OpenCode binary it also runs `debug config` in that
tree and verifies the resolved output. It does not read the separate OpenCode
auth store, but it does copy the target config, so a config that embeds an API
key will carry it into the temporary tree; use `--clean`/`--keep` deliberately.
It copies only that file, not plugins, MCP servers or relative instruction
files, so such a config may fail the engine check; use `--no-engine` or a
trimmed copy. It never calls a model and never touches the real config beyond
the exact target file. It proves that the binary reads the config and that the checker
reproduces the decisions; it does not prove that a model will never find an
indirect path.

## The exact checklist

- [ ] 1. Engine: V1 or V2, confirmed.
- [ ] 2. Scope: local project or global, with the exact file path; if multiple
      global files exist, the chosen one is recorded.
- [ ] 3. Paths and formats: relative, home, absolute, patterns; effects and
      shell guards confirmed in a matrix. Windows paths use `/` in patterns.
- [ ] 3b. Existing rules: summary printed; every conflict has a decision
      (`keep-existing`, `use-new` or `skip-path`); no silent override.
- [ ] 4. Generate: `permplan.py generate` produced the rules; the snippet was
      reviewed.
- [ ] 5. Verify: `permplan.py verify` passes; `permcheck.py --selftest` passes.
- [ ] 6. Backup and apply: backup exists; only the intended rules changed.
- [ ] 7. Reload/new session: `opencode reload` (V2) or restart (V1); new session.
- [ ] 8. Real allow + deny test: one of each, with harmless files.
- [ ] 9. Optional sandbox: offered after the real test; if yes, run
      `permplan.py sandbox`; if no, record that it was skipped.
- [ ] 10. Rollback: the backup path is recorded and the user knows how to
      restore it.

If any item is missing, the work is not done.

## Debugging a rule that does not work

1. Is the rule in the loaded source? `opencode debug config`.
2. Is the action right? `read` is not `edit`; `shell` is not `bash` in V2.
3. Does the pattern match the whole value? `permcheck.py --explain`.
4. Is the winner the intended rule? The last match wins.
5. Is it in the right layer and in a loaded file?
6. Was the config reloaded, and is the test in a new session?
7. Is `external_directory` involved for a path outside the project?
8. Did a saved "always allow" approval turn an `ask` into an `allow`?

See `patterns.md` for the pattern catalogue, `platforms.md` for OS paths and
Windows path forms, and `../v1/` or `../v2/` for engine-specific details.
