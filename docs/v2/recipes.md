# V2 recipes

Copy the block you need into the `permissions` array, then verify with
`permcheck.py`. Rules are evaluated top to bottom; the last match wins.

A safe order for most files:

1. default posture (`*` → `ask` / `allow`),
2. specific allows,
3. guards (`deny` / `ask`),
4. `external_directory` rules,
5. exceptions (`allow`).

Do not append a broad `allow` after existing guards.

## Protect a folder inside the project

```jsonc
{ "action": "read",  "resource": "secrets/**",    "effect": "deny" },
{ "action": "read",  "resource": "**/secrets/**", "effect": "deny" },
{ "action": "edit",  "resource": "secrets/**",    "effect": "deny" },
{ "action": "edit",  "resource": "**/secrets/**", "effect": "deny" },
{ "action": "shell", "resource": "*secrets/*",    "effect": "deny" },

// exceptions last
{ "action": "read",  "resource": "secrets/*.example",   "effect": "allow" },
{ "action": "read",  "resource": "**/secrets/*.example","effect": "allow" },
{ "action": "shell", "resource": "*secrets/*.example*", "effect": "allow" }
```

- Two path forms are needed: `**/secrets/**` requires a segment before
  `secrets`, so it does not cover the root-level folder.
- `*secrets/*` matches any command text containing `secrets/` — both root and
  nested. It also blocks `git add secrets/prod.env`, which is usually wanted.
- Add `glob`/`grep` rules only as extras; they match requested patterns and
  regexes, not paths.

## Allow a folder

If a broader deny blocks the folder, add an allow **after** that deny. With no
broader deny, the built-in policy already allows it and no rule is needed.

```jsonc
{ "action": "read", "resource": "notes/**", "effect": "allow" },
{ "action": "edit", "resource": "notes/**", "effect": "allow" }
```

For a folder outside the project, add the `external_directory` rule as well:

```jsonc
{ "action": "external_directory", "resource": "~/notes/*", "effect": "allow" },
{ "action": "read",               "resource": "~/notes/*", "effect": "allow" },
{ "action": "edit",               "resource": "~/notes/*", "effect": "allow" }
```

## Read-only folder

```jsonc
{ "action": "read", "resource": "docs/**",    "effect": "allow" },
{ "action": "read", "resource": "**/docs/**", "effect": "allow" },
{ "action": "edit", "resource": "docs/**",    "effect": "deny" },
{ "action": "edit", "resource": "**/docs/**", "effect": "deny" },
{ "action": "shell", "resource": "*docs/*",   "effect": "ask" }
```

`edit` covers `write` and `patch` too. The shell guard also asks for reads
through the shell; that is the trade-off. A shell command cannot express
"read-only" by itself.

## Ask before writes

```jsonc
{ "action": "edit", "resource": "config/**",    "effect": "ask" },
{ "action": "edit", "resource": "**/config/**", "effect": "ask" }
```

With `--auto`, `ask` is auto-approved. Use `deny` when the block must hold in
automatic mode.

## Folder outside the project

`external_directory` is checked before `read`/`edit` and is allowed by default.
Add a rule to restore the prompt:

```jsonc
{ "action": "external_directory", "resource": "~/reference/*", "effect": "ask" },
{ "action": "read",               "resource": "~/reference/*", "effect": "allow" },
{ "action": "edit",               "resource": "~/reference/*", "effect": "deny" }
```

- `~`, `~/`, `$HOME` and `$HOME/` are expanded for these three actions.
- `read: allow` does not cancel `external_directory: ask`; the directory check
  runs first and separately.
- Change `ask` to `deny` to block the whole folder.
- Use absolute paths for other locations, for example `/srv/data/*`.

## Hide secrets and `.env`

The built-in policy already asks for `*.env` and `*.env.*`, and allows
`*.env.example`. To make it a hard block and add a shell guard:

```jsonc
{ "action": "read",  "resource": "*.env",      "effect": "deny" },
{ "action": "read",  "resource": "*.env.*",    "effect": "deny" },
{ "action": "shell", "resource": "*envs/*",    "effect": "deny" },
{ "action": "shell", "resource": "*/.env*",    "effect": "deny" },
{ "action": "shell", "resource": "* .env",     "effect": "deny" },
{ "action": "shell", "resource": "* .env.*",   "effect": "deny" },

// exceptions last
{ "action": "read",  "resource": "*.env.example",     "effect": "allow" },
{ "action": "shell", "resource": "*envs/*.example*",  "effect": "allow" },
{ "action": "shell", "resource": "*.env.example*",    "effect": "allow" }
```

Requiring a space before `.env` (`* .env` and `* .env.*`) avoids blocking
literals such as `process.env.PORT`; `*/.env*` covers paths written with a slash
(`cat ./.env`).
Even so, a very broad `*.env*` shell pattern will produce false positives — test
it with the commands you actually run. A literal inside `python -c "open('.env')"`
is matched, but an obfuscated path is not — see the limits in
`semantics.md`.

## Shell allowlist

```jsonc
{ "action": "shell", "resource": "*",            "effect": "ask" },
{ "action": "shell", "resource": "git status *", "effect": "allow" },
{ "action": "shell", "resource": "git diff *",   "effect": "allow" },
{ "action": "shell", "resource": "git log *",    "effect": "allow" },
{ "action": "shell", "resource": "rg *",         "effect": "allow" }
```

The broad `* -> ask` **must be first**. Put it last and it overrides every
specific allow above it.

`git status *` also matches plain `git status` (trailing ` *` means optional
arguments), but not `git statuses`.

## Block a command family

```jsonc
{ "action": "shell", "resource": "git push *",      "effect": "deny" },
{ "action": "shell", "resource": "docker system *", "effect": "deny" },
{ "action": "shell", "resource": "git push --dry-run *", "effect": "allow" }
```

Exceptions go after the guard.

## Block one file

```jsonc
{ "action": "read",  "resource": "config/prod.json",    "effect": "deny" },
{ "action": "read",  "resource": "**/config/prod.json", "effect": "deny" },
{ "action": "edit",  "resource": "config/prod.json",    "effect": "deny" },
{ "action": "edit",  "resource": "**/config/prod.json", "effect": "deny" },
{ "action": "shell", "resource": "*config/prod.json*",  "effect": "deny" }
```

For a family of files prefer an extension pattern such as `*.pem` or
`**/*.key`, and add a shell guard for the same literal fragment.

## Restrict a subagent

Agent rules are appended after top-level rules, so they win:

```jsonc
{
  "agents": {
    "reviewer": {
      "description": "Read-only reviewer",
      "mode": "subagent",
      "permissions": [
        { "action": "edit",  "resource": "*", "effect": "deny" },
        { "action": "shell", "resource": "*", "effect": "deny" }
      ]
    }
  }
}
```

Built-in agents already carry their own policies — for example `plan` denies
edits outside its plan folder, and `general` denies subagents. Inspect them with
`opencode debug agents`.

## Per-folder matrix example

| Folder | read | edit | shell | external_directory |
|---|---|---|---|---|
| `./secrets` | deny | deny | deny | — |
| `./docs` | allow | deny | ask | — |
| `~/reference` | allow | deny | — | ask |

`permplan.py` can generate this matrix from a plan. Use `show` to confirm it
before generating JSON.

## Test recipe

```text
# /tmp/permissions-expectations.txt
deny  | shell | cat secrets/prod.env
deny  | shell | git status && cat secrets/prod.env
allow | shell | git status
ask   | shell | rm -rf build
ask   | read  | .env
allow | read  | .env.example
ask   | external_directory | ~/reference/notes.md
```

```bash
python3 scripts/permcheck.py --config /tmp/proposed.jsonc \
    --check /tmp/permissions-expectations.txt
```

Add a case for every folder and every action in the matrix. If a case fails,
use `--explain` to see which rule won.

## Existing rules and conflicts

A V2 target may already contain a list rule:

```jsonc
{ "action": "read", "resource": "secrets/**", "effect": "deny" }
```

A plan that allows `secrets` conflicts with it. `permplan.py conflicts`
reports one group for `secrets/**` and `**/secrets/**`, listing both existing
overlaps; `resolve` records the winner for the whole group:

```bash
python3 scripts/permplan.py conflicts --plan permissions.plan.json
python3 scripts/permplan.py resolve --plan permissions.plan.json \
    --id 1 --decision keep-existing
```

The equivalent V1 target is `"read": { "secrets/**": "deny" }`; the decision
is the same. `keep-existing` preserves the deny, `use-new` keeps the new allow,
and `skip-path` drops every new rule generated from that path.
