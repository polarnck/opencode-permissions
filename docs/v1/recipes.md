# V1 recipes

Copy the block you need into the `permission` object. Rules run in object
order; the last match wins. The safe order is:

1. default posture (`*` → `ask` / `allow`),
2. specific allows,
3. guards (`deny` / `ask`),
4. exceptions (`allow`),
5. `external_directory` rules.

Do not put a broad allow after the guards.

## Protect a folder inside the project

```jsonc
"permission": {
  "read": {
    "secrets/**": "deny",
    "**/secrets/**": "deny",
    "secrets/*.example": "allow",
    "**/secrets/*.example": "allow"
  },
  "edit": {
    "secrets/**": "deny",
    "**/secrets/**": "deny"
  },
  "bash": {
    "*": "ask",
    "cat *": "allow",
    "*secrets/*": "deny",
    "*secrets/*.example*": "allow"
  }
}
```

- `secrets/**` covers the root folder; `**/secrets/**` covers nested copies.
- `*secrets/*` is the shell substring guard. It also matches `mysecrets/`.
- Exceptions must be after the denies.

## Allow a folder

If a broader deny blocks it, add the allow after that deny:

```jsonc
"read": {
  "notes/**": "allow",
  "**/notes/**": "allow"
},
"edit": {
  "notes/**": "allow",
  "**/notes/**": "allow"
}
```

With no broader deny, the V1 primary-agent baseline already allows it and no
rule is needed.

## Read-only folder

```jsonc
"read": {
  "docs/**": "allow",
  "**/docs/**": "allow"
},
"edit": {
  "docs/**": "deny",
  "**/docs/**": "deny"
},
"bash": {
  "*docs/*": "ask"
}
```

`bash: *docs/*` also asks for reads through the shell. That is the trade-off:
a shell command cannot express "read-only" by itself.

## Folder outside the project

```jsonc
"permission": {
  "external_directory": {
    "~/reference/*": "ask"
  },
  "read": {
    "~/reference/*": "allow"
  },
  "edit": {
    "~/reference/*": "deny"
  }
}
```

- `external_directory` is checked first and separately.
- `read: allow` does not cancel `external_directory: ask`.
- Change the external effect to `deny` to block the whole folder.
- For another location use an absolute path, for example `/srv/data/*`.

## Hide `.env`

V1's baseline allows reads, so make the guards explicit:

```jsonc
"read": {
  "*.env": "deny",
  "*.env.*": "deny",
  "*.env.example": "allow"
},
"bash": {
  "* .env*": "deny",
  "*/.env*": "deny",
  "cat .env.example*": "allow"
}
```

`* .env*` avoids blocking `process.env.PORT`; `*/.env*` covers `cat ./.env`.
The exception for examples must come after the deny.

## Shell allowlist

```jsonc
"bash": {
  "*": "ask",
  "git status *": "allow",
  "git diff *": "allow",
  "git log *": "allow",
  "rg *": "allow"
}
```

The broad `*: ask` must be first. `git status *` also matches plain
`git status`, because a trailing ` *` makes the arguments optional.

## Block a command family

```jsonc
"bash": {
  "git push *": "deny",
  "docker system *": "deny",
  "git push --dry-run *": "allow"
}
```

The dry-run exception is after the deny.

## Block one file

```jsonc
"read": {
  "config/prod.json": "deny",
  "**/config/prod.json": "deny"
},
"edit": {
  "config/prod.json": "deny",
  "**/config/prod.json": "deny"
},
"bash": {
  "*config/prod.json*": "deny"
}
```

For a family of files prefer `*.pem` or `**/*.key`, plus a shell guard for the
same literal fragment.

## Restrict a subagent

```jsonc
{
  "agent": {
    "reviewer": {
      "description": "Read-only reviewer",
      "mode": "subagent",
      "permission": {
        "edit": "deny",
        "bash": "deny"
      }
    }
  }
}
```

Agent rules are appended after top-level rules. Built-in agents carry their own
policies; inspect them with `opencode debug agent <name>`.

## Verify

```text
# /tmp/permissions-expectations.txt
deny  | bash | cat secrets/prod.env
deny  | bash | git status && cat secrets/prod.env
allow | bash | git status
ask   | bash | rm -rf build
deny  | read | .env
ask   | external_directory | ~/reference/notes.md
```

```bash
python3 scripts/permcheck.py --config /tmp/proposed.jsonc \
    --check /tmp/permissions-expectations.txt
```

## Existing rules and conflicts

A V1 target may already contain a guard:

```jsonc
"permission": {
  "read": { "secrets/**": "deny" }
}
```

A plan that allows `secrets` produces `read: secrets/** -> allow` in canonical
form. `permplan.py conflicts` reports the exact and overlapping conflicts:

```text
[1] read existing overlaps -> new allow secrets/** path=secrets
    new rules: secrets/**, **/secrets/**
    existing deny secrets/** kind=exact sample=secrets/prod.env
```

Record the winner before generating. `secrets/**` and `**/secrets/**` are shown
as one group, so one id covers both forms:

```bash
python3 scripts/permplan.py resolve --plan permissions.plan.json \
    --id 1 --decision keep-existing
```

The equivalent V2 target is a list rule
`{ "action": "read", "resource": "secrets/**", "effect": "deny" }`; the
conflict and decisions are the same. `keep-existing` drops the new rule,
`use-new` appends the allow, and `skip-path` drops every new rule generated
from that path. For V1, a `use-new` rule that replaces an existing key must
move to the end of its tool map; `generate --full` does that, while a snippet
needs manual care and the command warns.
