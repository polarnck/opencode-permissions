# OpenCode Permissions SKILL

Set up and verify [OpenCode](https://opencode.ai/) permission rules without guessing - for V1 and V2, local or global.

Vibecoded and expanded version of my local skill. Point your agent at it and it
will handle the rest, including the common gotchas and mistakes, so it can set
everything up safely. Remember to always check the output.

Built by [@polarnck](https://x.com/polarnck) 

## What it does

- Asks whether you use OpenCode V1 or V2.
- Asks whether the rules should live in the project or in the global config.
- Takes folders, files, extensions and external paths, and turns them into
  `read`, `edit` and `shell` rules.
- Reads the rules you already have and asks before changing a decision.
- Generates, verifies, backs up and applies the change.
- Offers a disposable sandbox test at the end.

## Quick start

Place this folder where OpenCode looks for skills. Keep the directory name
`opencode-permissions`:

```bash
mkdir -p ~/.config/opencode/skills
cp -r opencode-permissions ~/.config/opencode/skills/
```

Or clone it directly:

```bash
git clone <repository-url> ~/.config/opencode/skills/opencode-permissions
```

On Windows the skills folder is
`%USERPROFILE%\.config\opencode\skills\opencode-permissions`.

Restart OpenCode, then ask:

```text
@opencode-permissions set up permissions for ./secrets and ~/reference
```

The agent asks the questions, prepares the rules, verifies them and applies them
with a backup.

## What the agent will ask

1. V1 or V2?
2. Local project or global config?
3. Which paths, and should they be blocked, ask before access, read-only or
   read-write?
4. If a new rule conflicts with an existing one: keep existing, use new, or skip?
5. Do you want a sandbox test at the end?

## Path examples

| You want | Say |
|---|---|
| block a folder | `secrets` |
| block one file | `config/prod.json` |
| block an extension | `**/*.pem` |
| read-only home folder | `~/reference` |
| external folder | `/srv/data` |
| Windows folder | `C:\data\secrets` |

## Requirements

- Python 3.9+ (no extra packages).
- OpenCode for live checks; offline checks work on a copied config.

## Layout

| Path | What |
|---|---|
| `SKILL.md` | Agent instructions and the full flow |
| `scripts/` | Checker, planner, V1/V2 engines and platform paths |
| `docs/` | V1/V2 semantics, recipes and checklists |
| `examples/` | Demo configs and a sample plan |

## Good to know

- Permissions are guardrails, not a sandbox.
- They do not hide files from `git status`; use `.gitignore`.
- The agent never overwrites your existing rules silently.
- Works on Windows, macOS and Linux; the skill detects the OS and config paths.

The full agent-facing flow, CLI flags and platform details are in `SKILL.md`.
