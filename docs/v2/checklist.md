# V2 checklist

Use this after `common/process.md` has selected V2.

## Before changing anything

- [ ] `opencode --version` reports a 2.x build.
- [ ] `opencode debug config` runs and lists the loaded sources.
- [ ] The target file uses a `permissions` list.
- [ ] The OS and global candidate list were printed (`permplan.py doctor`).
- [ ] The project config was found up the tree, not only in the current dir.
- [ ] I know which file is **global** and which is **project** for this task.
- [ ] I know which file the user wants changed, and I said it out loud.
- [ ] I have a backup path: `<config>.$(date +%F_%H-%M).bak`.
- [ ] The current config is valid JSONC (the checker loads it, or
      `opencode debug config` does not complain).
- [ ] I am not editing during an audit: audits are read-only.

## Audit an existing configuration

Run `python3 scripts/permcheck.py --audit`, then check each item:

- [ ] **Sources:** the printed order matches what the user expects; a stale
      project file is a common surprise.
- [ ] **Shape:** rules use `action` / `resource` / `effect`; no V1 `permission`
      map, no `bash`, no `task`.
- [ ] **Action coverage:** for each protected folder, are all relevant actions
      covered — `read`, `edit`, `shell`? `glob`/`grep` are extras, not path
      guards.
- [ ] **Order:** default posture first, specific allows next, guards later,
      exceptions last.
- [ ] **Broad allows:** no `* -> allow` after a deny (the audit flags this).
- [ ] **Disabled tools:** a final `* -> deny` for an action removes the tool
      from the model; confirm that is intentional.
- [ ] **Duplicates:** no duplicated `(action, resource)` pairs where the later
      one silently shadows the earlier one.
- [ ] **Pattern shape (paths):** no `./` in `read`/`edit` rules; no assumption
      that `[abc]` is a character class; no `**/x` expecting to match root-level
      `x`. A shell command may legitimately start with `./`.
- [ ] **Shell literals:** every shell guard contains text that actually appears
      in the commands it is meant to block.
- [ ] **External paths:** `external_directory` rules exist for folders outside
      the project, and `read`/`edit` rules match them too.
- [ ] **Agents:** per-agent rules are intentional; built-in agents have their
      own policies.
- [ ] **Saved approvals:** "always allow" answers live outside the file and can
      turn `ask` into `allow`.

Report each finding with severity (high / medium / low), evidence (winning rule
from `--explain`) and a suggested patch. Do not apply it during an audit.

## Writing rules for folders

- [ ] The user's intent is written as a matrix: folder × action × effect.
- [ ] The target array and insertion point are known; appending is not assumed.
- [ ] For each protected folder, the root form and the nested form are present
      when `**/` is used (`secrets/**` + `**/secrets/**`).
- [ ] Shell guards use the literal folder fragment (`*secrets/*`), not a
      filesystem glob.
- [ ] `deny` is used when the block must survive `--auto`; `ask` otherwise.
- [ ] Exceptions (`*.example`, dry-run flags) are placed **after** the guards.
- [ ] `external_directory` rules are present for folders outside the project,
      and the matching `read`/`edit` rules are separate.
- [ ] The default posture rule (for example `* -> ask`) is **first**, not last.
- [ ] No real secret values are written into the config; only paths/patterns.
- [ ] Comments explain why a guard exists, not what the code does.

## Existing rules and conflicts

- [ ] `permplan.py init` loaded existing rules with defaults off and printed
      the summary.
- [ ] `permplan.py conflicts` was run; every group shows its existing
      overlaps, new effect/resource and a realistic sample.
- [ ] Each group has one decision: keep existing, use new or skip this path.
- [ ] No existing rule was silently replaced.
- [ ] Stale resolutions are reported and reviewed; obsolete ones are dropped
      with `resolve --clear-stale`.
- [ ] `permplan.py generate` refuses while any conflict is unresolved or any
      resolution is stale.

## Verify before applying

- [ ] `python3 scripts/permcheck.py --selftest` passes.
- [ ] An expectations file covers every folder and every action in the matrix,
      plus at least one allowed and one denied case per folder.
- [ ] `--check` reports every expectation as `ok`.
- [ ] `--explain` was run on the three least obvious cases, and the winning
      rule is the intended one.
- [ ] If the config already existed, `--compare <backup> <new> --resources …`
      was run; every `changed` line is intended.
- [ ] Compound commands were tested (`git status && cat secrets/prod.env`).
- [ ] An external path was tested for both `external_directory` and `read`.
- [ ] `permplan.py verify` passes, including `--resolved` where available.
- [ ] The result was shown to the user before writing.

## Applying

- [ ] Backup created and its path recorded.
- [ ] The change touches only the intended rules; the diff is reviewed.
- [ ] JSONC is still valid (the checker or `opencode debug config` loads it).
- [ ] `opencode reload` was run; the client was restarted if needed.
- [ ] A **new** session was used for the real test.
- [ ] One real allowed case and one real blocked case were tested with harmless
      files.
- [ ] Optional sandbox offered after the real test; if yes,
      `permplan.py sandbox --plan ...` was run; if no, the skip was recorded.
- [ ] The user knows how to roll back: restore the backup, then reload.

## Debug "the rule does not work"

Work in this order; stop at the first "no":

1. [ ] Is the rule in the loaded file? `opencode debug config` sources.
2. [ ] Is the action correct? `read` ≠ `edit`; `shell` ≠ `bash`;
       `glob`/`grep` match patterns, not paths.
3. [ ] Does the pattern match the whole value? `--explain` shows every hit and
       the winner.
4. [ ] Is the winner the intended rule? A later allow beats an earlier deny.
5. [ ] Is it the right layer? Global vs project, top-level vs agent.
6. [ ] Was the config reloaded, and is the test in a new session?
7. [ ] Is `external_directory` involved for a path outside the project?
8. [ ] Did a saved "always allow" approval turn the `ask` into an `allow`?

## Red flags

| Snippet | Risk |
|---|---|
| `"*": "allow"` at the end of an action | Overrides every earlier guard |
| `"*": "deny"` as the last rule for an action | Removes the tool entirely |
| `./folder/**` | Never matches |
| `folder/**` only | Does not cover nested copies |
| `**/folder/**` only | Does not cover the root-level folder |
| `[abc]`, `{a,b}` assumptions | Literal characters, not regex/glob classes |
| Shell guard without the literal text | Never triggers |
| `ask` where the block must hold under `--auto` | Auto-approved |
| Hiding files from `git status` with permissions | Git ignores permissions; use `.gitignore` |
| `read` deny without a `shell` guard | `cat` still reads the file |

## Definition of done

- [ ] Intent and scope recorded (mode, folders, effects).
- [ ] Backup exists; the changed file and rollback path are known.
- [ ] `--check` passes; `--compare` has no unexplained changes.
- [ ] Reload/restart done; new session used.
- [ ] Real positive and negative cases tested.
- [ ] Optional sandbox offered; if skipped, that is recorded.
- [ ] Report written: what changed, why, evidence, how to roll back.
- [ ] Any remaining gap is stated explicitly (guardrails, not a sandbox).
