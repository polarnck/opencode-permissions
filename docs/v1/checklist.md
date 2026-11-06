# V1 checklist

Use this after `common/process.md` has selected V1.

## Before changing anything

- [ ] `opencode --version` reports a 1.x build.
- [ ] The target file uses a `permission` object.
- [ ] The OS and global candidate list were printed (`permplan.py doctor`).
- [ ] The project config was found up the tree, not only in the current dir.
- [ ] I know whether the target is the project file or the global file.
- [ ] I have a backup path: `<config>.$(date +%F_%H-%M).bak`.
- [ ] The file is valid JSONC (`permcheck.py --config FILE --audit` loads it).

## Writing V1 rules

- [ ] Every tool that needs a guard has its own entry: `read`, `edit`,
      `bash`, `external_directory` are independent.
- [ ] Default posture is first; specific allows next; guards later; exceptions
      last.
- [ ] Protected folders use both `folder/**` and `**/folder/**`.
- [ ] Shell guards use command text with a literal fragment (`*secrets/*`), not
      a filesystem glob.
- [ ] `.env` guards are explicit, because the V1 baseline allows reads.
- [ ] `external_directory` is inside `permission`, not top-level.
- [ ] No V2 names (`shell`, `subagent`) in a V1 file.
- [ ] No `./` path patterns.
- [ ] `deny` is used where `--auto` must not auto-approve.
- [ ] Exceptions are after the guards.

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

## Verify

- [ ] `permcheck.py --selftest` passes.
- [ ] `permcheck.py --config FILE --check expectations.txt` passes.
- [ ] `--explain` on the least obvious cases shows the intended winner.
- [ ] `--compare <backup> <new> --resources ...` shows only intended changes.
- [ ] A compound command (`git status && cat secrets/prod.env`) is covered.

## Apply and test

- [ ] Backup created and its path recorded.
- [ ] Only the intended rules changed.
- [ ] OpenCode restarted; a new session was started.
- [ ] One real allowed case and one real denied case were tested.
- [ ] Optional sandbox offered after the real test; if yes,
      `permplan.py sandbox --plan ...` was run; if no, the skip was recorded.
- [ ] The user knows the rollback command.

## Red flags

| Snippet | Risk |
|---|---|
| `"bash": "allow"` | Allows every shell command; usually too broad |
| `"*": "allow"` after a deny | Overrides the deny |
| `"*": "deny"` as the last rule | Removes the tool entirely |
| `./folder/**` | Never matches a read/edit path |
| `folder/**` only | Does not cover nested copies |
| `**/folder/**` only | Does not cover the root folder |
| `external_directory` at top level | Silently ignored in V1 |
| `shell` / `subagent` keys | V2 names; V1 uses `bash` / `task` |
| `read` deny without a `bash` guard | `cat` still reads the file |
