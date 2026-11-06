# Path and shell patterns: what works, what does not

This catalogue is shared by OpenCode V1 and V2. Both engines use the same
matcher: a pattern is anchored to the whole value, `*` matches any run of
characters (including `/`), `?` matches exactly one character, and the **last
matching rule wins**. `[abc]`, `{a,b}`, `(x)`, `+`, `^` and `$` are ordinary
literal characters, not glob classes or regular-expression syntax.

The checker is the source of truth; use `permcheck.py --explain` to confirm any
row against your installed engine.

## Path patterns

The value is the path the tool sees. For `read` and `edit` it is relative to
the workspace root; for `external_directory` it is the external path after
home expansion.

| Pattern | Value | Match | Why |
|---|---|---|---|
| `secrets/**` | `secrets/prod.env` | yes | `**` is two stars; the first `*` covers `prod.env` |
| `secrets/**` | `src/secrets/prod.env` | no | anchored at `secrets/`; the value starts with `src/` |
| `**/secrets/**` | `src/secrets/prod.env` | yes | the leading `**/` consumes `src/` |
| `**/secrets/**` | `secrets/prod.env` | no | `**/` still needs a segment before `secrets` |
| `*secrets/*` | `secrets/prod.env` | yes | substring match, no anchor at the start |
| `*secrets/*` | `src/secrets/prod.env` | yes | the first `*` crosses `/` |
| `*secrets/*` | `mysecrets/prod.env` | yes | `secrets` is a substring of `mysecrets`; over-matching is real |
| `secrets/*` | `secrets/a/b.txt` | yes | `*` crosses `/`, so it is not a single-segment glob |
| `secrets/*` | `Secrets/prod.env` | no | matching is case-sensitive |
| `*.env` | `.env` | yes | the `*` may be empty |
| `*.env` | `deep/.env` | yes | the `*` crosses `/`, so this is a basename match at any depth |
| `*.env` | `.env.production` | no | the pattern ends at `.env`; `.production` is extra text |
| `*.env.*` | `.env.production` | yes | a dot after `.env` followed by anything |
| `*.env.*` | `config/.env.local` | yes | same rule, any depth |
| `*.env.example` | `.env.example` | yes | the literal suffix is present |
| `*.env.example` | `.env.production.example` | no | there is no literal `.env.example` substring |
| `*.env*.example` | `.env.production.example` | yes | the `*` absorbs `production` |
| `*.pem` | `key.pem` | yes | basename match |
| `*.pem` | `a/b/key.pem` | yes | the leading `*` crosses `/` |
| `*.pem` | `c.pem` | yes | a root-level name also matches |
| `**/*.pem` | `a/b/key.pem` | yes | `**/` consumes the directory prefix |
| `**/*.pem` | `key.pem` | no | `**/` still needs a segment before the name |
| `**/*.pem` | `c.pem` | no | the root-level name has no segment before it |
| `./secrets/**` | `secrets/prod.env` | no | read/edit resources never start with `./` |
| `secrets/` | `secrets/prod.env` | no | a trailing slash is literal; there is no wildcard |
| `src/*` | `src\main.py` | yes | backslashes are normalised to `/` before matching |
| `?.md` | `a.md` | yes | `?` is exactly one character |
| `?.md` | `ab.md` | no | two characters do not fit one `?` |
| `[abc].md` | `[abc].md` | yes | brackets are literal characters, not a character class |
| `[abc].md` | `a.md` | no | no character-class expansion happens |
| `{a,b}.txt` | `{a,b}.txt` | yes | braces are literal characters |
| `{a,b}.txt` | `a.txt` | no | no brace alternation happens |
| `/srv/data/*` | `/srv/data/file.txt` | yes | absolute external path with a directory boundary |
| `/srv/data/*` | `/srv/data` | no | a file below the directory is required |
| `/srv/data/*` | `/srv/data/sub/file.txt` | yes | `*` crosses `/`, so this is not a shallow glob |
| `**/x` | `a/x` | yes | one segment before `x` |
| `**/x` | `x` | no | no segment before `x` |

### Root folder vs nested folder: why both forms

For a project folder `secrets`, the generated guard is two rules:

```jsonc
{ "action": "read", "resource": "secrets/**",    "effect": "deny" },
{ "action": "read", "resource": "**/secrets/**", "effect": "deny" }
```

- `secrets/**` covers the folder at the workspace root.
- `**/secrets/**` covers copies such as `src/secrets/`, but does **not** cover
  the root-level `secrets/` because `**/` needs a segment before `secrets`.
- `*secrets/*` is the compact shell equivalent. It covers both forms, at the
  cost of also matching `mysecrets/`.

### The `.env` suffix trap

`.env.production.example` does not contain the literal `.env.example`, so a
rule written as `*.env.example` does not allow it. Use `*.env*.example` when
you mean "any env example". The same applies to `.env.*`: `*.env.*` denies
`.env.example` too, so an exception for examples must come **after** the deny.

### `./`, trailing slashes and literal characters

- `./secrets/**` never matches `read` or `edit`; the engine receives
  `secrets/prod.env` without the `./`. Shell command text is raw and may
  legitimately start with `./`, so a shell pattern can include it.
- `secrets/` never matches a file path. It matches only the exact string
  `secrets/`; add `**` or `*` when you mean "inside the folder".
- `?` is a wildcard. `[abc]`, `{a,b}`, `(x)`, `+`, `^` and `$` are literal.
- Matching is case-sensitive in the builds this package was checked against.
  Some platform documentation mentions case-insensitive behaviour on Windows;
  the checker does not model that. Verify on the target platform.

### Home and external paths

`read`, `edit` and `external_directory` expand a leading `~`, `~/`, `$HOME` or
`$HOME/` when configuration loads. Shell resources are raw command text and are
not expanded.

| Pattern | Value | Action | Effect |
|---|---|---|---|
| `~/reference/*` | `~/reference/notes.md` | `read` | matches after expansion |
| `~/reference/*` | `~/reference/notes.md` | `external_directory` | matches after expansion |
| `~/reference/*` | `~/reference/notes.md` | `shell` | does not match; use a shell pattern such as `*reference/*` |

`external_directory` is checked **before** `read`/`edit` and is directory-level:

- A directory rule should end in `/*`, for example `/srv/data/*` or
  `~/reference/*`.
- A rule naming one file is not a reliable way to block that file. To block a
  single external file, deny it explicitly in `read` and `edit`, and keep the
  external directory check at `allow` or `ask`:
  `read: /srv/data/secret.txt -> deny`, `external_directory: /srv/data/* -> ask`.
- The generator warns when an external file produces a directory-level
  pattern, because `~/notes.md` becomes `~/*` (broader than the file).

## Shell patterns

The shell value is command text produced by the scanner. It is matched whole,
not parsed as a filesystem path. `*` crosses spaces and slashes.

| Pattern | Command | Match | Why |
|---|---|---|---|
| `git status` | `git status` | yes | exact command |
| `git status` | `git status --short` | no | extra arguments are extra text |
| `git status *` | `git status` | yes | trailing ` *` means optional arguments |
| `git status *` | `git status --short` | yes | optional arguments present |
| `git status *` | `git statuses` | no | the required space prevents this over-match |
| `*git status*` | `sudo git status` | yes | substring before and after |
| `*git status*` | `git statuses` | yes | substring matching is broad |
| `* .env*` | `cat .env` | yes | a space before `.env` is required |
| `* .env*` | `node -e "console.log(process.env.PORT)"` | no | `process.env` has no space before `.env` |
| `* .env*` | `cat ./.env` | no | the text is ` ./.env`, not ` .env` |
| `*/.env*` | `cat ./.env` | yes | catches a slash before `.env` |
| `*envs/*` | `cat envs/.env` | yes | substring `envs/` |
| `*envs/*` | `cat myenvs/x` | yes | `envs/` is a substring of `myenvs/` |
| `*cat *` | `copycat file` | yes | `cat ` appears inside `copycat ` |
| `cat *` | `cat .env` | yes | anchored at the start of the segment |
| `cat *` | `sudo cat .env` | no | the segment starts with `sudo` |

### Compound commands, quotes and redirections

- `&&`, `||`, `;`, `|`, `&` and newlines split a command into segments. Each
  segment is evaluated separately. Any `deny` denies the whole command;
  otherwise any `ask` asks; otherwise it is allowed.
- `git status && cat secrets/prod.env` is two segments. A guard on the second
  segment still denies the whole command.
- Separators inside quotes are not split:
  `git commit -m "a && b"` stays one segment.
- Redirections such as `2>&1` stay inside the segment.
- The checker's splitter is a deliberate approximation. It does not model
  subshells, command substitution or heredocs. Use `--no-split` to evaluate the
  raw string.

### Shell patterns are not path patterns

A shell rule such as `secrets/*` matches the command text `secrets/*`, not the
file. To block commands that mention a folder, use a substring pattern with
stars, for example `*secrets/*`. To block a command family, anchor it:
`git push *`.

## What permissions cannot do

- **They are not `.gitignore`.** `git status`, `git log` and `git ls-files`
  still show protected files. Git does not consult OpenCode permissions. Use
  `.gitignore` for git visibility and permissions for tool access.
- **They are not a sandbox.** Rules match text. Interpreters, base64, `cp`,
  redirections or a different spelling of a path can avoid a literal pattern.
- **`glob` and `grep` rules are weak path guards.** They match the requested
  glob or regular expression, not the files that would be found. Use `read`,
  `edit` and shell rules for folders.
- **A `read` deny does not stop `cat`.** Every action is independent; add a
  shell rule as well.
- **A specific `deny` does not disable a tool.** Only a final `* -> deny` for
  that action removes the tool from the model.

## Verify a claim

```bash
python3 scripts/permcheck.py --explain "cat ./secrets/prod.env"
python3 scripts/permcheck.py --action read --explain "secrets/prod.env"
python3 scripts/permcheck.py --selftest
```
