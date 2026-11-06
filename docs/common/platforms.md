# Platforms: Windows, macOS and Linux

The package uses `scripts/platforms.py` for every OS-specific decision:
config locations, project search, Windows path spelling and the isolated
sandbox environment. The checker and planner themselves stay platform-neutral.

## Detection

`platforms.system()` returns `Windows`, `macOS` or `Linux`; `is_windows()` is
true only on Windows. `home_dir()` prefers `USERPROFILE` on Windows, then
`HOME`, and falls back to `os.path.expanduser("~")`.

## Global config candidates

`doctor` prints every candidate with `exists`/`missing` in priority order:

| Priority | Label | Path |
|---|---|---|
| 1 | `OPENCODE_CONFIG` | the explicit file in that variable |
| 2 | `OPENCODE_CONFIG_DIR` | `<dir>/opencode.jsonc`, then `<dir>/opencode.json` |
| 3 | `XDG_CONFIG_HOME` | `<xdg>/opencode/opencode.jsonc`, then `.json` |
| 4 | `home` | `~/.config/opencode/opencode.jsonc`, then `.json` |
| 5 | `APPDATA` | `<APPDATA>/opencode/opencode.jsonc`, then `.json` (Windows only) |
| 5 | `LOCALAPPDATA` | `<LOCALAPPDATA>/opencode/opencode.jsonc`, then `.json` (Windows only) |
| 6 | `managed` (macOS/Linux) or `ProgramData` (Windows) | macOS `/Library/Application Support/opencode/...`; Linux `/etc/opencode/...`; Windows `%ProgramData%\opencode\...` |

Managed candidates are reporting-only and read-only. `find_global_config()`
returns the first existing editable candidate (managed entries are skipped).
If none exists, the canonical default is:

- `$XDG_CONFIG_HOME/opencode/opencode.jsonc` when `XDG_CONFIG_HOME` is set;
- otherwise `~/.config/opencode/opencode.jsonc` on every platform.

The default deliberately does **not** jump to `%APPDATA%`. The documented
OpenCode location is `~/.config/opencode` on Windows too; `%APPDATA%` is an
additional candidate, not the default.

## Project config search

`find_project_config(project)` checks these names at the project level:

1. `opencode.jsonc`
2. `opencode.json`
3. `.opencode/opencode.jsonc`
4. `.opencode/opencode.json`

It then walks up to the nearest directory containing `.git` (or the filesystem
root) and repeats the check. This mirrors OpenCode's project search, so a
config at a repository root is found from a nested app directory. The walk
stops at the git root; it does not scan above it.

## Windows paths

Accepted forms:

| Input | Normalised plan input |
|---|---|
| `C:\data\secrets` | `C:/data/secrets` |
| `C:/data/secrets` | `C:/data/secrets` |
| `\\server\share\data` | `//server/share/data` |
| `%USERPROFILE%\reference` | `~/reference` |
| `%APPDATA%\opencode` | expanded absolute path |

Generated patterns always use `/`. `to_pattern_path()` keeps the UNC prefix
`//server/share`, preserves `C:/`, and does not collapse `..` silently. A
Windows-absolute path used on macOS/Linux is not passed to `os.path.isdir` or
`os.path.isfile`; the planner infers the kind from its suffix and treats it as
external.

`expand_user()` understands `~`, `$HOME`, `%USERPROFILE%`, `%APPDATA%` and
`%LOCALAPPDATA%`. Other `%...%` tokens are left unchanged.

## macOS and Linux

- Global: `~/.config/opencode/opencode.jsonc`, `XDG_CONFIG_HOME` if set, or
  `OPENCODE_CONFIG` / `OPENCODE_CONFIG_DIR`.
- Managed: macOS `/Library/Application Support/opencode/`; Linux
  `/etc/opencode/`.
- Project search is identical to Windows, including `.git` stops.

## Sandbox environment

`sandbox_env(root)` builds an isolated environment for `debug config` and the
verifier:

- POSIX: `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`,
  `XDG_STATE_HOME`, `XDG_RUNTIME_DIR`, `TMPDIR`;
- Windows: `USERPROFILE`, `HOMEDRIVE`, `HOMEPATH`, `APPDATA`, `LOCALAPPDATA`,
  `TEMP`, `TMP`;
- keeps `PATH`, `SYSTEMROOT`, `WINDIR`, `COMSPEC` and `PATHEXT` on Windows;
- removes inherited `OPENCODE_CONFIG*` values, then points `OPENCODE_CONFIG` at
  the copied target inside the sandbox, so the engine cannot fall back to a
  real global or managed config;
- removes API keys, tokens, secrets, passwords, credential variables, cloud
  profiles (`AWS_*`, `AZURE_*`, `GOOGLE_*`, `KUBE*`), SSH agent sockets,
  Docker config, git askpass/global config and similar inherited state;
- points temp and runtime directories inside the sandbox root, so subprocesses
  do not fall back to the user's real temp directory.

The sandbox root itself comes from `tempfile.gettempdir()`, not a hard-coded
`/tmp`, so it works on Windows and macOS as well.

## Running the commands

Examples use `python3`. On Windows, use `py -3` or `python` instead. The
generated permission patterns do not depend on the local shell; they use `/`
and the matcher normalises `\` to `/`.
