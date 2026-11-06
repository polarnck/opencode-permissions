#!/usr/bin/env python3
"""platforms.py - shared OS, path and sandbox-environment helpers.

Stdlib only. The rest of the package uses this module so Windows, macOS and
Linux share one source of truth for config locations, path spelling and
isolated environments.
"""

from __future__ import annotations

import ntpath
import os
import platform
import tempfile
from typing import Dict, List, Optional, Sequence, Tuple

MANAGED_LABELS = ("managed", "ProgramData")

# Variables that grant access to credentials, user sessions or private state.
# The sandbox keeps the normal process environment (PATH, locale, Windows
# system variables) but removes these before running OpenCode or the verifier.
_SENSITIVE_EXACT = {
    "BASH_ENV",
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "DOCKER_CONFIG",
    "ENV",
    "GIT_ASKPASS",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_DIR",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_WORK_TREE",
    "GPG_AGENT_INFO",
    "KUBECONFIG",
    "KRB5CCNAME",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "NETRC",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "SSH_AGENT_PID",
    "SSH_ASKPASS",
    "SSH_AUTH_SOCK",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
}
_SENSITIVE_PREFIXES = (
    "AWS_",
    "AZURE_",
    "BITBUCKET_",
    "CARGO_REGISTRY_",
    "COHERE_",
    "DASHSCOPE_",
    "DEEPSEEK_",
    "DOCKER_",
    "FIREWORKS_",
    "GCP_",
    "GEMINI_",
    "GIT_",
    "GITLAB_",
    "GITHUB_",
    "GOOGLE_",
    "GPG_",
    "GROQ_",
    "HELM_",
    "HF_",
    "HUGGING_FACE_",
    "KRB5_",
    "KUBE",
    "MISTRAL_",
    "MOONSHOT_",
    "NEBIUS_",
    "NPM_",
    "NOVITA_",
    "OPENAI_",
    "OPENROUTER_",
    "OVH_",
    "PERPLEXITY_",
    "PIP_",
    "REPLICATE_",
    "SAMBANOVA_",
    "SCALEWAY_",
    "SILICONFLOW_",
    "SSH_",
    "TOGETHER_",
    "TWINE_",
    "VAULT_",
    "XAI_",
    "YARN_",
    "ZHIPU_",
)


def _is_sensitive_env(name: str) -> bool:
    upper = name.upper()
    if upper in _SENSITIVE_EXACT:
        return True
    if upper.startswith(_SENSITIVE_PREFIXES):
        return True
    return any(
        word in upper
        for word in ("API_KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
    )


def prepare_command(command: Sequence[str]) -> List[str]:
    """Wrap a Windows `.cmd`/`.bat` shim so subprocess can execute it."""
    prepared = list(command)
    if (
        is_windows()
        and prepared
        and str(prepared[0]).lower().endswith((".cmd", ".bat"))
    ):
        prepared = [os.environ.get("COMSPEC", "cmd.exe"), "/c"] + prepared
    return prepared


def _env(name: str) -> str:
    """Read an environment variable, tolerating case differences on Windows."""
    if name in os.environ:
        return os.environ[name]
    return os.environ.get(name.upper(), "")


def system() -> str:
    """Return `Windows`, `macOS` or `Linux`."""
    if os.name == "nt":
        return "Windows"
    name = platform.system()
    if name == "Darwin":
        return "macOS"
    if name == "Windows":
        return "Windows"
    if name == "Linux":
        return "Linux"
    return name or "Linux"


def is_windows() -> bool:
    return system() == "Windows"


def home_dir() -> str:
    """User home directory; prefer USERPROFILE on Windows, HOME elsewhere."""
    if is_windows():
        profile = _env("USERPROFILE")
        if profile:
            return profile
    home = _env("HOME")
    if home:
        return home
    return os.path.expanduser("~")


def _managed_candidates() -> List[Tuple[str, str]]:
    if is_windows():
        program_data = _env("ProgramData") or "C:\\ProgramData"
        base = os.path.join(program_data, "opencode")
        return [
            ("ProgramData", os.path.join(base, "opencode.jsonc")),
            ("ProgramData", os.path.join(base, "opencode.json")),
        ]
    if system() == "macOS":
        base = "/Library/Application Support/opencode"
        return [
            ("managed", os.path.join(base, "opencode.jsonc")),
            ("managed", os.path.join(base, "opencode.json")),
        ]
    base = "/etc/opencode"
    return [
        ("managed", os.path.join(base, "opencode.jsonc")),
        ("managed", os.path.join(base, "opencode.json")),
    ]


def global_config_candidates() -> List[Tuple[str, str]]:
    """Return (label, path) global config candidates in priority order."""
    candidates: List[Tuple[str, str]] = []

    explicit = _env("OPENCODE_CONFIG")
    if explicit:
        candidates.append(("OPENCODE_CONFIG", explicit))

    explicit_dir = _env("OPENCODE_CONFIG_DIR")
    if explicit_dir:
        candidates.extend(
            [
                ("OPENCODE_CONFIG_DIR", os.path.join(explicit_dir, "opencode.jsonc")),
                ("OPENCODE_CONFIG_DIR", os.path.join(explicit_dir, "opencode.json")),
            ]
        )

    xdg = _env("XDG_CONFIG_HOME")
    if xdg:
        base = os.path.join(xdg, "opencode")
        candidates.extend(
            [
                ("XDG_CONFIG_HOME", os.path.join(base, "opencode.jsonc")),
                ("XDG_CONFIG_HOME", os.path.join(base, "opencode.json")),
            ]
        )

    home_base = os.path.join(home_dir(), ".config", "opencode")
    candidates.extend(
        [
            ("home", os.path.join(home_base, "opencode.jsonc")),
            ("home", os.path.join(home_base, "opencode.json")),
        ]
    )

    if is_windows():
        appdata = _env("APPDATA")
        if appdata:
            base = os.path.join(appdata, "opencode")
            candidates.extend(
                [
                    ("APPDATA", os.path.join(base, "opencode.jsonc")),
                    ("APPDATA", os.path.join(base, "opencode.json")),
                ]
            )
        local = _env("LOCALAPPDATA")
        if local:
            base = os.path.join(local, "opencode")
            candidates.extend(
                [
                    ("LOCALAPPDATA", os.path.join(base, "opencode.jsonc")),
                    ("LOCALAPPDATA", os.path.join(base, "opencode.json")),
                ]
            )

    candidates.extend(_managed_candidates())

    seen = set()
    unique: List[Tuple[str, str]] = []
    for label, path in candidates:
        key = os.path.normcase(os.path.abspath(path))
        if key in seen:
            continue
        seen.add(key)
        unique.append((label, path))
    return unique


def find_global_config() -> str:
    """First existing editable global candidate, else the canonical default."""
    for label, path in global_config_candidates():
        if label in MANAGED_LABELS:
            continue
        if os.path.isfile(path):
            return path
    return os.path.join(config_home(), "opencode.jsonc")


def config_home() -> str:
    """Canonical OpenCode config directory (not necessarily an existing file)."""
    xdg = _env("XDG_CONFIG_HOME")
    if xdg:
        return os.path.join(xdg, "opencode")
    return os.path.join(home_dir(), ".config", "opencode")


def project_config_candidates(project: str) -> List[Tuple[str, str]]:
    """Return (name, path) project config candidates for one directory."""
    return [
        ("opencode.jsonc", os.path.join(project, "opencode.jsonc")),
        ("opencode.json", os.path.join(project, "opencode.json")),
        (".opencode/opencode.jsonc", os.path.join(project, ".opencode", "opencode.jsonc")),
        (".opencode/opencode.json", os.path.join(project, ".opencode", "opencode.json")),
    ]


def find_project_config(project: str) -> Optional[str]:
    """Walk from the project up to the nearest git root, checking candidates."""
    current = os.path.abspath(project)
    while True:
        for _, path in project_config_candidates(current):
            if os.path.isfile(path):
                return path
        if os.path.exists(os.path.join(current, ".git")):
            break
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


def is_absolute(path: str) -> bool:
    """POSIX absolute, Windows drive/UNC absolute, or a bare UNC path."""
    return (
        os.path.isabs(path)
        or path.startswith("\\\\")
        or path.startswith("//")
        or ntpath.isabs(path)
    )


def to_pattern_path(path: str) -> str:
    """Forward slashes for patterns; keep UNC prefixes and do not collapse `..`."""
    text = path.replace("\\", "/")
    if text == "/":
        return text
    if len(text) == 3 and text[1] == ":" and text.endswith("/"):
        return text
    return text.rstrip("/")


def expand_user(path: str) -> str:
    """Expand `~`, `$HOME`, `%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%`.

    Windows environment variable names are case-insensitive, so `%UserProfile%`
    is accepted as well as `%USERPROFILE%`.
    """
    home = home_dir()
    if path == "~":
        return home
    if path.startswith("~/"):
        path = home + path[1:]
    elif path == "$HOME":
        return home
    elif path.startswith("$HOME/"):
        path = home + path[5:]

    appdata = _env("APPDATA")
    if not appdata and is_windows():
        appdata = os.path.join(home, "AppData", "Roaming")
    local = _env("LOCALAPPDATA")
    if not local and is_windows():
        local = os.path.join(home, "AppData", "Local")

    replacements = {
        "%USERPROFILE%": home,
        "%APPDATA%": appdata,
        "%LOCALAPPDATA%": local,
    }
    for token, value in replacements.items():
        if not value:
            continue
        # Replace case-insensitively without compiling a regex per call.
        lowered = path.lower()
        token_lower = token.lower()
        start = 0
        pieces = []
        while True:
            found = lowered.find(token_lower, start)
            if found == -1:
                pieces.append(path[start:])
                break
            pieces.append(path[start:found])
            pieces.append(value)
            start = found + len(token)
        path = "".join(pieces)
    return path


def sandbox_env(root: str) -> Dict[str, str]:
    """Build an isolated environment for config-level sandbox checks."""
    home = os.path.join(root, "home")
    temp = os.path.join(root, "tmp")
    runtime = os.path.join(root, "runtime")
    os.makedirs(temp, exist_ok=True)
    os.makedirs(runtime, exist_ok=True)
    env = os.environ.copy()

    for key in list(env):
        upper = key.upper()
        if upper.startswith("OPENCODE_") and upper != "OPENCODE_DISABLE_AUTOUPDATE":
            env.pop(key, None)
            continue
        if _is_sensitive_env(key):
            env.pop(key, None)

    env.update(
        {
            "HOME": home,
            "XDG_CONFIG_HOME": os.path.join(home, ".config"),
            "XDG_DATA_HOME": os.path.join(home, ".local", "share"),
            "XDG_CACHE_HOME": os.path.join(home, ".cache"),
            "XDG_STATE_HOME": os.path.join(home, ".local", "state"),
            "XDG_RUNTIME_DIR": runtime,
            "TMPDIR": temp,
            "TEMP": temp,
            "TMP": temp,
            "USERPROFILE": home,
            "APPDATA": os.path.join(home, "AppData", "Roaming"),
            "LOCALAPPDATA": os.path.join(home, "AppData", "Local"),
            "OPENCODE_DISABLE_AUTOUPDATE": "1",
            "CI": "1",
        }
    )

    drive, tail = (
        ntpath.splitdrive(home) if is_windows() else os.path.splitdrive(home)
    )
    if drive:
        env["HOMEDRIVE"] = drive
        env["HOMEPATH"] = tail or os.sep
    else:
        env["HOMEDRIVE"] = ""
        env["HOMEPATH"] = home

    if is_windows():
        for key in ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
            if key in os.environ:
                env[key] = os.environ[key]
    return env


def temp_root() -> str:
    return tempfile.gettempdir()


def display_path(path: str) -> str:
    """Native separators for user output."""
    if is_windows():
        return path.replace("/", "\\")
    return path.replace("\\", "/")
