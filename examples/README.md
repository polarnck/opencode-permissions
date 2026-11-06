# Examples

These files are demo inputs. They do not change any configuration.

| File | What it is | Used by |
|---|---|---|
| `v1/opencode.jsonc` | A small V1 configuration: `permission` map, `bash` action, guards and exceptions. | `permcheck --config ... --audit`, `--list`, `--explain`, `--check` |
| `v2/opencode.jsonc` | The same policy in V2 shape: ordered `permissions` list, `shell` action. | `permcheck --config ... --audit`, `--list`, `--explain`, `--check` |
| `permissions.plan.json` | A plan produced by `permplan init`: engine, scope, target file and a list of paths with effects. | `permplan show`, `conflicts`, `generate`, `verify`, `sandbox` |
| `expectations.txt` | Expected decisions for `permcheck --check`, one per line as `effect \| action \| resource`. Lines starting with `#` are comments. | `permcheck --check examples/expectations.txt` |
| `resources.txt` | Resources (commands or paths) for `permcheck --compare`, one per line. | `permcheck --compare ... --resources examples/resources.txt` |

## `permissions.plan.json`

This is the input format of the planner. It is not a config file and it is not
loaded by OpenCode. The fields are:

| Field | Meaning |
|---|---|
| `schema` | Plan format version. Currently `1`. |
| `engine` | `v1` or `v2`. |
| `scope` | `local` (project config) or `global` (user config). |
| `project` | Absolute path of the project used for relative paths and live checks. |
| `config` | Absolute path of the file that will receive the rules. |
| `paths` | One object per path: `input`, `kind`, `location`, `effect`, `shell`. |
| `resolutions` | Optional conflict decisions: `keep-existing`, `use-new` or `skip-path`. |

The bundled plan points at `/tmp/opencode-permissions-example/project`, which
the runnable example in the main README creates. Generate your own plan with:

```bash
python3 scripts/permplan.py init --engine v2 --scope local --project /path/to/project
```

## `expectations.txt`

This is a small verification fixture, not a test suite. Each line states what
the checker should decide for one resource:

```text
deny  | shell | cat secrets/prod.env
allow | shell | git status
ask   | read  | .env
```

Both example configs pass it:

```bash
python3 scripts/permcheck.py --config examples/v1/opencode.jsonc --check examples/expectations.txt
python3 scripts/permcheck.py --config examples/v2/opencode.jsonc --check examples/expectations.txt
```

To verify your own rules, copy the file and replace the lines with your cases.
