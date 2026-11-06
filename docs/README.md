# Documentation map

| Path | Read it when |
|---|---|
| `../README.md` | You want installation, quick start and the human overview |
| `../SKILL.md` | You are the agent following the guided flow, CLI contract and limits |
| `common/process.md` | You need the full process and the exact checklist |
| `common/patterns.md` | You need the verified path and shell pattern catalogue |
| `common/platforms.md` | You need OS config paths, Windows path forms or sandbox env details |
| `v1/semantics.md` | You work with a V1 `permission` map |
| `v1/recipes.md` | You need V1 rule blocks to adapt |
| `v1/checklist.md` | You audit or apply a V1 change |
| `v2/semantics.md` | You work with a V2 `permissions` list |
| `v2/recipes.md` | You need V2 rule blocks to adapt |
| `v2/checklist.md` | You audit or apply a V2 change |
| `../examples/README.md` | You want to know what each example file is for |

Reading order for a new task:

1. `../SKILL.md` for the flow,
2. `common/process.md` for the checklist,
3. `common/patterns.md` before writing any path or shell pattern,
4. `common/platforms.md` when the target is Windows or when config locations
   differ between machines,
5. the `v1/` or `v2/` folder for the selected engine.

The two engines share the matcher and the last-match-wins rule. They differ in
the file shape and in action names:

| Concept | V1 | V2 |
|---|---|---|
| Rule container | `permission` object | `permissions` array |
| Shell action | `bash` | `shell` |
| Subagent action | `task` | `subagent` |
| Ordering | object insertion order | array order |
| Default policy modelled by the checker | primary-agent `*: allow` | four-rule base policy |
| Reload | restart the process | `opencode reload` (client restart may still be needed) |

The shared matcher and rule model live in `../scripts/core.py`; engine-specific
parsing, audit messages and rendering live in `../scripts/engines/v1.py` and
`../scripts/engines/v2.py`. When a file mixes the two shapes, the checker stops
with a configuration error instead of guessing.
