# ArtifactGen_garak

Turns pre-built **scenario** YAMLs into Garak probe artifacts: a multi-turn transcript plus a detector rubric for red-team evaluation.

Run commands from the repository root.

```
examples/scenarios/*.yaml
  → python -m ArtifactGen_garak.gen
  → runs/{scenario_id}/{scenario_id}-garak.json
  → runs/{scenario_id}/validation.json
```

## Setup

From the repository root:

```bash
pip install -r requirements.txt
cp .env.example .env   # set GEMINI_API_KEY or configure Ollama
```

Supported LLM backends: **Gemini** (default when `GEMINI_API_KEY` is set), **OpenAI**, **Ollama**, Hugging Face, or OpenRouter.

## Interactive demo

End-to-end Jupyter walkthrough (API key → scenario YAML → artifact → Garak `toolchat.ToolChat` attack):

```bash
pip install ipywidgets
jupyter notebook ArtifactGen_garak/Demo/demo.ipynb
```

## Generate artifacts

```bash
# One scenario
python3 -m ArtifactGen_garak.gen examples/scenarios/AP-T2-01-28712e.yaml --force -v

# All scenarios in examples/scenarios/
python3 -m ArtifactGen_garak.gen -v
```

| Flag | Effect |
|------|--------|
| `--force` | Write garak JSON even when structural validation fails |
| `--dry-run` | Classify + LLM + validate only — no files written |
| `--no-llm` | Skip LLM (useful to test pre-plan surface skips) |
| `--output-dir DIR` | Override default `runs/` output directory |
| `-v` | Verbose logging |

### Pipeline

1. **Classify** injection surface from scenario seed (`user_turn`, `tool_return`, `system_prompt`, or skip).
2. **Skip** unwritable surfaces (e.g. `tool_definition`) — writes a minimal artifact without calling the LLM.
3. **Generate** probe via one-shot LLM (`prompts/generate_artifact.md`).
4. **Validate** structural gates (rubric completeness, surface/turn alignment, schema).
5. **Gate** platform coverage: `full`, `partial`, or `skip`.

## Output layout

Each scenario gets its own directory under `runs/`:

```
runs/
  manifest.json
  AP-T2-01-28712e/
    AP-T2-01-28712e-garak.json    # probe artifact
    validation.json               # structural gate result
```

**`{scenario_id}-garak.json`** — probe artifact:

- `scenario_id`, `injection_surface`, `platform_coverage` (`full` | `partial` | `null` for skips)
- `narrative.summary`
- `model` — LLM used for generation (`null` on skip)
- `timestamp` — UTC ISO time when the artifact was written
- `turns[]` with adversarial attack turn
- `detector_rubric` (judge prompt + success/blocked rubrics)

**`validation.json`** — sidecar from the structural gate:

```json
{
  "ok": true,
  "checks": "Probe structural gate after LLM generation: ...",
  "errors": []
}
```

Skipped scenarios (unwritable surfaces) get a pre-plan `checks` string and no LLM call.

**`manifest.json`** — batch summary (`gate_result`, `gate_reason`, `artifact_path` per scenario).

## Reports

```bash
python reports/garak_meta_report.py   # → reports/garak_meta.html
```

## Modules

| Module | Role |
|--------|------|
| `gen.py` | CLI — orchestrates classify → generate → validate → save |
| `probe_spec.py` | `ScenarioProbe` schema, LLM call, `gate_probe_errors`, artifact dicts |
| `spec_io.py` | Paths and I/O for `runs/{id}/{id}-garak.json` and `validation.json` |
| `classify.py` | Injection-surface table, pre-plan skip, `platform_coverage` gates |
| `extract.py` | Load scenario YAML into `ScenarioContext` |
| `gate.py` | `gate_from_context` — full vs partial vs skip after probe |
| `llm.py` | Provider-agnostic completion (Gemini / Ollama) |
| `prompts/generate_artifact.md` | One-shot probe generation prompt |
