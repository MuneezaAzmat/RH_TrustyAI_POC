# Policy-Driven Agentic Red Teaming

Takes pre-built **scenario** YAMLs and produces a schema-v2 environment spec, then Garak artifacts.

```
examples/scenarios/*.yaml
  → python -m build_spec          # runs/{id}/spec.json  (schema_version 2)
  → python -m ArtifactGen_garak.gen
  → ArtifactGen_garak/artifacts/{id}.yaml
```

## Step 1 — environment spec

```bash
pip install pydantic pyyaml openai httpx

python -m build_spec examples/scenarios/AP-T2-06-85bd56.yaml --exploit embedded_instruction -v
```

`--exploit` selects `{name, description}` from `exploit_styles.json` (copied unchanged into `attack.exploit`). Omit it to pick a random wording pack.

Output: `runs/{id}/spec.json` with `source`, `task`, `environment`, `attack`, `observation`, `provenance`, `platform_coverage`. If gates fail, also `runs/{id}/validation.json`.

## Step 2 — Garak

Requires a v2 spec from step 1.

```bash
python -m ArtifactGen_garak.gen examples/scenarios/AP-T2-06-85bd56.yaml -v
```

Stamps `platform_coverage.garak` onto the spec and writes `garak_data` (chat history + judge rubric).

```bash
python garak_meta_report.py   # → reports/garak_meta.html
```

## LLM endpoint

| Env Variable | Description |
|---|---|
| `OPENAI_API_KEY` | API key (if required) |
| `OLLAMA_BASE_URL` | OpenAI-compatible base URL |
| `REDTEAM_MODEL` | Model name |

## Project structure

```
├── build_spec.py            # Step 1 CLI (YAML load + generate spec)
├── draft_spec.py            # Deterministic v2 draft extract
├── llm_complete_spec.py     # LLM complete + gate 1/2
├── environment_spec.py      # Pydantic schema v2
├── spec_io.py               # Load/save runs/{id}/spec.json
├── exploit_styles.json      # Exploit catalog
├── ArtifactGen_garak/       # Step 2
├── examples/scenarios/
└── runs/
```
