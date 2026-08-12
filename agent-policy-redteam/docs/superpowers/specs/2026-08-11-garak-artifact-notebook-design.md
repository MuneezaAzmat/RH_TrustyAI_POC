# Garak Artifact Demo Notebook — Design

**Date:** 2026-08-11  
**Status:** Approved for implementation

## Goal

Ship an asago-examples-style Jupyter notebook that:

1. Lets the user pick a forge scenario via dropdown
2. Labels it for Garak coverage: `full` | `partial` | `skip`
3. Calls an LLM to realize chat history + detector criteria
4. Writes the shared `ScenarioSpec` and the Garak YAML artifact (no full pipeline env/traces)

## Flow

```
Select scenario (dropdown over examples/scenarios/*.yaml)
  → load_or_build_scenario_spec(persist=True)  → runs/{id}/spec.json
  → gate_garak(spec)  → label: full | partial | skip
  → if skip: show reason; stop (no Garak YAML)
  → else realize(use_llm=True) with configured provider
  → save_config → ArtifactGen_garak/configs/{id}.yaml
```

## Labelling

“Label” means Garak gate coverage only (not enforcement-level triage):

| Label | Meaning |
|-------|---------|
| `full` | Surface + oracle fully supported |
| `partial` | Supported with downgrade (e.g. wrong_target → output_string) |
| `skip` | No Garak coverage (unwritable surface / unobservable oracle) |

## Artifacts

1. **`runs/{scenario_id}/spec.json`** — always persisted when the spec is built
2. **`ArtifactGen_garak/configs/{scenario_id}.yaml`** — only when gate ≠ `skip`

Garak YAML contents (existing shape):

- `prompts` — multi-turn chat history (probe input)
- `detection.oracle_predicates` — narrative rubrics for LLM-as-a-judge
- `detection.predicates` / patterns — programmatic detector checks

## LLM providers

Notebook config cell + provider dropdown sets OpenAI-compatible client knobs:

- Local Ollama
- OpenAI API
- Hugging Face Inference (OpenAI-compatible router)
- Claude via OpenAI-compatible gateway (e.g. OpenRouter) or Anthropic-compatible base URL

`realize.py` exposes `configure_llm(...)` so the notebook can reset base URL, API key, and model without restarting the kernel.

## Out of scope

- Full in-repo pipeline (env codegen, dry/attack runs, traces)
- Native Anthropic SDK (use OpenAI-compatible endpoint)
- Publishing as a separate asago-examples package
- Reshaping detection into a new `judge_rubrics` key (keep current YAML)

## UX (asago-style sections)

1. Configuration (provider / base URL / model / API key)
2. Select scenario (dropdown)
3. Optional attack pattern / variant
4. Run: label → realize → write artifacts
5. Inspect label, chat history, judge rubrics
6. Show output paths
