# ArtifactGen_garak

Emit Garak probe configs from the **shared ScenarioSpec** (same object the in-repo pipeline uses).

```
forge YAML → load_or_build_scenario_spec()
              ├─ runs/{id}/spec.json if present & current
              └─ else build from forge (+ write spec.json)
         → gate_garak() → realize() → configs/{id}.yaml
         → ForgeScenario probe + detector
```

Prefers the shared on-disk `ScenarioSpec` so Garak and the pipeline use the same file.
## Layout

```
ArtifactGen_garak/
  gen.py           # CLI
  gate.py          # Garak feasibility gate
  realize.py       # prompt/payload fill (LLM or --no-llm fallback)
  config_io.py     # write/load YAML configs
  configs/         # emitted per-scenario configs
  plugins/         # ForgeScenario probe + detector (symlink into ../garak)
```

## Generate configs

```bash
python -m ArtifactGen_garak.gen --dry-run
python -m ArtifactGen_garak.gen examples/scenarios/AP-T9-01-8c5d51.yaml --no-llm
python -m ArtifactGen_garak.gen … --attack-pattern progressive_escalation
# Optional: --attack-variant authority_impersonation (from attack_library.py)
# same flags as pipeline.py — both call load_or_build_scenario_spec()
```

## Install plugins into local Garak clone

```bash
GARAK_ROOT=../garak
ln -sf "$(pwd)/ArtifactGen_garak/plugins/probes/forge_scenario.py" \
  "$GARAK_ROOT/garak/probes/forge_scenario.py"
ln -sf "$(pwd)/ArtifactGen_garak/plugins/detectors/forge_scenario.py" \
  "$GARAK_ROOT/garak/detectors/forge_scenario.py"
```

## Run

```bash
export FORGE_SCENARIO_CONFIG="$(pwd)/ArtifactGen_garak/configs/AP-T9-01-8c5d51.yaml"
python -m garak --target_type ollama.OllamaGeneratorChat --target_name qwen2.5:14b \
  --probes forge_scenario.ForgeScenario --generations 1
```
