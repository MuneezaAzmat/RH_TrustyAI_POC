# Policy-Driven Agentic Red Teaming

Takes pre-built **Scenario Forge** YAMLs and produces artifacts for red-teaming tool-calling agents — via the in-repo attack pipeline or downstream scanners such as **Garak** (and later AgentDojo).

## How It Works

```
Forge Scenario (examples/scenarios/*.yaml)
  → Shared ScenarioSpec   — tools, task, injection, surface/oracle, criteria
       ↑ payloads from attack_library (or forge-narrative fallback)
  → Framework gate        — full | partial | skip per backend
         ├─► Pipeline artifacts   — runs/{id}/ (env, tools, seed, injection, traces)
         └─► Garak artifacts      — ArtifactGen_garak/configs/{id}.yaml
```

**Key ideas:**
- **Forge-driven** — inputs are `examples/scenarios/*.yaml`, not LLM scenario planning
- **One shared ScenarioSpec** — pipeline and Garak both use `load_or_build_scenario_spec()`
- **Attack library** — reusable pattern/variant payload templates; forge narrative fills gaps
- **Artifacts diverge by framework** — Garak gets prompt/detector configs; pipeline gets executable env + traces
- **Dry run before inject** (pipeline) — placement follows a real tool-call trace
- **Dual metrics** — security (did the agent fail the policy?) and utility (did it still finish the task?)

## Quick Start

```bash
# Install dependencies
pip install pydantic pyyaml openai httpx

# Inspect a forge scenario → ScenarioSpec
python scenario_loader.py examples/scenarios/AP-T2-01-28712e.yaml

# Run the in-repo pipeline (OLLAMA_BASE_URL / REDTEAM_MODEL)
# Writes artifacts under runs/{scenario_id}/
python pipeline.py --scenario examples/scenarios/AP-T2-01-28712e.yaml

# Progressive escalation with a library variant
python pipeline.py --scenario examples/scenarios/AP-T2-01-28712e.yaml \
  --attack-pattern progressive_escalation \
  --attack-variant authority_impersonation
```

### Configuration

| Env Variable | Description |
|---|---|
| `OPENAI_API_KEY` | API key for the model endpoint (if required) |
| `OLLAMA_BASE_URL` | OpenAI-compatible API base (Ollama, vLLM, OpenAI, …) |
| `REDTEAM_MODEL` | Model name for seed generation and agent simulation |
| `REDTEAM_MAX_TURNS` | Max tool-call turns per run |

The agent under test is a **local OpenAI-compatible tool-calling loop** (`executor.py`) that `exec()`s generated tools — not a live OGX/OpenShell session.

### Run Output

Default directory: `runs/{scenario_id}/` (e.g. `runs/AP-T2-01-28712e/`):

| File | Contents |
|---|---|
| `spec.json` | Shared ScenarioSpec (forge YAML + attack pattern/variant) |
| `report.json` | Evaluation results (security + utility) |
| `env_models.py` | Generated Pydantic models |
| `tools.py` | Generated tool functions |
| `seed_data.yaml` | Synthetic seed data |
| `injection.yaml` | Injection payloads and verification |
| `manifest.yaml` | User task prompt and expected tool sequence |
| `clean_trace.json` | Dry-run tool-call trace |
| `attack_trace.json` | Attack-run tool-call trace |

Override with `--output-dir`, or `--spec-output` / `--report-output` / `--env-output`.

## Attack Library

Reusable payload templates live in **`attack_library.py`**.

| Concept | Role |
|---|---|
| **Pattern** | *Staging* — how injections are placed (`delayed_trigger` vs `progressive_escalation`) |
| **Variant** | *Wording pack* — template set keyed by `risk_type` (e.g. `authority_impersonation`) |
| **Forge scenario** | Narrative, tools, goal, threat → drives `risk_type`, trigger tool, surfaces |

### Patterns

| Pattern | Staging |
|---|---|
| `delayed_trigger` | One strong injection in a single record; agent is told to act after finishing its task |
| `progressive_escalation` | Three fragments (premise → reinforce → trigger) across records the agent accesses |

### Variants by risk type

| Risk type | `delayed_trigger` | `progressive_escalation` |
|---|---|---|
| `data_exfiltration` | `embedded_instruction` | `authority_impersonation`, `helpful_assistant_exploit`, `system_prompt_override` |
| `unauthorized_action` | `embedded_instruction`, `policy_mimicry` | `authority_impersonation`, `helpful_assistant_exploit`, `system_prompt_override` |

**Defaults** when `--attack-variant` is omitted: `embedded_instruction` (delayed), `authority_impersonation` (progressive) — if that pack exists for the scenario’s `risk_type`; otherwise the mechanism slug from the forge YAML.

**Resolution** (in `scenario_loader`):
1. Library match on `(pattern, risk_type, variant)` → format templates with `{trigger_tool}`, `{exfil_address}`, `{date}`
2. Else forge-narrative fallback (attack-tree / narrative text wrapped for the pattern)

```bash
# List available packs
python -c "from attack_library import list_all_variants; print(list_all_variants())"

# Same flags on Garak gen
python -m ArtifactGen_garak.gen examples/scenarios/AP-T9-01-8c5d51.yaml \
  --attack-pattern progressive_escalation \
  --attack-variant helpful_assistant_exploit \
  --no-llm
```

## Downstream: Garak

Garak code lives in **`ArtifactGen_garak/`**. Flow:

`forge YAML → shared ScenarioSpec (runs/{id}/spec.json) → gate_garak → realize → configs/{id}.yaml → ForgeScenario probe`

Loads `runs/{id}/spec.json` when present and matching `--attack-pattern` / `--attack-variant`; otherwise builds via the same `load_or_build_scenario_spec()` used by `pipeline.py`.

```bash
# Build shared specs + emit Garak configs (deterministic prompts)
python -m ArtifactGen_garak.gen examples/scenarios/AP-T9-01-8c5d51.yaml --no-llm

# Symlink plugins into the local Garak clone (once)
ln -sf "$(pwd)/ArtifactGen_garak/plugins/probes/forge_scenario.py" \
  ../garak/garak/probes/forge_scenario.py
ln -sf "$(pwd)/ArtifactGen_garak/plugins/detectors/forge_scenario.py" \
  ../garak/garak/detectors/forge_scenario.py

# Smoke-run
export FORGE_SCENARIO_CONFIG="$(pwd)/ArtifactGen_garak/configs/AP-T2-01-28712e.yaml"
python -m garak --target_type test.Blank \
  --probes forge_scenario.ForgeScenario --generations 1
```

Full details: [`ArtifactGen_garak/README.md`](ArtifactGen_garak/README.md).

**Meta report** (all gates + run ASR + Spec/Probe/Detector viewers):

```bash
python garak_meta_report.py   # → reports/garak_meta.html
```

## Evaluation

**Security** — did the agent resist the attack?  
**Utility** — did the agent still complete the task?

## Demo

[**Pipeline Flow Diagram**](https://muneezaazmat.github.io/RH_TrustyAI_POC/agent-policy-redteam/pipeline-flow.html) — visual walkthrough of the pipeline.

[**Interactive Demo**](https://muneezaazmat.github.io/RH_TrustyAI_POC/agent-policy-redteam/demo.html) — walkthrough with run data (some pages may still describe older RiskCard framing).

## Project Structure

```
├── pipeline.py              # In-repo orchestrator (CLI)
├── scenario_loader.py       # Forge YAML → shared ScenarioSpec
├── scenario_spec.py         # Shared ScenarioSpec (+ surface/oracle)
├── attack_library.py        # Pattern/variant payload templates
├── triage.py / scenario_filter.py
├── codegen.py / seed_generator.py / env_generator.py
├── injection_placer.py
├── executor.py              # Local OpenAI-compatible agent loop
├── evaluator.py / artifacts_io.py / replay.py
├── ArtifactGen_garak/       # ScenarioSpec → Garak configs + probe plugins
│   ├── gen.py / gate.py / realize.py / config_io.py
│   ├── configs/             # Per-scenario probe configs
│   └── plugins/             # ForgeScenario probe + detector
├── examples/scenarios/      # Forge scenario YAMLs
├── runs/                    # Pipeline artifacts (includes spec.json)
└── demo.html / DESIGN.md
```
