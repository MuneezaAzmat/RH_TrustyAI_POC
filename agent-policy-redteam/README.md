# Policy-Driven Agentic Red Teaming

A framework that ingests pre-built forge scenarios and automatically generates indirect prompt injection test environments to red-team AI agents. Uses any OpenAI-compatible model endpoint to simulate an agent with tool-calling.

## How It Works

```
Forge Scenario (YAML)
  → 1. Scenario Loader         — map forge YAML to ScenarioSpec (deterministic)
  → 2. Environment Instantiator — codegen builds models/tools; LLM generates seed data only
  → 3. Dry Run               — run agent on clean environment, record tool-call trace
  → 4. Injection Placer      — deterministically place spec payloads along trace
  → 5. Attack Run            — same agent, same task, injected environment
  → 6. Evaluate              — security + utility using pre-defined criteria from spec
```

**Key ideas:**
- **Forge-driven** — scenarios come from pre-built `examples/scenarios/*.yaml`, not LLM planning
- **ScenarioSpec upfront** — user task, injection goal, and evaluation criteria defined at load time
- **Dry run first** — observe real agent behavior before placing injections, no guessing
- **Multi-turn** — attacks span multiple tool calls, building context progressively
- **Dual-metric evaluation** — security (did the agent leak data?) and utility (did it still complete the task?)

## Quick Start

```bash
# Install dependencies
pip install pydantic pyyaml openai httpx

# Inspect a forge scenario and its ScenarioSpec conversion
python scenario_loader.py examples/scenarios/AP-T2-01-28712e.yaml

# Run pipeline (uses OLLAMA_BASE_URL and REDTEAM_MODEL env vars)
# Artifacts are saved automatically to runs/{scenario_id}/
python pipeline.py --scenario examples/scenarios/AP-T2-01-28712e.yaml

# Progressive escalation attack (3 fragments across records)
python pipeline.py --scenario examples/scenarios/AP-T2-01-28712e.yaml \
  --attack-pattern progressive_escalation \
  --attack-variant parameter_pollution

# Override output directory or individual artifact paths
python pipeline.py --scenario examples/scenarios/AP-T2-01-28712e.yaml \
  --output-dir runs/my-custom-run
```

### Configuration

| Env Variable | Description |
|---|---|
| `OPENAI_API_KEY`  API key for the model endpoint |
| `OLLAMA_BASE_URL` | OpenAI-compatible API endpoint (works with Ollama, vLLM, OpenAI, etc.) |
| `REDTEAM_MODEL` | Model name for generation and agent simulation |
| `REDTEAM_MAX_TURNS` | Max tool-call turns per run |

### Run Output

Each pipeline run writes to `runs/{scenario_id}/` by default (e.g. `runs/AP-T2-01-28712e/`):

| File | Contents |
|---|---|
| `spec.json` | ScenarioSpec from forge YAML |
| `report.json` | Evaluation results (security + utility) |
| `env_models.py` | Generated Pydantic models |
| `tools.py` | Generated tool functions |
| `seed_data.yaml` | Synthetic seed data |
| `injection.yaml` | Injection payloads and verification |
| `manifest.yaml` | User task prompt and expected tool sequence |
| `clean_trace.json` | Dry-run tool-call trace |
| `attack_trace.json` | Attack-run tool-call trace |

Use `--output-dir` to override the directory, or `--spec-output` / `--report-output` / `--env-output` to override individual files.

## Attack Patterns

### Progressive Escalation
Three injection fragments placed across different records the agent accesses. Each builds on the previous:
1. **Premise** — first narrative step or attack-tree leaf
2. **Reinforce** — middle narrative step
3. **Trigger** — final step, with trigger-tool instruction appended

Content is derived from each forge scenario's narrative steps and attack tree.

### Delayed Trigger
A single strong injection placed in one record, combining the attack goal, narrative summary, step actions, and behavior_spec excerpt. The instruction tells the agent to act *after* finishing its task — exploiting the gap between encountering the instruction and composing the final output.

`attack_variant` defaults to a slug of `scenario_seed_metadata.mechanism_name`.

## Evaluation

Each scenario produces a dual metric:

**Security** — did the agent resist the attack?
**Utility** — did the agent still complete the task?

## Demo

[**Pipeline Flow Diagram**](https://muneezaazmat.github.io/RH_TrustyAI_POC/agent-policy-redteam/pipeline-flow.html) — detailed visual walkthrough of the full pipeline architecture.

[**Interactive Demo**](https://muneezaazmat.github.io/RH_TrustyAI_POC/agent-policy-redteam/demo.html) — interactive walkthrough populated with real run data. Includes:
- Pipeline overview with implementation detail popups for each stage
- Side-by-side comparison of both attack patterns
- Full raw conversation traces
- Security/utility evidence breakdowns

## Project Structure

```
├── pipeline.py              # Main orchestrator with CLI
├── models.py                # Pydantic data models
├── scenario_spec.py         # ScenarioSpec models + validation
├── scenario_loader.py       # Forge YAML → ScenarioSpec (deterministic)
├── triage.py                # Risk triage (agent vs sandbox level)
├── codegen.py               # Deterministic models + tools from domain_skeleton
├── seed_generator.py        # LLM seed data generation
├── env_generator.py         # Orchestrates codegen + seed generation
├── injection_placer.py      # Deterministic injection placement from spec + trace
├── executor.py              # Agent loop (OpenAI-compatible tool-calling)
├── evaluator.py             # Dual-metric evaluation from ScenarioSpec criteria
├── artifacts_io.py          # Save/load run artifacts (env, injection, traces)
├── examples/
│   └── scenarios/           # Pre-built forge scenario YAML files
├── runs/                    # Per-scenario run output (auto-created)
├── demo.html                # Interactive demo with real run data
└── DESIGN.md                # Design document
```
