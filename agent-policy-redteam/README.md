# Policy-Driven Agentic Red Teaming

Takes pre-built **scenario** YAMLs, classifies their injection surface, and generates red-teaming artifacts that can be run on downstream evaluation platforms.

```
examples/scenarios/*.yaml
  → classify (injection surface + platform coverage)
  → generate a platform-specific artifact
  → runs/{scenario_id}/
```

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env   # set GEMINI_API_KEY or configure Ollama
```

Supported LLM backends: **Gemini** (default when `GEMINI_API_KEY` is set) or **Ollama** (`REDTEAM_PROVIDER=ollama`).

## How it works

1. **Classify** the injection surface from the scenario seed (`user_turn`, `tool_return`, `system_prompt`, or skip).
2. **Skip** surfaces the target platform cannot express.
3. **Generate** a red-teaming artifact for that platform (transcript, probe, or equivalent).
4. **Validate** structural gates so the artifact is runnable downstream.
5. **Gate** platform coverage: `full`, `partial`, or `skip`.

## Supported platforms

| Platform | Status | Details |
|----------|--------|---------|
| [Garak](https://github.com/NVIDIA/garak) | Supported | [ArtifactGen_garak/README.md](ArtifactGen_garak/README.md) |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | Planned | — |
| [PyRIT](https://github.com/Azure/PyRIT) | Planned | — |

Each platform generator lives in its own `ArtifactGen_<platform>/` directory and writes artifacts under `runs/`.

## Project structure

```
├── ArtifactGen_garak/          # Garak artifact generator (supported)
├── examples/scenarios/         # Input scenario YAMLs
└── runs/                       # Generated artifacts (gitignored)
```
