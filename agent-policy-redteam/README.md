# Policy-Driven Agentic Red Teaming

A framework that takes structured risk assessments from [risk-landscaper](https://github.com/hjrnunes/risk-landscaper) and automatically generates indirect prompt injection scenarios to red-team AI agents. Uses any OpenAI-compatible model endpoint to simulate an agent with tool-calling. 

## How It Works

```
RiskCard (YAML)
  → 1. Risk Triage        — classify as agent-level vs sandbox-level
  → 2. Generate Environment — LLM co-generates user task + Pydantic models + CRUD tools + seed data
  → 3. Dry Run             — run agent on clean environment, record tool-call trace
  → 4. Inject Attacks      — place payloads along the observed trace (library or LLM-generated)
  → 5. Attack Run          — same agent, same task, injected environment
  → 6. Evaluate            — security (state diff, call trace, predicates) + utility (task completion)
```

**Key ideas:**
- **Policy-driven** — scenarios are generated from structured risk mappings.
- **Dry run first** — observe real agent behavior before placing injections
- **Multi-turn** — attacks span multiple tool calls, progressive atatck building
- **Dual-metric evaluation** — security (did the agent leak data?) and utility (did it still complete the task?)

## Quick Start

```bash
# Install dependencies
pip install pydantic pyyaml openai httpx

# Run (uses OPENAI_BASE_URL and REDTEAM_MODEL env vars)
python pipeline.py --riskcard examples/sample_riskcard.yaml

# Progressive escalation attack (3 fragments across records)
python pipeline.py --riskcard examples/sample_riskcard.yaml \
  --attack-pattern progressive_escalation \
  --attack-variant authority_impersonation

# Delayed trigger attack (single payload)
python pipeline.py --riskcard examples/sample_riskcard.yaml \
  --attack-pattern delayed_trigger \
  --attack-variant embedded_instruction

# Save JSON report
python pipeline.py --riskcard examples/sample_riskcard.yaml \
  --attack-pattern progressive_escalation \
  --report-output report.json
```

### Configuration

| Env Variable | Description |
|---|---|
| `OPENAI_API_KEY`  API key for the model endpoint |
| `OLLAMA_BASE_URL` | OpenAI-compatible API endpoint (works with Ollama, vLLM, OpenAI, etc.) |
| `REDTEAM_MODEL` | Model name for generation and agent simulation |
| `REDTEAM_MAX_TURNS` | Max tool-call turns per run |

## Attack Patterns

### Progressive Escalation
Three injection fragments placed across different records the agent accesses. Each builds on the previous:
1. **Premise** — establishes a fake compliance directive
2. **Reinforce** — references the directive, adds urgency
3. **Trigger** — instructs the agent to exfiltrate data

Variants: `authority_impersonation`, `helpful_assistant_exploit`, `system_prompt_override`

### Delayed Trigger
A single strong injection placed in one record. The instruction tells the agent to act *after* finishing its task — exploiting the gap between encountering the instruction and composing the final output.

Variants: `embedded_instruction`

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
├── triage.py                # Risk triage (agent vs sandbox level)
├── env_generator.py         # LLM Call 1: user task + environment generation
├── injection_generator.py   # LLM Call 2 / attack library: injection synthesis
├── attack_library.py        # Hardcoded proven injection patterns
├── executor.py              # Agent loop (OpenAI-compatible tool-calling)
├── evaluator.py             # Dual-metric evaluation (security + utility)
├── templates/               # Risk-type template prompts
│   ├── data_exfiltration.py
│   ├── unauthorized_action.py
│   └── data_corruption.py
├── examples/
│   └── sample_riskcard.yaml # Example RiskCard input
├── demo.html                # Interactive demo with real run data
└── DESIGN.md                # Design document
```
