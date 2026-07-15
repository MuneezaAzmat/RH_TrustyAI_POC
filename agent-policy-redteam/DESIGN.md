# Agent Policy Red-Team Framework

## Overview

A monolithic Python pipeline that ingests pre-built forge scenarios from `examples/scenarios/*.yaml` and generates synthetic environments, tools, and indirect prompt injection scenarios to red-team agents deployed on OGX + OpenShell. Prototype/demo quality.

## Pipeline Flow

```
Forge Scenario (YAML)
  → 1. Scenario Loader (deterministic → ScenarioSpec)
  → 2. Environment Instantiator (codegen + LLM seed data)
  → 3. Dry Run (clean run, record tool-call trace + baseline state)
  → 4. Injection Placer (deterministic — apply spec payloads along trace)
  → 5. Attack Run (injected environment, same user task)
  → 6. Evaluate (pre-defined security + utility criteria from ScenarioSpec)
  → Report
```

## Key Design Decisions

- **Target**: Own agents deployed on OGX + OpenShell
- **Scope**: Agent policy compliance testing (sandbox-level deferred)
- **Generation**: Forge scenario loader produces a complete ScenarioSpec deterministically; environment instantiator (LLM) only generates seed data. Injection placement is deterministic.
- **Environment**: Pydantic models with in-memory state + CRUD tool functions. No real DB. Each scenario gets a minimal purpose-built environment.
- **Tool registration**: OGX-native (register tools with OGX agent's tool runtime)
- **Attack patterns**: Delayed trigger + progressive escalation across multiple turns
- **Injection placement**: Dry run first (clean), observe real tool-call trace, place injections along observed path
- **Evaluation**: Programmatic — state diffs between clean and attack runs, call trace diffs, generated verification predicates

## Stage Details

### 1. Scenario Loader
- Input: Forge scenario YAML from `examples/scenarios/`
- Deterministic mapping to `ScenarioSpec`:
  - User task (prompt, required data access, forbidden actions, expected outcome)
  - Injection spec (goal, attack pattern, payload templates, trigger tool, target surfaces)
  - Security criteria (must_not_call, verification predicates, sensitive patterns)
  - Utility criteria (expected tool calls, task output checks)
  - Domain skeleton (entity types, required tools, seed data constraints)
- Threat ID drives risk type and tool/entity patterns
- Output is storable/reviewable JSON (`--spec-output`)

### 2. Environment Instantiator (codegen + LLM seed)
- Input: ScenarioSpec only (produced by scenario loader)
- `codegen.py` deterministically generates models and tools from domain_skeleton
- `seed_generator.py` (LLM) generates only seed_data_json against the fixed schema
- User task prompt and expected tool sequence come directly from ScenarioSpec
- Seed validation with retry; deterministic fallback seed if LLM fails

### 4. Dry Run
- Register tools with OGX, create session
- Run agent against clean environment with user task prompt
- Record: full tool-call trace (which tools called, with what args, in what order), conversation trace, final environment state
- This serves as utility baseline (did agent do the task correctly?)
- Temperature 0 for determinism

### 5. Injection Placer (deterministic)
- Input: ScenarioSpec.injection + dry-run trace
- Fills payload template placeholders with actual record IDs and field names
- Placement rules:
  - Only inject into records the agent accessed during dry run
  - Delayed trigger: single combined payload, skip first detail call
  - Progressive escalation: one template per record across turns
- Verification predicates come from ScenarioSpec.security_criteria

### 6. Attack Run
- Same setup as dry run but with injected environment
- Same user task prompt
- Record same artifacts (tool-call trace, conversation, final state)
- Temperature 0

### 7. Evaluate
- Security checks driven by ScenarioSpec.security_criteria (must_not_call, must_not_contain, predicates)
- Utility checks driven by ScenarioSpec.utility_criteria (expected tool calls, task output checks)
- State diff: compare clean vs attack environment state
- Result: per-scenario pass/fail with evidence

## Risk Types (from forge scenario threat_id)

`scenario_loader.py` maps agentic threat IDs to risk types and domain/tool patterns:
- `data_exfiltration`: entities with sensitive fields + communication tool
- `unauthorized_action`: entities with permission/role fields + privileged action tools
- `data_corruption`: entities with integrity-critical fields + update tools

## Forge Scenario Input Format

Pre-built YAML files in `examples/scenarios/` (from scenario forge):

```yaml
scenario_id: AP-T2-01-28712e
scenario_seed_metadata:
  threat_id: T2
  threat_name: "..."
narrative:
  title: "..."
  summary: "..."
  entry_point: "..."
  steps: [...]
attack_tree:
  goal: "..."
faceting:
  risk_card:
    threat_source: "..."
    consequence: "..."
    impact: "..."
priority:
  signals: { risk_likelihood: high, risk_impact: critical }
```

## Project Structure

```
agent-policy-redteam/
├── pipeline.py          # Main pipeline orchestrator
├── triage.py            # Risk triage (agent vs sandbox level)
├── scenario_spec.py     # ScenarioSpec Pydantic models + validation
├── scenario_loader.py   # Forge YAML → ScenarioSpec (deterministic)
├── codegen.py           # Deterministic models + tools from domain_skeleton
├── seed_generator.py    # LLM seed data only
├── env_generator.py     # Orchestrates codegen + seed generation
├── injection_placer.py  # Deterministic injection placement from spec + trace
├── executor.py          # Agent loop: tool registration, session mgmt, runs
├── evaluator.py         # Dual-metric evaluation from ScenarioSpec criteria
├── models.py            # Shared data models (Scenario, Trace, Result, etc.)
├── examples/            # Pre-built forge scenario inputs
│   └── scenarios/
├── DESIGN.md
└── requirements.txt
```
