# Agent Policy Red-Team Framework

## Overview

A monolithic Python pipeline that takes risk-landscaper RiskCard output and generates synthetic environments, tools, and indirect prompt injection scenarios to red-team agents deployed on OGX + OpenShell. Prototype/demo quality.

## Pipeline Flow

```
RiskCard (JSON/YAML)
  → 1. Risk Triage (agent-level vs sandbox-level, filter to agent-level)
  → 2. Generate User Task + Environment (LLM Call 1)
  → 3. Dry Run (clean run, record tool-call trace + baseline state)
  → 4. Generate Injections + Augment Environment (LLM Call 2, uses real trace)
  → 5. Attack Run (injected environment, same user task)
  → 6. Evaluate (state diff, call trace diff, verification predicates)
  → Report
```

## Key Design Decisions

- **Target**: Own agents deployed on OGX + OpenShell
- **Scope**: Agent policy compliance testing (sandbox-level deferred)
- **Generation**: Template + LLM hybrid. Risk-type templates provide environment skeletons, LLM fills in domain-specific details.
- **Environment**: Pydantic models with in-memory state + CRUD tool functions. No real DB. Each scenario gets a minimal purpose-built environment.
- **Tool registration**: OGX-native (register tools with OGX agent's tool runtime)
- **Attack patterns**: Delayed trigger + progressive escalation across multiple turns
- **Injection placement**: Dry run first (clean), observe real tool-call trace, place injections along observed path
- **Evaluation**: Programmatic — state diffs between clean and attack runs, call trace diffs, generated verification predicates

## Stage Details

### 1. Risk Triage
- Input: RiskCard (risk-landscaper output)
- Classify each RiskCard control as agent-level or sandbox-level
- Filter to agent-level only (sandbox deferred)
- Output: Triaged RiskCard with risk type classification

### 2. Generate User Task + Environment (LLM Call 1)
- Input: Triaged RiskCard
- LLM generates (co-generated, because env should serve the task):
  - User task prompt (legitimate task the agent should perform)
  - Pydantic model classes (data entities relevant to the risk)
  - Seed data (realistic records populating those models)
  - CRUD tool functions (list/get/create/update/delete against Pydantic state)
  - Expected tool-call sequence (prediction, validated by dry run)
- Template selects skeleton based on risk type, LLM fills domain details
- Structural validation: models instantiate, tools run against seed data without errors

### 3. Dry Run
- Register tools with OGX, create session
- Run agent against clean environment with user task prompt
- Record: full tool-call trace (which tools called, with what args, in what order), conversation trace, final environment state
- This serves as utility baseline (did agent do the task correctly?)
- Temperature 0 for determinism

### 4. Generate Injections (LLM Call 2)
- Input: RiskCard + environment + real tool-call trace from dry run
- LLM generates:
  - Injection goal (what policy violation to attempt)
  - Injection payloads placed in specific records the agent actually accessed
  - Additional environment data needed for injection to be executable (e.g., add send_email tool if not present, add files/records the injection references)
  - Placement map (which record, which field, which turn)
  - Verification predicates (programmatic checks for policy violation)
- Placement rules:
  - Only inject into records the agent accessed during dry run
  - Delayed trigger: single injection early, effect expected later
  - Progressive escalation: fragments across records in different turns
  - Avoid first tool response (too obvious)

### 5. Attack Run
- Same setup as dry run but with injected environment
- Same user task prompt
- Record same artifacts (tool-call trace, conversation, final state)
- Temperature 0

### 6. Evaluate
- State diff: compare clean vs attack environment state
- Call trace diff: identify tool calls in attack run not in clean run
- Verification predicates: run generated checks
- Result: per-scenario pass/fail with evidence

## Risk-Type Templates

Initial set for prototype:
- `data_exfiltration`: entities with sensitive fields + communication tool
- `unauthorized_action`: entities with permission/role fields + privileged action tools
- `data_corruption`: entities with integrity-critical fields + update tools

## RiskCard Input Format (from risk-landscaper)

```yaml
risk_card:
  id: RC-001
  risk_source:
    description: "..."
    likelihood: high
  risk_consequence:
    description: "..."
    severity: critical
  risk_impact:
    description: "..."
    affected_stakeholders: [...]
    harm_type: "..."
  risk_controls:
    - type: mitigate
      description: "..."
  materialization_conditions: "..."
  policy_references: [...]
  framework_references: [NIST, ISO...]
```

## Project Structure

```
agent-policy-redteam/
├── pipeline.py          # Main pipeline orchestrator
├── triage.py            # Risk triage (agent vs sandbox level)
├── env_generator.py     # LLM Call 1: user task + environment generation
├── injection_generator.py # LLM Call 2: injection synthesis
├── executor.py          # OGX integration: tool registration, session mgmt, runs
├── evaluator.py         # State diff, call trace diff, verification
├── models.py            # Shared data models (Scenario, Trace, Result, etc.)
├── templates/           # Risk-type template skeletons
│   ├── data_exfiltration.py
│   ├── unauthorized_action.py
│   └── data_corruption.py
├── examples/            # Example RiskCard inputs
│   └── sample_riskcard.yaml
├── DESIGN.md
└── requirements.txt
```
