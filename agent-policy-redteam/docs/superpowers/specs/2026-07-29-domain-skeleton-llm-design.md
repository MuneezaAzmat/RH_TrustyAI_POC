# DraftSpec extract + grounded LlmSpec rewrite

**Date:** 2026-07-29  
**Status:** Approved for planning  
**Scope:** Replace hardcoded finance/HR domain defaults in `scenario_loader.py` with a scenario-derived `DraftSpec` completed by an LLM into frozen `ScenarioSpec.llm_spec`.

The **full and final spec file** is `runs/{id}/spec.json`. That file is a `ScenarioSpec`. `llm_spec` is one field inside it (tools, entities, seed constraints), not the whole file.

## Names

| Name | What it is |
|---|---|
| **DraftSpec** | Incomplete environment spec pulled from the scenario YAML. Gaps allowed. No silent finance/HR fillers. |
| **`draft_spec.py`** | Deterministic extractor that builds the `DraftSpec`. |
| **LlmSpec** | Complete, codegen-ready tools/entities. LLM rewrite of the `DraftSpec`, then frozen as `llm_spec` in `spec.json`. |
| **`llm_gen_spec.py`** | LLM rewriter: `DraftSpec` + narrative → `LlmSpec`. |
| **ScenarioSpec** | Full frozen spec. Written to `runs/{id}/spec.json`. |

## Goal

No silent default tool packs (`_FINANCE_READ_TOOLS`, `_FINANCE_TRIGGER_TOOL`, `_FINANCE_TARGET_SURFACES`, etc.). Domain tools and entities are inferred from the scenario as a `DraftSpec`, completed where needed by an LLM grounded in that draft, frozen in `runs/{id}/spec.json`, then used for deterministic artifact generation (LLM only where already needed, e.g. seed data).

## Non-goals (this change)

- New CLI flags such as `--rebuild-spec`
- New idempotency / source-tag machinery beyond what `load_or_build_scenario_spec` already does
- Changing Garak probe plugins or evaluation logic
- Making `codegen.py` LLM-driven (stays template-based from frozen `LlmSpec`)

## Approach

**Full rewrite grounded in a deterministic DraftSpec** (not patch-only, not suggest-only):

1. Deterministically extract what the scenario YAML already implies (`draft_spec.py` → `DraftSpec`).
2. Always run the LLM over that `DraftSpec` to produce a complete `LlmSpec`.
3. Validate anchors + schema + codegen constraints.
4. Persist into `ScenarioSpec.llm_spec` / `spec.json`.
5. Downstream (`codegen`, seed, injection, ArtifactGen) consume the frozen spec unchanged.

## Data flow

```
scenario YAML
  → draft_spec.py       (named tools, surfaces, entity hints, trigger)
  → DraftSpec           (may be incomplete; no silent finance fillers)
  → llm_gen_spec.py     (input = narrative + DraftSpec; output = LlmSpec JSON)
  → validate            (Pydantic, anchors, ScenarioSpec consistency, codegen categories)
  → freeze LlmSpec in runs/{id}/spec.json as llm_spec
  → deterministic artifacts from frozen ScenarioSpec
```

### LLM rewrite rules

- **Must keep** every tool name, surface, and entity name already present in the `DraftSpec` (anchors).
- **May add** missing read tools, fields, privileged/communicate tools appropriate to the scenario.
- **May refine** descriptions, parameters, `record_count`, `seed_data_constraints`.
- **Must not** invent tool categories outside what `codegen` supports: `read` | `write` | `communicate` | `privileged`.

## Components

### 1. Deterministic extractor (`draft_spec.py`)

- Extract from scenario narrative / behavior_spec / attack tree text only.
- Emit an honest `DraftSpec` (gaps allowed).
- Remove `_FINANCE_*` (and similar) silent fillers from `scenario_loader.py`.

### 2. LLM rewriter (`llm_gen_spec.py`)

- Inputs: scenario narrative excerpts + `DraftSpec` JSON + category constraints.
- Output: complete `LlmSpec` JSON.
- Prompt: preserve `DraftSpec` anchors; complete and refine around them.

### 3. Validator / gate

- Parse the rewrite into Pydantic `LlmSpec`.
- Anchor check: `DraftSpec` tool names ⊆ rewritten tool names; draft surfaces appear on entities or injection surfaces.
- Existing `ScenarioSpec` consistency (trigger ∈ tools, forbidden actions, etc.).
- Reject categories/shapes `codegen` cannot emit.

### 4. Spec freeze

- Write the completed `LlmSpec` into `ScenarioSpec.llm_spec` via existing `write_scenario_spec`.
- Leave existing disk-load behavior of `load_or_build_scenario_spec` as-is (do not expand).

### 5. Unchanged downstream

- `codegen.py`, `seed_generator.py`, `injection_placer.py`, `ArtifactGen_garak` continue to consume frozen `spec.json`.

## Error handling

- Small fixed retry count on LLM / parse / validation failure (same spirit as `seed_generator` / `realize`).
- After retries: **fail loudly** with the `DraftSpec` + validation errors. No hardcoded finance fallback.
- Optional reuse of existing `--no-llm` where present: extract-only; if the `DraftSpec` does not validate as a complete buildable `LlmSpec`, error listing gaps. No new flags required for this design.

## Testing (lean)

- Unit: `draft_spec.py` extract on sample scenario YAMLs (tools/surfaces from text; no `_FINANCE_*` constants).
- Unit: anchor check rejects a rewrite that drops a `DraftSpec` tool name.
- Unit with mocked LLM client: fixed JSON → valid `LlmSpec` usable in a buildable `ScenarioSpec`.
- No mandatory live-LLM CI for this change.

## Success criteria

- Building a spec no longer depends on hardcoded finance/HR tool packs.
- `DraftSpec` comes from the scenario via `draft_spec.py`; LLM always audits/completes grounded in that draft.
- Frozen `llm_spec` in `runs/{id}/spec.json` is a complete `LlmSpec` sufficient for deterministic codegen.
- Failures are explicit when extract + LLM cannot produce a valid spec.
