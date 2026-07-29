# Domain skeleton: extract + grounded LLM rewrite

**Date:** 2026-07-29  
**Status:** Approved for planning  
**Scope:** Replace hardcoded finance/HR domain defaults in `scenario_loader.py` with scenario-derived drafts completed by an LLM into frozen `ScenarioSpec.domain_skeleton`.

## Goal

No silent default tool packs (`_FINANCE_READ_TOOLS`, `_FINANCE_TRIGGER_TOOL`, `_FINANCE_TARGET_SURFACES`, etc.). Domain tools and entities are inferred from the forge scenario, completed where needed by an LLM grounded in that draft, frozen in `runs/{id}/spec.json`, then used for deterministic artifact generation (LLM only where already needed, e.g. seed data).

## Non-goals (this change)

- New CLI flags such as `--rebuild-spec`
- New idempotency / source-tag machinery beyond what `load_or_build_scenario_spec` already does
- Changing Garak probe plugins or evaluation logic
- Making `codegen.py` LLM-driven (stays template-based from frozen skeleton)

## Approach

**Full rewrite grounded in a deterministic draft** (not patch-only, not suggest-only):

1. Deterministically extract what the forge YAML already implies.
2. Always run the LLM over that draft to produce a complete `DomainSkeleton`.
3. Validate anchors + schema + codegen constraints.
4. Persist into `ScenarioSpec` / `spec.json`.
5. Downstream (`codegen`, seed, injection, ArtifactGen) consume the frozen spec unchanged.

## Data flow

```
forge YAML
  → deterministic extract  (named tools, surfaces, entity hints, trigger)
  → draft DomainSkeleton   (may be incomplete; no silent finance fillers)
  → LLM rewrite            (input = narrative + draft; output = full DomainSkeleton JSON)
  → validate               (Pydantic, anchors, ScenarioSpec consistency, codegen categories)
  → freeze in runs/{id}/spec.json
  → deterministic artifacts from frozen spec
```

### LLM rewrite rules

- **Must keep** every tool name, surface, and entity name already present in the draft (anchors).
- **May add** missing read tools, fields, privileged/communicate tools appropriate to the scenario.
- **May refine** descriptions, parameters, `record_count`, `seed_data_constraints`.
- **Must not** invent tool categories outside what `codegen` supports: `read` | `write` | `communicate` | `privileged`.

## Components

### 1. Deterministic extractor (refactor `scenario_loader`)

- Extract from forge narrative / behavior_spec / attack tree text only.
- Emit an honest draft `DomainSkeleton` (gaps allowed).
- Remove `_FINANCE_*` (and similar) silent fillers.

### 2. LLM domain rewriter (new module, e.g. `domain_skeleton_llm.py`)

- Inputs: forge narrative excerpts + draft skeleton JSON + category constraints.
- Output: complete `DomainSkeleton` JSON.
- Prompt: preserve draft anchors; complete and refine around them.

### 3. Validator / gate

- Parse into Pydantic `DomainSkeleton`.
- Anchor check: draft tool names ⊆ rewritten tool names; draft surfaces appear on entities or injection surfaces.
- Existing `ScenarioSpec` consistency (trigger ∈ tools, forbidden actions, etc.).
- Reject categories/shapes `codegen` cannot emit.

### 4. Spec freeze

- Write completed skeleton into `ScenarioSpec` via existing `write_scenario_spec`.
- Leave existing disk-load behavior of `load_or_build_scenario_spec` as-is (do not expand).

### 5. Unchanged downstream

- `codegen.py`, `seed_generator.py`, `injection_placer.py`, `ArtifactGen_garak` continue to consume frozen `spec.json`.

## Error handling

- Small fixed retry count on LLM / parse / validation failure (same spirit as `seed_generator` / `realize`).
- After retries: **fail loudly** with draft + validation errors. No hardcoded finance fallback.
- Optional reuse of existing `--no-llm` where present: extract-only; if draft does not validate as a complete buildable skeleton, error listing gaps. No new flags required for this design.

## Testing (lean)

- Unit: deterministic extract on sample forge YAMLs (tools/surfaces from text; no `_FINANCE_*` constants).
- Unit: anchor check rejects a rewrite that drops a draft tool name.
- Unit with mocked LLM client: fixed JSON → valid `DomainSkeleton` usable in a buildable `ScenarioSpec`.
- No mandatory live-LLM CI for this change.

## Success criteria

- Building a spec no longer depends on hardcoded finance/HR tool packs.
- Draft comes from the scenario; LLM always audits/completes grounded in that draft.
- Frozen `domain_skeleton` in `spec.json` is sufficient for deterministic codegen.
- Failures are explicit when extract + LLM cannot produce a valid skeleton.
