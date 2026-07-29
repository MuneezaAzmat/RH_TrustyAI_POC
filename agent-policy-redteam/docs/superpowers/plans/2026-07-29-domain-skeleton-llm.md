# Domain Skeleton LLM Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace hardcoded finance/HR domain tool packs with a deterministic draft extracted from forge YAML, always completed by an LLM grounded in that draft, then frozen in `ScenarioSpec.domain_skeleton`.

**Architecture:** `scenario_loader` extracts an honest (possibly incomplete) `DomainSkeleton` from scenario text. `domain_skeleton_llm.complete_domain_skeleton` sends narrative + draft to the LLM and returns a full skeleton that must preserve draft anchors. `forge_scenario_to_spec` uses the completed skeleton; downstream codegen stays deterministic.

**Tech Stack:** Python 3, Pydantic `DomainSkeleton` / `ScenarioSpec`, OpenAI-compatible client (same pattern as `seed_generator.py`), `unittest`.

## Global Constraints

- No silent `_FINANCE_*` / `_hr_exfil_*` default tool packs.
- LLM rewrite is grounded in the draft: draft tool/entity/surface names must be preserved.
- Tool categories limited to `read` | `write` | `communicate` | `privileged` (codegen-compatible).
- No new CLI flags (`--rebuild-spec`, etc.); leave `load_or_build_scenario_spec` disk behavior as-is.
- On LLM failure after retries: fail loudly — no finance fallback.
- Spec: `docs/superpowers/specs/2026-07-29-domain-skeleton-llm-design.md`.

## File map

| File | Responsibility |
|------|----------------|
| `domain_skeleton_llm.py` | Anchor validation, prompt, LLM rewrite, retries |
| `scenario_loader.py` | Deterministic draft extract; wire LLM into `forge_scenario_to_spec` |
| `test_domain_skeleton.py` | Extract, anchors, mocked LLM completion |
| `README.md` / `DESIGN.md` | Brief note that domain skeleton is extract + LLM, not finance defaults |

---

### Task 1: Anchor validation helpers

**Files:**
- Create: `domain_skeleton_llm.py`
- Test: `test_domain_skeleton.py`

**Interfaces:**
- Produces:
  - `CODEGEN_CATEGORIES: frozenset[str]`
  - `def validate_anchors(draft: DomainSkeleton, rewritten: DomainSkeleton) -> list[str]`
  - `def validate_codegen_categories(skeleton: DomainSkeleton) -> list[str]`

- [ ] **Step 1: Write the failing tests**

```python
"""Tests for domain skeleton extract + grounded LLM completion."""

import unittest

from scenario_spec import DomainSkeleton, EntityFieldSpec, EntitySpec, ToolSpec


def _tool(name: str, category: str = "read", params: list[str] | None = None) -> ToolSpec:
    return ToolSpec(
        name=name,
        category=category,
        description=f"{name} tool",
        parameters=params or [],
    )


def _skel(tools: list[ToolSpec], surfaces: list[str] | None = None) -> DomainSkeleton:
    fields = [EntityFieldSpec(name="id", field_type="string")]
    for s in surfaces or []:
        fields.append(EntityFieldSpec(name=s, field_type="string"))
    return DomainSkeleton(
        entity_types=[EntitySpec(name="Record", fields=fields, record_count=5)],
        required_tools=tools,
        seed_data_constraints=[],
    )


class TestAnchors(unittest.TestCase):
    def test_validate_anchors_accepts_superset(self):
        from domain_skeleton_llm import validate_anchors

        draft = _skel([_tool("process_refund", "privileged", ["transaction_id"])], ["notes"])
        rewritten = _skel(
            [
                _tool("list_transactions"),
                _tool("get_transaction_detail", params=["transaction_id"]),
                _tool("process_refund", "privileged", ["transaction_id", "refund_amount"]),
            ],
            ["notes", "status"],
        )
        self.assertEqual(validate_anchors(draft, rewritten), [])

    def test_validate_anchors_rejects_dropped_tool(self):
        from domain_skeleton_llm import validate_anchors

        draft = _skel([_tool("process_refund", "privileged")])
        rewritten = _skel([_tool("list_transactions")])
        errors = validate_anchors(draft, rewritten)
        self.assertTrue(any("process_refund" in e for e in errors))

    def test_validate_codegen_categories_rejects_unknown(self):
        from domain_skeleton_llm import validate_codegen_categories

        bad = _skel([_tool("weird", category="read")])
        # Force invalid category by mutating model dump path — use model_construct
        bad = DomainSkeleton(
            entity_types=bad.entity_types,
            required_tools=[
                ToolSpec.model_construct(
                    name="weird",
                    category="admin",
                    description="x",
                    parameters=[],
                )
            ],
        )
        errors = validate_codegen_categories(bad)
        self.assertTrue(any("admin" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m unittest test_domain_skeleton.TestAnchors -v`  
Expected: FAIL with `ModuleNotFoundError: domain_skeleton_llm` (or import error).

- [ ] **Step 3: Implement helpers**

Create `domain_skeleton_llm.py`:

```python
"""Grounded LLM completion of DomainSkeleton drafts from forge scenarios."""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from openai import OpenAI

from scenario_spec import DomainSkeleton, EntitySpec, ToolSpec

log = logging.getLogger(__name__)

CODEGEN_CATEGORIES = frozenset({"read", "write", "communicate", "privileged"})
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
MODEL = os.environ.get("REDTEAM_MODEL", "qwen2.5:14b")
MAX_RETRIES = 2
_client = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(base_url=OLLAMA_BASE_URL, api_key="ollama")
    return _client


def validate_anchors(draft: DomainSkeleton, rewritten: DomainSkeleton) -> list[str]:
    """Return errors if rewritten drops draft tool / entity / surface names."""
    errors: list[str] = []
    draft_tools = {t.name for t in draft.required_tools}
    rewritten_tools = {t.name for t in rewritten.required_tools}
    missing_tools = draft_tools - rewritten_tools
    if missing_tools:
        errors.append(f"rewritten skeleton dropped draft tools: {sorted(missing_tools)}")

    draft_entities = {e.name for e in draft.entity_types}
    rewritten_entities = {e.name for e in rewritten.entity_types}
    missing_entities = draft_entities - rewritten_entities
    if missing_entities:
        errors.append(f"rewritten skeleton dropped draft entities: {sorted(missing_entities)}")

    draft_fields: set[str] = set()
    for e in draft.entity_types:
        draft_fields.update(f.name for f in e.fields)
    rewritten_fields: set[str] = set()
    for e in rewritten.entity_types:
        rewritten_fields.update(f.name for f in e.fields)
    missing_fields = draft_fields - rewritten_fields
    if missing_fields:
        errors.append(f"rewritten skeleton dropped draft fields: {sorted(missing_fields)}")

    return errors


def validate_codegen_categories(skeleton: DomainSkeleton) -> list[str]:
    errors: list[str] = []
    for tool in skeleton.required_tools:
        if tool.category not in CODEGEN_CATEGORIES:
            errors.append(
                f"tool '{tool.name}' has unsupported category '{tool.category}'; "
                f"allowed={sorted(CODEGEN_CATEGORIES)}"
            )
    return errors
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest test_domain_skeleton.TestAnchors -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add domain_skeleton_llm.py test_domain_skeleton.py
git commit -m "Add domain skeleton anchor and category validators."
```

---

### Task 2: Deterministic draft extractor (no finance defaults)

**Files:**
- Modify: `scenario_loader.py` (remove `_FINANCE_*`, replace `_build_domain_skeleton` / infer helpers)
- Test: `test_domain_skeleton.py`

**Interfaces:**
- Produces:
  - `def extract_domain_draft(scenario: dict) -> DomainSkeleton`
  - `def extract_named_tools(scenario: dict) -> list[str]`
  - `def extract_target_surfaces(scenario: dict) -> list[str]`
  - `def extract_trigger_tool(scenario: dict) -> str | None`
- Removes: `_FINANCE_READ_TOOLS`, `_FINANCE_TRIGGER_TOOL`, `_FINANCE_TARGET_SURFACES`, `_finance_domain_skeleton`, `_hr_exfil_domain_skeleton` as silent fillers

- [ ] **Step 1: Write the failing extract tests**

Add to `test_domain_skeleton.py`:

```python
from pathlib import Path

from scenario_loader import extract_domain_draft, extract_named_tools, extract_trigger_tool, load_scenario

SCENARIOS = Path(__file__).parent / "examples" / "scenarios"


class TestExtractDraft(unittest.TestCase):
    def test_extract_trigger_from_ap_t2_text(self):
        loaded = load_scenario(SCENARIOS / "AP-T2-01-28712e.yaml")
        tools = extract_named_tools(loaded.raw)
        self.assertIn("process_refund", tools)
        self.assertEqual(extract_trigger_tool(loaded.raw), "process_refund")

    def test_draft_has_no_finance_filler_reads_when_not_in_text(self):
        """Draft must not invent list_transactions unless mentioned or later LLM-added."""
        loaded = load_scenario(SCENARIOS / "AP-T2-01-28712e.yaml")
        draft = extract_domain_draft(loaded.raw)
        tool_names = {t.name for t in draft.required_tools}
        # process_refund is in narrative; list_transactions may or may not be —
        # assert we never pull from removed _FINANCE_READ_TOOLS constant path:
        # if list_transactions appears, it must be in the scenario text.
        text = str(loaded.raw).lower()
        for name in tool_names:
            if name in ("list_transactions", "get_transaction_detail"):
                self.assertIn(name, text)

    def test_finance_constants_removed(self):
        import scenario_loader as sl

        self.assertFalse(hasattr(sl, "_FINANCE_READ_TOOLS"))
        self.assertFalse(hasattr(sl, "_FINANCE_TRIGGER_TOOL"))
        self.assertFalse(hasattr(sl, "_FINANCE_TARGET_SURFACES"))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m unittest test_domain_skeleton.TestExtractDraft -v`  
Expected: FAIL (functions missing / constants still present).

- [ ] **Step 3: Implement extract helpers and remove finance defaults**

In `scenario_loader.py`:

1. Delete `_FINANCE_TARGET_SURFACES`, `_FINANCE_READ_TOOLS`, `_FINANCE_TRIGGER_TOOL`.
2. Expand `_TOOL_NAME_PATTERN` if needed to catch backtick-quoted names already covered.
3. Replace infer/build functions with:

```python
def extract_named_tools(scenario: dict) -> list[str]:
    text = _scenario_text(scenario)
    found = [m.group(1).lower() for m in _TOOL_NAME_PATTERN.finditer(text)]
    # de-dupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for name in found:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def extract_trigger_tool(scenario: dict) -> str | None:
    tools = extract_named_tools(scenario)
    privileged_hints = (
        "process_refund",
        "modify_payment",
        "change_role",
        "grant_admin",
        "delete_user",
        "send_email",
    )
    for name in tools:
        if name in privileged_hints:
            return name
    return tools[-1] if tools else None


def extract_target_surfaces(scenario: dict) -> list[str]:
    text = _scenario_text(scenario).lower()
    for hint, surface in _SURFACE_HINTS:
        if hint in text:
            return [surface]
    return []  # honest gap — LLM must fill


def extract_domain_draft(scenario: dict) -> DomainSkeleton:
    """Build a possibly incomplete DomainSkeleton from forge text only."""
    tools_found = extract_named_tools(scenario)
    trigger = extract_trigger_tool(scenario)
    surfaces = extract_target_surfaces(scenario)

    fields = [EntityFieldSpec(name="id", sensitive=False, field_type="string")]
    for surface in surfaces:
        if not any(f.name == surface for f in fields):
            fields.append(EntityFieldSpec(name=surface, sensitive=False, field_type="string"))

    required_tools: list[ToolSpec] = []
    for name in tools_found:
        category = "communicate" if name == "send_email" or "email" in name else "privileged"
        if name.startswith(("list_", "get_", "search_")):
            category = "read"
        params: list[str] = []
        if category == "communicate":
            params = ["to", "subject", "body"]
        elif category == "privileged":
            params = ["transaction_id"] if "refund" in name or "payment" in name else []
        elif name.startswith("get_"):
            params = ["record_id"]
        required_tools.append(
            ToolSpec(name=name, category=category, description=f"From scenario: {name}", parameters=params)
        )

    entity_name = "Record"
    text_l = _scenario_text(scenario).lower()
    if "transaction" in text_l or "refund" in text_l:
        entity_name = "Transaction"
    elif "employee" in text_l:
        entity_name = "Employee"

    return DomainSkeleton(
        entity_types=[EntitySpec(name=entity_name, fields=fields, record_count=5)],
        required_tools=required_tools,
        seed_data_constraints=[],
    )
```

4. Keep `forge_scenario_to_spec` on the old call path for this task (Task 4 rewires it). In Task 2 only:

- Add `extract_named_tools`, `extract_trigger_tool`, `extract_target_surfaces`, `extract_domain_draft`.
- Delete `_FINANCE_*` constants and delete `_finance_domain_skeleton` / `_hr_exfil_domain_skeleton`.
- Point `_build_domain_skeleton` at the extract draft:

```python
def _build_domain_skeleton(
    scenario: dict,
    risk_type: str,
    domain: str,
    trigger_tool: str,
    target_surfaces: list[str],
) -> DomainSkeleton:
    return extract_domain_draft(scenario)
```

- Point surfaces/trigger helpers at extract (no silent defaults):

```python
def _infer_target_surfaces(scenario: dict) -> list[str]:
    return extract_target_surfaces(scenario)


def _infer_trigger_tool(scenario: dict) -> str:
    found = extract_trigger_tool(scenario)
    if not found:
        raise ValueError(
            f"No trigger tool named in scenario text "
            f"({scenario.get('scenario_id', '?')})"
        )
    return found
```

Note: until Task 4, `forge_scenario_to_spec` may fail on scenarios with empty surfaces (no longer defaulting to `notes`). That is expected; Task 4 completes surfaces via LLM.
- [ ] **Step 4: Run extract tests**

Run: `python -m unittest test_domain_skeleton.TestExtractDraft -v`  
Expected: PASS

Also run: `python -m unittest test_scenario_filter -v`  
Expected: PASS (volume filter unchanged).

- [ ] **Step 5: Commit**

```bash
git add scenario_loader.py test_domain_skeleton.py
git commit -m "Extract domain drafts from scenario text without finance defaults."
```

---

### Task 3: LLM rewriter (mocked)

**Files:**
- Modify: `domain_skeleton_llm.py`
- Test: `test_domain_skeleton.py`

**Interfaces:**
- Consumes: `validate_anchors`, `validate_codegen_categories`, draft `DomainSkeleton`
- Produces:
  - `def complete_domain_skeleton(scenario: dict, draft: DomainSkeleton, *, client=None, use_llm: bool = True) -> DomainSkeleton`
  - Raises `RuntimeError` if cannot produce a valid skeleton after retries
  - When `use_llm=False`: return draft only if anchors/categories OK **and** draft has ≥1 tool and ≥1 entity field beyond `id` or non-empty tools with surfaces handled by caller; otherwise raise listing gaps

- [ ] **Step 1: Write failing completion tests**

```python
class TestCompleteDomainSkeleton(unittest.TestCase):
    def test_mocked_llm_preserves_anchors_and_adds_reads(self):
        from domain_skeleton_llm import complete_domain_skeleton

        draft = _skel([_tool("process_refund", "privileged", ["transaction_id"])], ["notes"])

        class FakeChoices:
            def __init__(self, content):
                self.message = type("M", (), {"content": content})()

        class FakeResp:
            def __init__(self, content):
                self.choices = [FakeChoices(content)]

        class FakeClient:
            def __init__(self):
                self.chat = self
                self.completions = self

            def create(self, **kwargs):
                payload = {
                    "entity_types": [
                        {
                            "name": "Transaction",
                            "record_count": 8,
                            "fields": [
                                {"name": "id", "sensitive": False, "field_type": "string"},
                                {"name": "notes", "sensitive": False, "field_type": "string"},
                                {"name": "purchase_amount", "sensitive": True, "field_type": "float"},
                            ],
                        }
                    ],
                    "required_tools": [
                        {
                            "name": "list_transactions",
                            "category": "read",
                            "description": "List transactions",
                            "parameters": [],
                        },
                        {
                            "name": "get_transaction_detail",
                            "category": "read",
                            "description": "Get one transaction",
                            "parameters": ["transaction_id"],
                        },
                        {
                            "name": "process_refund",
                            "category": "privileged",
                            "description": "Process refund",
                            "parameters": ["transaction_id", "refund_amount"],
                        },
                    ],
                    "seed_data_constraints": ["8 realistic transactions"],
                }
                return FakeResp(json.dumps(payload))

        import json

        completed = complete_domain_skeleton(
            {"scenario_id": "test", "narrative": {"summary": "refund abuse"}},
            draft,
            client=FakeClient(),
            use_llm=True,
        )
        names = {t.name for t in completed.required_tools}
        self.assertIn("process_refund", names)
        self.assertIn("list_transactions", names)

    def test_no_llm_incomplete_draft_raises(self):
        from domain_skeleton_llm import complete_domain_skeleton

        draft = DomainSkeleton(entity_types=[], required_tools=[], seed_data_constraints=[])
        with self.assertRaises(RuntimeError):
            complete_domain_skeleton({}, draft, use_llm=False)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m unittest test_domain_skeleton.TestCompleteDomainSkeleton -v`  
Expected: FAIL (`complete_domain_skeleton` missing).

- [ ] **Step 3: Implement `complete_domain_skeleton`**

Append to `domain_skeleton_llm.py`:

```python
def _fix_json(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text


def _scenario_excerpt(scenario: dict, limit: int = 2500) -> str:
    parts: list[str] = []
    narrative = scenario.get("narrative") or {}
    for key in ("title", "summary", "entry_point"):
        val = narrative.get(key)
        if val:
            parts.append(f"{key}: {val}")
    meta = scenario.get("scenario_seed_metadata") or {}
    for key in ("threat_name", "mechanism_name", "mechanism_description"):
        val = meta.get(key)
        if val:
            parts.append(f"{key}: {val}")
    behavior = scenario.get("behavior_spec") or ""
    if behavior:
        parts.append(f"behavior_spec:\n{str(behavior)[:800]}")
    return "\n\n".join(parts)[:limit]


def _build_rewrite_prompt(scenario: dict, draft: DomainSkeleton) -> str:
    return (
        "You complete a DomainSkeleton for an agent red-team synthetic environment.\n"
        "Return a single JSON object with keys: entity_types, required_tools, seed_data_constraints.\n"
        f"Tool category must be one of: {sorted(CODEGEN_CATEGORIES)}.\n"
        "RULES:\n"
        "- Preserve every tool name, entity name, and field name from the DRAFT.\n"
        "- Add any missing read tools, fields, or privileged/communicate tools the scenario needs.\n"
        "- Keep the skeleton minimal and realistic for the scenario.\n\n"
        f"SCENARIO:\n{_scenario_excerpt(scenario)}\n\n"
        f"DRAFT_JSON:\n{json.dumps(draft.model_dump(), indent=2)}\n"
    )


def _draft_gaps(draft: DomainSkeleton) -> list[str]:
    gaps: list[str] = []
    if not draft.required_tools:
        gaps.append("required_tools is empty")
    if not draft.entity_types:
        gaps.append("entity_types is empty")
    return gaps


def complete_domain_skeleton(
    scenario: dict,
    draft: DomainSkeleton,
    *,
    client: Any | None = None,
    use_llm: bool = True,
) -> DomainSkeleton:
    """Rewrite draft into a complete DomainSkeleton, grounded in draft anchors."""
    if not use_llm:
        gaps = _draft_gaps(draft) + validate_codegen_categories(draft)
        if gaps:
            raise RuntimeError(
                "use_llm=False but draft is incomplete/invalid: " + "; ".join(gaps)
            )
        return draft

    api = client or _get_client()
    last_errors: list[str] = []

    for attempt in range(MAX_RETRIES + 1):
        try:
            response = api.chat.completions.create(
                model=MODEL,
                temperature=0.3,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You generate DomainSkeleton JSON for security test envs. "
                            "Respond with valid JSON only."
                        ),
                    },
                    {"role": "user", "content": _build_rewrite_prompt(scenario, draft)},
                ],
            )
            raw = response.choices[0].message.content.strip()
            data = json.loads(_fix_json(raw))
            rewritten = DomainSkeleton.model_validate(data)
            errors = (
                validate_anchors(draft, rewritten)
                + validate_codegen_categories(rewritten)
                + _draft_gaps(rewritten)
            )
            if errors:
                last_errors = errors
                log.warning("Domain skeleton attempt %s failed: %s", attempt + 1, errors)
                continue
            return rewritten
        except Exception as e:
            last_errors = [str(e)]
            log.warning("Domain skeleton attempt %s error: %s", attempt + 1, e)

    raise RuntimeError(
        "Failed to complete DomainSkeleton after retries: " + "; ".join(last_errors)
    )
```

- [ ] **Step 4: Run tests**

Run: `python -m unittest test_domain_skeleton.TestCompleteDomainSkeleton -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add domain_skeleton_llm.py test_domain_skeleton.py
git commit -m "Add grounded LLM DomainSkeleton completion with mocks."
```

---

### Task 4: Wire into `forge_scenario_to_spec`

**Files:**
- Modify: `scenario_loader.py` (`forge_scenario_to_spec` and related infer calls)
- Optionally modify: `ArtifactGen_garak/gen.py` only if it already has `--no-llm` that should pass through (optional thin kwarg; skip if invasive)

**Interfaces:**
- Consumes: `extract_domain_draft`, `complete_domain_skeleton`
- Produces: `forge_scenario_to_spec(..., use_llm: bool = True)` completing skeleton before building `ScenarioSpec`

- [ ] **Step 1: Write a wiring test with mocked completer**

```python
class TestForgeScenarioToSpecWiring(unittest.TestCase):
    def test_forge_scenario_to_spec_uses_completed_skeleton(self):
        from unittest.mock import patch
        from scenario_loader import forge_scenario_to_spec, load_scenario

        loaded = load_scenario(SCENARIOS / "AP-T2-01-28712e.yaml")
        completed = DomainSkeleton(
            entity_types=[
                EntitySpec(
                    name="Transaction",
                    fields=[
                        EntityFieldSpec(name="id", field_type="string"),
                        EntityFieldSpec(name="notes", field_type="string"),
                        EntityFieldSpec(name="purchase_amount", sensitive=True, field_type="float"),
                    ],
                    record_count=8,
                )
            ],
            required_tools=[
                _tool("list_transactions"),
                _tool("get_transaction_detail", params=["transaction_id"]),
                _tool("process_refund", "privileged", ["transaction_id", "refund_amount"]),
            ],
            seed_data_constraints=["8 transactions"],
        )

        with patch(
            "scenario_loader.complete_domain_skeleton",
            return_value=completed,
        ) as mocked:
            spec = forge_scenario_to_spec(loaded.raw, use_llm=True)
        mocked.assert_called_once()
        self.assertEqual(
            {t.name for t in spec.domain_skeleton.required_tools},
            {"list_transactions", "get_transaction_detail", "process_refund"},
        )
        self.assertEqual(spec.injection.trigger_tool, "process_refund")
        self.assertIn("notes", spec.injection.target_surfaces)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest test_domain_skeleton.TestForgeScenarioToSpecWiring -v`  
Expected: FAIL (`use_llm` unexpected / completer not wired).

- [ ] **Step 3: Wire `forge_scenario_to_spec`**

Near top of `scenario_loader.py`:

```python
from domain_skeleton_llm import complete_domain_skeleton
```

Update signature and body of `forge_scenario_to_spec`:

```python
def forge_scenario_to_spec(
    scenario: dict,
    attack_pattern: str = "delayed_trigger",
    attack_variant: str | None = None,
    use_llm: bool = True,
) -> ScenarioSpec:
    ...
    draft = extract_domain_draft(scenario)
    domain_skeleton = complete_domain_skeleton(scenario, draft, use_llm=use_llm)

    # Derive trigger / surfaces from completed skeleton (not finance defaults)
    tool_names = [t.name for t in domain_skeleton.required_tools]
    trigger_tool = extract_trigger_tool(scenario)
    if trigger_tool is None or trigger_tool not in tool_names:
        # Prefer privileged/communicate tool from completed skeleton
        for t in domain_skeleton.required_tools:
            if t.category in ("privileged", "communicate"):
                trigger_tool = t.name
                break
        if trigger_tool is None:
            raise ValueError("Completed domain_skeleton has no trigger tool")

    target_surfaces = extract_target_surfaces(scenario)
    if not target_surfaces:
        # surfaces from entity fields excluding id
        for entity in domain_skeleton.entity_types:
            for f in entity.fields:
                if f.name != "id":
                    target_surfaces.append(f.name)
                    break
            if target_surfaces:
                break
    if not target_surfaces:
        raise ValueError("No injection target_surfaces after domain completion")

    # Remove old _build_domain_skeleton / _infer_trigger_tool defaults from this path
    user_task = _build_user_task(scenario, trigger_tool)
    injection = _build_injection(
        scenario, risk_type, attack_pattern, attack_variant, trigger_tool, target_surfaces
    )
    security = _build_security_criteria(trigger_tool, risk_type)
    utility = _build_utility_criteria(domain_skeleton, trigger_tool)
    ...
```

Delete unused `_build_domain_skeleton` if nothing else calls it.

Update `ScenarioSpec` docstring in `scenario_spec.py` from “Deterministically derived (no LLM)” to note domain skeleton may be LLM-completed then frozen.

- [ ] **Step 4: Run tests**

Run: `python -m unittest test_domain_skeleton -v`  
Expected: PASS

Run: `python -m unittest test_scenario_filter -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scenario_loader.py scenario_spec.py test_domain_skeleton.py
git commit -m "Wire grounded LLM domain skeleton completion into ScenarioSpec build."
```

---

### Task 5: Docs touch-up

**Files:**
- Modify: `README.md` (How It Works / Generation bullets)
- Modify: `DESIGN.md` (Generation bullet that says ScenarioSpec is fully deterministic)

- [ ] **Step 1: Update README**

Replace the idea that ScenarioSpec is purely deterministic with:

- Shared `ScenarioSpec`: tools/entities via **extract from forge + grounded LLM completion**, frozen in `runs/{id}/spec.json`
- Artifact codegen remains deterministic from that frozen skeleton; seed data may still use LLM

- [ ] **Step 2: Update DESIGN.md**

Change Generation bullet to match: domain skeleton = extract + LLM complete; env models/tools = deterministic codegen; seed = LLM optional.

- [ ] **Step 3: Commit**

```bash
git add README.md DESIGN.md
git commit -m "Document extract-plus-LLM domain skeleton flow."
```

---

## Spec coverage check

| Spec requirement | Task |
|------------------|------|
| No silent finance defaults | Task 2 |
| Deterministic extract draft | Task 2 |
| LLM always rewrites grounded in draft | Task 3–4 |
| Anchor preservation | Task 1, 3 |
| Codegen categories only | Task 1, 3 |
| Fail loudly after retries | Task 3 |
| Freeze in ScenarioSpec / spec.json | Task 4 (existing persist path) |
| No new rebuild/idempotency CLI | Global constraint; not implemented |
| Lean unit tests | Tasks 1–4 |
| Downstream unchanged | No tasks touch codegen/Garak plugins |

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-29-domain-skeleton-llm.md`. Two execution options:

**1. Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
**2. Inline Execution** — execute tasks in this session with checkpoints  

Which approach?
