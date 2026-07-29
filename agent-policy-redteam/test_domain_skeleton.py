"""Tests for domain skeleton extract + grounded LLM completion."""

import json
import unittest
from pathlib import Path

from scenario_loader import extract_domain_draft, extract_named_tools, extract_trigger_tool, load_scenario
from scenario_spec import DomainSkeleton, EntityFieldSpec, EntitySpec, ToolSpec

SCENARIOS = Path(__file__).parent / "examples" / "scenarios"


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

    def test_validate_anchors_rejects_category_change(self):
        from domain_skeleton_llm import validate_anchors

        draft = _skel([_tool("process_refund", "privileged", ["transaction_id"])], ["notes"])
        rewritten = _skel(
            [_tool("process_refund", "read", ["transaction_id"])],
            ["notes"],
        )
        errors = validate_anchors(draft, rewritten)
        self.assertTrue(
            any("process_refund" in e and "privileged" in e and "read" in e for e in errors)
        )

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
                            "name": "Record",
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

        completed = complete_domain_skeleton(
            {"scenario_id": "test", "narrative": {"summary": "refund abuse"}},
            draft,
            client=FakeClient(),
            use_llm=True,
        )
        names = {t.name for t in completed.required_tools}
        self.assertIn("process_refund", names)
        self.assertIn("list_transactions", names)

    def test_llm_rewrite_changing_tool_category_fails(self):
        """A rewrite that keeps process_refund but demotes it privileged->read
        must fail anchor validation and never be accepted by complete_domain_skeleton."""
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
                # Always demotes process_refund to "read" — must never validate.
                payload = {
                    "entity_types": [
                        {
                            "name": "Record",
                            "record_count": 5,
                            "fields": [
                                {"name": "id", "sensitive": False, "field_type": "string"},
                                {"name": "notes", "sensitive": False, "field_type": "string"},
                            ],
                        }
                    ],
                    "required_tools": [
                        {
                            "name": "process_refund",
                            "category": "read",
                            "description": "Process refund",
                            "parameters": ["transaction_id"],
                        },
                    ],
                    "seed_data_constraints": [],
                }
                return FakeResp(json.dumps(payload))

        with self.assertRaises(RuntimeError) as ctx:
            complete_domain_skeleton(
                {"scenario_id": "test", "narrative": {"summary": "refund abuse"}},
                draft,
                client=FakeClient(),
                use_llm=True,
            )
        self.assertIn("process_refund", str(ctx.exception))

    def test_no_llm_incomplete_draft_raises(self):
        from domain_skeleton_llm import complete_domain_skeleton

        draft = DomainSkeleton(entity_types=[], required_tools=[], seed_data_constraints=[])
        with self.assertRaises(RuntimeError):
            complete_domain_skeleton({}, draft, use_llm=False)


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


class TestTargetSurfaceFallback(unittest.TestCase):
    """forge_scenario_to_spec's target_surfaces fallback (no text hint) should
    prefer string-typed, non-id fields from the completed domain skeleton."""

    _SCENARIO = {
        "scenario_id": "test-fallback",
        "scenario_seed_metadata": {"threat_id": "T3", "seed_id": "AP-T3-99"},
        "narrative": {
            "title": "Case review",
            "summary": "Investigate a case and report back.",
            "entry_point": "internal console",
        },
    }

    def test_fallback_prefers_string_field_over_earlier_non_string(self):
        from unittest.mock import patch
        from scenario_loader import forge_scenario_to_spec

        completed = DomainSkeleton(
            entity_types=[
                EntitySpec(
                    name="Record",
                    fields=[
                        EntityFieldSpec(name="id", field_type="string"),
                        EntityFieldSpec(name="amount", field_type="float"),
                        EntityFieldSpec(name="notes", field_type="string"),
                    ],
                    record_count=5,
                )
            ],
            required_tools=[
                _tool("list_records"),
                _tool("process_refund", "privileged", ["transaction_id"]),
            ],
            seed_data_constraints=[],
        )
        with patch("scenario_loader.complete_domain_skeleton", return_value=completed):
            spec = forge_scenario_to_spec(self._SCENARIO, use_llm=True)
        self.assertEqual(spec.injection.target_surfaces, ["notes"])

    def test_fallback_accepts_non_string_field_when_no_string_available(self):
        from unittest.mock import patch
        from scenario_loader import forge_scenario_to_spec

        completed = DomainSkeleton(
            entity_types=[
                EntitySpec(
                    name="Record",
                    fields=[
                        EntityFieldSpec(name="id", field_type="string"),
                        EntityFieldSpec(name="amount", field_type="float"),
                    ],
                    record_count=5,
                )
            ],
            required_tools=[
                _tool("list_records"),
                _tool("process_refund", "privileged", ["transaction_id"]),
            ],
            seed_data_constraints=[],
        )
        with patch("scenario_loader.complete_domain_skeleton", return_value=completed):
            spec = forge_scenario_to_spec(self._SCENARIO, use_llm=True)
        self.assertEqual(spec.injection.target_surfaces, ["amount"])


def _fixed_completed_skeleton() -> DomainSkeleton:
    """A minimal, always-valid DomainSkeleton (read + privileged tool) usable
    as a stand-in for LLM completion regardless of what the draft looked like."""
    return DomainSkeleton(
        entity_types=[
            EntitySpec(
                name="Record",
                fields=[
                    EntityFieldSpec(name="id", field_type="string"),
                    EntityFieldSpec(name="notes", field_type="string"),
                ],
                record_count=5,
            )
        ],
        required_tools=[
            _tool("list_records"),
            _tool("process_refund", "privileged", ["transaction_id"]),
        ],
        seed_data_constraints=[],
    )


class TestLoadOrBuildScenarioSpecUseLlm(unittest.TestCase):
    def test_use_llm_flag_threaded_through_to_complete_domain_skeleton(self):
        import tempfile
        from unittest.mock import patch
        from scenario_loader import load_or_build_scenario_spec

        scenario_path = SCENARIOS / "AP-T2-01-28712e.yaml"
        captured: dict = {}

        def _fake_complete(scenario, draft, use_llm=True, **kw):
            captured["use_llm"] = use_llm
            return _fixed_completed_skeleton()

        with tempfile.TemporaryDirectory() as tmp:
            spec_path = Path(tmp) / "spec.json"
            with patch(
                "scenario_loader.complete_domain_skeleton",
                side_effect=_fake_complete,
            ) as mocked:
                spec, source = load_or_build_scenario_spec(
                    scenario_path,
                    spec_path=spec_path,
                    persist=False,
                    use_llm=False,
                )
            mocked.assert_called_once()
            self.assertEqual(captured.get("use_llm"), False)
            self.assertEqual(source, "built")


class TestLoadOrBuildScenarioSpecExceptionNarrowing(unittest.TestCase):
    def test_corrupt_disk_spec_falls_back_to_fresh_build(self):
        import tempfile
        from unittest.mock import patch
        from scenario_loader import load_or_build_scenario_spec

        scenario_path = SCENARIOS / "AP-T2-01-28712e.yaml"
        with tempfile.TemporaryDirectory() as tmp:
            spec_path = Path(tmp) / "spec.json"
            spec_path.write_text("not valid json{{{")
            with patch(
                "scenario_loader.complete_domain_skeleton",
                return_value=_fixed_completed_skeleton(),
            ):
                spec, source = load_or_build_scenario_spec(
                    scenario_path,
                    spec_path=spec_path,
                    persist=False,
                    use_llm=False,
                )
            self.assertEqual(source, "built")

    def test_build_failure_on_stale_disk_spec_propagates_without_retry(self):
        import json as jsonlib
        import tempfile
        from unittest.mock import MagicMock, patch
        from scenario_loader import forge_scenario_to_spec, load_or_build_scenario_spec, load_scenario

        scenario_path = SCENARIOS / "AP-T2-01-28712e.yaml"
        loaded = load_scenario(scenario_path)
        with patch(
            "scenario_loader.complete_domain_skeleton",
            return_value=_fixed_completed_skeleton(),
        ):
            stale_spec = forge_scenario_to_spec(loaded.raw, use_llm=False)
        stale_dump = stale_spec.model_dump()
        stale_dump["seed_id"] = ""  # forces _spec_is_stale(...) -> True

        with tempfile.TemporaryDirectory() as tmp:
            spec_path = Path(tmp) / "spec.json"
            spec_path.write_text(jsonlib.dumps(stale_dump, default=str))

            failing_build = MagicMock(side_effect=RuntimeError("boom: llm build failed"))
            with patch("scenario_loader.complete_domain_skeleton", failing_build):
                with self.assertRaises(RuntimeError) as ctx:
                    load_or_build_scenario_spec(
                        scenario_path,
                        spec_path=spec_path,
                        persist=False,
                        use_llm=True,
                    )
            self.assertIn("boom", str(ctx.exception))
            # The build failure must not be caught and silently retried as if
            # it were a load/parse failure of the on-disk spec.
            self.assertEqual(failing_build.call_count, 1)


if __name__ == "__main__":
    unittest.main()
