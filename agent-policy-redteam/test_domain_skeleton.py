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
