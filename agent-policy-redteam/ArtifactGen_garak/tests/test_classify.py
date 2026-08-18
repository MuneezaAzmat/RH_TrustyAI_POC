"""Tests for Garak gate classification."""

from __future__ import annotations

import unittest
from pathlib import Path

from ArtifactGen_garak.classify import classify_garak, lookup_surface
from ArtifactGen_garak.extract import load_scenario

SCENARIOS = Path(__file__).resolve().parents[2] / "examples" / "scenarios"


class TestClassify(unittest.TestCase):
    def test_t17_02_skip_surface(self):
        ctx = load_scenario(SCENARIOS / "AP-T17-02-8e8e3e.yaml")
        self.assertEqual(lookup_surface(ctx.seed_id), "tool_definition")
        result, reason = classify_garak(
            ctx,
            trigger_tool="process_refund",
            tools_grounded=True,
        )
        self.assertEqual(result, "skip")
        self.assertIn("tool_definition", reason)

    def test_t2_01_full_with_grounded_trigger(self):
        ctx = load_scenario(SCENARIOS / "AP-T2-01-28712e.yaml")
        self.assertIn("process_refund", ctx.quoted_tools)
        result, reason = classify_garak(
            ctx,
            trigger_tool="process_refund",
            tools_grounded=True,
        )
        self.assertEqual(result, "full")
        self.assertIn("supported", reason.lower())

    def test_t2_06_partial_inferred_tools(self):
        ctx = load_scenario(SCENARIOS / "AP-T2-06-85bd56.yaml")
        result, _ = classify_garak(
            ctx,
            trigger_tool="process_refund",
            tools_grounded=False,
        )
        self.assertEqual(result, "partial")


if __name__ == "__main__":
    unittest.main()
