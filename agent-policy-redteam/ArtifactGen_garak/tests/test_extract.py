"""Tests for scenario extraction."""

from __future__ import annotations

import unittest
from pathlib import Path

from ArtifactGen_garak.extract import load_scenario

SCENARIOS = Path(__file__).resolve().parents[2] / "examples" / "scenarios"


class TestExtract(unittest.TestCase):
    def test_t2_06_metadata(self):
        ctx = load_scenario(SCENARIOS / "AP-T2-06-85bd56.yaml")
        self.assertEqual(ctx.seed_id, "AP-T2-06")
        self.assertEqual(ctx.threat_id, "T2")
        self.assertTrue(ctx.narrative_summary)
        self.assertIn("tool_execution", ctx.zone_sequence)

    def test_t17_02_quoted_tools(self):
        ctx = load_scenario(SCENARIOS / "AP-T17-02-8e8e3e.yaml")
        self.assertIn("process_refund", ctx.quoted_tools)
        self.assertIn("modify_payment", ctx.quoted_tools)


if __name__ == "__main__":
    unittest.main()
