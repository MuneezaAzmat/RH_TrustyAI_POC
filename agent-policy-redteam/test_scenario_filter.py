"""Tests for volume/DDoS scenario filtering."""

import unittest

from scenario_filter import detect_volume_attack_text
from scenario_loader import (
    is_volume_attack_forge_scenario,
    load_scenario,
    triage_from_scenario,
)
from triage import filter_agent_level, filter_scenario_feasible


class TestVolumeFilterFalsePositives(unittest.TestCase):
    def test_high_volume_merchant_is_not_volume_attack(self):
        text = (
            "I exploit my compromised access to a high-volume merchant's "
            "Order Management System to inject a malicious payload."
        )
        self.assertIsNone(detect_volume_attack_text(text))

    def test_bulk_retrieval_exfil_is_not_volume_attack(self):
        text = (
            "Exfiltrate structured financial data in bulk, bypassing validation "
            "via bulk retrieval and display in the chat window."
        )
        self.assertIsNone(detect_volume_attack_text(text))

    def test_high_volume_refund_policy_is_not_volume_attack(self):
        text = (
            "Force unauthorized, high-volume refund executions through the "
            "reasoning engine without secondary approval."
        )
        self.assertIsNone(detect_volume_attack_text(text))


class TestVolumeFilterTruePositives(unittest.TestCase):
    def test_context_flood_still_detected(self):
        text = "Utilize high-volume, high-entropy conversational filler to saturate the context."
        self.assertIsNotNone(detect_volume_attack_text(text))

    def test_query_flood_still_detected(self):
        text = "Use automated scripts to flood the refund APIs with simultaneous requests."
        self.assertIsNotNone(detect_volume_attack_text(text))


class TestForgeScenarioClassification(unittest.TestCase):
    def test_t2_tool_misuse_scenarios_not_volume_filtered(self):
        for scenario_id in (
            "AP-T2-02-3f1185",
            "AP-T2-06-85bd56",
            "AP-T17-01-00d278",
        ):
            loaded = load_scenario(f"examples/scenarios/{scenario_id}.yaml")
            self.assertIsNone(
                is_volume_attack_forge_scenario(loaded.raw),
                msg=scenario_id,
            )

    def test_t8_context_flood_still_filtered(self):
        loaded = load_scenario("examples/scenarios/AP-T8-03-ccf918.yaml")
        self.assertIsNotNone(is_volume_attack_forge_scenario(loaded.raw))

    def test_t2_03_fleet_flood_still_filtered(self):
        loaded = load_scenario("examples/scenarios/AP-T2-03-7108ff.yaml")
        self.assertIsNotNone(is_volume_attack_forge_scenario(loaded.raw))


class TestFeasibleAgentScenarios(unittest.TestCase):
    def test_newly_feasible_t2_scenarios(self):
        for scenario_id in ("AP-T2-02-3f1185", "AP-T17-01-00d278"):
            loaded = load_scenario(f"examples/scenarios/{scenario_id}.yaml")
            triaged = triage_from_scenario(loaded.raw)
            feasible = filter_scenario_feasible(filter_agent_level([triaged]))
            self.assertEqual(len(feasible), 1, msg=scenario_id)


if __name__ == "__main__":
    unittest.main()
