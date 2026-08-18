"""Probe path and serialization tests."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from ArtifactGen_garak.extract import ScenarioContext, load_scenario
from ArtifactGen_garak.llm import MODEL
from ArtifactGen_garak.probe_spec import (
    PROBE_VALIDATION_CHECKS,
    DetectorRubric,
    ProbeTurn,
    ScenarioProbe,
    gate_probe_errors,
    probe_to_artifact_dict,
    skip_to_artifact_dict,
)
from ArtifactGen_garak.spec_io import (
    garak_artifact_path,
    save_validation,
    scenario_id_from_garak_path,
    validation_path,
)


class TestProbeArtifact(unittest.TestCase):
    def _minimal_ctx(self) -> ScenarioContext:
        return load_scenario(
            Path(__file__).resolve().parents[2] / "examples" / "scenarios" / "AP-T2-01-28712e.yaml"
        )

    def test_garak_artifact_path(self):
        p = garak_artifact_path("AP-T7-03-f2bbd2", Path("runs"))
        self.assertEqual(p, Path("runs/AP-T7-03-f2bbd2/AP-T7-03-f2bbd2-garak.json"))

    def test_validation_path(self):
        p = validation_path("AP-T7-03-f2bbd2", Path("runs"))
        self.assertEqual(p, Path("runs/AP-T7-03-f2bbd2/validation.json"))

    def test_scenario_id_from_garak_path(self):
        self.assertEqual(
            scenario_id_from_garak_path(
                Path("runs/AP-T7-03-f2bbd2/AP-T7-03-f2bbd2-garak.json")
            ),
            "AP-T7-03-f2bbd2",
        )
        self.assertEqual(
            scenario_id_from_garak_path(Path("runs/AP-T7-03-f2bbd2/garak.json")),
            "AP-T7-03-f2bbd2",
        )
        self.assertEqual(
            scenario_id_from_garak_path(Path("runs/AP-T7-03-f2bbd2-garak.json")),
            "AP-T7-03-f2bbd2",
        )

    def test_save_validation_includes_checks(self):
        path = save_validation(
            "AP-T2-01-test",
            True,
            [],
            Path("runs"),
            checks=PROBE_VALIDATION_CHECKS,
        )
        data = json.loads(path.read_text())
        self.assertTrue(data["ok"])
        self.assertIn("detector_rubric", data["checks"])
        self.assertEqual(data["errors"], [])

    def test_skip_to_artifact_dict(self):
        ctx = load_scenario(
            Path(__file__).resolve().parents[2]
            / "examples"
            / "scenarios"
            / "AP-T17-02-8e8e3e.yaml"
        )
        data = skip_to_artifact_dict(ctx)
        self.assertEqual(data["scenario_id"], ctx.scenario_id)
        self.assertEqual(data["injection_surface"], "tool_definition")
        self.assertIsNone(data["platform_coverage"])
        self.assertIsNone(data["model"])
        self.assertIn("timestamp", data)
        self.assertIn("summary", data["narrative"])
        self.assertNotIn("turns", data)
        self.assertNotIn("detector_rubric", data)

    def test_scenario_to_yaml_strips_narrative(self):
        ctx = self._minimal_ctx()
        from ArtifactGen_garak.probe_spec import scenario_to_yaml

        prompt_yaml = scenario_to_yaml(ctx)
        self.assertNotIn("narrative:", prompt_yaml)
        full_yaml = scenario_to_yaml(ctx, include_narrative=True)
        self.assertIn("narrative:", full_yaml)

    def test_probe_to_artifact_dict_shape(self):
        ctx = self._minimal_ctx()
        probe = ScenarioProbe(
            scenario_id=ctx.scenario_id,
            probe_name="test_probe",
            injection_surface="user_turn",
            turns=[
                ProbeTurn(role="system", content="sys"),
                ProbeTurn(role="user", content="attack", adversarial=True),
            ],
            attack_turn_index=1,
            detector_rubric=DetectorRubric(
                judge_prompt="judge",
                rubrics={"attack_success": ["emits refund"], "attack_blocked": ["declines"]},
            ),
        )
        data = probe_to_artifact_dict(ctx, probe, platform_coverage="full")
        self.assertEqual(data["scenario_id"], ctx.scenario_id)
        self.assertEqual(data["injection_surface"], "user_turn")
        self.assertEqual(list(data["narrative"].keys()), ["summary"])
        self.assertIn("summary", data["narrative"])
        self.assertEqual(data["platform_coverage"], "full")
        self.assertEqual(data["model"], MODEL)
        self.assertRegex(data["timestamp"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertNotIn("probe_name", data)
        self.assertNotIn("metadata", data)

    def test_probe_to_artifact_dict_omits_empty_tool_name(self):
        ctx = self._minimal_ctx()
        probe = ScenarioProbe(
            scenario_id="AP-T2-01-test",
            probe_name="test_probe",
            injection_surface="user_turn",
            turns=[
                ProbeTurn(role="system", content="sys"),
                ProbeTurn(role="user", content="attack", adversarial=True),
            ],
            attack_turn_index=1,
            detector_rubric=DetectorRubric(
                judge_prompt="judge",
                rubrics={"attack_success": ["emits refund"], "attack_blocked": ["declines"]},
            ),
        )
        data = probe_to_artifact_dict(ctx, probe, platform_coverage="partial")
        self.assertNotIn("tool_name", data["turns"][0])
        self.assertEqual(data["attack_turn_index"], 1)
        self.assertIn("detector_rubric", data)

    def test_gate_rejects_surface_mismatch(self):
        probe = ScenarioProbe(
            scenario_id="AP-T11-02-test",
            probe_name="test",
            injection_surface="user_turn",
            turns=[
                ProbeTurn(role="system", content="sys"),
                ProbeTurn(role="user", content="attack", adversarial=True),
            ],
            attack_turn_index=1,
            detector_rubric=DetectorRubric(
                judge_prompt="judge",
                rubrics={"attack_success": ["emits"], "attack_blocked": ["declines"]},
            ),
        )
        errors = gate_probe_errors(probe, expected_surface="tool_return")
        self.assertTrue(any("injection_surface" in e for e in errors))

    def test_gate_requires_tool_role_for_tool_return(self):
        probe = ScenarioProbe(
            scenario_id="AP-T11-02-test",
            probe_name="test",
            injection_surface="tool_return",
            turns=[
                ProbeTurn(role="system", content="sys"),
                ProbeTurn(role="user", content="attack", adversarial=True),
            ],
            attack_turn_index=1,
            detector_rubric=DetectorRubric(
                judge_prompt="judge",
                rubrics={"attack_success": ["emits"], "attack_blocked": ["declines"]},
            ),
        )
        errors = gate_probe_errors(probe, expected_surface="tool_return")
        self.assertIn("tool_return probe must end with role=tool", errors)


if __name__ == "__main__":
    unittest.main()
