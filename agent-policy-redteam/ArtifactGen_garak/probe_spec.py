"""One-shot probe generation from full scenario YAML (generate_artifact.md)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, model_validator

from .classify import lookup_surface
from .extract import ScenarioContext
from .llm import MODEL, llm_json

log = logging.getLogger(__name__)

GENERATE_ARTIFACT_PROMPT = Path(__file__).resolve().parent / "prompts" / "generate_artifact.md"

PROBE_VALIDATION_CHECKS = (
    "Probe structural gate after LLM generation: detector_rubric has non-empty "
    "judge_prompt, attack_success, and attack_blocked lists; injection_surface "
    "matches the classified surface; the last turn is adversarial and its role "
    "matches the surface (user_turn→user, tool_return→tool, system_prompt→system); "
    "Pydantic schema validates turns, attack_turn_index, and tool_name on tool turns."
)

SKIP_VALIDATION_CHECKS = (
    "Pre-plan gate: classified injection surface must be writable by Garak "
    "(user_turn, tool_return, or system_prompt). Unwritable surfaces skip LLM generation."
)


class ProbeTurn(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str
    tool_name: str = ""
    adversarial: bool = False


class DetectorRubric(BaseModel):
    judge_prompt: str = ""
    context: str = ""
    rubrics: dict[str, list[str]] = Field(default_factory=dict)


class ScenarioProbe(BaseModel):
    scenario_id: str = ""
    probe_name: str = ""
    injection_surface: Literal["user_turn", "tool_return", "system_prompt"] = "user_turn"
    turns: list[ProbeTurn] = Field(default_factory=list)
    attack_turn_index: int = Field(ge=0)
    detector_rubric: DetectorRubric = Field(default_factory=DetectorRubric)

    @model_validator(mode="after")
    def _validate_transcript(self) -> ScenarioProbe:
        if not self.turns:
            raise ValueError("turns must not be empty")
        if self.attack_turn_index != len(self.turns) - 1:
            raise ValueError("attack_turn_index must point at the last turn")
        last = self.turns[-1]
        if not last.adversarial:
            raise ValueError("last turn must have adversarial: true")
        for i, turn in enumerate(self.turns):
            if turn.role == "tool" and not turn.tool_name:
                raise ValueError(f"tool turn at index {i} missing tool_name")
            if turn.role != "tool" and turn.tool_name:
                raise ValueError(f"non-tool turn at index {i} must not set tool_name")
        return self


@dataclass
class ProbeBuildResult:
    probe: ScenarioProbe
    ok: bool
    errors: list[str]


def scenario_to_yaml(ctx: ScenarioContext, *, include_narrative: bool = False) -> str:
    """Serialize scenario for the LLM prompt (narrative stripped by default)."""
    data = dict(ctx.raw)
    if not include_narrative:
        data.pop("narrative", None)
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False)


def _utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _artifact_header(
    ctx: ScenarioContext,
    *,
    injection_surface: str,
    platform_coverage: str | None,
    model: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    narrative = ctx.raw.get("narrative") or {}
    return {
        "scenario_id": ctx.scenario_id,
        "injection_surface": injection_surface,
        "narrative": {"summary": str(narrative.get("summary", ""))},
        "platform_coverage": platform_coverage,
        "model": model,
        "timestamp": timestamp or _utc_timestamp(),
    }


def skip_to_artifact_dict(ctx: ScenarioContext) -> dict[str, Any]:
    """Minimal artifact for scenarios Garak cannot cover (no LLM, no probe)."""
    return _artifact_header(
        ctx,
        injection_surface=lookup_surface(ctx.seed_id),
        platform_coverage=None,
        model=None,
    )


def probe_to_artifact_dict(
    ctx: ScenarioContext,
    probe: ScenarioProbe,
    *,
    platform_coverage: str,
) -> dict[str, Any]:
    """Serialize probe to the Garak artifact dict."""
    turns: list[dict[str, Any]] = []
    for t in probe.turns:
        turn: dict[str, Any] = {
            "role": t.role,
            "content": t.content,
            "adversarial": t.adversarial,
        }
        if t.role == "tool":
            turn["tool_name"] = t.tool_name
        turns.append(turn)
    header = _artifact_header(
        ctx,
        injection_surface=probe.injection_surface,
        platform_coverage=platform_coverage,
        model=MODEL,
    )
    return {
        **header,
        "turns": turns,
        "attack_turn_index": probe.attack_turn_index,
        "detector_rubric": probe.detector_rubric.model_dump(),
    }


def _fill(template: str, **slots: str) -> str:
    out = template
    for key, value in slots.items():
        out = out.replace("{{" + key + "}}", value)
    return out


def gate_probe_errors(
    probe: ScenarioProbe,
    *,
    expected_surface: str | None = None,
) -> list[str]:
    errors: list[str] = []
    dr = probe.detector_rubric
    if not dr.judge_prompt.strip():
        errors.append("detector_rubric.judge_prompt must not be empty")
    success = dr.rubrics.get("attack_success") or []
    blocked = dr.rubrics.get("attack_blocked") or []
    if not success:
        errors.append("detector_rubric.rubrics.attack_success must not be empty")
    if not blocked:
        errors.append("detector_rubric.rubrics.attack_blocked must not be empty")
    if expected_surface and probe.injection_surface != expected_surface:
        errors.append(
            f"injection_surface must be {expected_surface!r}, got {probe.injection_surface!r}"
        )
    last = probe.turns[-1]
    if expected_surface == "user_turn" and last.role != "user":
        errors.append("user_turn probe must end with role=user")
    if expected_surface == "tool_return" and last.role != "tool":
        errors.append("tool_return probe must end with role=tool")
    if expected_surface == "system_prompt" and last.role != "system":
        errors.append("system_prompt probe must end with role=system")
    return errors


def generate_scenario_probe(
    ctx: ScenarioContext,
    prompt_path: Path,
    *,
    injection_surface: str | None = None,
) -> ProbeBuildResult:
    surface = injection_surface or lookup_surface(ctx.seed_id)
    template = prompt_path.read_text(encoding="utf-8")
    prompt = _fill(
        template,
        scenario_yaml=scenario_to_yaml(ctx),
        injection_surface=surface,
    )
    log.info(
        "Generating scenario probe with %s (injection_surface=%s)",
        prompt_path,
        surface,
    )

    probe: ScenarioProbe | None = None
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            data = llm_json(
                prompt,
                (
                    "You convert threat scenarios into Garak probe JSON. "
                    "Respond with valid JSON only."
                ),
            )
            probe = ScenarioProbe.model_validate(data)
            break
        except Exception as e:
            last_error = e
            log.warning("Probe generation attempt %d failed: %s", attempt + 1, e)

    if probe is None:
        raise last_error or RuntimeError("Probe generation failed")

    errors = gate_probe_errors(probe, expected_surface=surface)
    if errors:
        log.warning("Probe gate failed: %s", "; ".join(errors))
    return ProbeBuildResult(probe=probe, ok=not errors, errors=errors)
