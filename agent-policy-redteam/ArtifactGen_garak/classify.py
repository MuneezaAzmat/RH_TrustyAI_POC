"""Deterministic injection-surface lookup + Garak gate classification."""

from __future__ import annotations

from typing import Literal

from .extract import ScenarioContext, name_in_source

GateResult = Literal["full", "partial", "skip"]
InjectionSurface = Literal[
    "user_turn",
    "tool_return",
    "system_prompt",
    "tool_definition",
    "data_store",
    "none",
]

_CLASSIFICATION: dict[str, str] = {
    "AP-T2": "user_turn",
    "AP-T3": "user_turn",
    "AP-T7-01": "user_turn",
    "AP-T7-02": "tool_return",
    "AP-T7-03": "tool_return",
    "AP-T7-04": "tool_return",
    "AP-T7-05": "tool_return",
    "AP-T8": "user_turn",
    "AP-T9": "tool_return",
    "AP-T11-01": "user_turn",
    "AP-T11-02": "tool_return",
    "AP-T11-03": "user_turn",
    "AP-T15-01": "user_turn",
    "AP-T15-02": "tool_return",
    "AP-T17-01": "system_prompt",
    "AP-T17-02": "tool_definition",
}

GARAK_WRITABLE = {"user_turn", "tool_return", "system_prompt"}


def lookup_surface(seed_id: str) -> InjectionSurface:
    if seed_id in _CLASSIFICATION:
        return _CLASSIFICATION[seed_id]  # type: ignore[return-value]
    prefix = "-".join(seed_id.split("-")[:2])
    return _CLASSIFICATION.get(prefix, "user_turn")  # type: ignore[return-value]


def first_injection_step(ctx: ScenarioContext) -> int | None:
    narrative = ctx.raw.get("narrative") or {}
    for step in narrative.get("steps") or []:
        zone = str(step.get("zone", ""))
        if zone in ("input", "tool_execution"):
            return int(step.get("step_number", 0)) or None
    return None


def surface_skip_reason(ctx: ScenarioContext, *, surface: str | None = None) -> str | None:
    """Deterministic pre-plan gate: return skip reason, or None to proceed."""
    sid = ctx.seed_id or ctx.scenario_id
    surf = surface or lookup_surface(ctx.seed_id)

    if surf in ("none", "data_store"):
        return f"unclassified or data_store surface for {sid}"
    if surf == "tool_definition":
        return f"Garak cannot write to tool_definition surface ({sid})"
    if surf not in GARAK_WRITABLE:
        return f"Garak cannot write to {surf} ({sid})"
    return None


def classify_garak(
    ctx: ScenarioContext,
    *,
    surface: str | None = None,
    trigger_tool: str = "",
    oracle_kind: str = "forbidden_call",
    tools_grounded: bool = True,
) -> tuple[GateResult, str]:
    """Return (gate_result, reason) after probe generation — full / partial / skip."""
    sid = ctx.seed_id or ctx.scenario_id
    surf = surface or lookup_surface(ctx.seed_id)

    skip = surface_skip_reason(ctx, surface=surf)
    if skip:
        return "skip", skip
    if oracle_kind == "state_vs_log":
        return "skip", f"Garak cannot observe state_vs_log oracle ({sid})"
    observable_kinds = ("forbidden_call", "forbidden_argument", "output_string")
    if oracle_kind not in observable_kinds:
        return "skip", f"Garak cannot observe {oracle_kind} ({sid})"

    if oracle_kind == "output_string":
        return "partial", f"output-oracle attack ({sid})"

    if oracle_kind in ("forbidden_call", "forbidden_argument") and not trigger_tool:
        return "skip", f"no grounded trigger tool for {sid}"

    if not tools_grounded:
        return "partial", f"tools inferred from prose, not quoted in scenario ({sid})"

    if trigger_tool and not name_in_source(trigger_tool, ctx.grounding_text):
        return "partial", f"trigger tool {trigger_tool!r} not quoted in scenario ({sid})"

    if surf in GARAK_WRITABLE and first_injection_step(ctx) is None and surf != "system_prompt":
        return "partial", f"no clear injection step in narrative ({sid})"

    return "full", "fully supported"
