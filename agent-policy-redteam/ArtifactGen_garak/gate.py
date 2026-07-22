"""Framework gates: can a backend express a shared ScenarioSpec?"""

from __future__ import annotations

import logging
from typing import Literal

from scenario_spec import InjectionSurface, OracleTarget, ScenarioSpec

log = logging.getLogger(__name__)

GateResult = Literal["full", "partial", "skip"]

GARAK_WRITABLE: set[InjectionSurface] = {
    "user_turn",
    "tool_return",
    "system_prompt",
}
GARAK_OBSERVABLE: set[OracleTarget] = {
    "forbidden_call",
    "output_string",
}


def gate_garak(spec: ScenarioSpec) -> tuple[GateResult, ScenarioSpec, str]:
    """Gate a shared ScenarioSpec for Garak.

    Returns (result, possibly-downgraded spec, reason).
    """
    surface = spec.injection_surface
    oracle = spec.oracle_target
    sid = spec.seed_id or spec.scenario_id

    if surface == "none":
        return "skip", spec, f"unclassified surface for {sid}"

    if surface == "tool_definition":
        return "skip", spec, f"Garak cannot write to tool_definition surface ({sid})"

    if oracle == "state_vs_log":
        return "skip", spec, f"Garak cannot observe state_vs_log oracle ({sid})"

    if oracle == "cross_turn":
        return "skip", spec, f"Garak cannot observe cross_turn oracle ({sid})"

    if surface not in GARAK_WRITABLE:
        return "skip", spec, f"Garak cannot write to {surface} ({sid})"

    if oracle == "wrong_target":
        downgraded = spec.model_copy(update={"oracle_target": "output_string"})
        log.info("Downgraded %s oracle: wrong_target → output_string", sid)
        return "partial", downgraded, "wrong_target downgraded to output_string"

    if oracle not in GARAK_OBSERVABLE:
        return "skip", spec, f"Garak cannot observe {oracle} ({sid})"

    return "full", spec, "fully supported"
