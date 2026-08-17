"""Framework gates: can Garak run an EnvironmentSpec?"""

from __future__ import annotations

import logging
from typing import Literal

from environment_spec import EnvironmentSpec

log = logging.getLogger(__name__)

GateResult = Literal["full", "partial", "skip"]

GARAK_WRITABLE = {"user_turn", "tool_return", "system_prompt"}
GARAK_OBSERVABLE = {"forbidden_call", "output_string"}


def gate_garak(spec: EnvironmentSpec) -> tuple[GateResult, EnvironmentSpec, str]:
    surface = spec.injection_surface
    oracle = spec.oracle_target
    sid = spec.seed_id or spec.scenario_id

    if surface == "none":
        return "skip", spec, f"unclassified surface for {sid}"
    if surface == "tool_definition":
        return "skip", spec, f"Garak cannot write to tool_definition surface ({sid})"
    if oracle == "state_vs_log":
        return "skip", spec, f"Garak cannot observe state_vs_log oracle ({sid})"
    if surface not in GARAK_WRITABLE:
        return "skip", spec, f"Garak cannot write to {surface} ({sid})"
    if oracle not in GARAK_OBSERVABLE:
        return "skip", spec, f"Garak cannot observe {oracle} ({sid})"
    return "full", spec, "fully supported"


def stamp_garak_coverage(spec: EnvironmentSpec, result: GateResult, reason: str) -> EnvironmentSpec:
    coverage = dict(spec.platform_coverage)
    coverage["garak"] = {"result": result, "reason": reason}
    return spec.model_copy(update={"platform_coverage": coverage})
