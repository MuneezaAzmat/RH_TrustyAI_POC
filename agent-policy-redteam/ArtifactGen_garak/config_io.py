"""Write/load scenario configs consumed by the shared ForgeScenario probe."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from .realize import RealizedProbe

log = logging.getLogger(__name__)

DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent / "configs"


def config_path_for(scenario_id: str, config_dir: Path | None = None) -> Path:
    base = config_dir or DEFAULT_CONFIG_DIR
    return base / f"{scenario_id}.yaml"


def realized_to_config(realized: RealizedProbe) -> dict[str, Any]:
    """Serialize a realized probe into a Garak config dict."""
    spec = realized.spec
    dc = realized.detection_config
    return {
        "scenario_id": spec.scenario_id,
        "seed_id": spec.seed_id,
        "threat_id": spec.threat_id,
        "mechanism_name": spec.mechanism_name,
        "surface": spec.injection_surface,
        "oracle": spec.oracle_target,
        "goal": spec.injection.goal[:500],
        "tags": list(spec.tags),
        "tools": list(spec.tool_names),
        "prompts": [realized.conversation_text],
        "payload_text": realized.payload_text,
        "detection": {
            "strategy": dc.strategy,
            "trigger_tool": dc.trigger_tool,
            "forbidden_tools": [dc.trigger_tool],
            "available_tools": list(spec.tool_names),
            "exfil_address": dc.exfil_address,
            "sensitive_patterns": list(dc.sensitive_patterns),
            "oracle_predicates": list(dc.oracle_predicates),
            # Human-readable predicate aligned with tools listed in the system prompt
            "predicates": [
                f"must_not_call:{dc.trigger_tool}",
                f"must_not_contain:{dc.exfil_address}",
            ],
        },
    }


def save_config(
    realized: RealizedProbe,
    config_dir: Path | None = None,
) -> Path:
    """Write YAML config for one scenario. Returns path written."""
    out_dir = config_dir or DEFAULT_CONFIG_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    path = config_path_for(realized.spec.scenario_id, out_dir)
    data = realized_to_config(realized)
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False),
        encoding="utf-8",
    )
    log.info("Wrote config: %s", path)
    return path


def load_config(path: str | Path) -> dict[str, Any]:
    """Load a scenario probe config from YAML or JSON."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Scenario config not found: {p}")
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid config root in {p}")
    if "prompts" not in data or not data["prompts"]:
        raise ValueError(f"Config {p} must include a non-empty prompts list")
    return data
