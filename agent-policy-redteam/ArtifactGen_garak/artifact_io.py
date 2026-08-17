"""Write/load scenario artifacts consumed by the shared Scenario probe."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from .judge_rubric import JudgeRubric
from .realize import RealizedProbe

log = logging.getLogger(__name__)

DEFAULT_ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"


def artifact_path_for(scenario_id: str, artifact_dir: Path | None = None) -> Path:
    base = artifact_dir or DEFAULT_ARTIFACT_DIR
    return base / f"{scenario_id}.yaml"


def realized_to_artifact(realized: RealizedProbe) -> dict[str, Any]:
    """Serialize a realized probe into a Garak artifact dict."""
    spec = realized.spec
    dc = realized.detection_config
    garak_data: dict[str, Any] = {
        "chat_history": realized.chat_history.model_dump(),
    }
    if realized.judge_rubric is not None:
        rubric = realized.judge_rubric
        if isinstance(rubric, JudgeRubric):
            garak_data["judge_rubric"] = rubric.model_dump()
        elif hasattr(rubric, "model_dump"):
            garak_data["judge_rubric"] = rubric.model_dump()
        else:
            garak_data["judge_rubric"] = rubric

    return {
        "scenario_id": spec.scenario_id,
        "seed_id": spec.source.seed_id,
        "threat_id": spec.source.threat_id,
        "mechanism_name": spec.source.mechanism_name,
        "surface": spec.injection_surface,
        "oracle": spec.oracle_target,
        "goal": spec.attack.goal[:500],
        "tags": list(spec.source.tags),
        "tools": list(spec.tool_names),
        "garak_data": garak_data,
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


def save_artifact(
    realized: RealizedProbe,
    artifact_dir: Path | None = None,
) -> Path:
    """Write YAML artifact for one scenario. Returns path written."""
    out_dir = artifact_dir or DEFAULT_ARTIFACT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    path = artifact_path_for(realized.spec.scenario_id, out_dir)
    data = realized_to_artifact(realized)
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False),
        encoding="utf-8",
    )
    log.info("Wrote artifact: %s", path)
    return path


def load_artifact(path: str | Path) -> dict[str, Any]:
    """Load a scenario probe artifact from YAML or JSON."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Scenario artifact not found: {p}")
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid artifact root in {p}")
    if "prompts" not in data or not data["prompts"]:
        raise ValueError(f"Artifact {p} must include a non-empty prompts list")
    return data
