"""Load/save Garak probe outputs under runs/{scenario_id}/."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

DEFAULT_RUNS_DIR = Path("runs")
GARAK_SUFFIX = "-garak.json"
VALIDATION_FILE = "validation.json"
MANIFEST_FILE = "manifest.json"
LEGACY_GARAK_FILE = "garak.json"


def runs_dir(base: Path | None = None) -> Path:
    return base if base is not None else DEFAULT_RUNS_DIR


def scenario_run_dir(scenario_id: str, base: Path | None = None) -> Path:
    return runs_dir(base) / scenario_id


def garak_filename(scenario_id: str) -> str:
    return f"{scenario_id}{GARAK_SUFFIX}"


def garak_artifact_path(scenario_id: str, base: Path | None = None) -> Path:
    return scenario_run_dir(scenario_id, base) / garak_filename(scenario_id)


def validation_path(scenario_id: str, base: Path | None = None) -> Path:
    return scenario_run_dir(scenario_id, base) / VALIDATION_FILE


def scenario_id_from_garak_path(path: Path) -> str:
    stem = path.stem
    if stem.endswith("-garak"):
        return stem[: -len("-garak")]
    if path.name == LEGACY_GARAK_FILE and path.parent.name.startswith("AP-"):
        return path.parent.name
    return stem


def save_garak_artifact(scenario_id: str, data: dict[str, Any], base: Path | None = None) -> Path:
    out = scenario_run_dir(scenario_id, base)
    out.mkdir(parents=True, exist_ok=True)
    path = out / garak_filename(scenario_id)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    log.info("Wrote garak artifact: %s", path)
    return path


def save_validation(
    scenario_id: str,
    ok: bool,
    errors: list[str],
    base: Path | None = None,
    *,
    checks: str = "",
) -> Path:
    out = scenario_run_dir(scenario_id, base)
    out.mkdir(parents=True, exist_ok=True)
    path = out / VALIDATION_FILE
    path.write_text(
        json.dumps({"ok": ok, "checks": checks, "errors": errors}, indent=2),
        encoding="utf-8",
    )
    return path


def load_garak_artifact(path: str | Path) -> dict[str, Any]:
    """Load a Garak probe artifact from JSON (or legacy YAML)."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Garak artifact not found: {p}")
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid artifact root in {p}")
    if data.get("turns"):
        return data
    if data.get("prompts"):
        return data
    raise ValueError(f"Artifact {p} must include turns[] or legacy prompts[]")
