"""Load and save frozen schema-v2 EnvironmentSpec files."""

from __future__ import annotations

from pathlib import Path

from environment_spec import EnvironmentSpec
from plan_spec import SpecPlan

RUNS_DIR = Path("runs")
SPEC_FILE = "spec.json"
PLAN_FILE = "spec_plan.json"


def default_run_dir(scenario_id: str, output_dir: Path | str | None = None) -> Path:
    if output_dir:
        return Path(output_dir)
    return RUNS_DIR / scenario_id


def load_spec(run_dir: Path | str) -> EnvironmentSpec:
    path = Path(run_dir) / SPEC_FILE
    if not path.is_file():
        raise FileNotFoundError(f"Step 2 requires {path} from step 1")
    return EnvironmentSpec.model_validate_json(path.read_text(encoding="utf-8"))


def save_spec(run_dir: Path | str, spec: EnvironmentSpec) -> Path:
    path = Path(run_dir) / SPEC_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(spec.model_dump_json(indent=2), encoding="utf-8")
    return path


def save_plan(run_dir: Path | str, plan: SpecPlan) -> Path:
    path = Path(run_dir) / PLAN_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_plan(run_dir: Path | str) -> SpecPlan:
    path = Path(run_dir) / PLAN_FILE
    if not path.is_file():
        raise FileNotFoundError(f"Spec plan not found: {path}")
    return SpecPlan.model_validate_json(path.read_text(encoding="utf-8"))
