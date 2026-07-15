"""Save and load scenario artifacts as split files for reproducible replay."""

import json
import logging
from pathlib import Path

import yaml

from models import DryRunTrace, GeneratedEnvironment, InjectionScenario, SavedScenarioArtifacts

log = logging.getLogger(__name__)

RUNS_DIR = Path("runs")
SPEC_FILE = "spec.json"
REPORT_FILE = "report.json"
CLEAN_TRACE_FILE = "clean_trace.json"
ATTACK_TRACE_FILE = "attack_trace.json"
ENV_MODELS_FILE = "env_models.py"
TOOLS_FILE = "tools.py"
SEED_DATA_FILE = "seed_data.yaml"
INJECTION_FILE = "injection.yaml"
MANIFEST_FILE = "manifest.yaml"


def default_run_dir(scenario_id: str, output_dir: str | Path | None = None) -> Path:
    """Resolve the run output directory for a scenario."""
    if output_dir:
        return Path(output_dir)
    return RUNS_DIR / scenario_id


class _LiteralStr(str):
    """Marker type for YAML literal block scalars."""


def _literal_representer(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(_LiteralStr, _literal_representer)


def _injection_to_yaml_dict(injection: InjectionScenario) -> dict:
    data = injection.model_dump()
    data["additional_seed_data"] = json.loads(data.pop("additional_seed_data_json") or "{}")
    for payload in data["payloads"]:
        payload["payload_text"] = _LiteralStr(payload["payload_text"])
    return data


def _yaml_dict_to_injection(data: dict) -> InjectionScenario:
    injection_data = dict(data)
    additional_seed = injection_data.pop("additional_seed_data", {})
    injection_data["additional_seed_data_json"] = json.dumps(additional_seed)
    return InjectionScenario(**injection_data)


def save_artifacts(path: str, artifacts: SavedScenarioArtifacts) -> None:
    """Write env models, tools, seed data, and injection into a run directory."""
    out_dir = Path(path)
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / ENV_MODELS_FILE).write_text(artifacts.environment.pydantic_model_code)
    (out_dir / TOOLS_FILE).write_text(artifacts.environment.tool_function_code)

    seed_data = json.loads(artifacts.environment.seed_data_json)
    with open(out_dir / SEED_DATA_FILE, "w") as f:
        yaml.dump(seed_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    with open(out_dir / INJECTION_FILE, "w") as f:
        yaml.dump(
            _injection_to_yaml_dict(artifacts.injection_scenario),
            f,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )

    manifest = {
        "user_task_prompt": artifacts.environment.user_task_prompt,
        "expected_tool_sequence": artifacts.environment.expected_tool_sequence,
    }
    with open(out_dir / MANIFEST_FILE, "w") as f:
        yaml.dump(manifest, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    log.info(
        "Saved artifacts to %s (%s, %s, %s, %s, %s)",
        out_dir,
        ENV_MODELS_FILE,
        TOOLS_FILE,
        SEED_DATA_FILE,
        INJECTION_FILE,
        MANIFEST_FILE,
    )


def save_trace(path: str | Path, trace: DryRunTrace, filename: str = CLEAN_TRACE_FILE) -> None:
    """Write a dry-run or attack trace JSON file into a run directory."""
    out_path = Path(path) / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(trace.model_dump(), f, indent=2, default=str)
    log.info("Saved trace to %s", out_path)


def load_artifacts(path: str) -> SavedScenarioArtifacts:
    """Load artifacts from a run directory or legacy monolithic YAML file."""
    artifact_path = Path(path)

    if artifact_path.is_file():
        return _load_legacy_yaml(artifact_path)

    if not artifact_path.is_dir():
        raise FileNotFoundError(f"Artifact path not found: {artifact_path}")

    env_models = (artifact_path / ENV_MODELS_FILE).read_text()
    tools = (artifact_path / TOOLS_FILE).read_text()

    with open(artifact_path / SEED_DATA_FILE) as f:
        seed_data = yaml.safe_load(f)

    with open(artifact_path / INJECTION_FILE) as f:
        injection = _yaml_dict_to_injection(yaml.safe_load(f))

    with open(artifact_path / MANIFEST_FILE) as f:
        manifest = yaml.safe_load(f)

    environment = GeneratedEnvironment(
        user_task_prompt=manifest["user_task_prompt"],
        pydantic_model_code=env_models,
        tool_function_code=tools,
        seed_data_json=json.dumps(seed_data),
        expected_tool_sequence=manifest["expected_tool_sequence"],
    )
    return SavedScenarioArtifacts(environment=environment, injection_scenario=injection)


def _load_legacy_yaml(path: Path) -> SavedScenarioArtifacts:
    with open(path) as f:
        data = yaml.safe_load(f)

    env_data = dict(data["environment"])
    env_data["seed_data_json"] = json.dumps(env_data.pop("seed_data"))
    injection_data = dict(data["injection_scenario"])
    additional_seed = injection_data.pop("additional_seed_data", {})
    injection_data["additional_seed_data_json"] = json.dumps(additional_seed)

    return SavedScenarioArtifacts(
        environment=GeneratedEnvironment(**env_data),
        injection_scenario=InjectionScenario(**injection_data),
    )
