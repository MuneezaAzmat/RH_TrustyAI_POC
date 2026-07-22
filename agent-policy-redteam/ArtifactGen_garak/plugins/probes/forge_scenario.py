"""Config-driven Garak probe for forge scenarios.

Installed into the local garak clone as garak.probes.forge_scenario.
Loads prompts/goal/tags from a YAML config produced by ArtifactGen_garak.gen.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import yaml

from garak import _config
from garak.probes.base import Probe
from garak.probes._tier import Tier

log = logging.getLogger(__name__)

# Env fallback when probe_options are not set
_ENV_CONFIG = "FORGE_SCENARIO_CONFIG"


def _load_scenario_config(path: str) -> dict:
    p = Path(path).expanduser()
    if not p.is_file():
        raise FileNotFoundError(
            f"Forge scenario config not found: {p}. "
            f"Generate with: python -m ArtifactGen_garak.gen --no-llm"
        )
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict) or not data.get("prompts"):
        raise ValueError(f"Invalid forge scenario config: {p}")
    return data


class ForgeScenario(Probe):
    """Run a forge scenario attack using a YAML/JSON config file.

    Set ``config_path`` via probe_options or env ``FORGE_SCENARIO_CONFIG``.
    """

    lang = "en"
    active = False
    tier = Tier.UNLISTED
    goal = "execute forge scenario attack from config"
    doc_uri = ""
    tags = ["owasp:llm01", "payload:promptinject", "quality:Security:PromptInjection"]
    primary_detector = "forge_scenario.ForgeScenarioDetector"
    prompts = []

    DEFAULT_PARAMS = Probe.DEFAULT_PARAMS | {
        "config_path": "",
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)

        path = getattr(self, "config_path", "") or os.environ.get(_ENV_CONFIG, "")
        if not path:
            raise ValueError(
                "ForgeScenario requires config_path "
                f"(probe_options or {_ENV_CONFIG})"
            )

        cfg = _load_scenario_config(path)
        self.config_path = str(Path(path).expanduser().resolve())
        self.scenario_id = cfg.get("scenario_id", Path(path).stem)
        self.goal = cfg.get("goal") or self.goal
        if cfg.get("tags"):
            self.tags = list(cfg["tags"])
        self.prompts = list(cfg["prompts"])
        self.detection = cfg.get("detection") or {}
        self.description = (
            f"Forge scenario {self.scenario_id}: "
            f"{cfg.get('mechanism_name', self.goal)}"
        )
        log.info(
            "ForgeScenario loaded %s (%d prompts) from %s",
            self.scenario_id,
            len(self.prompts),
            self.config_path,
        )
