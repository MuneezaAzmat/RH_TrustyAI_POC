"""Step 1 CLI: scenario YAML → schema-v2 ``runs/{id}/spec.json``.

Flow::

    scenario YAML
      → choose exploit from exploit_styles.json
      → plan_spec.generate_spec_plan()          (pass 1)
      → materialize_spec.materialize_spec()     (pass 2)
      → gate 1 (schema) + gate 2 (completeness)
      → spec_io.save_spec()
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

from draft_spec import (
    scenario_actor_beliefs_excerpt,
    scenario_attack_tree_excerpt,
    scenario_narrative_excerpt,
    scenario_narrative_plan_excerpt,
    scenario_plan_grounding_text,
)
from environment_spec import EnvironmentSpec, ExploitStyle
from llm_complete_spec import SpecBuildResult, generate_environment_spec
from plan_spec import PlanBuildResult, gate_plan_errors, generate_spec_plan
from spec_io import PLAN_FILE, SPEC_FILE, default_run_dir, load_spec, save_plan, save_spec

log = logging.getLogger(__name__)

DEFAULT_SCENARIOS_DIR = Path(__file__).parent / "examples" / "scenarios"
_EXPLOIT_CATALOG = Path(__file__).parent / "exploit_styles.json"
_STAGING_NAMES = frozenset({"delayed_trigger", "progressive_escalation"})


def load_exploit_catalog() -> list[dict]:
    data = json.loads(_EXPLOIT_CATALOG.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{_EXPLOIT_CATALOG} must be a JSON array of styles")
    return data


def list_style_names() -> list[str]:
    return [style["name"] for style in load_exploit_catalog()]


def get_style(name: str) -> dict | None:
    for style in load_exploit_catalog():
        if style.get("name") == name:
            return dict(style)
    return None


def choose_exploit(name: str | None = None) -> dict:
    """Return ``{name, description}`` from exploit_styles.json."""
    if name:
        style = get_style(name)
        if not style:
            raise ValueError(f"Unknown exploit {name!r}. Known: {list_style_names()}")
        return {"name": style["name"], "description": style["description"]}
    packs = [s for s in load_exploit_catalog() if s.get("name") not in _STAGING_NAMES]
    pick = random.choice(packs or load_exploit_catalog())
    return {"name": pick["name"], "description": pick["description"]}


@dataclass
class LoadedScenario:
    path: Path
    raw: dict

    @property
    def scenario_id(self) -> str:
        return str(self.raw.get("scenario_id", self.path.stem))


def list_scenario_files(directory: str | Path = DEFAULT_SCENARIOS_DIR) -> list[Path]:
    return sorted(Path(directory).glob("AP-*.yaml"))


def load_scenario(path: str | Path) -> LoadedScenario:
    scenario_path = Path(path)
    if not scenario_path.exists():
        raise FileNotFoundError(f"Scenario file not found: {scenario_path}")
    data = yaml.safe_load(scenario_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "scenario_id" not in data:
        raise ValueError(f"Invalid scenario YAML: {scenario_path}")
    loaded = LoadedScenario(path=scenario_path, raw=data)
    feature = scenario_path.with_suffix(".feature")
    if feature.exists():
        loaded.raw["_feature_text"] = feature.read_text(encoding="utf-8")
    return loaded


def summarize_scenario(loaded: LoadedScenario) -> str:
    narrative = loaded.raw.get("narrative") or {}
    tree = loaded.raw.get("attack_tree") or {}
    meta = loaded.raw.get("scenario_seed_metadata") or {}
    return "\n".join(
        [
            f"ID:          {loaded.scenario_id}",
            f"File:        {loaded.path}",
            f"Threat:      {meta.get('threat_id')} — {meta.get('threat_name')}",
            f"Title:       {narrative.get('title', loaded.scenario_id)}",
            f"Entry:       {narrative.get('entry_point', 'n/a')}",
            f"Attack goal: {tree.get('goal', 'n/a')}",
        ]
    )


def _is_v2_spec(path: Path) -> bool:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False
    return data.get("schema_version") == 2


def build_spec_plan(
    scenario_path: str | Path,
    *,
    run_dir: str | Path | None = None,
    exploit_name: str | None = None,
    persist: bool = True,
    force: bool = False,
) -> tuple[PlanBuildResult, str]:
    """Pass 1 only: narrative + draft → ``runs/{id}/spec_plan.json``."""
    loaded = load_scenario(scenario_path)
    out_dir = default_run_dir(loaded.scenario_id, run_dir)
    path = out_dir / PLAN_FILE

    if path.is_file() and not force:
        from spec_io import load_plan

        plan = load_plan(out_dir)
        grounding = scenario_plan_grounding_text(loaded.raw)
        exploit = ExploitStyle.model_validate(choose_exploit(exploit_name))
        errors = gate_plan_errors(
            plan,
            source_text=grounding,
            exploit_name=exploit.name,
        )
        log.info("Loaded spec plan from %s", path)
        return PlanBuildResult(plan=plan, ok=not errors, errors=errors), "disk"

    exploit = ExploitStyle.model_validate(choose_exploit(exploit_name))
    attack_tree = scenario_attack_tree_excerpt(loaded.raw)
    narrative = scenario_narrative_plan_excerpt(loaded.raw)
    actor_beliefs = scenario_actor_beliefs_excerpt(loaded.raw)
    grounding = scenario_plan_grounding_text(loaded.raw)
    result = generate_spec_plan(
        attack_tree,
        narrative,
        actor_beliefs,
        exploit,
        grounding_text=grounding,
    )
    if persist:
        save_plan(out_dir, result.plan)
        if not result.ok:
            sidecar = out_dir / "plan_validation.json"
            sidecar.write_text(
                json.dumps({"ok": result.ok, "errors": result.errors}, indent=2),
                encoding="utf-8",
            )
            log.warning("Wrote plan validation sidecar %s", sidecar)
    source = "rebuilt" if path.is_file() else "built"
    return result, source


def build_environment_spec(
    scenario_path: str | Path,
    *,
    run_dir: str | Path | None = None,
    exploit_name: str | None = None,
    persist: bool = True,
    force: bool = False,
) -> tuple[EnvironmentSpec, str, SpecBuildResult | None]:
    """Build or load ``runs/{id}/spec.json``.

    Returns ``(spec, source, build_result)``. ``build_result`` is None when loaded from disk.
    """
    loaded = load_scenario(scenario_path)
    out_dir = default_run_dir(loaded.scenario_id, run_dir)
    path = out_dir / SPEC_FILE

    if path.is_file() and not force and _is_v2_spec(path):
        spec = load_spec(out_dir)
        log.info("Loaded EnvironmentSpec from %s", path)
        return spec, "disk", None

    exploit = ExploitStyle.model_validate(choose_exploit(exploit_name))
    plan_result, _plan_source = build_spec_plan(
        scenario_path,
        run_dir=run_dir,
        exploit_name=exploit.name,
        persist=persist,
        force=False,
    )
    if not plan_result.ok:
        plan_result, _plan_source = build_spec_plan(
            scenario_path,
            run_dir=run_dir,
            exploit_name=exploit.name,
            persist=persist,
            force=True,
        )
    if not plan_result.ok:
        raise RuntimeError(
            "Pass 1 plan gate failed: " + "; ".join(plan_result.errors)
        )

    narrative = scenario_narrative_excerpt(loaded.raw)
    attack_tree = scenario_attack_tree_excerpt(loaded.raw)
    result = generate_environment_spec(
        narrative,
        loaded.raw,
        plan_result.plan,
        exploit,
        persist_dir=out_dir if persist else None,
        attack_tree=attack_tree,
        source_text=scenario_plan_grounding_text(loaded.raw),
    )
    if persist:
        save_spec(out_dir, result.spec)
        if not result.ok:
            sidecar = out_dir / "validation.json"
            sidecar.write_text(
                json.dumps(
                    {
                        "ok": result.ok,
                        "gate1_errors": result.gate1_errors,
                        "gate2": result.gate2.model_dump() if result.gate2 else None,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            log.warning("Wrote validation sidecar %s", sidecar)
    source = "rebuilt" if path.is_file() else "built"
    return result.spec, source, result


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Step 1: scenario YAML → runs/{id}/spec.json (schema v2 EnvironmentSpec)",
    )
    parser.add_argument(
        "scenarios",
        nargs="*",
        help="Scenario YAML path(s). If omitted, processes all in examples/scenarios/",
    )
    parser.add_argument(
        "--dir",
        default=str(DEFAULT_SCENARIOS_DIR),
        help="Scenario directory when no paths are given",
    )
    parser.add_argument(
        "--run-dir",
        default=None,
        help="Override runs/{scenario_id}/ output directory",
    )
    parser.add_argument(
        "--exploit",
        default=None,
        choices=list_style_names(),
        help="Exploit style from exploit_styles.json (default: random wording pack)",
    )
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="Pass 1 only: write runs/{id}/spec_plan.json and stop",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Rebuild spec even if a v2 spec.json exists",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-5s %(name)s: %(message)s",
    )

    paths = [Path(p) for p in args.scenarios] if args.scenarios else list_scenario_files(args.dir)
    if not paths:
        print("No scenario files found.", file=sys.stderr)
        sys.exit(1)

    run_dir = Path(args.run_dir) if args.run_dir else None
    counts = {"disk": 0, "built": 0, "rebuilt": 0, "error": 0, "invalid": 0}
    exit_code = 0

    for path in paths:
        try:
            if args.plan_only:
                result, source = build_spec_plan(
                    path,
                    run_dir=run_dir,
                    exploit_name=args.exploit,
                    force=args.force,
                )
                out = default_run_dir(load_scenario(path).scenario_id, run_dir) / PLAN_FILE
                log.info("%s → %s (%s)", path.name, out, source)
                print(summarize_scenario(load_scenario(path)))
                tool_names = [t.name for t in result.plan.tools]
                print(
                    f"  goal: {result.plan.attack_goal}"
                )
                print(
                    f"  oracle: {result.plan.oracle.tool}  "
                    f"pass_when: {result.plan.oracle.pass_when}"
                )
                print(f"  signal: {result.plan.success_criteria.observable_signal}")
                print(f"  tools: {tool_names}")
                if not result.ok:
                    counts["invalid"] += 1
                    exit_code = 1
                    log.error("Plan failed gate; see %s", out.parent / "plan_validation.json")
                else:
                    counts[source if source in counts else "built"] += 1
                continue

            spec, source, result = build_environment_spec(
                path,
                run_dir=run_dir,
                exploit_name=args.exploit,
                force=args.force,
            )
            out = default_run_dir(spec.scenario_id, run_dir) / SPEC_FILE
            log.info("%s → %s (%s)", path.name, out, source)
            print(summarize_scenario(load_scenario(path)))
            print(
                f"  spec_id: {spec.spec_id}  exploit: {spec.attack.exploit.name}  "
                f"tools: {spec.tool_names}"
            )
            if result is not None and not result.ok:
                counts["invalid"] += 1
                exit_code = 1
                log.error("Spec failed gates; see %s", out.parent / "validation.json")
            else:
                counts[source if source in counts else "built"] += 1
        except Exception as e:
            log.error("ERROR %s: %s", path.name, e)
            counts["error"] += 1
            exit_code = 1

    print(f"\n{'='*50}")
    print("Spec build summary")
    print(f"{'='*50}")
    print(f"Total:    {len(paths)}")
    print(f"  Disk:     {counts['disk']}")
    print(f"  Built:    {counts['built']}")
    print(f"  Rebuilt:  {counts['rebuilt']}")
    print(f"  Invalid:  {counts['invalid']}")
    print(f"  Error:    {counts['error']}")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
