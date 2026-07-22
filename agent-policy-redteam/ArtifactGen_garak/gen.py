"""CLI: forge scenario / shared ScenarioSpec → Garak configs.

Prefers ``runs/{scenario_id}/spec.json`` when present and up to date;
otherwise builds from forge YAML and persists the shared spec.

Usage:
    python -m ArtifactGen_garak.gen
    python -m ArtifactGen_garak.gen examples/scenarios/AP-T9-01-8c5d51.yaml
    python -m ArtifactGen_garak.gen --dry-run
    python -m ArtifactGen_garak.gen --no-llm
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from attack_library import list_patterns
from artifacts_io import SPEC_FILE, default_run_dir
from scenario_loader import list_scenario_files, load_or_build_scenario_spec, load_scenario

from .config_io import DEFAULT_CONFIG_DIR, save_config
from .gate import gate_garak
from .realize import realize

log = logging.getLogger(__name__)


def _process_scenario(
    path: Path,
    config_dir: Path,
    dry_run: bool = False,
    use_llm: bool = True,
    run_dir: Path | None = None,
    persist_spec: bool = True,
    attack_pattern: str = "delayed_trigger",
    attack_variant: str | None = None,
) -> dict:
    loaded = load_scenario(path)
    scenario_id = loaded.scenario_id
    out_dir = default_run_dir(scenario_id, run_dir)

    spec, spec_source = load_or_build_scenario_spec(
        path,
        run_dir=out_dir,
        attack_pattern=attack_pattern,
        attack_variant=attack_variant,
        persist=persist_spec,
    )
    result, gated_spec, reason = gate_garak(spec)

    entry = {
        "scenario_id": scenario_id,
        "seed_id": spec.seed_id,
        "threat_id": spec.threat_id,
        "surface": spec.injection_surface,
        "oracle": spec.oracle_target,
        "attack_pattern": spec.injection.attack_pattern,
        "attack_variant": spec.injection.attack_variant,
        "gate_result": result,
        "gate_reason": reason,
        "config_path": None,
        "spec_id": spec.spec_id,
        "spec_source": spec_source,
        "spec_path": str(out_dir / SPEC_FILE),
    }

    if result == "skip":
        log.info("SKIP %s — %s (spec=%s)", scenario_id, reason, spec_source)
        return entry

    if dry_run:
        log.info(
            "DRY-RUN %s — gate=%s (%s) spec=%s",
            scenario_id,
            result,
            reason,
            spec_source,
        )
        return entry

    realized = realize(gated_spec, use_llm=use_llm)
    config_path = save_config(realized, config_dir)
    entry["config_path"] = str(config_path)
    entry["surface"] = gated_spec.injection_surface
    entry["oracle"] = gated_spec.oracle_target
    log.info(
        "DONE %s → %s (spec=%s from %s)",
        scenario_id,
        config_path.name,
        entry["spec_path"],
        spec_source,
    )
    return entry


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Shared ScenarioSpec → Garak probe configs "
            "(loads runs/{id}/spec.json when available)"
        ),
    )
    parser.add_argument(
        "scenarios",
        nargs="*",
        help="Scenario YAML file(s). If omitted, processes all in examples/scenarios/",
    )
    parser.add_argument(
        "--config-dir",
        default=str(DEFAULT_CONFIG_DIR),
        help=f"Where to write YAML configs (default: {DEFAULT_CONFIG_DIR})",
    )
    parser.add_argument(
        "--attack-pattern",
        default="delayed_trigger",
        choices=list_patterns(),
        help="Attack pattern from attack_library (same as pipeline.py)",
    )
    parser.add_argument(
        "--attack-variant",
        default=None,
        help=(
            "Library variant (e.g. authority_impersonation, embedded_instruction). "
            "Default: library default for the risk type, else mechanism slug from YAML"
        ),
    )
    parser.add_argument(
        "--run-dir",
        default=None,
        help="Override runs/{scenario_id}/ for shared spec.json (default: runs/{id})",
    )
    parser.add_argument(
        "--no-persist-spec",
        action="store_true",
        help="Do not write/upgrade runs/{id}/spec.json",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Load/build ScenarioSpec + gate only — no LLM, no config output",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM realize; use deterministic conversation fallback",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-5s %(name)s: %(message)s",
    )

    config_dir = Path(args.config_dir)
    run_dir = Path(args.run_dir) if args.run_dir else None
    paths = [Path(s) for s in args.scenarios] if args.scenarios else list_scenario_files()
    if not paths:
        print("No scenario files found.", file=sys.stderr)
        sys.exit(1)

    manifest: list[dict] = []
    counts = {"full": 0, "partial": 0, "skip": 0, "error": 0}

    for path in paths:
        try:
            entry = _process_scenario(
                path,
                config_dir,
                dry_run=args.dry_run,
                use_llm=not args.no_llm,
                run_dir=run_dir,
                persist_spec=not args.no_persist_spec,
                attack_pattern=args.attack_pattern,
                attack_variant=args.attack_variant,
            )
            manifest.append(entry)
            counts[entry["gate_result"]] += 1
        except Exception as e:
            log.error("ERROR processing %s: %s", path.name, e)
            manifest.append({
                "scenario_id": path.stem,
                "gate_result": "error",
                "error": str(e),
            })
            counts["error"] += 1

    if not args.dry_run:
        config_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = config_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
        log.info("Manifest written to %s", manifest_path)

    print(f"\n{'='*50}")
    print("Garak config generation summary")
    print(f"{'='*50}")
    print(f"Total scenarios: {len(manifest)}")
    print(f"  Full:    {counts['full']}")
    print(f"  Partial: {counts['partial']}")
    print(f"  Skip:    {counts['skip']}")
    print(f"  Error:   {counts['error']}")
    if not args.dry_run and (counts["full"] + counts["partial"]) > 0:
        print(f"\nConfigs: {config_dir}/")

    print(
        f"\n{'Scenario':<25} {'Spec':<10} {'Surface':<15} "
        f"{'Oracle':<15} {'Gate':<8} {'Reason'}"
    )
    print("-" * 100)
    for e in manifest:
        sid = e.get("scenario_id", "?")
        src = e.get("spec_source", e.get("error", "?"))
        surface = e.get("surface", "?")
        oracle = e.get("oracle", "?")
        gr = e.get("gate_result", "?")
        reason = e.get("gate_reason", e.get("error", ""))
        print(f"{sid:<25} {src:<10} {surface:<15} {oracle:<15} {gr:<8} {reason}")


if __name__ == "__main__":
    main()
