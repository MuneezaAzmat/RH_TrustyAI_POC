"""CLI: frozen EnvironmentSpec → Garak artifacts (step 2).

Requires ``runs/{scenario_id}/spec.json`` from step 1.

Usage:
    python -m ArtifactGen_garak.gen
    python -m ArtifactGen_garak.gen examples/scenarios/AP-T9-01-8c5d51.yaml
    python -m ArtifactGen_garak.gen --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from spec_io import SPEC_FILE, default_run_dir, load_spec, save_spec

from .artifact_io import DEFAULT_ARTIFACT_DIR, save_artifact
from .gate import gate_garak, stamp_garak_coverage
from .judge_rubric import generate_judge_rubric
from .realize import RealizedProbe, _build_detection_config, realize_chat, serialize_tagged

log = logging.getLogger(__name__)

EXAMPLES_DIR = Path("examples/scenarios")


def list_scenario_files() -> list[Path]:
    if not EXAMPLES_DIR.is_dir():
        return []
    return sorted(EXAMPLES_DIR.glob("*.yaml"))


def _process_scenario(
    path: Path,
    artifact_dir: Path,
    dry_run: bool = False,
    run_dir: Path | None = None,
) -> dict:
    scenario_id = path.stem
    out_dir = default_run_dir(scenario_id, run_dir)

    spec = load_spec(out_dir)
    result, gated_spec, reason = gate_garak(spec)
    stamped = stamp_garak_coverage(gated_spec, result, reason)
    save_spec(out_dir, stamped)

    entry = {
        "scenario_id": scenario_id,
        "seed_id": stamped.source.seed_id,
        "threat_id": stamped.source.threat_id,
        "surface": stamped.injection_surface,
        "oracle": stamped.oracle_target,
        "exploit": stamped.attack.exploit.name,
        "gate_result": result,
        "gate_reason": reason,
        "artifact_path": None,
        "spec_id": stamped.spec_id,
        "spec_source": "runs",
        "spec_path": str(out_dir / SPEC_FILE),
    }

    if result == "skip":
        log.info("SKIP %s — %s (spec stamped)", scenario_id, reason)
        return entry

    if dry_run:
        log.info(
            "DRY-RUN %s — gate=%s (%s) spec stamped",
            scenario_id,
            result,
            reason,
        )
        return entry

    chat_history = realize_chat(stamped)
    judge_rubric = generate_judge_rubric(stamped)
    detection_config = _build_detection_config(stamped)
    realized = RealizedProbe(
        spec=stamped,
        chat_history=chat_history,
        conversation_text=serialize_tagged(chat_history),
        payload_text=chat_history.payload_text,
        detection_config=detection_config,
        judge_rubric=judge_rubric,
    )
    artifact_path = save_artifact(realized, artifact_dir)
    entry["artifact_path"] = str(artifact_path)
    entry["surface"] = stamped.injection_surface
    entry["oracle"] = stamped.oracle_target
    log.info(
        "DONE %s → %s (spec=%s)",
        scenario_id,
        artifact_path.name,
        entry["spec_path"],
    )
    return entry


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Frozen EnvironmentSpec (runs/{id}/spec.json) → Garak probe artifacts "
            "with garak_data chat history and judge rubric"
        ),
    )
    parser.add_argument(
        "scenarios",
        nargs="*",
        help="Scenario YAML file(s). If omitted, processes all in examples/scenarios/",
    )
    parser.add_argument(
        "--artifact-dir",
        "--config-dir",
        dest="artifact_dir",
        default=str(DEFAULT_ARTIFACT_DIR),
        help=f"Where to write YAML artifacts (default: {DEFAULT_ARTIFACT_DIR})",
    )
    parser.add_argument(
        "--run-dir",
        default=None,
        help="Override runs/{scenario_id}/ for shared spec.json (default: runs/{id})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Load spec + gate + stamp only — no artifact output",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-5s %(name)s: %(message)s",
    )

    artifact_dir = Path(args.artifact_dir)
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
                artifact_dir,
                dry_run=args.dry_run,
                run_dir=run_dir,
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
        artifact_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = artifact_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
        log.info("Manifest written to %s", manifest_path)

    print(f"\n{'='*50}")
    print("Garak artifact generation summary")
    print(f"{'='*50}")
    print(f"Total scenarios: {len(manifest)}")
    print(f"  Full:    {counts['full']}")
    print(f"  Partial: {counts['partial']}")
    print(f"  Skip:    {counts['skip']}")
    print(f"  Error:   {counts['error']}")
    if not args.dry_run and (counts["full"] + counts["partial"]) > 0:
        print(f"\nArtifacts: {artifact_dir}/")

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
