"""CLI entry point: scenario YAML → Garak probe + detector files.

Usage:
    python garak_gen.py                                        # all scenarios
    python garak_gen.py examples/scenarios/AP-T2-01-*.yaml     # single file
    python garak_gen.py --output-dir garak_out/                # custom output
    python garak_gen.py --dry-run                              # classify only
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from garak_emitter import emit
from garak_ir import classify, gate
from garak_realizer import realize
from scenario_loader import list_scenario_files, load_scenario

log = logging.getLogger(__name__)

DEFAULT_OUTPUT_DIR = Path("garak_out")


def _process_scenario(
    path: Path,
    output_dir: Path,
    dry_run: bool = False,
) -> dict:
    """Process a single scenario YAML. Returns manifest entry."""
    loaded = load_scenario(path)
    scenario_id = loaded.scenario_id

    ir = classify(loaded.raw)

    result, gated_ir, reason = gate(ir)

    entry = {
        "scenario_id": scenario_id,
        "seed_id": ir.seed_id,
        "threat_id": ir.threat_id,
        "surface": ir.injection_surface.value,
        "oracle": ir.oracle_target.value,
        "gate_result": result,
        "gate_reason": reason,
        "probe_path": None,
        "detector_path": None,
    }

    if result == "skip":
        log.info("SKIP %s — %s", scenario_id, reason)
        return entry

    if dry_run:
        log.info("DRY-RUN %s — gate=%s (%s)", scenario_id, result, reason)
        return entry

    realized = realize(gated_ir)
    probe_path, detector_path = emit(realized, output_dir)

    entry["probe_path"] = str(probe_path)
    entry["detector_path"] = str(detector_path)
    entry["surface"] = gated_ir.injection_surface.value
    entry["oracle"] = gated_ir.oracle_target.value

    log.info("DONE %s → %s, %s", scenario_id, probe_path.name, detector_path.name)
    return entry


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate Garak probe + detector files from scenario YAMLs",
    )
    parser.add_argument(
        "scenarios",
        nargs="*",
        help="Scenario YAML file(s). If omitted, processes all in examples/scenarios/",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Classify and gate only — no LLM calls, no file output",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-5s %(name)s: %(message)s",
    )

    output_dir = Path(args.output_dir)

    if args.scenarios:
        paths = [Path(s) for s in args.scenarios]
    else:
        paths = list_scenario_files()

    if not paths:
        print("No scenario files found.", file=sys.stderr)
        sys.exit(1)

    manifest: list[dict] = []
    counts = {"full": 0, "partial": 0, "skip": 0, "error": 0}

    for path in paths:
        try:
            entry = _process_scenario(path, output_dir, dry_run=args.dry_run)
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

    # Write manifest
    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = output_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
        log.info("Manifest written to %s", manifest_path)

    # Summary
    print(f"\n{'='*50}")
    print(f"Garak Generation Summary")
    print(f"{'='*50}")
    print(f"Total scenarios: {len(manifest)}")
    print(f"  Full:    {counts['full']}")
    print(f"  Partial: {counts['partial']}")
    print(f"  Skip:    {counts['skip']}")
    print(f"  Error:   {counts['error']}")
    if not args.dry_run and (counts["full"] + counts["partial"]) > 0:
        print(f"\nOutput: {output_dir}/")

    # Print classification table
    print(f"\n{'Scenario':<25} {'Surface':<15} {'Oracle':<15} {'Gate':<8} {'Reason'}")
    print("-" * 90)
    for e in manifest:
        sid = e.get("scenario_id", "?")
        surface = e.get("surface", "?")
        oracle = e.get("oracle", "?")
        gr = e.get("gate_result", "?")
        reason = e.get("gate_reason", e.get("error", ""))
        print(f"{sid:<25} {surface:<15} {oracle:<15} {gr:<8} {reason}")


if __name__ == "__main__":
    main()
