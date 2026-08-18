"""CLI: scenario YAML → runs/{scenario_id}/{scenario_id}-garak.json (one-shot LLM)."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path

from .classify import lookup_surface, surface_skip_reason
from .extract import ScenarioContext, load_scenario
from .gate import gate_from_context
from .probe_spec import (
    GENERATE_ARTIFACT_PROMPT,
    PROBE_VALIDATION_CHECKS,
    SKIP_VALIDATION_CHECKS,
    generate_scenario_probe,
    probe_to_artifact_dict,
    skip_to_artifact_dict,
)
from .spec_io import (
    MANIFEST_FILE,
    runs_dir,
    save_garak_artifact,
    save_validation,
)

log = logging.getLogger(__name__)

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples" / "scenarios"


@dataclass
class GenResult:
    scenario_id: str
    ok: bool
    gate: str
    gate_reason: str = ""
    artifact_path: str | None = None
    errors: list[str] | None = None


def generate_artifact(
    ctx: ScenarioContext,
    *,
    prompt_path: Path | None = None,
    output_dir: Path | None = None,
    use_llm: bool = True,
    force: bool = False,
    dry_run: bool = False,
) -> GenResult:
    """Scenario YAML → runs/{scenario_id}/{scenario_id}-garak.json."""
    prompt = prompt_path or GENERATE_ARTIFACT_PROMPT
    out_base = runs_dir(output_dir)

    skip_reason = surface_skip_reason(ctx)
    if skip_reason:
        log.info("SKIP %s — %s", ctx.scenario_id, skip_reason)
        artifact_path: str | None = None
        if not dry_run:
            save_validation(
                ctx.scenario_id,
                True,
                [],
                out_base,
                checks=SKIP_VALIDATION_CHECKS,
            )
            path = save_garak_artifact(
                ctx.scenario_id, skip_to_artifact_dict(ctx), out_base
            )
            artifact_path = str(path)
            log.info("DONE %s → %s (no coverage)", ctx.scenario_id, path.name)
        return GenResult(
            scenario_id=ctx.scenario_id,
            ok=True,
            gate="skip",
            gate_reason=skip_reason,
            artifact_path=artifact_path,
        )

    if not use_llm:
        return GenResult(
            scenario_id=ctx.scenario_id,
            ok=False,
            gate="error",
            errors=["Artifact generation requires LLM (omit --no-llm)"],
        )

    injection_surface = lookup_surface(ctx.seed_id)
    log.info(
        "Classified %s injection_surface=%s",
        ctx.scenario_id,
        injection_surface,
    )

    probe_result = generate_scenario_probe(
        ctx, prompt, injection_surface=injection_surface
    )
    save_validation(
        ctx.scenario_id,
        probe_result.ok,
        probe_result.errors,
        out_base,
        checks=PROBE_VALIDATION_CHECKS,
    )

    trigger = ""
    for name in ctx.quoted_tools:
        if any(k in name for k in ("refund", "payment", "modify")):
            trigger = name
            break
    if not trigger and ctx.quoted_tools:
        trigger = ctx.quoted_tools[0]
    gate_result, gate_reason = gate_from_context(
        ctx,
        surface=injection_surface,
        trigger_tool=trigger,
        oracle_kind="forbidden_call" if trigger else "output_string",
        tools_grounded=bool(ctx.quoted_tools),
    )
    if not probe_result.ok:
        detail = "; ".join(probe_result.errors)
        gate_result = "partial" if force else "error"
        gate_reason = f"{gate_reason}; {detail}" if detail else gate_reason

    if not probe_result.ok and not force:
        log.warning("Probe gate failed for %s: %s", ctx.scenario_id, probe_result.errors)
        return GenResult(
            scenario_id=ctx.scenario_id,
            ok=False,
            gate="error",
            gate_reason=gate_reason,
            errors=probe_result.errors,
        )

    if dry_run:
        log.info("DRY-RUN %s — gate=%s (%s)", ctx.scenario_id, gate_result, gate_reason)
        return GenResult(
            scenario_id=ctx.scenario_id,
            ok=True,
            gate=gate_result,
            gate_reason=gate_reason,
        )

    artifact_path = save_garak_artifact(
        ctx.scenario_id,
        probe_to_artifact_dict(
            ctx, probe_result.probe, platform_coverage=gate_result
        ),
        out_base,
    )
    log.info("DONE %s → %s", ctx.scenario_id, artifact_path.name)
    return GenResult(
        scenario_id=ctx.scenario_id,
        ok=True,
        gate=gate_result,
        gate_reason=gate_reason,
        artifact_path=str(artifact_path),
        errors=probe_result.errors if probe_result.errors else None,
    )


def list_scenario_files() -> list[Path]:
    if not EXAMPLES_DIR.is_dir():
        return []
    return sorted(EXAMPLES_DIR.glob("AP-*.yaml"))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Scenario YAML → runs/{scenario_id}/{scenario_id}-garak.json",
    )
    parser.add_argument(
        "scenarios",
        nargs="*",
        help="Scenario YAML file(s). If omitted, processes all in examples/scenarios/",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Override runs/ output directory (default: runs/)",
    )
    parser.add_argument(
        "--prompt",
        default=None,
        help="Override probe prompt (default: prompts/generate_artifact.md)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Classify + LLM + validate only — do not write garak JSON",
    )
    parser.add_argument("--no-llm", action="store_true", help="Refuse LLM (only useful for skip check)")
    parser.add_argument("--force", action="store_true", help="Write garak JSON even if probe validation fails")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-5s %(name)s: %(message)s",
    )

    output_dir = Path(args.output_dir) if args.output_dir else None
    prompt_path = Path(args.prompt) if args.prompt else None
    paths = [Path(s) for s in args.scenarios] if args.scenarios else list_scenario_files()
    if not paths:
        print("No scenario files found.", file=sys.stderr)
        sys.exit(1)

    manifest: list[dict] = []
    counts = {"full": 0, "partial": 0, "skip": 0, "error": 0}

    for path in paths:
        try:
            ctx = load_scenario(path)
            result = generate_artifact(
                ctx,
                prompt_path=prompt_path,
                output_dir=output_dir,
                use_llm=not args.no_llm,
                force=args.force,
                dry_run=args.dry_run,
            )
            entry = {
                "scenario_id": result.scenario_id,
                "gate_result": result.gate,
                "gate_reason": result.gate_reason,
                "artifact_path": result.artifact_path,
            }
            if result.errors:
                entry["errors"] = result.errors
            manifest.append(entry)
            counts[result.gate] += 1
        except Exception as e:
            log.error("ERROR processing %s: %s", path.name, e)
            manifest.append({
                "scenario_id": path.stem,
                "gate_result": "error",
                "error": str(e),
            })
            counts["error"] += 1

    if not args.dry_run:
        out = runs_dir(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        manifest_path = out / MANIFEST_FILE
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

    print(f"\n{'Scenario':<25} {'Gate':<8} {'Reason'}")
    print("-" * 70)
    for e in manifest:
        sid = e.get("scenario_id", "?")
        gr = e.get("gate_result", "?")
        reason = e.get("gate_reason", e.get("error", ""))
        print(f"{sid:<25} {gr:<8} {reason}")

    if counts["error"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
