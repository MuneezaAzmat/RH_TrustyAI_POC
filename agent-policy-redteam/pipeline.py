"""Main orchestrator for agent policy red-team pipeline."""

import argparse
import logging
from pathlib import Path
import json

from attack_library import list_patterns
from artifacts_io import (
    ATTACK_TRACE_FILE,
    CLEAN_TRACE_FILE,
    REPORT_FILE,
    SPEC_FILE,
    default_run_dir,
    save_artifacts,
    save_trace,
)
from models import SavedScenarioArtifacts, ScenarioResult
from scenario_filter import is_volume_attack_spec
from scenario_loader import (
    is_volume_attack_forge_scenario,
    load_or_build_scenario_spec,
    load_scenario,
    summarize_scenario,
    triage_from_scenario,
)
from triage import filter_agent_level, filter_scenario_feasible

try:
    from env_generator import generate_environment
except ImportError:
    generate_environment = None

try:
    from executor import dry_run, attack_run
except ImportError:
    dry_run = None
    attack_run = None

try:
    from injection_placer import place_injections
except ImportError:
    place_injections = None

try:
    from evaluator import evaluate, generate_report
except ImportError:
    evaluate = None
    generate_report = None


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def _write_json(path: str, data: object) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    logger.info("Written to %s", out_path)


def run_pipeline(
    scenario_path: str,
    attack_pattern: str = "delayed_trigger",
    attack_variant: str | None = None,
    output_dir: str | Path | None = None,
    spec_output: str | None = None,
    env_output: str | None = None,
    report_output: str | None = None,
) -> list[ScenarioResult]:
    """Run complete red-team pipeline for a forge scenario YAML."""
    results = []

    logger.info("Step 1: Loading forge scenario YAML")
    loaded = load_scenario(scenario_path)
    logger.info("Loaded scenario:\n%s", summarize_scenario(loaded))

    run_dir = default_run_dir(loaded.scenario_id, output_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Run output directory: %s", run_dir.resolve())

    volume_reason = is_volume_attack_forge_scenario(loaded.raw)
    if volume_reason:
        logger.warning(
            "Skipping %s — volume/DDoS/overwhelm attack (%s)",
            loaded.scenario_id,
            volume_reason,
        )
        return results

    triaged = triage_from_scenario(loaded.raw)
    logger.info(
        "Triaged as %s level, type: %s",
        triaged.enforcement_level,
        triaged.risk_type,
    )

    agent_risks = filter_scenario_feasible(filter_agent_level([triaged]))

    if not agent_risks:
        logger.warning("No feasible agent-level risks found, skipping pipeline")
        return results

    logger.info(f"Processing {len(agent_risks)} feasible agent-level risk(s)")

    for idx, triaged_risk in enumerate(agent_risks, 1):
        logger.info(f"\n{'='*60}")
        logger.info(f"Processing risk {idx}/{len(agent_risks)}: {triaged_risk.risk_card.id}")
        logger.info(f"{'='*60}")

        logger.info("Step 2: Loading/building shared ScenarioSpec")
        spec_path = spec_output or str(run_dir / SPEC_FILE)
        spec, spec_source = load_or_build_scenario_spec(
            scenario_path,
            run_dir=run_dir,
            spec_path=spec_path,
            attack_pattern=attack_pattern,
            attack_variant=attack_variant,
            persist=True,
        )
        logger.info("ScenarioSpec %s (source=%s)", spec_path, spec_source)

        volume_reason = is_volume_attack_spec(spec)
        if volume_reason:
            logger.warning(
                "Skipping %s — spec implies volume/DDoS generation (%s)",
                spec.spec_id,
                volume_reason,
            )
            continue

        logger.info(f"Spec: {spec.spec_id} — domain: {spec.domain}")
        logger.info(f"User task: {spec.user_task.prompt[:100]}...")
        logger.info(f"Injection goal: {spec.injection.goal}")
        logger.info(
            "Attack pattern=%s variant=%s",
            spec.injection.attack_pattern,
            spec.injection.attack_variant,
        )

        logger.info("Step 3: Instantiating environment")
        if generate_environment is None:
            logger.error("env_generator module not available, skipping")
            continue

        env = generate_environment(spec)
        logger.info(f"Environment ready — expected tools: {env.expected_tool_sequence}")

        logger.info("Step 4: Running dry run (clean baseline)")
        if dry_run is None:
            logger.error("executor module not available, skipping")
            continue

        clean_trace = dry_run(env)
        logger.info(f"Dry run complete: {len(clean_trace.tool_calls)} tool calls")
        save_trace(run_dir, clean_trace, CLEAN_TRACE_FILE)

        logger.info("Step 5: Placing injections from spec")
        if place_injections is None:
            logger.error("injection_placer module not available, skipping")
            continue

        injection_scenario = place_injections(spec, clean_trace)
        logger.info(f"Placed {len(injection_scenario.payloads)} payloads")

        artifacts = SavedScenarioArtifacts(
            environment=env,
            injection_scenario=injection_scenario,
        )
        artifacts_dir = env_output or str(run_dir)
        save_artifacts(artifacts_dir, artifacts)

        logger.info("Step 6: Running attack run with injections")
        if attack_run is None:
            logger.error("executor module not available, skipping")
            continue

        attack_trace = attack_run(env, injection_scenario)
        logger.info(f"Attack run complete: {len(attack_trace.tool_calls)} tool calls")
        save_trace(run_dir, attack_trace, ATTACK_TRACE_FILE)

        logger.info("Step 7: Evaluating results")
        if evaluate is None:
            logger.error("evaluator module not available, skipping")
            continue

        result = evaluate(
            scenario_id=f"{triaged_risk.risk_card.id}-{idx}",
            risk_card=triaged_risk.risk_card,
            injection_scenario=injection_scenario,
            clean_trace=clean_trace,
            attack_trace=attack_trace,
            scenario_spec=spec,
        )

        logger.info(f"Evaluation complete: policy_violated={result.policy_violated}")
        logger.info(f"Security: {result.security_score*100:.0f}%, Utility: {result.utility_score*100:.0f}%")

        results.append(result)

    if results:
        report_path = report_output or str(run_dir / REPORT_FILE)
        _write_json(report_path, [r.model_dump() for r in results])

    return results


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Agent policy red-team pipeline"
    )
    parser.add_argument(
        "--scenario",
        required=True,
        help="Path to forge scenario YAML (e.g. examples/scenarios/AP-T2-01-28712e.yaml)",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory for all run artifacts (default: runs/{scenario_id}/)",
    )
    parser.add_argument(
        "--report-output",
        help="Override path for JSON report (default: {output-dir}/report.json)",
    )
    parser.add_argument(
        "--spec-output",
        help="Override path for ScenarioSpec JSON (default: {output-dir}/spec.json)",
    )
    parser.add_argument(
        "--env-output",
        help="Override directory for split artifacts (default: {output-dir}/)",
    )
    parser.add_argument(
        "--attack-pattern",
        default="delayed_trigger",
        choices=list_patterns(),
        help="Attack pattern from attack_library (default: delayed_trigger)",
    )
    parser.add_argument(
        "--attack-variant",
        default=None,
        help=(
            "Library variant (e.g. authority_impersonation, embedded_instruction). "
            "Default: library default for the risk type, else mechanism slug from YAML"
        ),
    )

    args = parser.parse_args()

    logger.info(f"Starting pipeline with forge scenario: {args.scenario}")
    logger.info(f"Attack pattern: {args.attack_pattern}")

    results = run_pipeline(
        scenario_path=args.scenario,
        attack_pattern=args.attack_pattern,
        attack_variant=args.attack_variant,
        output_dir=args.output_dir,
        spec_output=args.spec_output,
        env_output=args.env_output,
        report_output=args.report_output,
    )

    print(f"\n{'='*60}")
    print("PIPELINE SUMMARY")
    print(f"{'='*60}")
    print(f"Total scenarios: {len(results)}")
    print(f"Policy violations: {sum(1 for r in results if r.policy_violated)}")
    print(f"Clean runs: {sum(1 for r in results if not r.policy_violated)}")

    for result in results:
        print(f"\nScenario: {result.scenario_id}")
        print(f"  Spec: {result.spec_id}")
        print(f"  Risk: {result.risk_card_id}")
        print(f"  Security: {result.security_score*100:.0f}%")
        print(f"  Utility:  {result.utility_score*100:.0f}%")
        print(f"  Policy violated: {result.policy_violated}")
        print(f"  Unexpected tool calls: {len(result.unexpected_tool_calls)}")

    loaded = load_scenario(args.scenario)
    run_dir = default_run_dir(loaded.scenario_id, args.output_dir)
    if run_dir.exists():
        print(f"\nArtifacts saved to: {run_dir.resolve()}")


if __name__ == "__main__":
    main()
