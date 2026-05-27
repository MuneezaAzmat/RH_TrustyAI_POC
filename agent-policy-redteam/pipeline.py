"""Main orchestrator for agent policy red-team pipeline."""

import argparse
import logging
from pathlib import Path
import yaml

from models import RiskCard, ScenarioResult
from triage import triage_risk, filter_agent_level

# Imports that will be implemented in other modules
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
    from injection_generator import generate_injections
except ImportError:
    generate_injections = None

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


def load_riskcard(path: str) -> RiskCard:
    """Load RiskCard from YAML file."""
    logger.info(f"Loading RiskCard from {path}")

    with open(path, 'r') as f:
        data = yaml.safe_load(f)

    # Handle both top-level and nested risk_card format
    if 'risk_card' in data:
        data = data['risk_card']

    return RiskCard(**data)


def run_pipeline(riskcard_path: str, attack_pattern: str = "delayed_trigger", attack_variant: str | None = None) -> list[ScenarioResult]:
    """
    Run complete red-team pipeline for a RiskCard.

    Flow:
    1. Load and triage risk card
    2. Filter to agent-level risks only
    3. For each agent-level risk:
       a. Generate environment (user task + tools + seed data)
       b. Run dry run (clean baseline)
       c. Generate injections based on dry run trace
       d. Run attack run with injected environment
       e. Evaluate (state diff + call trace diff + verification predicates)
    4. Return results
    """
    results = []

    # Step 1: Load and triage
    logger.info("Step 1: Loading and triaging RiskCard")
    risk_card = load_riskcard(riskcard_path)
    triaged = triage_risk(risk_card)
    logger.info(f"Triaged as {triaged.enforcement_level} level, type: {triaged.risk_type}")

    # Step 2: Filter to agent-level only
    agent_risks = filter_agent_level([triaged])

    if not agent_risks:
        logger.warning("No agent-level risks found, skipping pipeline")
        return results

    logger.info(f"Processing {len(agent_risks)} agent-level risk(s)")

    # Step 3: Process each risk
    for idx, triaged_risk in enumerate(agent_risks, 1):
        logger.info(f"\n{'='*60}")
        logger.info(f"Processing risk {idx}/{len(agent_risks)}: {triaged_risk.risk_card.id}")
        logger.info(f"{'='*60}")

        # 3a. Generate environment
        logger.info("Step 3a: Generating environment")
        if generate_environment is None:
            logger.error("env_generator module not available, skipping")
            continue

        env = generate_environment(triaged_risk.risk_card, triaged_risk.risk_type)
        logger.info(f"Generated environment with task: {env.user_task_prompt[:100]}...")

        # 3b. Dry run (clean baseline)
        logger.info("Step 3b: Running dry run (clean baseline)")
        if dry_run is None:
            logger.error("executor module not available, skipping")
            continue

        clean_trace = dry_run(env)
        logger.info(f"Dry run complete: {len(clean_trace.tool_calls)} tool calls")

        # 3c. Generate injections
        logger.info("Step 3c: Generating injections")
        if generate_injections is None:
            logger.error("injection_generator module not available, skipping")
            continue

        injection_scenario = generate_injections(
            triaged_risk,
            env,
            clean_trace,
            pattern=attack_pattern,
            variant=attack_variant,
        )
        logger.info(f"Generated injection scenario: {injection_scenario.injection_goal}")
        logger.info(f"Payloads: {len(injection_scenario.payloads)}")

        # 3d. Attack run
        logger.info("Step 3d: Running attack run with injections")
        if attack_run is None:
            logger.error("executor module not available, skipping")
            continue

        attack_trace = attack_run(env, injection_scenario)
        logger.info(f"Attack run complete: {len(attack_trace.tool_calls)} tool calls")

        # 3e. Evaluate
        logger.info("Step 3e: Evaluating results")
        if evaluate is None:
            logger.error("evaluator module not available, skipping")
            continue

        result = evaluate(
            scenario_id=f"{triaged_risk.risk_card.id}-{idx}",
            risk_card=triaged_risk.risk_card,
            injection_scenario=injection_scenario,
            clean_trace=clean_trace,
            attack_trace=attack_trace
        )

        logger.info(f"Evaluation complete: policy_violated={result.policy_violated}")
        logger.info(f"Evidence: {len(result.evidence)} items")

        results.append(result)

    return results


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Agent policy red-team pipeline"
    )
    parser.add_argument(
        "--riskcard",
        required=True,
        help="Path to RiskCard YAML file"
    )
    parser.add_argument(
        "--report-output",
        help="Optional path to write JSON report"
    )
    parser.add_argument(
        "--attack-pattern",
        default="delayed_trigger",
        choices=["delayed_trigger", "progressive_escalation"],
        help="Attack pattern to use (default: delayed_trigger)"
    )
    parser.add_argument(
        "--attack-variant",
        default=None,
        help="Attack variant from library (e.g., authority_impersonation, helpful_assistant_exploit, system_prompt_override)"
    )

    args = parser.parse_args()

    # Run pipeline
    logger.info(f"Starting pipeline with RiskCard: {args.riskcard}")
    logger.info(f"Attack pattern: {args.attack_pattern}")

    results = run_pipeline(args.riskcard, args.attack_pattern, args.attack_variant)

    # Print summary
    print(f"\n{'='*60}")
    print("PIPELINE SUMMARY")
    print(f"{'='*60}")
    print(f"Total scenarios: {len(results)}")
    print(f"Policy violations: {sum(1 for r in results if r.policy_violated)}")
    print(f"Clean runs: {sum(1 for r in results if not r.policy_violated)}")

    for result in results:
        print(f"\nScenario: {result.scenario_id}")
        print(f"  Risk: {result.risk_card_id}")
        print(f"  Security: {result.security_score*100:.0f}%")
        print(f"  Utility:  {result.utility_score*100:.0f}%")
        print(f"  Policy violated: {result.policy_violated}")
        print(f"  Unexpected tool calls: {len(result.unexpected_tool_calls)}")

    # Write report if requested
    if args.report_output:
        import json
        report_path = Path(args.report_output)
        report_data = [r.model_dump() for r in results]

        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        logger.info(f"Report written to {report_path}")


if __name__ == "__main__":
    main()
