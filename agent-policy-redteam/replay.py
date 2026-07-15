"""Replay an attack run from saved environment + injection artifacts."""

import argparse
import json
import logging

from artifacts_io import load_artifacts
from executor import attack_run

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def replay_attack(artifacts_path: str) -> None:
    artifacts = load_artifacts(artifacts_path)
    logger.info(
        "Loaded artifacts — tools in env: %s",
        artifacts.environment.expected_tool_sequence,
    )
    logger.info("Injection payloads: %d", len(artifacts.injection_scenario.payloads))

    trace = attack_run(artifacts.environment, artifacts.injection_scenario)
    logger.info("Replay complete: %d tool calls", len(trace.tool_calls))

    for tc in trace.tool_calls:
        print(f"  Turn {tc.turn_number}: {tc.name}({json.dumps(tc.arguments)})")


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay attack from saved artifacts")
    parser.add_argument(
        "--artifacts",
        required=True,
        help="Path to artifact directory (or legacy monolithic YAML)",
    )
    args = parser.parse_args()
    replay_attack(args.artifacts)


if __name__ == "__main__":
    main()
