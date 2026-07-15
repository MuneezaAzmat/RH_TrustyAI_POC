"""Environment instantiator: deterministic codegen + LLM seed data."""

import json
import logging

from codegen import generate_model_code, generate_tool_code
from models import GeneratedEnvironment
from scenario_spec import ScenarioSpec
from seed_generator import generate_seed_data, validate_seed

log = logging.getLogger(__name__)


def _validate_tools(spec: ScenarioSpec, model_code: str, tool_code: str) -> list[str]:
    errors: list[str] = []
    try:
        exec_globals: dict = {}
        exec(model_code, exec_globals)
        for obj in exec_globals.values():
            if isinstance(obj, type) and hasattr(obj, "model_fields"):
                try:
                    obj.model_rebuild(_types_namespace=exec_globals)
                except Exception:
                    pass
        tool_globals = dict(exec_globals)
        exec(tool_code, tool_globals)

        for tool in spec.domain_skeleton.required_tools:
            if tool.name not in tool_globals:
                errors.append(f"Missing required tool: {tool.name}")
    except Exception as e:
        errors.append(f"Code execution failed: {e}")
    return errors


def generate_environment(spec: ScenarioSpec) -> GeneratedEnvironment:
    """Build environment from spec: codegen for models/tools, LLM for seed data."""
    log.info("Generating environment for %s via spec-driven codegen", spec.spec_id)

    model_code = generate_model_code(spec)
    tool_code = generate_tool_code(spec)

    code_errors = _validate_tools(spec, model_code, tool_code)
    if code_errors:
        raise RuntimeError(f"Codegen failed validation: {code_errors}")

    seed_json = generate_seed_data(spec, model_code)
    seed = json.loads(seed_json)
    seed_errors = validate_seed(spec, seed, model_code)
    if seed_errors:
        log.warning("Final seed validation issues (non-fatal): %s", seed_errors)

    env = GeneratedEnvironment(
        user_task_prompt=spec.user_task.prompt,
        pydantic_model_code=model_code,
        tool_function_code=tool_code,
        seed_data_json=seed_json,
        expected_tool_sequence=spec.utility_criteria.expected_tool_calls,
    )

    log.info(
        "Environment ready — tools: %s, records: %d collections",
        [t.name for t in spec.domain_skeleton.required_tools],
        len(spec.domain_skeleton.entity_types),
    )
    return env
