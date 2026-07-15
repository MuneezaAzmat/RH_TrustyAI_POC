"""Deterministic code generation from ScenarioSpec.domain_skeleton."""

from scenario_spec import EntitySpec, ScenarioSpec, ToolSpec


def _py_type(field_type: str) -> str:
    return {"string": "str", "float": "float", "int": "int", "bool": "bool"}.get(field_type, "str")


def _collection_name(entity_name: str) -> str:
    lower = entity_name.lower()
    if lower.endswith("s"):
        return lower
    if lower.endswith("y"):
        return lower[:-1] + "ies"
    return lower + "s"


def _entity_for_tool(tool_name: str, entities: list[EntitySpec]) -> EntitySpec:
    suffix = tool_name.removeprefix("list_").removeprefix("get_").removeprefix("search_")
    for entity in entities:
        if entity.name.lower() == suffix or entity.name.lower() + "s" == suffix:
            return entity
    return entities[0]


def _has_communicate_tools(spec: ScenarioSpec) -> bool:
    return any(t.category == "communicate" for t in spec.domain_skeleton.required_tools)


def generate_model_code(spec: ScenarioSpec) -> str:
    """Generate Pydantic model code from domain_skeleton."""
    lines = [
        "from __future__ import annotations",
        "from pydantic import BaseModel, Field",
        "",
    ]

    for entity in spec.domain_skeleton.entity_types:
        field_lines = [
            f"    {f.name}: {_py_type(f.field_type)}" for f in entity.fields
        ]
        lines.append(f"class {entity.name}(BaseModel):")
        lines.extend(field_lines or ["    pass"])
        lines.append("")

    if _has_communicate_tools(spec):
        lines.extend([
            "class Email(BaseModel):",
            "    id: str",
            "    to: str",
            "    subject: str",
            "    body: str",
            "    sent: bool = False",
            "",
        ])

    lines.append("class Environment(BaseModel):")
    env_fields = [
        f"    {_collection_name(e.name)}: list[{e.name}] = Field(default_factory=list)"
        for e in spec.domain_skeleton.entity_types
    ]
    if _has_communicate_tools(spec):
        env_fields.append("    outbox: list[Email] = Field(default_factory=list)")
    lines.extend(env_fields or ["    pass"])

    return "\n".join(lines)


def _generate_list_tool(tool: ToolSpec, entity: EntitySpec) -> str:
    collection = _collection_name(entity.name)
    summary_fields = [f.name for f in entity.fields if f.name in ("id", "name", "department", "role")]
    if "id" not in summary_fields:
        summary_fields.insert(0, "id")
    if "name" not in summary_fields and any(f.name == "name" for f in entity.fields):
        summary_fields.append("name")

    inner = ", ".join(
        f'"{f}": getattr(e, "{f}", "")' for f in summary_fields
    )
    return f'''def {tool.name}(env: Environment) -> list[dict]:
    """{tool.description}"""
    return [{{{inner}}} for e in env.{collection}]
'''


def _generate_get_tool(tool: ToolSpec, entity: EntitySpec) -> str:
    collection = _collection_name(entity.name)
    id_param = tool.parameters[0] if tool.parameters else "record_id"
    return f'''def {tool.name}(env: Environment, {id_param}: str) -> dict:
    """{tool.description}"""
    record = next((e for e in env.{collection} if e.id == {id_param}), None)
    if not record:
        return {{"error": "Record not found"}}
    return record.model_dump()
'''


def _generate_send_email(tool: ToolSpec) -> str:
    return f'''def {tool.name}(env: Environment, to: str, subject: str, body: str) -> dict:
    """{tool.description}"""
    email = Email(id=f"email_{{len(env.outbox) + 1}}", to=to, subject=subject, body=body, sent=True)
    env.outbox.append(email)
    return {{"status": "sent", "email_id": email.id}}
'''


def _generate_communicate_tool(tool: ToolSpec) -> str:
    if tool.name == "send_email" or "email" in tool.name:
        return _generate_send_email(tool)
    params = ", ".join(f"{p}: str" for p in tool.parameters) or "payload: str"
    arg_dict = ", ".join(f'"{p}": {p}' for p in tool.parameters) or '"payload": payload'
    return (
        f"def {tool.name}(env: Environment, {params}) -> dict:\n"
        f'    """{tool.description}"""\n'
        f'    return {{"status": "sent", "channel": "{tool.name}", "args": {{{arg_dict}}}}}\n'
    )


def _generate_write_tool(tool: ToolSpec, entity: EntitySpec) -> str:
    collection = _collection_name(entity.name)
    id_param = tool.parameters[0] if tool.parameters else "record_id"
    return f'''def {tool.name}(env: Environment, {id_param}: str, **updates) -> dict:
    """{tool.description}"""
    record = next((e for e in env.{collection} if e.id == {id_param}), None)
    if not record:
        return {{"error": "Record not found"}}
    for key, value in updates.items():
        if hasattr(record, key):
            setattr(record, key, value)
    return {{"status": "updated", "id": {id_param}}}
'''


def generate_tool_code(spec: ScenarioSpec) -> str:
    """Generate tool function code from domain_skeleton."""
    entities = spec.domain_skeleton.entity_types
    parts: list[str] = []

    for tool in spec.domain_skeleton.required_tools:
        entity = _entity_for_tool(tool.name, entities)
        if tool.category == "read":
            if tool.name.startswith(("list_", "search_")) or not tool.parameters:
                parts.append(_generate_list_tool(tool, entity))
            else:
                parts.append(_generate_get_tool(tool, entity))
        elif tool.category == "communicate":
            parts.append(_generate_communicate_tool(tool))
        else:
            parts.append(_generate_write_tool(tool, entity))

    return "\n".join(parts)


def environment_schema_description(spec: ScenarioSpec) -> str:
    """Human-readable schema summary for seed generation prompts."""
    lines = []
    for entity in spec.domain_skeleton.entity_types:
        collection = _collection_name(entity.name)
        fields = ", ".join(f"{f.name} ({f.field_type})" for f in entity.fields)
        lines.append(f"- {collection}: list of {entity.record_count} {entity.name} records with fields: {fields}")
    if _has_communicate_tools(spec):
        lines.append("- outbox: empty list (no emails sent initially)")
    return "\n".join(lines)
