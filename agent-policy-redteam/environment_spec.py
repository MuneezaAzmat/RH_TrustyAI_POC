"""Schema v2 environment spec: scenario → typed environment + attack + oracles."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExploitStyle(BaseModel):
    name: str
    description: str


class SourceSpec(BaseModel):
    scenario_id: str
    seed_id: str
    threat_id: str
    threat_name: str = ""
    mechanism_name: str = ""
    domain: str
    tags: list[str] = Field(default_factory=list)
    narrative_summary: str = ""


class TaskSpec(BaseModel):
    benign_goal: str
    user_prompt: str
    forbidden_actions: list[str] = Field(default_factory=list)


class ToolIOField(BaseModel):
    name: str
    type: str
    required: bool | None = None
    unit: str | None = None
    values: list[str] | None = None


class SideEffect(BaseModel):
    store: str
    field: str
    write: str


class EnvironmentTool(BaseModel):
    name: str
    kind: Literal["read", "write", "communicate", "privileged"]
    purpose: str
    inputs: list[ToolIOField]
    outputs: list[ToolIOField]
    side_effects: list[SideEffect] = Field(default_factory=list)


class DataStoreField(BaseModel):
    name: str
    type: str
    sensitive: bool = False
    injectable: bool = False
    unique: bool | None = None


class DataStore(BaseModel):
    id: str
    form: Literal["relational_table", "document_collection", "kv", "vector"]
    purpose: str
    record_count: int = Field(ge=1, le=50)
    fields: list[DataStoreField]


class AgentSpec(BaseModel):
    id: str
    role: str
    interface: str
    tools: list[str]
    data_stores: list[str] = Field(default_factory=list)


class RagSpec(BaseModel):
    """Retrieval layer when the attack flows through poisoned context."""

    id: str = "primary_rag"
    purpose: str = ""
    corpus_store: str
    chunk_fields: list[str]
    retrieval_trigger: str
    injectable_field: str


class McpServerSpec(BaseModel):
    """MCP server exposing tools to the agent."""

    id: str
    purpose: str
    tools: list[str] = Field(default_factory=list)


class CredentialSpec(BaseModel):
    """Scoped secret the agent or tools may use."""

    id: str
    purpose: str
    scope: str = ""


class EnvironmentBlock(BaseModel):
    agents: list[AgentSpec]
    tools: list[EnvironmentTool]
    data_stores: list[DataStore] = Field(default_factory=list)
    rag: RagSpec | None = None
    mcp_servers: list[McpServerSpec] = Field(default_factory=list)
    credentials: list[CredentialSpec] = Field(default_factory=list)


class PlacementTarget(BaseModel):
    component: str


class AttackPlacement(BaseModel):
    surface: str
    target: PlacementTarget
    timing: str
    payload_intent: str


class AttackSpec(BaseModel):
    goal: str
    exploit: ExploitStyle
    placement: AttackPlacement


class OracleCheck(BaseModel):
    id: str
    kind: Literal["tool_call", "output_content", "state_change", "retrieved_data", "custom"]
    pass_when: str
    tool: str | None = None
    channel: str | None = None
    store: str | None = None
    where: str | None = None

    @model_validator(mode="after")
    def validate_custom(self) -> "OracleCheck":
        if self.kind == "custom" and (not self.where or not self.pass_when):
            raise ValueError("custom oracle requires where and pass_when")
        return self


class ObservationSpec(BaseModel):
    success_if_any: list[OracleCheck]


class InferredField(BaseModel):
    path: str
    reason: str


class ProvenanceSpec(BaseModel):
    extracted: list[str] = Field(default_factory=list)
    inferred: list[InferredField] = Field(default_factory=list)


class EnvironmentSpec(BaseModel):
    """Full schema-v2 spec written to ``runs/{id}/spec.json``."""

    model_config = ConfigDict(extra="ignore")

    spec_id: str
    schema_version: Literal[2] = 2
    source: SourceSpec
    task: TaskSpec
    environment: EnvironmentBlock
    attack: AttackSpec
    observation: ObservationSpec
    provenance: ProvenanceSpec
    platform_coverage: dict[str, Any] = Field(default_factory=dict)

    @property
    def scenario_id(self) -> str:
        return self.source.scenario_id

    @property
    def seed_id(self) -> str:
        return self.source.seed_id

    @property
    def threat_id(self) -> str:
        return self.source.threat_id

    @property
    def mechanism_name(self) -> str:
        return self.source.mechanism_name

    @property
    def tags(self) -> list[str]:
        return list(self.source.tags)

    @property
    def tool_names(self) -> list[str]:
        return [t.name for t in self.environment.tools]

    @property
    def injection_surface(self) -> str:
        return self.attack.placement.surface

    @property
    def payload_intent(self) -> str:
        return self.attack.placement.payload_intent

    @property
    def trigger_tool(self) -> str:
        for tool in self.environment.tools:
            if tool.kind == "privileged":
                return tool.name
        for check in self.observation.success_if_any:
            if check.kind == "tool_call" and check.tool:
                return check.tool
        if self.task.forbidden_actions:
            return self.task.forbidden_actions[0]
        return self.tool_names[-1] if self.tool_names else ""

    @property
    def oracle_target(self) -> str:
        kinds = {c.kind for c in self.observation.success_if_any}
        if "output_content" in kinds:
            return "output_string"
        if "state_change" in kinds:
            return "state_vs_log"
        return "forbidden_call"


def _tool_by_name(spec: EnvironmentSpec, name: str) -> EnvironmentTool | None:
    return next((t for t in spec.environment.tools if t.name == name), None)


def _store_by_id(spec: EnvironmentSpec, store_id: str) -> DataStore | None:
    return next((s for s in spec.environment.data_stores if s.id == store_id), None)


def path_exists(spec: EnvironmentSpec, path: str) -> bool:
    """True if a conceptual dotted path names something in the spec."""
    p = path.strip().lstrip("/")
    if p in {
        "task",
        "task.user_prompt",
        "task.benign_goal",
        "task.forbidden_actions",
        "attack.exploit",
        "attack.goal",
        "source.scenario_id",
        "source.tags",
    }:
        return True

    tool_match = re.search(r"tools\.([A-Za-z0-9_]+)", p)
    if tool_match:
        tool = _tool_by_name(spec, tool_match.group(1))
        if tool is None:
            return False
        field_match = re.search(r"(?:inputs|outputs)\.([A-Za-z0-9_]+)", p)
        if field_match:
            names = {f.name for f in tool.inputs + tool.outputs}
            return field_match.group(1) in names
        return True

    store_match = re.search(r"data_stores\.([A-Za-z0-9_]+)", p)
    if store_match:
        store = _store_by_id(spec, store_match.group(1))
        if store is None:
            return False
        field_match = re.search(r"fields\.([A-Za-z0-9_]+)", p)
        if field_match:
            return any(f.name == field_match.group(1) for f in store.fields)
        return True

    if p.startswith("environment.rag") or p == "rag":
        return spec.environment.rag is not None

    mcp_match = re.search(r"mcp_servers\.([A-Za-z0-9_]+)", p)
    if mcp_match:
        return any(s.id == mcp_match.group(1) for s in spec.environment.mcp_servers)

    cred_match = re.search(r"credentials\.([A-Za-z0-9_]+)", p)
    if cred_match:
        return any(c.id == cred_match.group(1) for c in spec.environment.credentials)

    if p.startswith("task.") or p.startswith("source.") or p.startswith("attack."):
        return True
    return False


def placement_target_exists(spec: EnvironmentSpec, component: str) -> bool:
    c = component.strip()
    if c.startswith("task."):
        return hasattr(spec.task, c.split(".", 1)[1])
    if c.startswith("environment.rag"):
        return spec.environment.rag is not None
    if "data_stores." in c or c.startswith("environment."):
        return path_exists(spec, c)
    if c in spec.tool_names:
        return True
    return path_exists(spec, c)


def _validate_rag(spec: EnvironmentSpec, errors: list[str]) -> None:
    rag = spec.environment.rag
    if rag is None:
        return
    store = _store_by_id(spec, rag.corpus_store)
    if store is None:
        errors.append(f"environment.rag.corpus_store {rag.corpus_store!r} not in data_stores")
        return
    field_names = {f.name for f in store.fields}
    for field in rag.chunk_fields:
        if field not in field_names:
            errors.append(f"environment.rag.chunk_fields references unknown field {field!r}")
    if rag.injectable_field not in field_names:
        errors.append(
            f"environment.rag.injectable_field {rag.injectable_field!r} not on store {rag.corpus_store}"
        )
    elif store.fields:
        injectable = next(f for f in store.fields if f.name == rag.injectable_field)
        if not injectable.injectable:
            errors.append(
                f"environment.rag.injectable_field {rag.injectable_field!r} must be injectable on store {rag.corpus_store}"
            )


def _validate_mcp_servers(spec: EnvironmentSpec, tool_names: set[str], errors: list[str]) -> None:
    for server in spec.environment.mcp_servers:
        if not server.id.strip():
            errors.append("environment.mcp_servers entry missing id")
        if not server.purpose.strip():
            errors.append(f"mcp_server {server.id} missing purpose")
        for tool in server.tools:
            if tool not in tool_names:
                errors.append(f"mcp_server {server.id} references unknown tool {tool}")


def _validate_credentials(spec: EnvironmentSpec, errors: list[str]) -> None:
    seen: set[str] = set()
    for cred in spec.environment.credentials:
        if not cred.id.strip():
            errors.append("environment.credentials entry missing id")
        elif cred.id in seen:
            errors.append(f"duplicate credential id {cred.id}")
        else:
            seen.add(cred.id)
        if not cred.purpose.strip():
            errors.append(f"credential {cred.id} missing purpose")


def name_in_source(name: str, source_text: str) -> bool:
    """True if ``name`` appears in narrative / attack-tree text (case-insensitive)."""
    return bool(name) and name.lower() in (source_text or "").lower()


def _inferred_covers_tool(spec: EnvironmentSpec, name: str) -> bool:
    prefix = f"environment.tools.{name}"
    return any(
        inf.path == prefix or inf.path.startswith(prefix + ".")
        for inf in spec.provenance.inferred
    )


def gate1_schema_errors(
    spec: EnvironmentSpec,
    *,
    chosen_exploit: ExploitStyle,
    source_text: str = "",
) -> list[str]:
    """Gate 1: schema, referential integrity, and tool-name grounding (no LLM)."""
    errors: list[str] = []

    if spec.schema_version != 2:
        errors.append("schema_version must be 2")
    if spec.platform_coverage != {}:
        errors.append("platform_coverage must be {} at generation time")

    if spec.attack.exploit.name != chosen_exploit.name:
        errors.append("attack.exploit.name does not match chosen exploit")
    if spec.attack.exploit.description != chosen_exploit.description:
        errors.append("attack.exploit.description does not match chosen exploit")

    if not spec.observation.success_if_any:
        errors.append("observation.success_if_any must not be empty")

    tool_names = {t.name for t in spec.environment.tools}
    store_ids = {s.id for s in spec.environment.data_stores}

    for agent in spec.environment.agents:
        for tool in agent.tools:
            if tool not in tool_names:
                errors.append(f"agent {agent.id} references unknown tool {tool}")
        for store in agent.data_stores:
            if store not in store_ids:
                errors.append(f"agent {agent.id} references unknown data store {store}")

    for tool in spec.environment.tools:
        if not tool.purpose.strip():
            errors.append(f"tool {tool.name} missing purpose")
        for item in tool.inputs + tool.outputs:
            if not item.name or not item.type:
                errors.append(f"tool {tool.name} has untyped I/O")
        if tool.kind in ("write", "privileged") and not tool.side_effects:
            errors.append(f"tool {tool.name} ({tool.kind}) missing side_effects")
        for effect in tool.side_effects:
            store = _store_by_id(spec, effect.store)
            if store is None:
                errors.append(f"tool {tool.name} side_effect references unknown store {effect.store}")
            elif not any(f.name == effect.field for f in store.fields):
                errors.append(
                    f"tool {tool.name} side_effect field {effect.field} not on store {effect.store}"
                )

    _validate_rag(spec, errors)
    _validate_mcp_servers(spec, tool_names, errors)
    _validate_credentials(spec, errors)

    if not placement_target_exists(spec, spec.attack.placement.target.component):
        errors.append(
            f"attack.placement.target.component {spec.attack.placement.target.component!r} does not exist"
        )

    for check in spec.observation.success_if_any:
        if check.kind == "tool_call" and check.tool and check.tool not in tool_names:
            errors.append(f"oracle {check.id} references unknown tool {check.tool}")
        if (
            source_text
            and check.kind == "tool_call"
            and check.tool
            and not name_in_source(check.tool, source_text)
        ):
            errors.append(
                f"oracle {check.id} tool {check.tool} is not grounded in narrative/attack tree"
            )
        if check.kind == "output_content" and check.channel and check.channel != "chat":
            errors.append(f"oracle {check.id} output_content channel must be chat")
        if check.store and check.store not in store_ids:
            errors.append(f"oracle {check.id} references unknown store {check.store}")

    if source_text:
        for tool in spec.environment.tools:
            if name_in_source(tool.name, source_text):
                continue
            if _inferred_covers_tool(spec, tool.name):
                continue
            errors.append(
                f"tool {tool.name} does not appear in narrative/attack tree and is not listed in provenance.inferred"
            )

    for inferred in spec.provenance.inferred:
        if not path_exists(spec, inferred.path):
            errors.append(f"provenance.inferred path does not exist: {inferred.path}")

    return errors
