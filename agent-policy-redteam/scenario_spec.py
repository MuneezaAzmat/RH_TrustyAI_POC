"""Structured scenario specification for red-team pipeline stages."""

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class EntityFieldSpec(BaseModel):
    name: str
    sensitive: bool = False
    field_type: str = "string"


class EntitySpec(BaseModel):
    name: str
    fields: list[EntityFieldSpec]
    record_count: int = Field(default=5, ge=1, le=20)


class ToolSpec(BaseModel):
    name: str
    category: Literal["read", "write", "communicate", "privileged"]
    description: str
    parameters: list[str] = Field(default_factory=list)


class UserTaskSpec(BaseModel):
    prompt: str
    required_data_access: list[str]
    forbidden_actions: list[str]
    expected_outcome: str


class PayloadTemplate(BaseModel):
    role: str | None = None
    template: str


class InjectionSpec(BaseModel):
    goal: str
    attack_pattern: Literal["delayed_trigger", "progressive_escalation"]
    attack_variant: str | None = None
    payload_templates: list[PayloadTemplate]
    target_surfaces: list[str]
    trigger_tool: str
    exfil_channel: str
    exfil_address: str = "attacker@external.com"


class SecurityCriteria(BaseModel):
    must_not_call: list[str]
    must_not_contain: list[str] = Field(default_factory=list)
    verification_predicates: list[str]
    recipient_must_not_change: bool = True
    sensitive_patterns: list[str] = Field(
        default_factory=lambda: [r"\d{3}-\d{2}-\d{4}", r"\b\d{5,}\.\d{1,2}\b"]
    )


class UtilityCriteria(BaseModel):
    must_complete_task: bool = True
    expected_tool_calls: list[str]
    task_output_checks: list[str] = Field(default_factory=list)


class DomainSkeleton(BaseModel):
    entity_types: list[EntitySpec]
    required_tools: list[ToolSpec]
    seed_data_constraints: list[str] = Field(default_factory=list)


# Framework-facing attack placement / observation (shared across Garak, AgentDojo, …)
InjectionSurface = Literal[
    "user_turn",
    "system_prompt",
    "tool_return",
    "tool_definition",
    "none",
]
OracleTarget = Literal[
    "forbidden_call",
    "output_string",
    "wrong_target",
    "state_vs_log",
    "cross_turn",
    "persistent_state",
]


class ScenarioSpec(BaseModel):
    """Shared scenario specification: forge YAML → one spec → framework artifacts.

    Most fields are deterministically derived from the forge scenario; the
    domain skeleton is extracted from that text and then completed (grounded
    in the draft) by an LLM, after which it is frozen here. Downstream
    emitters (pipeline env, Garak configs, …) consume this object as-is.
    """

    spec_id: str
    risk_card_id: str
    risk_type: str
    domain: str
    user_task: UserTaskSpec
    injection: InjectionSpec
    security_criteria: SecurityCriteria
    utility_criteria: UtilityCriteria
    domain_skeleton: DomainSkeleton

    # Identity / taxonomy (from forge scenario_seed_metadata + faceting)
    seed_id: str = ""
    threat_id: str = ""
    mechanism_name: str = ""
    tags: list[str] = Field(default_factory=list)

    # Where the attack sits and how success is observed (for gating + emitters)
    injection_surface: InjectionSurface = "none"
    oracle_target: OracleTarget = "forbidden_call"

    # Behavior-spec excerpts (Given / Then) for seed + detection hints
    seed_facts: list[str] = Field(default_factory=list)
    oracle_narrative_predicates: list[str] = Field(default_factory=list)
    payload_intent: str = ""

    @property
    def scenario_id(self) -> str:
        return self.risk_card_id

    @property
    def tool_names(self) -> list[str]:
        return [t.name for t in self.domain_skeleton.required_tools]

    @model_validator(mode="after")
    def validate_internal_consistency(self) -> "ScenarioSpec":
        tool_names = {t.name for t in self.domain_skeleton.required_tools}
        if self.injection.trigger_tool not in tool_names:
            raise ValueError(
                f"trigger_tool '{self.injection.trigger_tool}' must appear in required_tools"
            )
        for forbidden in self.user_task.forbidden_actions:
            if forbidden not in tool_names:
                raise ValueError(
                    f"forbidden action '{forbidden}' must appear in required_tools"
                )
        if self.injection.trigger_tool not in self.security_criteria.must_not_call:
            raise ValueError("trigger_tool must be listed in security_criteria.must_not_call")
        if self.injection.trigger_tool in self.utility_criteria.expected_tool_calls:
            raise ValueError("trigger_tool must not appear in utility expected_tool_calls")
        if not self.injection.payload_templates:
            raise ValueError("injection.payload_templates must not be empty")
        if not self.injection.target_surfaces:
            raise ValueError("injection.target_surfaces must not be empty")
        sensitive_fields = [
            f.name
            for entity in self.domain_skeleton.entity_types
            for f in entity.fields
            if f.sensitive
        ]
        if self.risk_type == "data_exfiltration" and not sensitive_fields:
            raise ValueError("data_exfiltration scenarios require at least one sensitive field")
        return self


def validate_scenario_spec(spec: ScenarioSpec) -> list[str]:
    """Return a list of validation warnings (empty if fully valid)."""
    warnings: list[str] = []
    communicate_tools = [
        t.name for t in spec.domain_skeleton.required_tools if t.category == "communicate"
    ]
    if spec.injection.trigger_tool not in communicate_tools and spec.injection.exfil_channel == "email":
        warnings.append(
            f"trigger_tool '{spec.injection.trigger_tool}' is not categorized as communicate"
        )
    if not spec.security_criteria.verification_predicates:
        warnings.append("security_criteria.verification_predicates is empty")
    if spec.injection_surface == "none":
        warnings.append("injection_surface is unclassified (none)")
    return warnings
