"""Shared Pydantic v2 data models for agent policy red-team framework."""

from typing import Any, Literal
from pydantic import BaseModel, Field


class RiskSource(BaseModel):
    """Risk source with description and likelihood."""
    description: str
    likelihood: Literal["low", "medium", "high", "critical"]


class RiskConsequence(BaseModel):
    """Risk consequence with description and severity."""
    description: str
    severity: Literal["low", "medium", "high", "critical"]


class RiskImpact(BaseModel):
    """Risk impact with affected stakeholders and harm type."""
    description: str
    affected_stakeholders: list[str]
    harm_type: str


class RiskControl(BaseModel):
    """Risk control with type and description."""
    type: Literal["detect", "evaluate", "mitigate", "eliminate"]
    description: str


class RiskCard(BaseModel):
    """RiskCard from risk-landscaper output."""
    id: str
    risk_source: RiskSource
    risk_consequence: RiskConsequence
    risk_impact: RiskImpact
    risk_controls: list[RiskControl]
    materialization_conditions: str
    policy_references: list[str]
    framework_references: list[str]


class TriagedRisk(BaseModel):
    """Triaged RiskCard with enforcement level and risk type classification."""
    risk_card: RiskCard
    enforcement_level: Literal["agent", "sandbox"]
    risk_type: Literal["data_exfiltration", "unauthorized_action", "data_corruption", "other"]


class GeneratedEnvironment(BaseModel):
    """Generated environment components from LLM Call 1."""
    user_task_prompt: str
    pydantic_model_code: str
    tool_function_code: str
    seed_data_json: str
    expected_tool_sequence: list[str]


class ToolCall(BaseModel):
    """Record of a single tool call."""
    name: str
    arguments: dict
    response: Any
    turn_number: int


class DryRunTrace(BaseModel):
    """Complete trace of a clean or attack run."""
    tool_calls: list[ToolCall]
    conversation: list[dict]
    final_state_snapshot: str


class InjectionPayload(BaseModel):
    """Single injection payload placed in environment data."""
    target_record_id: str
    target_field: str
    payload_text: str
    turn_number: int
    pattern_type: Literal["delayed_trigger", "progressive_escalation"]


class InjectionScenario(BaseModel):
    """Complete injection scenario with payloads and verification."""
    injection_goal: str
    payloads: list[InjectionPayload]
    additional_env_code: str
    additional_seed_data_json: str
    verification_predicates: list[str]


class ScenarioResult(BaseModel):
    """Evaluation result for a single scenario."""
    scenario_id: str
    risk_card_id: str
    policy_violated: bool
    evidence: list[str]
    clean_trace: DryRunTrace
    attack_trace: DryRunTrace
    state_diff: dict
    unexpected_tool_calls: list[ToolCall]
    utility_score: float = 0.0
    utility_evidence: list[str] = Field(default_factory=list)
    security_score: float = 0.0
    security_evidence: list[str] = Field(default_factory=list)
