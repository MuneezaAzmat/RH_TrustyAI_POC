"""Scenario YAML → deterministic context for Garak spec building."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_QUOTED_TOOL_RE = re.compile(r"`([a-z][a-z0-9_]{1,48})`")


def name_in_source(name: str, source_text: str) -> bool:
    return bool(name) and name.lower() in (source_text or "").lower()


def scenario_narrative_text(scenario: dict) -> str:
    narrative = scenario.get("narrative") or {}
    meta = scenario.get("scenario_seed_metadata") or {}
    faceting = scenario.get("faceting") or {}
    risk = faceting.get("risk_card") or {}
    tree = scenario.get("attack_tree") or {}

    parts = [
        narrative.get("title", ""),
        narrative.get("summary", ""),
        narrative.get("entry_point", ""),
        meta.get("mechanism_description", ""),
        meta.get("threat_name", ""),
        tree.get("goal", ""),
        risk.get("threat", ""),
        risk.get("consequence", ""),
        scenario.get("behavior_spec", ""),
        scenario.get("_feature_text", ""),
    ]

    for step in narrative.get("steps") or []:
        parts.extend(
            [
                step.get("action", ""),
                step.get("effect", ""),
                step.get("control_point", ""),
            ]
        )

    actor = scenario.get("actor_profile") or {}
    for key in ("intentions", "desires"):
        parts.extend(actor.get(key) or [])

    return " ".join(p for p in parts if p)


def collect_tags(scenario: dict) -> list[str]:
    faceting = scenario.get("faceting") or {}
    taxonomy = faceting.get("taxonomy_chain") or {}
    tags: list[str] = []
    for key in ("owasp_llm_ids", "atlas_technique_ids", "agentic_threat_ids"):
        for item in taxonomy.get(key) or []:
            tags.append(str(item))
    return tags


def scenario_actor_beliefs_excerpt(scenario: dict) -> str:
    actor = scenario.get("actor_profile") or {}
    beliefs = actor.get("beliefs") or []
    lines = [f"- {str(b).strip()}" for b in beliefs if str(b).strip()]
    return "\n".join(lines)


def scenario_narrative_plan_excerpt(scenario: dict) -> str:
    narrative = scenario.get("narrative") or {}
    lines: list[str] = []
    summary = (narrative.get("summary") or "").strip()
    if summary:
        lines.append(f"summary: {summary}")
    entry_point = (narrative.get("entry_point") or "").strip()
    if entry_point:
        lines.append(f"entry_point: {entry_point}")
    zone_sequence = narrative.get("zone_sequence") or []
    if zone_sequence:
        lines.append(f"zone_sequence: {', '.join(str(z) for z in zone_sequence)}")
    for step in narrative.get("steps") or []:
        zone = step.get("zone", "")
        action = (step.get("action") or "").strip()
        effect = (step.get("effect") or "").strip()
        step_no = step.get("step_number", "?")
        if action:
            lines.append(f"[step {step_no}|{zone}] {action}")
        if effect:
            lines.append(f"  effect: {effect}")
    return "\n".join(lines).strip()


def scenario_attack_tree_excerpt(scenario: dict) -> str:
    tree = scenario.get("attack_tree") or {}
    lines: list[str] = []
    goal = tree.get("goal", "")
    if goal:
        lines.append(f"goal: {goal}")

    def _walk(node: dict) -> None:
        zone = node.get("zone", "")
        description = (node.get("description") or "").strip()
        if description:
            lines.append(f"[{zone}] {description}")
        for child in node.get("children") or []:
            _walk(child)

    root = tree.get("root")
    if root:
        _walk(root)
    return "\n".join(lines).strip()


def scenario_plan_grounding_text(scenario: dict) -> str:
    parts = [
        scenario_attack_tree_excerpt(scenario),
        scenario_actor_beliefs_excerpt(scenario),
        scenario_narrative_plan_excerpt(scenario),
    ]
    return "\n".join(part for part in parts if part.strip())


def quoted_tool_names(scenario: dict) -> list[str]:
    text = scenario_narrative_text(scenario)
    seen: set[str] = set()
    out: list[str] = []
    for match in _QUOTED_TOOL_RE.finditer(text):
        name = match.group(1)
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


@dataclass
class ScenarioContext:
    scenario_id: str
    raw: dict
    seed_id: str
    threat_id: str
    threat_name: str
    mechanism_name: str
    narrative_summary: str
    entry_point: str
    zone_sequence: list[str]
    tags: list[str]
    attack_goal: str
    beliefs_excerpt: str
    narrative_excerpt: str
    attack_tree_excerpt: str
    grounding_text: str
    quoted_tools: list[str] = field(default_factory=list)
    behavior_spec: str = ""


def load_scenario(path: str | Path) -> ScenarioContext:
    scenario_path = Path(path)
    if not scenario_path.exists():
        raise FileNotFoundError(f"Scenario file not found: {scenario_path}")
    data = yaml.safe_load(scenario_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "scenario_id" not in data:
        raise ValueError(f"Invalid scenario YAML: {scenario_path}")
    feature = scenario_path.with_suffix(".feature")
    if feature.exists():
        data["_feature_text"] = feature.read_text(encoding="utf-8")
    return extract_scenario(data)


def extract_scenario(scenario: dict[str, Any]) -> ScenarioContext:
    meta = scenario.get("scenario_seed_metadata") or {}
    narrative = scenario.get("narrative") or {}
    tree = scenario.get("attack_tree") or {}
    return ScenarioContext(
        scenario_id=str(scenario["scenario_id"]),
        raw=scenario,
        seed_id=str(meta.get("seed_id", "")),
        threat_id=str(meta.get("threat_id", "")),
        threat_name=str(meta.get("threat_name", "")),
        mechanism_name=str(meta.get("mechanism_name", "")),
        narrative_summary=str(narrative.get("summary", "")),
        entry_point=str(narrative.get("entry_point", "")),
        zone_sequence=[str(z) for z in (narrative.get("zone_sequence") or [])],
        tags=collect_tags(scenario),
        attack_goal=str(tree.get("goal") or narrative.get("summary", "")),
        beliefs_excerpt=scenario_actor_beliefs_excerpt(scenario),
        narrative_excerpt=scenario_narrative_plan_excerpt(scenario),
        attack_tree_excerpt=scenario_attack_tree_excerpt(scenario),
        grounding_text=scenario_plan_grounding_text(scenario),
        quoted_tools=quoted_tool_names(scenario),
        behavior_spec=str(scenario.get("behavior_spec", "")),
    )
