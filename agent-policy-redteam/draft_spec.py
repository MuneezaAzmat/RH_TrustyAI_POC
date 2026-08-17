"""Scenario text helpers for pass-1 planning and grounding."""

from __future__ import annotations


def scenario_narrative_text(scenario: dict) -> str:
    """Collect attack narrative text from a scenario for extract and filtering."""
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


def infer_domain(scenario: dict) -> str:
    text = scenario_narrative_text(scenario).lower()
    if any(k in text for k in ("klarna", "refund", "payment", "transaction", "invoice")):
        return "finance"
    if any(k in text for k in ("employee", "hr", "salary", "ssn")):
        return "hr"
    if any(k in text for k in ("dispute", "marketplace", "merchant")):
        return "marketplace"
    return "general"


def scenario_actor_beliefs_excerpt(scenario: dict) -> str:
    """Actor beliefs from scenario YAML — backend capabilities for tool planning."""
    actor = scenario.get("actor_profile") or {}
    beliefs = actor.get("beliefs") or []
    lines = [f"- {str(b).strip()}" for b in beliefs if str(b).strip()]
    return "\n".join(lines)


def scenario_narrative_plan_excerpt(scenario: dict) -> str:
    """Narrative summary, entry point, zones, and steps for pass-1 planning."""
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
    """Attack tree for pass-1 planning: goal plus each node's zone and description only."""
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
    """Attack tree + beliefs + summary/steps for pass-1 plan gate grounding."""
    parts = [
        scenario_attack_tree_excerpt(scenario),
        scenario_actor_beliefs_excerpt(scenario),
        scenario_narrative_plan_excerpt(scenario),
    ]
    return "\n".join(part for part in parts if part.strip())


def scenario_narrative_excerpt(scenario: dict) -> str:
    """Narrative summary for gate-2 review prompts."""
    narrative = scenario.get("narrative") or {}
    return (narrative.get("summary") or "").strip()


def scenario_narrative_only_excerpt(scenario: dict) -> str:
    """Alias for :func:`scenario_narrative_excerpt`."""
    return scenario_narrative_excerpt(scenario)
