"""Risk triage logic for classifying enforcement levels and risk types."""

from models import RiskCard, TriagedRisk


def triage_risk(risk_card: RiskCard) -> TriagedRisk:
    """
    Classify risk card by enforcement level and risk type.

    Enforcement level:
    - sandbox: if controls mention network/filesystem/process/credential/sandbox/container/isolation
    - agent: everything else

    Risk type:
    - data_exfiltration: if source/consequence mention exfiltrat/leak/expos/sensitive data
    - unauthorized_action: if source/consequence mention privilege/unauthorized/permission/escalat
    - data_corruption: if source/consequence mention integrity/tamper/corrupt/modif
    - other: fallback
    """
    # Classify enforcement level by examining risk controls
    enforcement_level = "agent"
    sandbox_keywords = [
        "network", "filesystem", "process", "credential",
        "sandbox", "container", "isolation"
    ]

    controls_text = " ".join(
        control.description.lower() for control in risk_card.risk_controls
    )

    if any(keyword in controls_text for keyword in sandbox_keywords):
        enforcement_level = "sandbox"

    # Classify risk type by examining source and consequence
    risk_text = (
        risk_card.risk_source.description.lower() + " " +
        risk_card.risk_consequence.description.lower()
    )

    risk_type = "other"

    exfiltration_keywords = ["exfiltrat", "leak", "expos", "sensitive data", "disclosure"]
    unauthorized_keywords = ["privilege", "unauthorized", "permission", "escalat", "access control"]
    corruption_keywords = ["integrity", "tamper", "corrupt", "modif", "alter"]

    if any(keyword in risk_text for keyword in exfiltration_keywords):
        risk_type = "data_exfiltration"
    elif any(keyword in risk_text for keyword in unauthorized_keywords):
        risk_type = "unauthorized_action"
    elif any(keyword in risk_text for keyword in corruption_keywords):
        risk_type = "data_corruption"

    return TriagedRisk(
        risk_card=risk_card,
        enforcement_level=enforcement_level,
        risk_type=risk_type
    )


def filter_agent_level(risks: list[TriagedRisk]) -> list[TriagedRisk]:
    """Filter to only agent-level risks (sandbox-level deferred)."""
    return [risk for risk in risks if risk.enforcement_level == "agent"]
