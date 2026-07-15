"""Filter out volume/DDoS/overwhelm scenarios unsuitable for lightweight env generation."""

import re

from models import RiskCard
from scenario_spec import ScenarioSpec

# Attack narratives that imply simulating large datasets, floods, or queue saturation.
VOLUME_ATTACK_KEYWORDS: tuple[str, ...] = (
    "ddos",
    "d dos",
    "denial of service",
    "denial-of-service",
    "overwhelm",
    "overwhelming",
    "overwhelmed",
    "flood",
    "flooding",
    "flooded",
    "queue saturation",
    "saturate the queue",
    "context flooding",
    "context_flooding",
    "cognitive exhaustion",
    "resource exhaustion",
    "alert flooding",
    "dispute flooding",
    "automated dispute flood",
    "micro-dispute",
    "mass dispute",
    "simultaneous dispute",
)

# Contextual high-volume phrasing that describes flooding/saturation (T8-style), not merchant scale.
HIGH_VOLUME_ATTACK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"high[- ]volume[,]?\s+high[- ]entropy", re.IGNORECASE),
    re.compile(r"high[- ]volume[,]?\s+fragmented", re.IGNORECASE),
    re.compile(
        r"high[- ]volume[,]?\s+(?:conversational|semantically)", re.IGNORECASE
    ),
    re.compile(r"utilizing high[- ]volume[,]?\s+high[- ]entropy", re.IGNORECASE),
    re.compile(r"automated script.*high[- ]volume", re.IGNORECASE),
    re.compile(r"high[- ]volume\s+malicious\s+operation", re.IGNORECASE),
)

HIGH_COUNT_ATTACK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\bhundreds of\s+(?:requests?|disputes?|records?|cases?|alerts?|transactions?|emails?|queries?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bthousands of\s+(?:requests?|disputes?|records?|cases?|alerts?|transactions?|emails?|emails?|queries?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\btens of thousands of\s+(?:requests?|disputes?|records?|cases?|alerts?|transactions?|emails?|queries?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bdozens of simultaneous\s+(?:requests?|disputes?|records?|cases?|alerts?|transactions?|emails?|queries?)\b",
        re.IGNORECASE,
    ),
)

# e.g. "500 disputes", "1000 records"
_HIGH_COUNT_PATTERN = re.compile(
    r"\b(\d{3,})\s+(requests?|disputes?|records?|cases?|alerts?|transactions?|emails?)\b",
    re.IGNORECASE,
)

MAX_TOTAL_RECORDS = 25


def detect_volume_attack_text(text: str) -> str | None:
    """Return a reason string if text describes a volume/DDoS-style attack, else None."""
    lower = text.lower()

    for keyword in VOLUME_ATTACK_KEYWORDS:
        if keyword in lower:
            return f"volume/DDoS keyword: '{keyword}'"

    for pattern in HIGH_VOLUME_ATTACK_PATTERNS:
        match = pattern.search(text)
        if match:
            return f"high-volume attack pattern: '{match.group(0)}'"

    for pattern in HIGH_COUNT_ATTACK_PATTERNS:
        match = pattern.search(text)
        if match:
            return f"high-count phrase: '{match.group(0)}'"

    match = _HIGH_COUNT_PATTERN.search(text)
    if match:
        return f"high-count quantity: '{match.group(0)}'"

    return None


def _risk_card_narrative(risk_card: RiskCard) -> str:
    return " ".join(
        [
            risk_card.risk_source.description,
            risk_card.risk_consequence.description,
            risk_card.risk_impact.description,
            risk_card.materialization_conditions,
        ]
    )


def is_volume_attack_risk_card(risk_card: RiskCard) -> str | None:
    """Return skip reason if the RiskCard describes a volume/DDoS attack."""
    return detect_volume_attack_text(_risk_card_narrative(risk_card))


def is_volume_attack_spec(spec: ScenarioSpec) -> str | None:
    """Return skip reason if a planned ScenarioSpec still implies volume generation."""
    text = " ".join(
        [
            spec.injection.goal,
            spec.user_task.prompt,
            spec.user_task.expected_outcome,
            *spec.domain_skeleton.seed_data_constraints,
        ]
    )
    reason = detect_volume_attack_text(text)
    if reason:
        return reason

    total_records = sum(e.record_count for e in spec.domain_skeleton.entity_types)
    if total_records > MAX_TOTAL_RECORDS:
        return f"record_count total {total_records} exceeds limit {MAX_TOTAL_RECORDS}"

    return None
