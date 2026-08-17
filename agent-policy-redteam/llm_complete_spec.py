"""LLM completion + gates for schema-v2 environment specs."""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from openai import OpenAI
from pydantic import BaseModel

from environment_spec import EnvironmentSpec, ExploitStyle, gate1_schema_errors

log = logging.getLogger(__name__)

GENERATE_PROMPT = Path(__file__).resolve().parent / "prompts" / "generate_spec.md"
VALIDATE_PROMPT = Path(__file__).resolve().parent / "prompts" / "validate_spec.md"
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
MODEL = os.environ.get("REDTEAM_MODEL", "qwen2.5:14b")
MAX_RETRIES = 2
_client = None


class Finding(BaseModel):
    severity: str
    path: str
    issue: str


class Gate2Result(BaseModel):
    ok: bool
    findings: list[Finding] = []


class SpecBuildResult(BaseModel):
    spec: EnvironmentSpec
    ok: bool
    gate1_errors: list[str] = []
    gate2: Gate2Result | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        api_key = os.environ.get("OPENAI_API_KEY") or "ollama"
        _client = OpenAI(base_url=OLLAMA_BASE_URL, api_key=api_key)
    return _client


def _fix_json(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return re.sub(r",\s*([}\]])", r"\1", text)


def _fill(template: str, **slots: str) -> str:
    out = template
    for key, value in slots.items():
        out = out.replace("{{" + key + "}}", value)
    return out


def _llm_json(prompt: str, system: str) -> dict[str, Any]:
    response = _get_client().chat.completions.create(
        model=MODEL,
        temperature=0.2,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
    )
    raw = response.choices[0].message.content.strip()
    return json.loads(_fix_json(raw))


def _complete_once(
    narrative: str,
    draft: dict,
    exploit: ExploitStyle,
    extra: str = "",
) -> EnvironmentSpec:
    template = GENERATE_PROMPT.read_text(encoding="utf-8")
    prompt = _fill(
        template,
        exploit_json=exploit.model_dump_json(indent=2),
        draft_json=json.dumps(draft, indent=2),
        narrative=narrative,
    )
    if extra:
        prompt += "\n\nPREVIOUS ATTEMPT FAILED:\n" + extra
    data = _llm_json(prompt, "You complete red-team environment specs. Respond with valid JSON only.")
    data["attack"] = data.get("attack") or {}
    data["attack"]["exploit"] = exploit.model_dump()
    data["platform_coverage"] = {}
    data["schema_version"] = 2
    return EnvironmentSpec.model_validate(data)


def _gate2(spec: EnvironmentSpec, narrative: str, exploit: ExploitStyle) -> Gate2Result:
    template = VALIDATE_PROMPT.read_text(encoding="utf-8")
    prompt = _fill(
        template,
        exploit_json=exploit.model_dump_json(indent=2),
        narrative=narrative,
        spec_json=spec.model_dump_json(indent=2),
    )
    data = _llm_json(prompt, "You review environment specs. Respond with valid JSON only.")
    findings = [Finding.model_validate(f) for f in data.get("findings") or []]
    critical = [f for f in findings if f.severity == "critical"]
    passed = bool(data.get("pass", False)) and not critical
    return Gate2Result(ok=passed, findings=findings)


def generate_environment_spec(
    narrative: str,
    draft: dict,
    exploit: ExploitStyle,
) -> SpecBuildResult:
    """Draft → LLM complete → gate 1 → gate 2, with one repair pass each."""
    last_errors: list[str] = []
    spec: EnvironmentSpec | None = None

    for attempt in range(MAX_RETRIES + 1):
        extra = "\n".join(f"  - {e}" for e in last_errors) if last_errors else ""
        log.info("Completing environment spec (attempt %d/%d)", attempt + 1, MAX_RETRIES + 1)
        try:
            spec = _complete_once(narrative, draft, exploit, extra=extra)
        except Exception as e:
            last_errors = [str(e)]
            log.warning("Spec completion failed: %s", e)
            continue
        gate1 = gate1_schema_errors(spec, chosen_exploit=exploit)
        if gate1:
            last_errors = gate1
            log.warning("Gate 1 failed: %s", "; ".join(gate1))
            continue
        break
    else:
        if spec is None:
            raise RuntimeError(
                "Failed to complete environment spec: " + "; ".join(last_errors)
            )
        return SpecBuildResult(spec=spec, ok=False, gate1_errors=last_errors)

    gate1 = gate1_schema_errors(spec, chosen_exploit=exploit)
    if gate1:
        return SpecBuildResult(spec=spec, ok=False, gate1_errors=gate1)

    try:
        gate2 = _gate2(spec, narrative, exploit)
    except Exception as e:
        log.warning("Gate 2 failed to run: %s", e)
        return SpecBuildResult(
            spec=spec,
            ok=False,
            gate1_errors=[],
            gate2=Gate2Result(
                ok=False,
                findings=[Finding(severity="critical", path="gate2", issue=str(e))],
            ),
        )

    if gate2.ok:
        return SpecBuildResult(spec=spec, ok=True, gate2=gate2)

    criticals = [f for f in gate2.findings if f.severity == "critical"]
    repair_note = "Gate 2 critical findings:\n" + "\n".join(
        f"  - {f.path}: {f.issue}" for f in criticals
    )
    log.info("Repairing spec after gate 2 criticals")
    try:
        spec = _complete_once(narrative, draft, exploit, extra=repair_note)
    except Exception as e:
        log.warning("Repair completion failed: %s", e)
        return SpecBuildResult(spec=spec, ok=False, gate2=gate2)

    gate1 = gate1_schema_errors(spec, chosen_exploit=exploit)
    if gate1:
        return SpecBuildResult(spec=spec, ok=False, gate1_errors=gate1, gate2=gate2)

    try:
        gate2 = _gate2(spec, narrative, exploit)
    except Exception as e:
        return SpecBuildResult(
            spec=spec,
            ok=False,
            gate2=Gate2Result(
                ok=False,
                findings=[Finding(severity="critical", path="gate2", issue=str(e))],
            ),
        )
    return SpecBuildResult(spec=spec, ok=gate2.ok, gate2=gate2)
