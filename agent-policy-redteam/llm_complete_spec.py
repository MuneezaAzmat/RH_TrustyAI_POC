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
from spec_io import SPEC_FILE, save_spec

log = logging.getLogger(__name__)

_PROMPTS = Path(__file__).resolve().parent / "prompts"
GENERATE_PROMPT = Path(
    os.environ.get("REDTEAM_GENERATE_PROMPT") or (_PROMPTS / "generate_spec.md")
)
if not GENERATE_PROMPT.is_absolute():
    GENERATE_PROMPT = Path(__file__).resolve().parent / GENERATE_PROMPT
REFINE_PROMPT = _PROMPTS / "refine_spec.md"
VALIDATE_PROMPT = _PROMPTS / "validate_spec.md"
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


def _coerce(data: dict[str, Any], exploit: ExploitStyle) -> EnvironmentSpec:
    data = dict(data)
    data["attack"] = data.get("attack") or {}
    data["attack"]["exploit"] = exploit.model_dump()
    data["platform_coverage"] = {}
    data["schema_version"] = 2
    return EnvironmentSpec.model_validate(data)


def _persist(
    persist_dir: Path | None,
    spec: EnvironmentSpec | None,
    data: dict[str, Any] | None = None,
) -> None:
    if persist_dir is None:
        return
    persist_dir = Path(persist_dir)
    if spec is not None:
        save_spec(persist_dir, spec)
        log.info("Wrote %s", persist_dir / SPEC_FILE)
        return
    if data is None:
        return
    path = persist_dir / SPEC_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    log.info("Wrote unparsed candidate %s", path)


def _generate(
    narrative: str,
    attack_tree: str,
    draft: dict,
    exploit: ExploitStyle,
) -> dict[str, Any]:
    template = GENERATE_PROMPT.read_text(encoding="utf-8")
    log.info("Generating spec with %s", GENERATE_PROMPT)
    prompt = _fill(
        template,
        exploit_json=exploit.model_dump_json(indent=2),
        draft_json=json.dumps(draft, indent=2),
        narrative=narrative,
        attack_tree=attack_tree,
    )
    return _llm_json(
        prompt, "You complete red-team environment specs. Respond with valid JSON only."
    )


def _refine(spec_json: str, feedback: str) -> dict[str, Any]:
    template = REFINE_PROMPT.read_text(encoding="utf-8")
    prompt = _fill(
        template,
        spec_json=spec_json,
        validation_feedback=feedback,
    )
    return _llm_json(
        prompt, "You edit environment specs to fix validation errors. Return the full JSON only."
    )


def _gate2(
    spec: EnvironmentSpec,
    narrative: str,
    attack_tree: str,
    exploit: ExploitStyle,
) -> Gate2Result:
    template = VALIDATE_PROMPT.read_text(encoding="utf-8")
    prompt = _fill(
        template,
        exploit_json=exploit.model_dump_json(indent=2),
        narrative=narrative,
        attack_tree=attack_tree,
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
    persist_dir: str | Path | None = None,
    *,
    attack_tree: str = "",
    source_text: str | None = None,
) -> SpecBuildResult:
    """Generate once, write spec, gate 1, then refine in place (not regenerate)."""
    persist = Path(persist_dir) if persist_dir else None
    grounding = source_text or "\n".join(
        part for part in [narrative, attack_tree] if part.strip()
    )
    last_errors: list[str] = []
    spec: EnvironmentSpec | None = None
    candidate: dict[str, Any] | None = None

    for attempt in range(MAX_RETRIES + 1):
        log.info("Spec attempt %d/%d", attempt + 1, MAX_RETRIES + 1)
        try:
            if candidate is None:
                candidate = _generate(narrative, attack_tree, draft, exploit)
            else:
                spec_json = (
                    spec.model_dump_json(indent=2)
                    if spec is not None
                    else json.dumps(candidate, indent=2)
                )
                feedback = "\n".join(f"- {e}" for e in last_errors)
                log.info("Refining spec from disk candidate (%d issue(s))", len(last_errors))
                candidate = _refine(spec_json, feedback)
            spec = _coerce(candidate, exploit)
            candidate = json.loads(spec.model_dump_json())
        except Exception as e:
            last_errors = [str(e)]
            log.warning("Spec JSON/schema failed: %s", e)
            _persist(persist, None, candidate)
            continue

        _persist(persist, spec)
        gate1 = gate1_schema_errors(
            spec, chosen_exploit=exploit, source_text=grounding
        )
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

    try:
        gate2 = _gate2(spec, narrative, attack_tree, exploit)
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
    feedback = "Gate 2 critical findings:\n" + "\n".join(
        f"- {f.path}: {f.issue}" for f in criticals
    )
    log.info("Refining spec after gate 2 criticals")
    try:
        candidate = _refine(spec.model_dump_json(indent=2), feedback)
        spec = _coerce(candidate, exploit)
        _persist(persist, spec)
    except Exception as e:
        log.warning("Gate 2 refine failed: %s", e)
        return SpecBuildResult(spec=spec, ok=False, gate2=gate2)

    gate1 = gate1_schema_errors(spec, chosen_exploit=exploit, source_text=grounding)
    if gate1:
        return SpecBuildResult(spec=spec, ok=False, gate1_errors=gate1, gate2=gate2)

    try:
        gate2 = _gate2(spec, narrative, attack_tree, exploit)
    except Exception as e:
        return SpecBuildResult(
            spec=spec,
            ok=False,
            gate2=Gate2Result(
                ok=False,
                findings=[Finding(severity="critical", path="gate2", issue=str(e))],
            ),
        )
    _persist(persist, spec)
    return SpecBuildResult(spec=spec, ok=gate2.ok, gate2=gate2)
