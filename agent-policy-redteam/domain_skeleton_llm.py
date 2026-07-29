"""Grounded LLM completion of DomainSkeleton drafts from forge scenarios."""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from openai import OpenAI

from scenario_spec import DomainSkeleton, EntitySpec, ToolSpec

log = logging.getLogger(__name__)

CODEGEN_CATEGORIES = frozenset({"read", "write", "communicate", "privileged"})
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
MODEL = os.environ.get("REDTEAM_MODEL", "qwen2.5:14b")
MAX_RETRIES = 2
_client = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(base_url=OLLAMA_BASE_URL, api_key="ollama")
    return _client


def validate_anchors(draft: DomainSkeleton, rewritten: DomainSkeleton) -> list[str]:
    """Return errors if rewritten drops draft tool / entity / surface names."""
    errors: list[str] = []
    draft_tools = {t.name for t in draft.required_tools}
    rewritten_tools = {t.name for t in rewritten.required_tools}
    missing_tools = draft_tools - rewritten_tools
    if missing_tools:
        errors.append(f"rewritten skeleton dropped draft tools: {sorted(missing_tools)}")

    draft_entities = {e.name for e in draft.entity_types}
    rewritten_entities = {e.name for e in rewritten.entity_types}
    missing_entities = draft_entities - rewritten_entities
    if missing_entities:
        errors.append(f"rewritten skeleton dropped draft entities: {sorted(missing_entities)}")

    draft_fields: set[str] = set()
    for e in draft.entity_types:
        draft_fields.update(f.name for f in e.fields)
    rewritten_fields: set[str] = set()
    for e in rewritten.entity_types:
        rewritten_fields.update(f.name for f in e.fields)
    missing_fields = draft_fields - rewritten_fields
    if missing_fields:
        errors.append(f"rewritten skeleton dropped draft fields: {sorted(missing_fields)}")

    return errors


def validate_codegen_categories(skeleton: DomainSkeleton) -> list[str]:
    errors: list[str] = []
    for tool in skeleton.required_tools:
        if tool.category not in CODEGEN_CATEGORIES:
            errors.append(
                f"tool '{tool.name}' has unsupported category '{tool.category}'; "
                f"allowed={sorted(CODEGEN_CATEGORIES)}"
            )
    return errors
