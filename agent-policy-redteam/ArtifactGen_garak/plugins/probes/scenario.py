# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Replay a generated ArtifactGen scenario transcript through Garak.

Loads ``SCENARIO_CONFIG`` (or ``config_path``) — a ``{id}-garak.json`` artifact —
and places the OpenAI-style ``messages`` list on ``Conversation.notes["messages"]``.
Pair with ``generators.toolchat.ToolChat`` so tool histories and ``tool_calls``
survive the round trip to the target model.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path

from garak import _config
from garak.attempt import Conversation, Message, Turn
import garak.probes
from garak.probes._tier import Tier

log = logging.getLogger(__name__)

_TOOL_SIG_RE = re.compile(
    r"`([A-Za-z_][A-Za-z0-9_]*)\s*\(([^`]*)\)`"
)
_PARAM_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*([A-Za-z_][A-Za-z0-9_\[\]| ]*))?"
)


def load_artifact(path: str | Path) -> dict:
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise FileNotFoundError(f"Scenario artifact not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Artifact root must be an object: {p}")
    return data


def extract_openai_tools(system_content: str) -> list[dict]:
    """Best-effort OpenAI tool schemas from a system prompt that names ``fn(args)``."""
    tools: list[dict] = []
    seen: set[str] = set()
    for name, raw_args in _TOOL_SIG_RE.findall(system_content or ""):
        if name in seen:
            continue
        seen.add(name)
        properties: dict[str, dict] = {}
        required: list[str] = []
        for pname, ptype in _PARAM_RE.findall(raw_args or ""):
            if pname in {"str", "int", "float", "bool", "Optional"}:
                continue
            json_type = "string"
            ptl = (ptype or "").lower()
            if "int" in ptl:
                json_type = "integer"
            elif "float" in ptl or "number" in ptl:
                json_type = "number"
            elif "bool" in ptl:
                json_type = "boolean"
            properties[pname] = {"type": json_type}
            if "optional" not in ptl and "none" not in ptl:
                required.append(pname)
        schema: dict = {"type": "object", "properties": properties}
        if required:
            schema["required"] = required
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": f"{name} tool advertised by the scenario system prompt.",
                    "parameters": schema,
                },
            }
        )
    return tools


def turns_to_openai_messages(turns: list[dict]) -> list[dict]:
    """Convert artifact turns into chat-completions messages ToolChat can replay."""
    messages: list[dict] = []
    for i, turn in enumerate(turns or []):
        role = str(turn.get("role") or "user")
        content = turn.get("content") if turn.get("content") is not None else ""
        if role != "tool":
            messages.append({"role": role, "content": content})
            continue

        tool_name = str(turn.get("tool_name") or "unknown_tool")
        call_id = f"call_{i:03d}"
        if messages and messages[-1].get("role") == "assistant":
            if not messages[-1].get("tool_calls"):
                messages[-1]["tool_calls"] = [
                    {
                        "id": call_id,
                        "type": "function",
                        "function": {"name": tool_name, "arguments": "{}"},
                    }
                ]
                if messages[-1].get("content") is None:
                    messages[-1]["content"] = ""
        else:
            messages.append(
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {"name": tool_name, "arguments": "{}"},
                        }
                    ],
                }
            )
        messages.append(
            {
                "role": "tool",
                "tool_call_id": call_id,
                "name": tool_name,
                "content": content,
            }
        )
    return messages


def conversation_from_artifact(artifact: dict) -> Conversation:
    turns = artifact.get("turns") or []
    messages = turns_to_openai_messages(turns)
    system = ""
    for t in turns:
        if t.get("role") == "system":
            system = t.get("content") or ""
            break
    sid = artifact.get("scenario_id") or "scenario"
    return Conversation(
        turns=[Turn("user", Message(text=f"[scenario] {sid}"))],
        notes={
            "messages": messages,
            "scenario_id": sid,
            "injection_surface": artifact.get("injection_surface"),
            "detector_rubric": artifact.get("detector_rubric") or {},
            "tools": extract_openai_tools(system),
        },
    )


class Scenario(garak.probes.Probe):
    """Replay one ArtifactGen Garak JSON artifact as a ToolChat conversation."""

    lang = "en"
    active = False
    tier = Tier.INFORMATIONAL
    doc_uri = "https://github.com/NVIDIA/garak"
    goal = "elicit a policy-violating next message from a scenario transcript"
    primary_detector = "scenario.ScenarioDetector"
    tags = [
        "owasp:llm01",
        "owasp:llm07",
        "quality:Security:PromptInjection",
        "payload:agentic:scenario",
    ]
    parallelisable_attempts = True

    DEFAULT_PARAMS = garak.probes.Probe.DEFAULT_PARAMS | {
        "config_path": "",
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        path = (self.config_path or os.environ.get("SCENARIO_CONFIG") or "").strip()
        if not path:
            raise ValueError(
                "scenario.Scenario requires SCENARIO_CONFIG or config_path "
                "pointing at a {id}-garak.json artifact"
            )
        self.artifact = load_artifact(path)
        self.config_path = str(Path(path).resolve())
        summary = ((self.artifact.get("narrative") or {}).get("summary") or "").strip()
        if summary:
            self.goal = summary[:240]
        self.prompts = [conversation_from_artifact(self.artifact)]
        log.info(
            "Loaded scenario probe %s from %s (%d turns)",
            self.artifact.get("scenario_id"),
            self.config_path,
            len(self.artifact.get("turns") or []),
        )

    def _attempt_prestore_hook(self, attempt, seq=None):
        attempt.notes["scenario_id"] = self.artifact.get("scenario_id")
        attempt.notes["injection_surface"] = self.artifact.get("injection_surface")
        attempt.notes["detector_rubric"] = self.artifact.get("detector_rubric") or {}
        attempt.notes["config_path"] = self.config_path
        return attempt


DEFAULT_CLASS = "Scenario"
