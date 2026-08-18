"""Convert ArtifactGen turns into OpenAI chat-completions messages + tool schemas.

Kept free of garak imports so the notebook can use it before plugins are installed.
"""

from __future__ import annotations

import re

_TOOL_SIG_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)\s*\(([^`]*)\)`")
_PARAM_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*([A-Za-z_][A-Za-z0-9_\[\]| ]*))?"
)


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
