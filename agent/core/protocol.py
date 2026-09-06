"""JSON action protocol shared by mock and Ollama backends."""

from __future__ import annotations

import json
import re
from typing import Any

from agent.core.types import ToolCall

_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def parse_model_output(raw: str) -> ToolCall | str:
    """Return a ToolCall or a final-answer string."""
    data = _extract_json(raw)
    if data is None:
        stripped = (raw or "").strip()
        return stripped or "I could not produce a structured action."

    thought = str(data.get("thought") or "")
    if "final" in data and data["final"] is not None:
        return str(data["final"])
    tool = data.get("tool")
    if not tool:
        return str(data.get("final") or thought or raw)
    args = data.get("args") or {}
    if not isinstance(args, dict):
        args = {"raw": args}
    return ToolCall(name=str(tool), args=args, thought=thought)


def emit_action(thought: str, tool: str, args: dict[str, Any]) -> str:
    return json.dumps({"thought": thought, "tool": tool, "args": args}, indent=2)


def emit_final(thought: str, final: str) -> str:
    return json.dumps({"thought": thought, "final": final}, indent=2)


def _extract_json(raw: str) -> dict[str, Any] | None:
    text = (raw or "").strip()
    if not text:
        return None
    fenced = _FENCE_RE.search(text)
    if fenced:
        text = fenced.group(1)
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start : end + 1])
                return data if isinstance(data, dict) else None
            except json.JSONDecodeError:
                return None
        return None
