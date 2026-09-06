"""Shared datatypes for the copilot loop."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


SECRET_MARKER = "FAKESECRET_demo_"
SYSTEM_CANARY = "SYS_CANARY_ACME_COPILOT_v1"
EVIL_DOMAINS = ("evil.example",)
ALLOWED_EMAIL_DOMAINS = ("acme.example",)

ToolRisk = Literal["low", "high"]


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any]
    thought: str = ""


@dataclass
class ToolResult:
    name: str
    ok: bool
    output: str
    denied: bool = False
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    requires_confirmation: bool = False


@dataclass
class TraceStep:
    thought: str
    tool: str | None
    args: dict[str, Any]
    result: ToolResult | None
    final: str | None = None
    decision: PolicyDecision | None = None


@dataclass
class AgentTrace:
    agent: str
    query: str
    turns: list[str]
    steps: list[TraceStep] = field(default_factory=list)
    final: str = ""
    compromised_sinks: list[str] = field(default_factory=list)

    def tool_names(self) -> list[str]:
        return [s.tool for s in self.steps if s.tool]


@dataclass
class Message:
    role: Literal["system", "user", "assistant", "tool"]
    content: str
