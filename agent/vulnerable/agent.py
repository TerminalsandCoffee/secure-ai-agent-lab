"""Acme Support Copilot — vulnerable build."""

from __future__ import annotations

from agent.core.audit import AuditLog
from agent.core.llm import LLMBackend, load_backend
from agent.core.loop import AgentRunner, AllowAllPolicy
from agent.core.tools_common import build_vulnerable_tools
from agent.paths import LabPaths
from agent.vulnerable.prompts import SYSTEM_PROMPT


def build_vulnerable_agent(
    paths: LabPaths | None = None,
    llm: LLMBackend | None = None,
    memory: dict[str, str] | None = None,
) -> AgentRunner:
    paths = paths or LabPaths.from_root()
    paths.ensure_runtime_dirs()
    store = memory if memory is not None else {}
    audit = AuditLog(paths.logs / "vulnerable.jsonl")
    return AgentRunner(
        name="vulnerable",
        system_prompt=SYSTEM_PROMPT,
        llm=llm or load_backend(gullible=True),
        tools=build_vulnerable_tools(paths, store),
        policy=AllowAllPolicy(),
        audit=audit,
        memory=store,
        trust_memory=True,
        filter_final=False,
    )
