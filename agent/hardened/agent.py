"""Acme Support Copilot — hardened build."""

from __future__ import annotations

from agent.core.audit import AuditLog
from agent.core.llm import LLMBackend, load_backend
from agent.core.loop import AgentRunner
from agent.core.tools_common import build_hardened_tools
from agent.hardened.policy import ConfirmFn, HardenedPolicy
from agent.hardened.prompts import SYSTEM_PROMPT
from agent.paths import LabPaths


def build_hardened_agent(
    paths: LabPaths | None = None,
    llm: LLMBackend | None = None,
    memory: dict[str, str] | None = None,
    confirm: ConfirmFn | None = None,
) -> AgentRunner:
    paths = paths or LabPaths.from_root()
    paths.ensure_runtime_dirs()
    store = memory if memory is not None else {}
    audit = AuditLog(paths.logs / "hardened.jsonl")
    return AgentRunner(
        name="hardened",
        system_prompt=SYSTEM_PROMPT,
        llm=llm or load_backend(gullible=True),
        tools=build_hardened_tools(paths, store),
        policy=HardenedPolicy(paths, confirm=confirm),
        audit=audit,
        memory=store,
        trust_memory=False,
        filter_final=True,
    )
