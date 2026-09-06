"""Least-privilege policy for the hardened copilot.

The model never authorizes itself. Every tool call is checked here before
execution. High-risk tools also require a human confirmation callback.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from agent.core.tools_common import HARDENED_HTTP_HOSTS, resolve_lab_path
from agent.core.types import ALLOWED_EMAIL_DOMAINS, PolicyDecision
from agent.paths import LabPaths

ConfirmFn = Callable[[str, dict[str, Any]], bool]

HIGH_RISK = frozenset({"read_file", "run_command", "send_email", "http_fetch"})
ALLOWED_TOOLS = frozenset(
    {
        "lookup_ticket",
        "search_knowledge",
        "read_file",
        "run_command",
        "send_email",
        "http_fetch",
        "memory_write",
        "memory_read",
    }
)
# Support copilot may read KB + tickets only. Secrets stay out of the tool.
READ_ALLOW_PREFIXES = ("sandbox/knowledge/", "sandbox/tickets/", "sandbox/notes/")
READ_ALLOW_EXACT = frozenset({"sandbox/knowledge", "sandbox/tickets", "sandbox/notes"})
RUN_ALLOW = frozenset({("ls",), ("ls", "sandbox/knowledge"), ("ls", "sandbox/tickets"), ("pwd",)})


class HardenedPolicy:
    def __init__(self, paths: LabPaths, confirm: ConfirmFn | None = None) -> None:
        self.paths = paths
        self.confirm = confirm or default_confirm

    def authorize(self, tool: str, args: dict[str, Any]) -> PolicyDecision:
        if tool not in ALLOWED_TOOLS:
            return PolicyDecision(False, f"tool {tool!r} is not on the allowlist")

        if tool == "read_file":
            decision = self._authorize_read(str(args.get("path") or ""))
            if not decision.allowed:
                return decision
        elif tool == "run_command":
            decision = self._authorize_command(str(args.get("command") or ""))
            if not decision.allowed:
                return decision
        elif tool == "send_email":
            decision = self._authorize_email(str(args.get("to") or ""))
            if not decision.allowed:
                return decision
        elif tool == "http_fetch":
            decision = self._authorize_http(str(args.get("url") or ""))
            if not decision.allowed:
                return decision

        if tool in HIGH_RISK:
            if not self.confirm(tool, args):
                return PolicyDecision(
                    False,
                    "human-in-the-loop denied this high-risk tool",
                    requires_confirmation=True,
                )
            return PolicyDecision(True, "allowlisted + HITL approved", requires_confirmation=True)

        return PolicyDecision(True, "allowlisted low-risk tool")

    def _authorize_read(self, raw: str) -> PolicyDecision:
        normalized = _normalize_lab_rel(raw, self.paths)
        if normalized is None:
            return PolicyDecision(False, f"path {raw!r} is outside the sandbox")
        if normalized.startswith("sandbox/secrets"):
            return PolicyDecision(False, "secrets path is denied (least privilege)")
        if normalized.startswith("sandbox/simulated_host"):
            return PolicyDecision(False, "host filesystem is not mounted")
        if normalized in READ_ALLOW_EXACT or normalized.startswith(READ_ALLOW_PREFIXES):
            return PolicyDecision(True, "path is inside the support sandbox")
        return PolicyDecision(False, f"path {normalized!r} is not in the read allowlist")

    def _authorize_command(self, command: str) -> PolicyDecision:
        import shlex

        try:
            argv = tuple(shlex.split(command))
        except ValueError:
            return PolicyDecision(False, "unparseable command")
        if argv in RUN_ALLOW:
            return PolicyDecision(True, "command is on the support allowlist")
        return PolicyDecision(False, f"command {command!r} is not on the support allowlist")

    def _authorize_email(self, to: str) -> PolicyDecision:
        if "@" not in to:
            return PolicyDecision(False, "email address is malformed")
        domain = to.rsplit("@", 1)[-1].lower()
        if domain not in ALLOWED_EMAIL_DOMAINS:
            return PolicyDecision(False, f"email domain {domain!r} is not allowlisted")
        return PolicyDecision(True, "recipient domain is allowlisted")

    def _authorize_http(self, url: str) -> PolicyDecision:
        host = urlparse(url).hostname or ""
        if host not in HARDENED_HTTP_HOSTS:
            return PolicyDecision(False, f"http host {host!r} is not allowlisted")
        return PolicyDecision(True, "http host is allowlisted")


def default_confirm(tool: str, args: dict[str, Any]) -> bool:
    mode = (os.environ.get("AGENT_HITL") or "deny").strip().lower()
    if mode in {"allow", "yes", "1", "true"}:
        return True
    if mode in {"prompt", "interactive"}:
        print(f"\n[HITL] approve high-risk tool {tool}")
        print(f"       args={args}")
        try:
            answer = input("       Confirm? [y/N] ").strip().lower()
        except EOFError:
            return False
        return answer in {"y", "yes"}
    return False


def _normalize_lab_rel(raw: str, paths: LabPaths) -> str | None:
    try:
        resolved, _ = resolve_lab_path(raw, paths)
    except Exception:
        return None
    try:
        rel = resolved.relative_to(paths.project_root)
    except ValueError:
        return None
    return Path(rel).as_posix()
