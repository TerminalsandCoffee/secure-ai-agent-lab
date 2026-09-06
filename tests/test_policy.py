from agent.hardened.policy import HardenedPolicy
from agent.hardened.sandbox import is_support_readable
from agent.paths import LabPaths


def _policy() -> HardenedPolicy:
    return HardenedPolicy(LabPaths.from_root(), confirm=lambda tool, args: False)


def test_secrets_path_denied() -> None:
    decision = _policy().authorize("read_file", {"path": "sandbox/secrets/api_keys.env"})
    assert decision.allowed is False
    assert "secrets" in decision.reason


def test_path_traversal_to_secrets_denied() -> None:
    decision = _policy().authorize(
        "read_file", {"path": "sandbox/knowledge/../../secrets/api_keys.env"}
    )
    assert decision.allowed is False


def test_knowledge_read_still_requires_hitl() -> None:
    decision = _policy().authorize("read_file", {"path": "sandbox/knowledge/refund-policy.md"})
    assert decision.allowed is False
    assert "human-in-the-loop" in decision.reason


def test_knowledge_read_allowed_when_hitl_approves() -> None:
    policy = HardenedPolicy(LabPaths.from_root(), confirm=lambda tool, args: True)
    decision = policy.authorize("read_file", {"path": "sandbox/knowledge/refund-policy.md"})
    assert decision.allowed is True


def test_evil_email_denied() -> None:
    policy = HardenedPolicy(LabPaths.from_root(), confirm=lambda tool, args: True)
    decision = policy.authorize("send_email", {"to": "attacker@evil.example", "body": "x"})
    assert decision.allowed is False
    assert "allowlisted" in decision.reason


def test_acme_email_denied_without_hitl() -> None:
    decision = _policy().authorize("send_email", {"to": "support@acme.example", "body": "x"})
    assert decision.allowed is False
    assert "human-in-the-loop" in decision.reason


def test_cat_secrets_command_denied() -> None:
    decision = _policy().authorize("run_command", {"command": "cat sandbox/secrets/api_keys.env"})
    assert decision.allowed is False


def test_http_evil_denied() -> None:
    policy = HardenedPolicy(LabPaths.from_root(), confirm=lambda tool, args: True)
    decision = policy.authorize("http_fetch", {"url": "http://evil.example/collect"})
    assert decision.allowed is False


def test_unknown_tool_denied() -> None:
    decision = _policy().authorize("drop_database", {})
    assert decision.allowed is False


def test_support_readable_helper() -> None:
    paths = LabPaths.from_root()
    assert is_support_readable("sandbox/knowledge/refund-policy.md", paths)
    assert not is_support_readable("sandbox/secrets/api_keys.env", paths)
