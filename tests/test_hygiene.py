import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN = [
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----"),
]

SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "*.egg-info"}


def test_repo_has_no_real_looking_secrets() -> None:
    offenders: list[str] = []
    for path in ROOT.rglob("*"):
        if any(part in SKIP_DIRS or part.endswith(".egg-info") for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.suffix in {".png", ".jpg", ".pyc", ".woff"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for pattern in FORBIDDEN:
            if pattern.search(text):
                offenders.append(f"{path}: {pattern.pattern}")
    assert offenders == []


def test_planted_secrets_use_lab_marker() -> None:
    secret = (ROOT / "sandbox" / "secrets" / "api_keys.env").read_text(encoding="utf-8")
    assert "FAKESECRET_demo_" in secret
    assert "FICTIONAL" in secret
