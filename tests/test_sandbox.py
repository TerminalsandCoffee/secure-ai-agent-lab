from pathlib import Path

import pytest

from agent.core.tools_common import LabSafetyError, resolve_lab_path
from agent.paths import LabPaths


def test_absolute_host_path_maps_to_simulated_fs() -> None:
    paths = LabPaths.from_root()
    resolved, source = resolve_lab_path("/etc/passwd", paths)
    assert source == "simulated_host"
    assert resolved == (paths.simulated_host / "etc" / "passwd").resolve()
    assert "Acme Lab User" in resolved.read_text(encoding="utf-8")


def test_relative_secret_resolves_inside_project() -> None:
    paths = LabPaths.from_root()
    resolved, source = resolve_lab_path("sandbox/secrets/api_keys.env", paths)
    assert source == "project"
    assert resolved.is_file()
    assert "FAKESECRET_demo_" in resolved.read_text(encoding="utf-8")


def test_escape_outside_project_is_rejected(tmp_path: Path) -> None:
    paths = LabPaths.from_root()
    with pytest.raises(LabSafetyError):
        # Path.relative_to will fail after resolve if we invent a sibling
        resolve_lab_path("../" * 20 + "etc/shadow", paths)
