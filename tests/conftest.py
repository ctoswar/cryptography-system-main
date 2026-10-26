"""Shared fixtures for the AC3 v2 test suite."""

import secrets
import sys
from pathlib import Path

import pytest

# Make the project root importable regardless of how pytest is invoked.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ac3 import AC3Cipher  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_master_key(monkeypatch):
    """The real process env must never satisfy a test's key lookup."""
    monkeypatch.delenv("AC3_MASTER_KEY", raising=False)


@pytest.fixture()
def cipher() -> AC3Cipher:
    """A cipher with an ephemeral master key (no .env involved)."""
    return AC3Cipher(secrets.token_bytes(32))


@pytest.fixture()
def env_dir(tmp_path) -> Path:
    """Isolated directory so KeyManager tests never touch the real .env."""
    return tmp_path


@pytest.fixture()
def client(env_dir):
    """Flask test client wired to an isolated key store."""
    import app as app_module
    from ac3 import CMainController

    app_module.controller = CMainController(env_path=env_dir / ".env")
    app_module.app.config["TESTING"] = True
    yield app_module.app.test_client()
    app_module.app.config["TESTING"] = True  # restore after tests that flip it
