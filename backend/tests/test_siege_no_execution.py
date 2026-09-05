"""
Safety guard: the Siege Tower module plans and documents; it never acts.

Siege Tower must not be able to execute commands or reach into a target. This
test fails if the router or adapter grows an import of process-spawning or
network-client machinery. It is a coarse guard, deliberately — the real
guarantee is architectural (the engine is a standalone, dependency-free package
with no network or subprocess access), and this keeps that guarantee honest.
"""
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1]
_FILES = [
    _BACKEND / "app" / "routers" / "siege.py",
    _BACKEND / "app" / "services" / "siege_adapter.py",
]

# Tokens that would indicate command execution or a client connection to a
# target. `os.getenv` is fine; `os.system`/`os.popen` are not.
_FORBIDDEN = [
    "subprocess", "os.system", "os.popen", "pty.spawn",
    "import socket", "paramiko", "import httpx", "import requests",
    "create_subprocess", "asyncio.subprocess",
]


def test_siege_module_has_no_execution_or_egress_imports():
    for path in _FILES:
        src = path.read_text()
        for token in _FORBIDDEN:
            assert token not in src, f"{path.name} must not reference {token!r}"
