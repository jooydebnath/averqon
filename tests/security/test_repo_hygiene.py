"""Static security regression checks over the source tree and deployment files."""
import ast
import re
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PY = [p for d in ("app", "cli") for p in (ROOT / d).rglob("*.py")]
UNITS = sorted((ROOT / "deploy" / "systemd").glob("*.service"))
BANNED_CALLS = {"eval", "exec", "compile", "__import__"}


def calls(tree):
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            f = n.func
            yield (f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""), n


def builtin_calls(tree):
    return [(n.func.id, n) for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]


@pytest.mark.parametrize("path", PY, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_dangerous_calls(path):
    tree = ast.parse(path.read_text())
    for name, node in builtin_calls(tree):
        assert name not in BANNED_CALLS, f"{path}:{node.lineno} uses {name}()"
    for name, node in calls(tree):
        assert name not in {"system", "popen"} or "os" not in ast.dump(node.func), f"{path}:{node.lineno} shell exec"
        for kw in node.keywords:
            if kw.arg == "shell":
                assert isinstance(kw.value, ast.Constant) and kw.value.value is False, f"{path}:{node.lineno} shell=True"


def test_subprocess_only_in_sanctioned_modules():
    allowed = {"app/utils/process.py"}
    for p in PY:
        rel = str(p.relative_to(ROOT))
        src = p.read_text()
        if re.search(r"^\s*(import subprocess|from subprocess)", src, re.MULTILINE):
            assert rel in allowed, f"{rel} imports subprocess directly; use app.utils.process.run_command"


SECRET = re.compile(r"""(?i)(password|secret|token|api[_-]?key)\s*=\s*["'][^"'\s]{8,}["']""")


def test_no_hardcoded_secrets():
    for p in PY:
        for i, line in enumerate(p.read_text().splitlines(), 1):
            if SECRET.search(line) and "get_secret_value" not in line and "# noqa" not in line and "SecretStr" not in line:
                pytest.fail(f"{p}:{i} looks like a hardcoded secret: {line.strip()[:80]}")


def test_no_sql_string_formatting():
    for p in PY:
        for node in ast.walk(ast.parse(p.read_text())):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "execute" and node.args:
                a = node.args[0]
                assert not isinstance(a, ast.JoinedStr | ast.BinOp), f"{p}:{node.lineno} dynamic SQL"


def test_jwt_algorithm_pinned():
    src = (ROOT / "app/auth/security.py").read_text()
    assert 'algorithms=["HS256"]' in src and "verify_signature" not in src and '"none"' not in src


@pytest.mark.parametrize("unit", UNITS, ids=lambda p: p.name)
def test_systemd_hardening(unit):
    t = unit.read_text()
    for must in ("NoNewPrivileges=yes", "ProtectSystem=strict", "PrivateTmp=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes"):
        assert must in t, f"{unit.name} lacks {must}"
    if unit.name != "averqon-executor.service":
        assert "User=averqon" in t and "CapabilityBoundingSet=\n" in t + "\n", f"{unit.name} must be unprivileged with no capabilities"
        assert "CAP_NET_ADMIN" not in t
    else:
        assert "CAP_NET_ADMIN" in t and "ProtectHome=yes" in t and "ReadWritePaths=/var/lib/averqon /run/averqon" in t
        assert "CAP_SYS_ADMIN" not in t and "CAP_SYS_MODULE" not in t


def test_only_executor_is_root():
    for u in UNITS:
        root = "User=root" in u.read_text()
        assert root == (u.name == "averqon-executor.service")


def test_scripts_are_safe():
    for s in (ROOT / "scripts").glob("*.sh"):
        text = s.read_text()
        assert s.stat().st_mode & stat.S_IXUSR, f"{s.name} not executable"
        assert re.search(r"^set -[euo]+", text, re.MULTILINE) or s.name == "averqon-emergency-disable.sh"
        assert "eval " not in text and "curl | sh" not in text and "| bash" not in text
        assert "flush ruleset" not in text and "iptables -F\n" not in text and not re.search(r"iptables\s+-F\s*$", text, re.MULTILINE)


def test_firewall_code_never_flushes_ruleset():
    for p in (ROOT / "app" / "firewall").rglob("*.py"):
        assert "flush ruleset" not in p.read_text().replace('"flush ruleset" not in', ""), p


def test_default_bind_is_loopback_and_secrets_have_no_default():
    from app.core.config import ApiSettings, Settings
    assert ApiSettings().host == "127.0.0.1" and Settings().secret_key is None
