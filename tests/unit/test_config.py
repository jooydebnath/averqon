
import pytest

from app.core.config import Settings, load_settings
from app.core.errors import ConfigError


def write(tmp_path, text, mode=0o600):
    p = tmp_path / "c.yaml"
    p.write_text(text)
    p.chmod(mode)
    return p


def test_defaults_and_file(tmp_path):
    s = load_settings(write(tmp_path, "firewall:\n  table_name: fw\n"))
    assert s.firewall.table_name == "fw"
    assert s.environment == "development"


def test_env_overrides_file(tmp_path, monkeypatch):
    monkeypatch.setenv("AVERQON_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("AVERQON_API__PORT", "9000")
    s = load_settings(write(tmp_path, "log_level: ERROR\napi:\n  port: 1234\n"))
    assert s.log_level == "DEBUG" and s.api.port == 9000


def test_insecure_permissions_rejected(tmp_path):
    with pytest.raises(ConfigError):
        load_settings(write(tmp_path, "{}", 0o644))


@pytest.mark.parametrize("text", ["firewall:\n  table_name: 'bad name;'\n", "[1,2]", "a: [", "database:\n  url: mysql://x\n"])
def test_invalid_rejected(tmp_path, text):
    with pytest.raises(ConfigError):
        load_settings(write(tmp_path, text))


def test_missing_file():
    with pytest.raises(ConfigError):
        load_settings(__import__("pathlib").Path("/nonexistent/x.yaml"))


def test_secret_required_and_production_length():
    with pytest.raises(ConfigError):
        Settings().require_secret()
    with pytest.raises(ConfigError):
        Settings(environment="production", secret_key="short").require_secret()
    assert Settings(environment="production", secret_key="x" * 32).require_secret() == "x" * 32


def test_secret_not_in_repr():
    assert "supersecretvalue" not in repr(Settings(secret_key="supersecretvalue"))


def test_example_config_is_valid():
    from pathlib import Path
    p = Path(__file__).resolve().parents[2] / "configs" / "averqon.example.yaml"
    s = load_settings(p, enforce_permissions=False)
    assert s.environment == "production" and s.firewall.table_name == "averqon" and s.ids.autoban


def test_nested_env_secrets_merge_with_yaml(tmp_path, monkeypatch):
    monkeypatch.setenv("AVERQON_NOTIFICATIONS__TELEGRAM__BOT_TOKEN", "123:ABC")
    monkeypatch.setenv("AVERQON_SECRET_KEY", "k" * 40)
    s = load_settings(write(tmp_path, "notifications:\n  telegram:\n    enabled: true\n    chat_id: '42'\n"))
    t = s.notifications.telegram
    assert t.enabled and t.chat_id == "42" and t.bot_token.get_secret_value() == "123:ABC"
    assert "123:ABC" not in repr(s) and s.require_secret() == "k" * 40
