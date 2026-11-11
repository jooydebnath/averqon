from typer.testing import CliRunner

from cli.main import app

r = CliRunner()


def test_version():
    assert r.invoke(app, ["version"]).stdout.strip() == "0.1.0"


def test_validate_json(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("log_level: INFO\n")
    p.chmod(0o600)
    out = r.invoke(app, ["config", "validate", str(p), "--json"])
    assert out.exit_code == 0 and '"valid": true' in out.stdout
    p.write_text("log_level: NOPE\n")
    assert r.invoke(app, ["config", "validate", str(p), "--json"]).exit_code == 1
