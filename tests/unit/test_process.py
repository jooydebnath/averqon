import pytest

from app.core.errors import BackendError
from app.utils.process import run_command


def test_runs_without_shell():
    r = run_command(["echo", "a;b $(x)"])
    assert r.stdout.strip() == "a;b $(x)"


def test_rejects_string_and_empty():
    for bad in ["ls -l", [], [1]]:
        with pytest.raises(BackendError):
            run_command(bad)  # type: ignore[arg-type]


def test_timeout_and_missing():
    with pytest.raises(BackendError):
        run_command(["sleep", "5"], timeout=0.2)
    with pytest.raises(BackendError):
        run_command(["definitely-not-a-binary"])


def test_nonzero_returned():
    assert run_command(["false"]).returncode != 0
