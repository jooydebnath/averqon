"""Safe subprocess execution: argv lists only, never a shell, always a timeout."""

from __future__ import annotations

import logging
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass

from app.core.errors import BackendError

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def run_command(
    argv: Sequence[str], *, timeout: float = 10.0, input_text: str | None = None
) -> CommandResult:
    """Run ``argv`` without a shell. Raises BackendError on timeout / missing binary.

    A non-zero exit is returned, not raised; callers decide how to treat it.
    """
    if isinstance(argv, str) or not argv or not all(isinstance(a, str) for a in argv):
        raise BackendError("argv must be a non-empty list of strings")
    log.debug("exec: %s", list(argv))
    try:
        proc = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise BackendError(f"command timed out: {argv[0]}") from exc
    except FileNotFoundError as exc:
        raise BackendError(f"command not found: {argv[0]}") from exc
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)
