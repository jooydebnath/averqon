"""Logging setup with optional JSON output and secret redaction."""

from __future__ import annotations

import json
import logging
import re
import sys

_REDACT = re.compile(r"(?i)(password|secret|token|authorization|api[_-]?key)(\s*[=:]\s*)\S+")


class RedactingFilter(logging.Filter):
    """Mask values of obviously sensitive key=value pairs in log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _REDACT.sub(r"\1\2***", record.getMessage())
        record.args = None
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging(level: str = "INFO", json_output: bool = False) -> None:
    """Configure the root logger idempotently."""
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(RedactingFilter())
    handler.setFormatter(
        JsonFormatter() if json_output else logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
