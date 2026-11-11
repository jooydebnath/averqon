"""Domain exception hierarchy. API layer maps these to safe HTTP responses."""

from __future__ import annotations


class AverqonError(Exception):
    """Base class; ``public_message`` is safe to show to API clients."""

    code = "internal_error"
    public_message = "Internal error"

    def __init__(self, detail: str | None = None) -> None:
        super().__init__(detail or self.public_message)
        self.detail = detail or self.public_message


class ValidationFailed(AverqonError, ValueError):
    code = "validation_error"
    public_message = "Invalid input"


class ConfigError(AverqonError):
    code = "config_error"
    public_message = "Invalid configuration"


class BackendError(AverqonError):
    code = "backend_error"
    public_message = "Firewall backend error"


class PermissionDenied(AverqonError):
    code = "forbidden"
    public_message = "Forbidden"
