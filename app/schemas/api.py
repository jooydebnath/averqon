"""Request/response schemas for the REST API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.auth.rbac import ROLES
from app.auth.security import USERNAME
from app.firewall.rules.models import FirewallRule
from app.utils import validation as v


class Page[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginIn(Strict):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: str
    role: str
    username: str


class BanIn(Strict):
    network: str
    ttl_seconds: int | None = Field(default=None, ge=1)
    reason: str = Field(default="", max_length=200)

    @field_validator("network")
    @classmethod
    def _n(cls, val: str) -> str:
        return str(v.parse_network(val))


class UnbanIn(Strict):
    network: str

    @field_validator("network")
    @classmethod
    def _n(cls, val: str) -> str:
        return str(v.parse_network(val))


class WhitelistIn(Strict):
    network: str
    comment: str = Field(default="", max_length=100)

    @field_validator("network")
    @classmethod
    def _n(cls, val: str) -> str:
        return str(v.parse_network(val))


class UserCreate(Strict):
    username: str
    password: str = Field(max_length=256)
    role: str

    @field_validator("username")
    @classmethod
    def _u(cls, val: str) -> str:
        if not USERNAME.fullmatch(val):
            raise ValueError("username must be 3-64 chars of letters, digits, _ . @ -")
        return val

    @field_validator("role")
    @classmethod
    def _r(cls, val: str) -> str:
        if val not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        return val


class UserUpdate(Strict):
    role: str | None = None
    enabled: bool | None = None
    password: str | None = Field(default=None, max_length=256)

    @field_validator("role")
    @classmethod
    def _r(cls, val: str | None) -> str | None:
        if val is not None and val not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        return val


class RuleOpts(Strict):
    dry_run: bool = False
    force: bool = False


JSON = dict[str, Any]


class RuleIn(FirewallRule):
    """Rule as submitted by a client: ``id`` is server-assigned and must not be supplied."""

    @field_validator("id")
    @classmethod
    def _no_id(cls, val: int | None) -> int | None:
        if val is not None:
            raise ValueError("id is read-only")
        return val
