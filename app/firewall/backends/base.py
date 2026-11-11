"""Backend abstraction. Backends render + apply a FirewallState to Averqon-owned objects only."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence

from app.firewall.policies.policy import FirewallState
from app.utils.process import CommandResult, run_command

Runner = Callable[..., CommandResult]


class FirewallBackend(ABC):
    """Contract every backend implements.

    PRIVILEGED: ``apply``, ``restore``, ``teardown``, ``ban``, ``unban`` change kernel
    state and need CAP_NET_ADMIN. They must only touch objects Averqon owns.
    """

    name: str

    def __init__(self, runner: Runner = run_command) -> None:
        self._run = runner

    def _exec(self, argv: Sequence[str], input_text: str | None = None, timeout: float = 15.0) -> CommandResult:
        return self._run(list(argv), timeout=timeout, input_text=input_text)

    @abstractmethod
    def render(self, state: FirewallState) -> str:
        """Pure function: desired state -> backend ruleset text."""

    @abstractmethod
    def check(self, ruleset: str) -> None:
        """Validate without applying. Raises BackendError on invalid ruleset."""

    @abstractmethod
    def apply(self, ruleset: str) -> None:
        """Atomically install a rendered ruleset."""

    @abstractmethod
    def export(self) -> str | None:
        """Return text that ``restore`` can re-install, or None if nothing is installed."""

    @abstractmethod
    def restore(self, snapshot: str | None) -> None:
        """Atomically return to a previously exported snapshot (None = remove ours)."""

    @abstractmethod
    def teardown(self) -> None:
        """Remove everything Averqon installed (emergency recovery / uninstall)."""

    @abstractmethod
    def ban(self, network: str, ttl_seconds: int | None) -> None:
        """Add a live ban without a full reload."""

    @abstractmethod
    def unban(self, network: str) -> None:
        """Remove a live ban."""

    @abstractmethod
    def counters(self) -> dict[str, int]:
        """Packet/byte counters of Averqon-owned rules."""
