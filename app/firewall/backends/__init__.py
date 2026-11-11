"""Backend selection."""

from __future__ import annotations

from app.core.errors import BackendError
from app.firewall.backends.base import FirewallBackend
from app.firewall.backends.iptables import IptablesBackend
from app.firewall.backends.nftables import NftablesBackend
from app.firewall.capabilities import Capabilities

__all__ = ["FirewallBackend", "IptablesBackend", "NftablesBackend", "select_backend"]


def select_backend(caps: Capabilities, preference: str = "auto", table: str = "averqon") -> FirewallBackend:
    """Pick a backend honouring the preference only if the host supports it."""
    choice = caps.preferred_backend if preference == "auto" else preference
    if choice == "nftables" and caps.nftables_usable:
        return NftablesBackend(table=table, nft=caps.nft_path or "nft")
    if choice == "iptables" and caps.iptables_usable:
        return IptablesBackend(
            iptables=caps.iptables_path or "iptables", ip6tables=caps.ip6tables_path or "ip6tables",
            restore=caps.iptables_restore_path or "iptables-restore",
        )
    raise BackendError(f"backend '{choice}' is not available on this host")
