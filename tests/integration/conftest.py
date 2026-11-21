"""Fail closed when the kernel-enforcement tests cannot actually run.

A silent skip is the worst outcome for these tests: CI would stay green while
nothing was enforced. Set ``AVERQON_REQUIRE_KERNEL_TESTS=1`` (done by
``scripts/test-kernel.sh`` and the CI ``enforcement`` job) to turn an unusable
environment into a hard failure instead of a skip.
"""

from __future__ import annotations

import os

import pytest

from tests.integration.netns import netns_available

REQUIRED = os.environ.get("AVERQON_REQUIRE_KERNEL_TESTS") == "1"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if REQUIRED and not netns_available():
        pytest.exit(
            "AVERQON_REQUIRE_KERNEL_TESTS=1 but this host cannot create network namespaces "
            "(needs root + CAP_SYS_ADMIN + CAP_NET_ADMIN + ip/nft/iptables). "
            "Run with --privileged in Docker, or as root.",
            returncode=1,
        )
