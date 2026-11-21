# Contributing
    pip install -e '.[dev,server]'
    ruff check . && pytest              # 408 tests, no privileges needed
    ./scripts/test-kernel.sh            # 16 packet-level kernel tests (Docker, --privileged)
Never modify the host firewall in tests; enforcement tests must run inside network namespaces they create and delete (`tests/integration/netns.py`). Every new firewall input must go through `app/utils/validation.py`.
