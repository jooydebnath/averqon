# Contributing
    pip install -e '.[dev,server]'
    ruff check . && pytest
Never modify the host firewall in tests; enforcement tests must run inside `unshare -n` namespaces. Every new firewall input must go through `app/utils/validation.py`.
