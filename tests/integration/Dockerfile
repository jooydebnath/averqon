# Real kernel-enforcement test image: needs --privileged (network namespaces).
#
#   docker build -f tests/integration/Dockerfile -t averqon-kernel-tests .
#   docker run --rm --privileged averqon-kernel-tests
#
# Or just: ./scripts/test-kernel.sh
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3.12 python3.12-venv iproute2 nftables iptables ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN python3.12 -m venv /opt/venv \
 && /opt/venv/bin/pip install -q -e '.[dev,server]'
ENV PATH="/opt/venv/bin:${PATH}"

CMD ["pytest", "-q", "-m", "integration", "tests/integration", "-rs"]
