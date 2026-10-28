# Development image for the regtest stack (dev/compose.yaml). It runs the
# makers, the `rill` CLI, the bootstrap/miner tooling and the web dev server.
# The repository is bind-mounted read-only at /src at runtime; the editable
# Python installs below resolve through that mount, so source edits apply
# after a container restart without rebuilding.
#
# Compilers (build-essential, cmake) live only in the `build` stage. The final
# image gets the finished native library and Python venv, not the toolchain.
FROM oven/bun:1.3.11 AS bun
FROM ghcr.io/astral-sh/uv:0.9.2 AS uv

# ---------------------------------------------------------------------------
# Build stage: native crypto library + Python venv
# ---------------------------------------------------------------------------
FROM python:3.14-slim-trixie AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential cmake ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /usr/local/bin/uv

# Native crypto facade. CMake downloads the checksum-pinned secp256k1 release.
COPY rill-crypto/CMakeLists.txt /build/rill-crypto/CMakeLists.txt
COPY rill-crypto/c /build/rill-crypto/c
RUN cmake -S /build/rill-crypto -B /build/native -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
    && cmake --build /build/native --parallel \
    && mkdir -p /opt/rill/native \
    && cp -a /build/native/librill_crypto.so* /opt/rill/native/

# Python packages, installed editable from /src. The same paths exist in the
# final stage (and at runtime via the bind mount), so the venv copies over
# as-is. Both stages share the python:3.14-slim-trixie base, so the venv's
# interpreter link to /usr/local/bin/python3.14 stays valid.
COPY rill-core/packages/core /src/rill-core/packages/core
COPY rill-crypto/python /src/rill-crypto/python
COPY rill-provider /src/rill-provider
COPY rill-cli /src/rill-cli
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv --python /usr/local/bin/python3.14 /opt/venv \
    && cd /src/rill-cli && uv pip install --python /opt/venv/bin/python -r requirements-dev.txt

# ---------------------------------------------------------------------------
# Final stage
# ---------------------------------------------------------------------------
FROM python:3.14-slim-trixie

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl socat jq \
    && rm -rf /var/lib/apt/lists/*

COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
COPY --from=uv /uv /usr/local/bin/uv

COPY --from=build /opt/rill/native /opt/rill/native
COPY --from=build /opt/venv /opt/venv

# Python sources the editable installs point at. Services that don't bind-mount
# the whole repo (chain, broadcast, user-node) still need them in the image.
COPY rill-core/packages/core /src/rill-core/packages/core
COPY rill-crypto/python /src/rill-crypto/python
COPY rill-provider /src/rill-provider
COPY rill-cli /src/rill-cli

# JavaScript dependencies. Compose mounts named volumes over these
# node_modules directories, seeded from the image on first use.
COPY rill-payments/package.json rill-payments/bun.lock /src/rill-payments/
RUN --mount=type=cache,target=/root/.bun/install/cache \
    cd /src/rill-payments && bun install --frozen-lockfile --ignore-scripts
COPY rill-web/package.json rill-web/bun.lock /src/rill-web/
COPY rill-payments /src/rill-payments
RUN --mount=type=cache,target=/root/.bun/install/cache \
    cd /src/rill-web && bun install --frozen-lockfile --ignore-scripts

COPY dev/entrypoint.sh /usr/local/bin/rill-dev-entrypoint
ENV VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RILL_CRYPTO_LIBRARY=/opt/rill/native/librill_crypto.so
WORKDIR /src
ENTRYPOINT ["rill-dev-entrypoint"]
CMD ["sleep", "infinity"]