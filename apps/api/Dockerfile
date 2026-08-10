# syntax=docker/dockerfile:1.7.0@sha256:4611ea7b7d89ce41ec5c63df83076ccec3fe8daa32a2d9c96e5decb72e9a8d67
FROM ghcr.io/astral-sh/uv:0.6.5@sha256:226f0f279625c9df16379cac7208721ee25c59382b360c8095abd64328657b4a AS uv

FROM python:3.11.9-slim-bookworm@sha256:2856e6af199e8128161abd320575eb9b341f3b76f017b5d0c9cd364f60d8a050 AS builder
COPY --from=uv /uv /uvx /bin/
WORKDIR /workspace
COPY pyproject.toml uv.lock uv.toml ./
COPY apps/api/pyproject.toml apps/api/pyproject.toml
COPY apps/worker/pyproject.toml apps/worker/pyproject.toml
COPY packages/contracts/pyproject.toml packages/contracts/pyproject.toml
COPY packages/llm/pyproject.toml packages/llm/pyproject.toml
COPY packages/security/pyproject.toml packages/security/pyproject.toml
COPY packages/storage/pyproject.toml packages/storage/pyproject.toml
COPY apps/api/src apps/api/src
COPY apps/worker/src apps/worker/src
COPY packages/contracts/src packages/contracts/src
COPY packages/llm/src packages/llm/src
COPY packages/security/src packages/security/src
COPY packages/storage/src packages/storage/src
RUN uv sync --frozen --no-dev --no-editable --package nexus-api

FROM python:3.11.9-slim-bookworm@sha256:2856e6af199e8128161abd320575eb9b341f3b76f017b5d0c9cd364f60d8a050 AS runtime
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && python -m pip uninstall -y setuptools wheel \
    && groupadd --gid 10001 nexus \
    && useradd --uid 10001 --gid nexus --create-home nexus \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY --from=builder /workspace/.venv /workspace/.venv
ENV PATH="/workspace/.venv/bin:$PATH" PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "nexus_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
