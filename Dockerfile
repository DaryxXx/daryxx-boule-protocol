ARG PYTHON_IMAGE=python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a

FROM ${PYTHON_IMAGE} AS builder

ARG UV_VERSION=0.9.5
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app
RUN python -m pip install --no-cache-dir "uv==${UV_VERSION}"

COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv lock --check \
    && uv sync --frozen --no-dev --no-editable --compile-bytecode

FROM ${PYTHON_IMAGE} AS runtime

ENV HOME=/home/boule \
    PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/app/.venv

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 boule \
    && useradd --create-home --uid 10001 --gid 10001 boule \
    && install -d -o boule -g boule -m 0700 /data

WORKDIR /app
COPY --from=builder --chown=10001:10001 /app/.venv /app/.venv

USER boule
VOLUME ["/data"]
EXPOSE 8786

ENTRYPOINT ["boule"]
CMD ["registry", "serve", "/data", "--host", "0.0.0.0", "--port", "8786", "--allow-insecure-bind", "--json"]
