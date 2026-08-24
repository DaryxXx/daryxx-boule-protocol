FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 boule

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir .

USER boule
VOLUME ["/data"]
EXPOSE 8786

ENTRYPOINT ["boule"]
CMD ["registry", "serve", "/data", "--host", "0.0.0.0", "--port", "8786", "--allow-insecure-bind", "--json"]
