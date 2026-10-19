# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir .

RUN useradd -m -u 1000 janissary && chown -R janissary:janissary /app
USER janissary

ENTRYPOINT ["janissary"]
CMD ["--help"]
