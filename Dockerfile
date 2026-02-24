FROM python:3.13-slim AS base

LABEL maintainer="Agent-Safe Contributors"
LABEL description="Agent-Safe: governance and policy enforcement for AI agents"
LABEL org.opencontainers.image.source="https://github.com/your-org/agent-safe"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first (layer caching)
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir .

# Default config mount point
VOLUME /config

# Default entrypoint is the CLI
ENTRYPOINT ["agent-safe"]
CMD ["--help"]
