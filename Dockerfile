# Multi-Stage Hardened Cloud Run Container for Google Cloud Professional Agentic Architect Suite
# Follows Cloud Run v2 & gVisor best practices: non-root user, slim image, deterministic builds, healthcheck.

# Stage 1: Dependency Builder
FROM python:3.13-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --upgrade pip && \
    pip wheel --wheel-dir /build/wheels .

# Stage 2: Minimal Hardened Runtime
FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

RUN groupadd -r appgroup && useradd -r -g appgroup -d /app -s /sbin/nologin appuser

WORKDIR /app

COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

COPY src/ ./src/
COPY SPECIFICATION.md ./SPECIFICATION.md

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health')" || exit 1

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
