# Multi-stage Dockerfile for the CoEvolve Sandbox API service.
# Stage 1: install dependencies into a virtualenv
# Stage 2: slim runtime image

FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---- runtime ----
FROM python:3.11-slim

RUN groupadd -r coevolve && useradd -r -g coevolve -d /app coevolve

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY packages/api /app/packages/api
COPY packages/elo /app/packages/elo
COPY packages/agents /app/packages/agents
COPY packages/judge /app/packages/judge
COPY packages/sandbox /app/packages/sandbox
COPY packages/evolution /app/packages/evolution
COPY packages/telemetry /app/packages/telemetry
COPY data /app/data

# Set PYTHONPATH so imports work
ENV PYTHONPATH=/app

# Non-root user
RUN chown -R coevolve:coevolve /app
USER coevolve

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()"

CMD ["uvicorn", "packages.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
