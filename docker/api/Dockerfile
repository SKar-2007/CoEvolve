# Multi-stage Dockerfile for the CoEvolve Sandbox API service.
# Stage 1: install dependencies into a virtualenv
# Stage 2: slim runtime image

FROM python:3.14-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---- runtime ----
FROM python:3.14-slim

RUN groupadd -r coevolve && useradd -r -g coevolve -d /app coevolve

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code (whole packages tree so new modules like
# training_service.py, cost_tracking.py, batch_trainer.py are never missed)
COPY packages /app/packages
COPY config /app/config
COPY data /app/data

# Set PYTHONPATH so imports work
ENV PYTHONPATH=/app

# Non-root user
RUN chown -R coevolve:coevolve /app
USER coevolve

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health').read()"

CMD ["uvicorn", "packages.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
