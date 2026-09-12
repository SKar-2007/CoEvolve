# Slim hardened image used as the API service base (multi-stage, no toolchain).
FROM python:3.11-slim AS builder
RUN pip install --no-cache-dir pipenv wheel

FROM python:3.11-slim AS runtime
RUN groupadd -r app && useradd -r -g app -d /srv app
WORKDIR /srv
COPY --chown=app:app packages/api /srv/api
COPY --chown=app:app packages/sandbox /srv/sandbox
RUN pip install --no-cache-dir fastapi uvicorn pydantic pydantic-settings docker
USER app
EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]