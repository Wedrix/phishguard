FROM node:22-bookworm-slim AS frontend
WORKDIR /src/frontend
ARG VITE_FIREBASE_API_KEY
ARG VITE_FIREBASE_AUTH_DOMAIN
ARG VITE_FIREBASE_PROJECT_ID
ENV VITE_FIREBASE_API_KEY=$VITE_FIREBASE_API_KEY \
    VITE_FIREBASE_AUTH_DOMAIN=$VITE_FIREBASE_AUTH_DOMAIN \
    VITE_FIREBASE_PROJECT_ID=$VITE_FIREBASE_PROJECT_ID
RUN corepack enable && corepack prepare pnpm@10.15.1 --activate
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

FROM ghcr.io/astral-sh/uv:0.11.31 AS uv

FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STATIC_DIR=/app/frontend/dist \
    ALEMBIC_CONFIG=/app/backend/alembic.ini \
    PATH=/app/backend/.venv/bin:$PATH
WORKDIR /app/backend
COPY --from=uv /uv /usr/local/bin/uv
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --locked --no-dev --no-install-project
COPY backend/ ./
COPY fetcher/src/phishguard_fetcher/data/public-suffix-list.dat /app/backend/data/public-suffix-list.dat
RUN uv sync --locked --no-dev --no-editable
COPY --from=frontend /src/frontend/dist /app/frontend/dist
RUN chown -R 65532:65532 /app
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "-m", "phishguard.cli"]
CMD ["web"]
