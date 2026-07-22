from __future__ import annotations

from fastapi import FastAPI

from . import __version__
from .fetch import SafeFetcher
from .models import EnrichmentRequest, EnrichmentResponse


def create_app(fetcher: SafeFetcher | None = None) -> FastAPI:
    service = fetcher or SafeFetcher()
    app = FastAPI(
        title="PhishGuard Isolated Fetcher",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/healthz", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def ready() -> dict[str, str]:
        return {"status": "ready"}

    @app.post("/internal/v1/enrich", response_model=EnrichmentResponse)
    async def enrich(request: EnrichmentRequest) -> EnrichmentResponse:
        return await service.enrich(request)

    return app


app = create_app()

