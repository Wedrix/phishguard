from __future__ import annotations

import logging
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError

from phishguard.api.errors import ApiError
from phishguard.api.governance import router as governance_router
from phishguard.api.routes import router as api_router
from phishguard.application.auth import AuthenticationError
from phishguard.config import Settings
from phishguard.domain.model import SklearnUrlModel, UrlModel
from phishguard.infrastructure.database import create_schema, make_engine, make_session_factory
from phishguard.infrastructure.encryption import configured_cipher

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None, engine: Engine | None = None) -> FastAPI:
    settings = settings or Settings()
    engine = engine or make_engine(settings.database_url)
    app = FastAPI(
        title="PhishGuard API",
        version="0.1.0",
        docs_url="/docs" if settings.environment == "development" else None,
        redoc_url=None,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = make_session_factory(engine)
    app.state.cipher = configured_cipher(settings.kms_key_name, settings.phishguard_encryption_key, settings.environment)
    app.state.model = _load_model(settings)
    if settings.environment == "test":
        create_schema(engine)

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["Content-Type", "Idempotency-Key", "X-CSRF-Token", "X-Correlation-ID"],
        )

    @app.middleware("http")
    async def correlation_and_security(request: Request, call_next):
        supplied = request.headers.get("X-Correlation-ID")
        try:
            correlation_id = str(uuid.UUID(supplied)) if supplied else str(uuid.uuid4())
        except ValueError:
            correlation_id = str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        try:
            response = await call_next(request)
        except Exception:
            logger.exception(
                "unhandled request failure",
                extra={"correlation_id": request.state.correlation_id},
            )
            response = _error_response(
                request,
                500,
                "internal_error",
                "The request could not be completed",
            )
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.url.path.startswith("/api/v1/"):
            # API responses can contain scan metadata or, on the deliberate
            # reveal path, decrypted source material. Do not retain either in
            # browser or intermediary caches after expiry/deletion.
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        firebase_frame = (
            f" https://{settings.identity_project_id}.firebaseapp.com" if settings.identity_project_id else ""
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self' https://identitytoolkit.googleapis.com "
            "https://securetoken.googleapis.com; "
            f"frame-src 'self'{firebase_frame}; object-src 'none'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'"
        )
        return response

    @app.exception_handler(ApiError)
    async def api_error(request: Request, exc: ApiError) -> JSONResponse:
        return _error_response(request, exc.status_code, exc.code, exc.message, exc.fields)

    @app.exception_handler(AuthenticationError)
    async def auth_error(request: Request, exc: AuthenticationError) -> JSONResponse:
        return _error_response(request, 401, "authentication_failed", str(exc))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        fields = {".".join(str(part) for part in error["loc"]): error["msg"] for error in exc.errors()[:20]}
        return _error_response(request, 422, "validation_failed", "Request validation failed", fields)

    @app.exception_handler(IntegrityError)
    async def integrity_error(request: Request, exc: IntegrityError) -> JSONResponse:
        logger.info("database constraint rejected request", extra={"correlation_id": request.state.correlation_id})
        return _error_response(request, 409, "conflict", "The requested state conflicts with an existing record")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = (
            "not_found"
            if exc.status_code == 404
            else "method_not_allowed"
            if exc.status_code == 405
            else "http_error"
        )
        message = (
            "Resource was not found"
            if exc.status_code == 404
            else "Method is not allowed"
            if exc.status_code == 405
            else "The request could not be completed"
        )
        return _error_response(request, exc.status_code, code, message)

    @app.get("/healthz", include_in_schema=False)
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def ready() -> dict[str, str]:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return {"status": "ready"}

    app.include_router(api_router)
    app.include_router(governance_router)
    _serve_frontend(app, settings.static_dir)
    return app


def _load_model(settings: Settings) -> UrlModel | None:
    configured = (settings.model_path, settings.model_sha256, settings.model_version)
    if not any(configured):
        return None
    if not all(configured):
        raise RuntimeError("MODEL_PATH, MODEL_SHA256, and MODEL_VERSION must be configured together")
    assert settings.model_path and settings.model_sha256 and settings.model_version
    try:
        return SklearnUrlModel(settings.model_path, settings.model_sha256, settings.model_version)
    except Exception:
        logger.exception(
            "approved model could not be loaded; using rule-only fallback",
            extra={"model_version": settings.model_version},
        )
        return None


def _error_response(
    request: Request,
    status: int,
    code: str,
    message: str,
    fields: dict[str, object] | None = None,
) -> JSONResponse:
    return JSONResponse(
        {
            "error": {
                "code": code,
                "message": message,
                "correlation_id": request.state.correlation_id,
                "fields": fields or {},
            }
        },
        status_code=status,
    )


def _serve_frontend(app: FastAPI, static_dir: Path) -> None:
    root = static_dir.resolve()
    if not root.is_dir() or not (root / "index.html").is_file():
        return

    @app.get("/{path:path}", include_in_schema=False)
    def frontend(path: str) -> FileResponse:
        if path == "api" or path.startswith("api/"):
            raise ApiError(404, "not_found", "Resource was not found")
        requested = (root / path).resolve()
        if requested.is_relative_to(root) and requested.is_file():
            return FileResponse(requested)
        return FileResponse(root / "index.html")


app = create_app()
