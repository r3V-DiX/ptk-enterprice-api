import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.core.request_id import RequestIDMiddleware
from app.core.auth import AuthError, ScopeError
from app.middleware.api_logger import ApiLoggerMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="ptk-enterprise-api",
    version="1.0.0",
    docs_url="/docs" if settings.ENV == "development" else None,
    redoc_url=None,
)

app.add_middleware(RequestIDMiddleware)
app.add_middleware(ApiLoggerMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError):
    return exc.response


@app.exception_handler(ScopeError)
async def scope_error_handler(request: Request, exc: ScopeError):
    return exc.response


# Routers
from app.api.v1 import admin as admin_router      # noqa: E402
from app.api.v1 import scans as scans_router      # noqa: E402
from app.api.v1 import findings as findings_router  # noqa: E402
from app.api.v1 import projects as projects_router  # noqa: E402
from app.api.v1 import assets as assets_router    # noqa: E402
from app.api.v1 import usage as usage_router      # noqa: E402
app.include_router(admin_router.router, prefix="/v1")
app.include_router(scans_router.router, prefix="/v1")
app.include_router(findings_router.router, prefix="/v1")
app.include_router(projects_router.router, prefix="/v1")
app.include_router(assets_router.router, prefix="/v1")
app.include_router(usage_router.router, prefix="/v1")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/ready")
async def ready():
    from app.core.database import engine
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception as e:
        logger.error("Readiness check failed: %s", e)
        return JSONResponse(status_code=503, content={"status": "not ready", "detail": str(e)})


@app.get("/live")
async def live():
    return {"status": "alive"}


@app.get("/version")
async def version():
    return {"version": "1.0.0", "env": settings.ENV}
