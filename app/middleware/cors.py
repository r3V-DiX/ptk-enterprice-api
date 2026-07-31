"""
Dynamic CORS middleware.

Two tiers:

1. Admin portal origins (ADMIN_PORTAL_ORIGINS):
   Strict allowlist, credentials=true — required because the admin portal
   authenticates with session cookies.

2. All other origins (client API, Postman, curl, server-to-server):
   Echo back the requesting Origin dynamically. No credentials header.
   Actual per-origin security is enforced by the per-key cors_origins check
   in app/core/auth.py — that is the real gate. The middleware just needs to
   let the preflight through so the browser will send the request.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from app.core.config import settings

CORS_METHODS = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
CORS_HEADERS = "Authorization, Content-Type, X-Request-ID, X-Request-Id"


class DynamicCORSMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        # Normalise: strip trailing slash once, lowercase scheme+host
        self._admin_origins: set[str] = {
            o.rstrip("/") for o in settings.ADMIN_PORTAL_ORIGINS
        }

    async def dispatch(self, request: Request, call_next) -> Response:
        origin = (
            request.headers.get("Origin") or
            request.headers.get("origin", "")
        ).rstrip("/")

        # ── Preflight fast-path ────────────────────────────────────────────────
        if request.method == "OPTIONS":
            # No Origin → not a browser preflight, pass through normally
            if not origin:
                return await call_next(request)

            if origin in self._admin_origins:
                return Response(
                    status_code=204,
                    headers={
                        "Access-Control-Allow-Origin": origin,
                        "Access-Control-Allow-Credentials": "true",
                        "Access-Control-Allow-Methods": CORS_METHODS,
                        "Access-Control-Allow-Headers": CORS_HEADERS,
                        "Access-Control-Max-Age": "600",
                        "Vary": "Origin",
                    },
                )

            # Dynamic: echo origin for client API preflights
            return Response(
                status_code=204,
                headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Methods": CORS_METHODS,
                    "Access-Control-Allow-Headers": CORS_HEADERS,
                    "Access-Control-Max-Age": "600",
                    "Vary": "Origin",
                },
            )

        # ── Actual request ─────────────────────────────────────────────────────
        response = await call_next(request)

        if not origin:
            return response

        if origin in self._admin_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Vary"] = "Origin"
        else:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"

        return response