import json
import logging
import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger(__name__)

# Endpoints that generate very high volume and add no value in the log
_SKIP_ENDPOINTS = {"/health", "/live", "/ready"}


class ApiLoggerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        start = time.time()
        response: Response = await call_next(request)
        latency_ms = int((time.time() - start) * 1000)

        path = request.url.path
        if path in _SKIP_ENDPOINTS:
            return response

        # Best-effort DB write — never block the response
        try:
            from app.core.database import SessionLocal
            from app.models.api_log import ApiLog

            request_id = getattr(request.state, "request_id", None)
            client_id = getattr(request.state, "client_id", None)
            api_key_id = getattr(request.state, "api_key_id", None)
            ip = request.client.host if request.client else None
            user_agent = request.headers.get("user-agent", None)
            qs = str(request.url.query) or None

            # Pull error code out of the response body without consuming the stream.
            # The response body is already a starlette BackgroundTasks / BytesIO — safe to peek.
            error_code: str | None = None
            try:
                if response.status_code >= 400:
                    body_bytes = b""
                    async for chunk in response.body_iterator:
                        body_bytes += chunk
                    # Rebuild the response so the client still receives the body
                    from starlette.responses import Response as RawResponse
                    response = RawResponse(
                        content=body_bytes,
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        media_type=response.media_type,
                    )
                    parsed = json.loads(body_bytes)
                    error_code = parsed.get("error", {}).get("code")
            except Exception:
                pass  # non-JSON or streaming body — skip error_code extraction

            with SessionLocal() as db:
                log = ApiLog(
                    client_id=client_id,
                    api_key_id=api_key_id,
                    request_id=request_id or "00000000",
                    endpoint=path,
                    method=request.method,
                    status_code=response.status_code,
                    latency_ms=latency_ms,
                    ip_address=ip,
                    user_agent=user_agent,
                    query_string=qs,
                    error_code=error_code,
                )
                db.add(log)
                db.commit()

            logger.debug(
                "[%s] %s %s %d %dms",
                request_id or "-",
                request.method,
                path,
                response.status_code,
                latency_ms,
            )

        except Exception as exc:
            logger.warning("api_logger failed: %s", exc)

        return response
