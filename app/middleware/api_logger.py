import logging
import time
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class ApiLoggerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        start = time.time()
        response = await call_next(request)
        latency_ms = int((time.time() - start) * 1000)

        # Best-effort DB write — never block the response
        try:
            from app.core.database import SessionLocal
            from app.models.api_log import ApiLog

            request_id = getattr(request.state, "request_id", None)
            client_id = getattr(request.state, "client_id", None)
            api_key_id = getattr(request.state, "api_key_id", None)
            ip = request.client.host if request.client else None

            with SessionLocal() as db:
                log = ApiLog(
                    client_id=client_id,
                    api_key_id=api_key_id,
                    request_id=request_id or "00000000",
                    endpoint=str(request.url.path),
                    method=request.method,
                    status_code=response.status_code,
                    latency_ms=latency_ms,
                    ip_address=ip,
                )
                db.add(log)
                db.commit()
        except Exception as exc:
            logger.warning("api_logger failed: %s", exc)

        return response
