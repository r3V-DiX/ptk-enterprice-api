import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Attach X-Request-ID to every response. First 8 chars of a uuid4 hex."""

    async def dispatch(self, request: Request, call_next):
        request_id = uuid.uuid4().hex[:8]
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
