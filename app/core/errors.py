from fastapi import Request
from fastapi.responses import JSONResponse

ERROR_MESSAGES = {
    "INVALID_API_KEY": (401, "The supplied API key is invalid or has been revoked."),
    "EXPIRED_API_KEY": (401, "The supplied API key has expired."),
    "INSUFFICIENT_SCOPE": (403, "The API key does not have permission to perform this action."),
    "RATE_LIMIT_EXCEEDED": (429, "Rate limit exceeded. Please slow down your request rate."),
    "SCAN_NOT_FOUND": (404, "The requested scan was not found."),
    "TARGET_INVALID": (422, "The supplied target is invalid or unsupported."),
    "IDEMPOTENCY_CONFLICT": (409, "A scan with this idempotency key already exists."),
    "SCAN_IN_PROGRESS": (409, "A scan for this target is already in progress."),
    "INTERNAL_ERROR": (500, "An internal server error occurred."),
    "CLIENT_NOT_FOUND": (404, "The requested client was not found."),
    "PROJECT_NOT_FOUND": (404, "The requested project was not found."),
    "ASSET_NOT_FOUND": (404, "The requested asset was not found."),
    "KEY_NOT_FOUND": (404, "The requested API key was not found."),
    "REPORT_NOT_READY": (409, "The scan must be completed before a report can be generated."),
    "SCAN_QUOTA_EXCEEDED": (429, "Monthly scan quota for this API key has been reached."),
    "ADMIN_AUTH_REQUIRED": (401, "Admin authentication required."),
    "INVALID_CODE": (401, "Invalid or expired OTP code."),
    "EMAIL_NOT_ALLOWED": (403, "This email is not authorised for admin access."),
    "TOO_MANY_REQUESTS": (429, "Too many requests. Please wait and try again."),
}


def error_response(code: str, request_id: str, message: str | None = None) -> JSONResponse:
    status_code, default_message = ERROR_MESSAGES.get(code, (500, "An error occurred."))
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message or default_message,
                "request_id": request_id,
            }
        },
    )


def get_request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "00000000")
