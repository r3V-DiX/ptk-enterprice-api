"""
Tests for per-key CORS origin enforcement in app/core/auth.py.

Strategy: mock verify_api_key + check_rate_limit so we only test
the CORS branch in get_api_key(), not DB or rate-limit logic.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.responses import JSONResponse

from app.core.auth import get_api_key, AuthError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_api_key(cors_origins=None, rate_limit_rpm=60):
    """Return a mock ApiKey with the given cors_origins."""
    key = MagicMock()
    key.id = "key-001"
    key.client_id = "client-001"
    key.key_prefix = "ptk_test"
    key.rate_limit_rpm = rate_limit_rpm
    key.cors_origins = cors_origins
    return key


def _make_request(origin: str | None = None, auth: str = "Bearer ptk_test_abc123"):
    """Return a mock FastAPI Request with the given Origin header."""
    headers = {"Authorization": auth}
    if origin is not None:
        headers["origin"] = origin
    req = MagicMock()
    req.headers = headers
    req.client = MagicMock(host="127.0.0.1")
    state = MagicMock()
    state.request_id = "test-req-id"
    req.state = state
    return req


async def _run(request, api_key):
    """Call get_api_key with mocked dependencies."""
    db = MagicMock()
    with patch("app.core.auth.check_rate_limit", return_value=True), \
         patch("app.services.key_service.verify_api_key", return_value=api_key), \
         patch("asyncio.to_thread", new=AsyncMock(return_value=api_key)):
        return await get_api_key(request=request, db=db)


# ---------------------------------------------------------------------------
# No cors_origins set — unrestricted key
# ---------------------------------------------------------------------------

class TestNoCorsRestriction:
    def test_no_origin_header_passes(self):
        """Key with no cors_origins: request without Origin header is allowed."""
        key = _make_api_key(cors_origins=None)
        req = _make_request(origin=None)
        result = asyncio.get_event_loop().run_until_complete(_run(req, key))
        assert result is key

    def test_any_origin_passes(self):
        """Key with no cors_origins: any Origin header is allowed."""
        key = _make_api_key(cors_origins=None)
        req = _make_request(origin="https://random.example.com")
        result = asyncio.get_event_loop().run_until_complete(_run(req, key))
        assert result is key

    def test_empty_list_treated_as_no_restriction(self):
        """cors_origins=[] (cleared) behaves like None — no restriction."""
        key = _make_api_key(cors_origins=[])
        req = _make_request(origin=None)
        # Empty list is falsy — same code path as None
        result = asyncio.get_event_loop().run_until_complete(_run(req, key))
        assert result is key


# ---------------------------------------------------------------------------
# cors_origins set — restricted key
# ---------------------------------------------------------------------------

class TestCorsRestricted:
    def test_correct_origin_passes(self):
        """Request from allowed origin passes CORS check."""
        key = _make_api_key(cors_origins=["https://app.example.com"])
        req = _make_request(origin="https://app.example.com")
        result = asyncio.get_event_loop().run_until_complete(_run(req, key))
        assert result is key

    def test_correct_origin_trailing_slash_normalized(self):
        """Trailing slash on Origin header is stripped before comparison."""
        key = _make_api_key(cors_origins=["https://app.example.com"])
        req = _make_request(origin="https://app.example.com/")
        result = asyncio.get_event_loop().run_until_complete(_run(req, key))
        assert result is key

    def test_wrong_origin_blocked(self):
        """Request from a different origin is rejected with 403."""
        key = _make_api_key(cors_origins=["https://app.example.com"])
        req = _make_request(origin="https://evil.attacker.com")
        with pytest.raises(AuthError) as exc_info:
            asyncio.get_event_loop().run_until_complete(_run(req, key))
        resp: JSONResponse = exc_info.value.response
        assert resp.status_code == 403
        import json
        body = json.loads(resp.body)
        assert body["error"]["code"] == "CORS_ORIGIN_NOT_ALLOWED"

    def test_no_origin_header_blocked_when_restricted(self):
        """Server-to-server request (no Origin) is blocked when cors_origins is set."""
        key = _make_api_key(cors_origins=["https://app.example.com"])
        req = _make_request(origin=None)
        with pytest.raises(AuthError) as exc_info:
            asyncio.get_event_loop().run_until_complete(_run(req, key))
        resp: JSONResponse = exc_info.value.response
        assert resp.status_code == 403
        import json
        body = json.loads(resp.body)
        assert body["error"]["code"] == "CORS_ORIGIN_NOT_ALLOWED"

    def test_second_allowed_origin_passes(self):
        """When multiple origins are allowed, any one of them passes."""
        key = _make_api_key(cors_origins=[
            "https://app.example.com",
            "https://staging.example.com",
        ])
        req = _make_request(origin="https://staging.example.com")
        result = asyncio.get_event_loop().run_until_complete(_run(req, key))
        assert result is key

    def test_subdomain_not_included(self):
        """A subdomain is not matched by the parent domain — exact match only."""
        key = _make_api_key(cors_origins=["https://example.com"])
        req = _make_request(origin="https://sub.example.com")
        with pytest.raises(AuthError) as exc_info:
            asyncio.get_event_loop().run_until_complete(_run(req, key))
        resp: JSONResponse = exc_info.value.response
        assert resp.status_code == 403

    def test_http_vs_https_not_interchangeable(self):
        """http:// and https:// are treated as different origins."""
        key = _make_api_key(cors_origins=["https://app.example.com"])
        req = _make_request(origin="http://app.example.com")
        with pytest.raises(AuthError) as exc_info:
            asyncio.get_event_loop().run_until_complete(_run(req, key))
        resp: JSONResponse = exc_info.value.response
        assert resp.status_code == 403

    def test_port_matters(self):
        """Origins with and without port number are distinct."""
        key = _make_api_key(cors_origins=["https://app.example.com"])
        req = _make_request(origin="https://app.example.com:8080")
        with pytest.raises(AuthError) as exc_info:
            asyncio.get_event_loop().run_until_complete(_run(req, key))
        resp: JSONResponse = exc_info.value.response
        assert resp.status_code == 403
