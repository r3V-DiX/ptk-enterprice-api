"""
Tests for DynamicCORSMiddleware in app/middleware/cors.py.

What we're verifying:
  1. Preflight (OPTIONS) — any origin gets echoed back (client API paths)
  2. Preflight — admin portal origin gets echoed + credentials header
  3. Preflight — no Origin header passes through (non-browser tools)
  4. Actual requests — ACAO header is echoed on the response
  5. Admin actual requests — ACAO + credentials headers on response
  6. No Origin on actual request — no CORS headers added (no crash)
  7. Admin origin cannot leak credentials header to non-admin origin
  8. Trailing slash on Origin is normalised correctly
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from unittest.mock import patch

# Patch settings before the middleware module is imported so the admin origins
# list is fixed for the duration of the tests.
ADMIN_ORIGIN = "http://localhost:3001"
CLIENT_ORIGIN = "https://app.client.com"
OTHER_ORIGIN = "https://evil.attacker.com"


@pytest.fixture(scope="module")
def test_app():
    """Minimal FastAPI app with DynamicCORSMiddleware attached."""
    with patch(
        "app.middleware.cors.settings",
        ADMIN_PORTAL_ORIGINS=[ADMIN_ORIGIN],
        CORS_ORIGINS=[],
    ):
        from app.middleware.cors import DynamicCORSMiddleware

        app = FastAPI()
        app.add_middleware(DynamicCORSMiddleware)

        @app.get("/v1/scans")
        def scans():
            return {"scans": []}

        yield app


@pytest.fixture(scope="module")
def client(test_app):
    return TestClient(test_app, raise_server_exceptions=True)


# ─── Preflight — client origins ──────────────────────────────────────────────

class TestPreflightClientOrigins:
    def test_client_origin_preflight_allowed(self, client):
        """Any client origin gets a 204 with ACAO echoed back."""
        r = client.options(
            "/v1/scans",
            headers={
                "Origin": CLIENT_ORIGIN,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization",
            },
        )
        assert r.status_code == 204
        assert r.headers["access-control-allow-origin"] == CLIENT_ORIGIN

    def test_client_origin_no_credentials_header(self, client):
        """Client origin preflights must NOT receive Allow-Credentials: true."""
        r = client.options(
            "/v1/scans",
            headers={
                "Origin": CLIENT_ORIGIN,
                "Access-Control-Request-Method": "GET",
            },
        )
        assert "access-control-allow-credentials" not in r.headers

    def test_unknown_origin_preflight_echoed(self, client):
        """Any unknown origin is echoed — Layer 2 (auth.py) handles blocking."""
        r = client.options(
            "/v1/scans",
            headers={
                "Origin": OTHER_ORIGIN,
                "Access-Control-Request-Method": "DELETE",
            },
        )
        assert r.status_code == 204
        assert r.headers["access-control-allow-origin"] == OTHER_ORIGIN

    def test_preflight_methods_header_present(self, client):
        """Response includes Access-Control-Allow-Methods."""
        r = client.options(
            "/v1/scans",
            headers={"Origin": CLIENT_ORIGIN, "Access-Control-Request-Method": "POST"},
        )
        assert "access-control-allow-methods" in r.headers

    def test_preflight_headers_header_present(self, client):
        """Response includes Access-Control-Allow-Headers with Authorization."""
        r = client.options(
            "/v1/scans",
            headers={"Origin": CLIENT_ORIGIN, "Access-Control-Request-Method": "GET"},
        )
        assert "Authorization" in r.headers.get("access-control-allow-headers", "")

    def test_preflight_max_age_present(self, client):
        """Access-Control-Max-Age is set to cache the preflight result."""
        r = client.options(
            "/v1/scans",
            headers={"Origin": CLIENT_ORIGIN, "Access-Control-Request-Method": "GET"},
        )
        assert r.headers.get("access-control-max-age") == "600"


# ─── Preflight — admin portal origin ─────────────────────────────────────────

class TestPreflightAdminOrigin:
    def test_admin_origin_preflight_allowed(self, client):
        """Admin portal origin gets 204 with ACAO echoed."""
        r = client.options(
            "/v1/scans",
            headers={
                "Origin": ADMIN_ORIGIN,
                "Access-Control-Request-Method": "GET",
            },
        )
        assert r.status_code == 204
        assert r.headers["access-control-allow-origin"] == ADMIN_ORIGIN

    def test_admin_origin_preflight_has_credentials(self, client):
        """Admin portal origin preflight MUST include Allow-Credentials: true."""
        r = client.options(
            "/v1/scans",
            headers={
                "Origin": ADMIN_ORIGIN,
                "Access-Control-Request-Method": "GET",
            },
        )
        assert r.headers.get("access-control-allow-credentials") == "true"


# ─── Preflight — no Origin header ────────────────────────────────────────────

class TestPreflightNoOrigin:
    def test_options_without_origin_passes_through(self, client):
        """OPTIONS with no Origin is not a browser preflight — must not return 400."""
        r = client.options("/v1/scans")
        # Should reach the endpoint (405 Method Not Allowed since endpoint is GET-only)
        # or 200 — either way, NOT 400 from the middleware
        assert r.status_code != 400

    def test_options_without_origin_no_cors_headers(self, client):
        """Non-browser OPTIONS should not have CORS headers injected."""
        r = client.options("/v1/scans")
        assert "access-control-allow-origin" not in r.headers


# ─── Actual requests — response headers ──────────────────────────────────────

class TestActualRequestHeaders:
    def test_client_origin_acao_echoed_on_response(self, client):
        """Real GET from a client origin: ACAO header is echoed on the response."""
        r = client.get("/v1/scans", headers={"Origin": CLIENT_ORIGIN})
        assert r.headers.get("access-control-allow-origin") == CLIENT_ORIGIN

    def test_client_origin_no_credentials_on_response(self, client):
        """Real GET from client origin must NOT have Allow-Credentials: true."""
        r = client.get("/v1/scans", headers={"Origin": CLIENT_ORIGIN})
        assert "access-control-allow-credentials" not in r.headers

    def test_admin_origin_acao_and_credentials_on_response(self, client):
        """Real GET from admin origin gets both ACAO and Allow-Credentials: true."""
        r = client.get("/v1/scans", headers={"Origin": ADMIN_ORIGIN})
        assert r.headers.get("access-control-allow-origin") == ADMIN_ORIGIN
        assert r.headers.get("access-control-allow-credentials") == "true"

    def test_no_origin_no_cors_headers_on_response(self, client):
        """Request with no Origin (server-to-server / curl) gets no CORS headers."""
        r = client.get("/v1/scans")
        assert "access-control-allow-origin" not in r.headers
        assert "access-control-allow-credentials" not in r.headers

    def test_vary_origin_set_on_response(self, client):
        """Vary: Origin must be set so proxies don't cache the wrong ACAO."""
        r = client.get("/v1/scans", headers={"Origin": CLIENT_ORIGIN})
        assert "Origin" in r.headers.get("vary", "")


# ─── Isolation: admin credentials header must not leak ───────────────────────

class TestIsolation:
    def test_client_origin_never_gets_credentials_header(self, client):
        """Even if a client sends the admin portal origin path — wrong key — no leak."""
        # Client is calling from their own origin, not the admin origin
        r = client.get("/v1/scans", headers={"Origin": CLIENT_ORIGIN})
        assert r.headers.get("access-control-allow-credentials") is None

    def test_trailing_slash_on_admin_origin_normalised(self, client):
        """Origin: http://localhost:3001/ (trailing slash) is treated as admin origin."""
        r = client.get("/v1/scans", headers={"Origin": ADMIN_ORIGIN + "/"})
        # Middleware strips trailing slash — should match admin_origins
        assert r.headers.get("access-control-allow-origin") == ADMIN_ORIGIN
        assert r.headers.get("access-control-allow-credentials") == "true"

    def test_subdomain_of_admin_origin_is_not_admin(self, client):
        """sub.localhost:3001 does NOT get credentials — exact match only."""
        r = client.get("/v1/scans", headers={"Origin": "http://sub.localhost:3001"})
        assert r.headers.get("access-control-allow-credentials") is None