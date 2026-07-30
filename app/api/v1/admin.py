"""
Admin API — thin shim.

main.py imports: from app.api.v1 import admin as admin_router
                 app.include_router(admin_router.router, prefix="/v1")

This module re-exports a single combined `router` so that import stays unchanged.
All logic lives in admin_clients.py, admin_keys.py, and admin_shared.py.
"""
from fastapi import APIRouter

from app.api.v1.admin_clients import router as _clients_router
from app.api.v1.admin_keys import router as _keys_router

# Combined router — re-exported as `router` so main.py needs zero changes
router = APIRouter()
router.include_router(_clients_router)
router.include_router(_keys_router)

# Re-export helpers used by tests or other modules that may import from here
from app.api.v1.admin_shared import (  # noqa: E402, F401
    _admin_auth,
    _is_bootstrap,
    _has_admin_session,
    _client_response,
)