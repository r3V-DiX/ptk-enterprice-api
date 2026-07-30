from fastapi import APIRouter
from fastapi.responses import HTMLResponse
import os

router = APIRouter(tags=["admin-portal"])
_TPL = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "templates", "admin.html")


@router.get("/admin", response_class=HTMLResponse, include_in_schema=False)
async def admin_portal():
    with open(_TPL, encoding="utf-8") as f:
        return HTMLResponse(f.read())
