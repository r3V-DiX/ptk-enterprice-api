from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "enterprise",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)
celery_app.conf.task_routes = {
    "app.tasks.scan_tasks.*": {"queue": "enterprise_scans"}
}
celery_app.conf.task_serializer = "json"
celery_app.conf.result_serializer = "json"
celery_app.conf.accept_content = ["json"]
celery_app.conf.beat_schedule = {
    "reap-stale-scans": {
        "task": "reap_stale_scans",
        "schedule": 300.0,  # every 5 minutes
    },
}
celery_app.conf.timezone = "UTC"
