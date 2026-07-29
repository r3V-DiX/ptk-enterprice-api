from app.tasks.celery_config import celery_app  # noqa: F401
import app.tasks.scan_tasks  # noqa: F401 — registers run_scan task
import app.tasks.reaper_tasks  # noqa: F401 — registers reap_stale_scans task

# Start worker:  celery -A celery_worker.celery_app worker -Q enterprise_scans -l info
# Start beat:    celery -A celery_worker.celery_app beat -l info
