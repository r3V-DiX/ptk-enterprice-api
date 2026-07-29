import logging
import warnings
from celery import Celery
from celery.signals import setup_logging
from app.core.config import settings

# Suppress noisy urllib3 SSL warnings from scan plugins
warnings.filterwarnings("ignore", message="Unverified HTTPS request")


@setup_logging.connect
def configure_celery_logging(**kwargs):
    """Single consistent log format for all celery processes."""
    logging.config.dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": "[%(asctime)s] %(levelname)-8s %(name)s  %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "stream": "ext://sys.stdout",
            }
        },
        "root": {"level": "INFO", "handlers": ["console"]},
        "loggers": {
            # Quiet down noisy third-party libs
            "urllib3": {"level": "ERROR"},
            "httpx":   {"level": "WARNING"},
            "httpcore": {"level": "WARNING"},
            "amqp":    {"level": "WARNING"},
            "kombu":   {"level": "WARNING"},
            # Keep our app logs at INFO
            "app":     {"level": "INFO", "propagate": True},
            "celery":  {"level": "INFO", "propagate": True},
        },
    })


import logging.config  # noqa: E402 — must be after the signal handler is defined

celery_app = Celery(
    "enterprise",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.tasks.scan_tasks", "app.tasks.reaper_tasks"],
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
        "schedule": 300.0,
    },
}
celery_app.conf.timezone = "UTC"
# Show task received/succeeded/failed/retried in worker output
celery_app.conf.worker_send_task_events = True
celery_app.conf.task_track_started = True
