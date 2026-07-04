import asyncio

from fastapi import APIRouter

from lnbits.tasks import create_permanent_unique_task

from .crud import db
from .tasks import cleanup_old_signing_logs
from .views import nsec_oracle_generic_router
from .views_api import nsec_oracle_api_router

nsec_oracle_static_files = [
    {
        "path": "/nsec_oracle/static",
        "name": "nsec_oracle_static",
    }
]
nsec_oracle_ext: APIRouter = APIRouter(prefix="/nsec_oracle", tags=["nsec_oracle"])
nsec_oracle_ext.include_router(nsec_oracle_generic_router)
nsec_oracle_ext.include_router(nsec_oracle_api_router)

scheduled_tasks: list[asyncio.Task] = []


def nsec_oracle_stop():
    for task in scheduled_tasks:
        try:
            task.cancel()
        except Exception:  # noqa: S110 — best-effort cancel on shutdown
            pass


def nsec_oracle_start():
    scheduled_tasks.append(
        create_permanent_unique_task(
            "ext_nsec_oracle_log_cleanup", cleanup_old_signing_logs
        )
    )


__all__ = [
    "db",
    "nsec_oracle_ext",
    "nsec_oracle_start",
    "nsec_oracle_static_files",
    "nsec_oracle_stop",
]
