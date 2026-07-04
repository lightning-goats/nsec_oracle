import asyncio

from fastapi import APIRouter

from lnbits.tasks import create_permanent_unique_task

from .crud import db
from .tasks import cleanup_old_signing_logs
from .views import nsecbunker_generic_router
from .views_api import nsecbunker_api_router

nsecbunker_static_files = [
    {
        "path": "/nsecbunker/static",
        "name": "nsecbunker_static",
    }
]
nsecbunker_ext: APIRouter = APIRouter(prefix="/nsecbunker", tags=["nsecbunker"])
nsecbunker_ext.include_router(nsecbunker_generic_router)
nsecbunker_ext.include_router(nsecbunker_api_router)

scheduled_tasks: list[asyncio.Task] = []


def nsecbunker_stop():
    for task in scheduled_tasks:
        try:
            task.cancel()
        except Exception:  # noqa: S110 — best-effort cancel on shutdown
            pass


def nsecbunker_start():
    scheduled_tasks.append(
        create_permanent_unique_task(
            "ext_nsecbunker_log_cleanup", cleanup_old_signing_logs
        )
    )


__all__ = [
    "db",
    "nsecbunker_ext",
    "nsecbunker_start",
    "nsecbunker_static_files",
    "nsecbunker_stop",
]
