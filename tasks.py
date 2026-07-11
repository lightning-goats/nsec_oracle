import asyncio

from loguru import logger

from .crud import delete_old_signing_logs
from .models import LOG_RETENTION_DAYS

LOG_CLEANUP_INTERVAL = 3600  # 1 hour


async def cleanup_old_signing_logs():
    while True:
        try:
            await asyncio.sleep(LOG_CLEANUP_INTERVAL)
            await delete_old_signing_logs(LOG_RETENTION_DAYS)
            logger.debug("nsec_oracle: signing log cleanup complete")
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.warning(f"nsec_oracle: log cleanup error: {exc}")
