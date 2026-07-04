import asyncio

from loguru import logger

from .crud import delete_old_signing_logs

LOG_CLEANUP_INTERVAL = 3600  # 1 hour
LOG_RETENTION_DAYS = 30


async def cleanup_old_signing_logs():
    while True:
        try:
            await asyncio.sleep(LOG_CLEANUP_INTERVAL)
            await delete_old_signing_logs(LOG_RETENTION_DAYS)
            logger.debug("nsecbunker: signing log cleanup complete")
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.warning(f"nsecbunker: log cleanup error: {exc}")
