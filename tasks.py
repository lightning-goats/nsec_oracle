import asyncio
import json
import time

import websockets
from loguru import logger

from .crud import (
    delete_old_signing_logs,
    get_active_connections,
    get_decrypted_private_key,
    get_key,
)
from .nip46 import (
    NIP46_KIND,
    _event_p_tag,
    build_connect_ack,
    connection_dial_url,
    ensure_relay_allows,
    process_incoming_event,
)

LOG_CLEANUP_INTERVAL = 3600  # 1 hour
LOG_RETENTION_DAYS = 30
SUPERVISOR_INTERVAL = 15  # re-evaluate the relay/key set this often


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


def nostrrelay_installed() -> bool:
    try:
        import lnbits.extensions.nostrrelay  # noqa: F401

        return True
    except ImportError:
        return False


async def _conns_for_url(dial_url: str) -> list:
    return [
        c for c in await get_active_connections() if connection_dial_url(c) == dial_url
    ]


async def _signer_pubkeys_for_url(dial_url: str) -> list[str]:
    """Distinct signer pubkeys of active connections dialed on this relay URL."""
    pubkeys: set[str] = set()
    for conn in await _conns_for_url(dial_url):
        key = await get_key(conn.key_id)
        if key:
            pubkeys.add(key.pubkey_hex)
    return sorted(pubkeys)


async def _send_pending_acks(ws, dial_url: str) -> None:
    """nostrconnect://: proactively acknowledge any connection still awaiting it."""
    for conn in await _conns_for_url(dial_url):
        if not conn.pending_connect or not conn.client_pubkey:
            continue
        key = await get_key(conn.key_id)
        if not key:
            continue
        signer_priv = await get_decrypted_private_key(key.id)
        ack = await build_connect_ack(
            signer_priv, key.pubkey_hex, conn.client_pubkey, conn.secret
        )
        await ws.send(json.dumps(["EVENT", ack]))
        logger.info(
            f"nsecbunker: sent nostrconnect ack to {conn.client_pubkey[:12]}..."
        )


async def _handle_event(ws, dial_url: str, event: dict) -> None:
    signer_pubkey = _event_p_tag(event)
    if not signer_pubkey:
        return
    signer_key = None
    relevant = []
    for conn in await _conns_for_url(dial_url):
        key = await get_key(conn.key_id)
        if key and key.pubkey_hex == signer_pubkey:
            signer_key = key
            relevant.append(conn)
    if not signer_key:
        return
    response = await process_incoming_event(event, signer_key, relevant)
    if response:
        await ws.send(json.dumps(["EVENT", response]))


async def _ensure_local_accounts(dial_url: str) -> None:
    """Pre-authorize signer keys on local relays so responses can be published."""
    for conn in await _conns_for_url(dial_url):
        if not conn.is_local:
            continue
        key = await get_key(conn.key_id)
        if key:
            await ensure_relay_allows(conn.relay_id, key.pubkey_hex)


async def _subscribe(ws, dial_url: str, signer_pubkeys: list[str]) -> None:
    await ws.send(
        json.dumps(
            [
                "REQ",
                "nsecbunker-nip46",
                {
                    "kinds": [NIP46_KIND],
                    "#p": signer_pubkeys,
                    "since": int(time.time()),
                },
            ]
        )
    )
    logger.info(
        f"nsecbunker: nip46 listening on {dial_url} "
        f"for {len(signer_pubkeys)} key(s)"
    )


async def _consume_messages(ws, dial_url: str) -> None:
    async for raw in ws:
        try:
            msg = json.loads(raw)
        except (ValueError, TypeError):
            continue
        if not isinstance(msg, list) or not msg:
            continue
        if msg[0] == "EVENT" and len(msg) >= 3:
            await _handle_event(ws, dial_url, msg[2])
        elif msg[0] == "AUTH":
            logger.warning(
                f"nsecbunker: relay {dial_url} requires NIP-42 auth; "
                "NIP-46 is not supported on auth-gated relays yet"
            )
        elif msg[0] == "CLOSED":
            logger.warning(
                f"nsecbunker: relay {dial_url} closed subscription: {msg}"
            )
            return


async def _relay_loop(dial_url: str) -> None:
    """Maintain one websocket to a relay (local or remote) and service NIP-46
    requests for every connection dialed there."""
    backoff = 1
    while True:
        try:
            async with websockets.connect(
                dial_url, open_timeout=10, ping_interval=20, ping_timeout=20
            ) as ws:
                backoff = 1
                signer_pubkeys = await _signer_pubkeys_for_url(dial_url)
                if not signer_pubkeys:
                    await asyncio.sleep(SUPERVISOR_INTERVAL)
                    continue
                await _ensure_local_accounts(dial_url)
                await _subscribe(ws, dial_url, signer_pubkeys)
                await _send_pending_acks(ws, dial_url)
                await _consume_messages(ws, dial_url)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(
                f"nsecbunker: relay {dial_url} connection error: {exc}; "
                f"retrying in {min(backoff, 30)}s"
            )
            await asyncio.sleep(min(backoff, 30))
            backoff *= 2


async def _current_topology() -> list[tuple[str, str]]:
    """(dial_url, signer_pubkey) pairs for every active connection."""
    topology = []
    for conn in await get_active_connections():
        key = await get_key(conn.key_id)
        url = connection_dial_url(conn)
        if key and url:
            topology.append((url, key.pubkey_hex))
    return topology


def _reconcile_handlers(
    handlers: dict[str, asyncio.Task], dial_urls: set[str]
) -> None:
    for url in list(handlers):
        if url not in dial_urls:
            handlers.pop(url).cancel()
    for url in dial_urls:
        task = handlers.get(url)
        if task is None or task.done():
            handlers[url] = asyncio.create_task(_relay_loop(url))


async def nip46_listener() -> None:
    """Supervisor: keep one ``_relay_loop`` per local relay that has active
    connections, restarting the set only when the (relay, signer-key) topology
    changes so runtime client bindings don't churn the subscriptions."""
    handlers: dict[str, asyncio.Task] = {}
    current_sig: tuple | None = None
    try:
        while True:
            if nostrrelay_installed():
                try:
                    topology = await _current_topology()
                    sig = tuple(sorted(set(topology)))
                    if sig != current_sig:
                        current_sig = sig
                        _reconcile_handlers(
                            handlers, {url for url, _ in topology}
                        )
                except Exception as exc:
                    logger.warning(f"nsecbunker: nip46 supervisor error: {exc}")
            await asyncio.sleep(SUPERVISOR_INTERVAL)
    except asyncio.CancelledError:
        for task in handlers.values():
            task.cancel()
        raise
