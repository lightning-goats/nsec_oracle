"""NIP-46 (Nostr Connect / remote signing) engine.

Turns kind:24133 request events received from a local nostrrelay into signed
response events, reusing the bunker's existing key store, per-kind permission
model and rate limiting. Transport (websockets) lives in ``tasks.py``; this
module is pure request/response logic so it can be unit tested without a relay.
"""

import json
import secrets as _secrets
from urllib.parse import parse_qs, quote, urlparse

from loguru import logger
from pynostr.event import Event

from lnbits.settings import settings

from .crud import (
    bind_connection_client,
    clear_pending_connect,
    get_decrypted_private_key,
    touch_connection,
)
from .models import BunkerConnection, BunkerKey
from .services import (
    _HAS_NOSTR_SDK,
    nip04_decrypt,
    nip04_encrypt,
    nip44_decrypt,
    nip44_encrypt,
    sign_event,
)

NIP46_KIND = 24133


# --- relay URLs -------------------------------------------------------------


def _base_ws(url: str) -> str:
    return url.rstrip("/").replace("https://", "wss://").replace("http://", "ws://")


def local_relay_ws_internal(relay_id: str) -> str:
    """Loopback URL the bunker itself connects to (reliable, never external)."""
    return f"ws://127.0.0.1:{settings.port}/nostrrelay/{relay_id}"


def local_relay_ws_external(relay_id: str) -> str:
    """Publicly reachable URL embedded in the ``bunker://`` URI for clients."""
    return f"{_base_ws(settings.lnbits_baseurl)}/nostrrelay/{relay_id}"


def connection_dial_url(conn: BunkerConnection) -> str:
    """URL the bunker's own listener dials (loopback for local relays)."""
    if conn.is_local:
        return local_relay_ws_internal(conn.relay_id)
    return conn.relay_url or ""


def connection_client_url(conn: BunkerConnection) -> str:
    """Relay URL advertised to the remote client."""
    if conn.is_local:
        return local_relay_ws_external(conn.relay_id)
    return conn.relay_url or ""


def bunker_uri(signer_pubkey_hex: str, client_relay_url: str, secret: str) -> str:
    relay = quote(client_relay_url, safe="")
    return f"bunker://{signer_pubkey_hex}?relay={relay}&secret={quote(secret, safe='')}"


def parse_nostrconnect(uri: str) -> dict:
    """Parse a ``nostrconnect://<client-pubkey>?relay=..&secret=..&perms=..&name=..``
    URI. Returns dict with client_pubkey, relay_url, secret, perms, name.
    Raises ValueError if malformed."""
    uri = uri.strip()
    if not uri.startswith("nostrconnect://"):
        raise ValueError("Not a nostrconnect:// URI")
    parsed = urlparse(uri)
    client_pubkey = parsed.netloc or parsed.path.strip("/")
    if len(client_pubkey) != 64:
        raise ValueError("nostrconnect URI missing a valid client pubkey")
    qs = parse_qs(parsed.query)
    relays = qs.get("relay", [])
    if not relays:
        raise ValueError("nostrconnect URI missing a relay")
    secret_list = qs.get("secret", [])
    if not secret_list or not secret_list[0]:
        raise ValueError("nostrconnect URI missing a secret")
    return {
        "client_pubkey": client_pubkey,
        "relay_url": relays[0],  # first relay; multi-relay is a future extension
        "secret": secret_list[0],
        "perms": (qs.get("perms", [""])[0]),
        "name": (qs.get("name", [""])[0]),
    }


# --- NIP-44 content crypto (kind 24133 payloads) ----------------------------


def _nip44_encrypt_raw(sender_privkey_hex: str, peer_pubkey_hex: str, text: str) -> str:
    from nostr_sdk import (
        Nip44Version,
    )
    from nostr_sdk import (
        PublicKey as NsPK,
    )
    from nostr_sdk import (
        SecretKey as NsSK,
    )
    from nostr_sdk import (
        nip44_encrypt as _enc,
    )

    return _enc(
        NsSK.parse(sender_privkey_hex), NsPK.parse(peer_pubkey_hex), text,
        Nip44Version.V2,
    )


def _nip44_decrypt_raw(
    receiver_privkey_hex: str, peer_pubkey_hex: str, payload: str
) -> str:
    from nostr_sdk import (
        PublicKey as NsPK,
    )
    from nostr_sdk import (
        SecretKey as NsSK,
    )
    from nostr_sdk import (
        nip44_decrypt as _dec,
    )

    return _dec(NsSK.parse(receiver_privkey_hex), NsPK.parse(peer_pubkey_hex), payload)


# --- relay account auto-allow ----------------------------------------------


async def ensure_relay_allows(relay_id: str, pubkey_hex: str) -> None:
    """Best-effort: mark a pubkey as an allowed account on the local relay so it
    can publish/read even when the relay is paid/allow-listed. Silently no-ops if
    the nostrrelay extension isn't installed."""
    try:
        from lnbits.extensions.nostrrelay.crud import (
            create_account,
            get_account,
            update_account,
        )
        from lnbits.extensions.nostrrelay.models import (
            NostrAccount,
        )
    except ImportError:
        return
    try:
        existing = await get_account(relay_id, pubkey_hex)
        if existing and getattr(existing, "pubkey", ""):
            existing.allowed = True
            existing.blocked = False
            await update_account(existing)
        else:
            await create_account(
                NostrAccount(pubkey=pubkey_hex, relay_id=relay_id, allowed=True)
            )
    except Exception as exc:
        logger.warning(f"nsecbunker: could not allow {pubkey_hex[:12]} on relay: {exc}")


# --- request dispatch -------------------------------------------------------


def _event_p_tag(event: dict) -> str | None:
    for tag in event.get("tags", []):
        if len(tag) >= 2 and tag[0] == "p":
            return tag[1]
    return None


async def build_response_event(
    signer_privkey_hex: str,
    signer_pubkey_hex: str,
    client_pubkey_hex: str,
    response: dict,
) -> dict:
    content = _nip44_encrypt_raw(
        signer_privkey_hex, client_pubkey_hex, json.dumps(response)
    )
    event = Event(
        kind=NIP46_KIND,
        tags=[["p", client_pubkey_hex]],
        content=content,
        pubkey=signer_pubkey_hex,
    )
    event.sign(signer_privkey_hex)
    return event.to_dict()


async def _dispatch(
    conn: BunkerConnection,
    signer_key: BunkerKey,
    method: str,
    params: list,
) -> tuple[str | None, str | None]:
    """Return ``(result, error)`` for a NIP-46 method against a bound connection."""
    if method == "get_public_key":
        return signer_key.pubkey_hex, None

    if method == "ping":
        return "pong", None

    if method == "get_relays":
        url = connection_client_url(conn)
        return json.dumps({url: {"read": True, "write": True}}), None

    if method == "sign_event":
        try:
            unsigned = json.loads(params[0])
        except (IndexError, ValueError, TypeError):
            return None, "invalid sign_event params"
        try:
            signed = await sign_event(
                wallet_id=conn.wallet,
                extension_id=conn.id,
                unsigned_event=unsigned,
                key_id=conn.key_id,
            )
        except PermissionError as exc:
            return None, str(exc)
        except LookupError as exc:
            return None, str(exc)
        return json.dumps(signed), None

    if method in _ENCRYPTION_METHODS:
        return await _dispatch_encryption(conn, method, params)

    return None, f"unsupported method: {method}"


_ENCRYPTION_METHODS = {
    "nip04_encrypt": nip04_encrypt,
    "nip04_decrypt": nip04_decrypt,
    "nip44_encrypt": nip44_encrypt,
    "nip44_decrypt": nip44_decrypt,
}


async def _dispatch_encryption(
    conn: BunkerConnection, method: str, params: list
) -> tuple[str | None, str | None]:
    if not conn.allow_encryption:
        return None, "encryption not permitted for this connection"
    if len(params) < 2:
        return None, f"invalid {method} params"
    peer, text = params[0], params[1]
    try:
        result = await _ENCRYPTION_METHODS[method](
            conn.wallet, conn.key_id, peer, text
        )
        return result, None
    except (LookupError, RuntimeError) as exc:
        return None, str(exc)


async def process_incoming_event(
    event: dict,
    signer_key: BunkerKey,
    connections: list[BunkerConnection],
) -> dict | None:
    """Decrypt a kind:24133 request addressed to ``signer_key``, dispatch it
    against the matching connection, and return a signed response event to
    publish (or ``None`` if the event can't be handled)."""
    if not _HAS_NOSTR_SDK:
        return None

    client_pubkey = event.get("pubkey")
    if not client_pubkey:
        return None

    signer_priv = await get_decrypted_private_key(signer_key.id)
    try:
        plaintext = _nip44_decrypt_raw(
            signer_priv, client_pubkey, event.get("content", "")
        )
        request = json.loads(plaintext)
        req_id = request["id"]
        method = request["method"]
        params = request.get("params", []) or []
    except Exception as exc:
        logger.debug(f"nsecbunker: undecryptable/invalid nip46 request: {exc}")
        return None

    # `connect` binds a client to a connection by proving the shared secret.
    if method == "connect":
        secret = params[1] if len(params) > 1 else None
        conn = next(
            (
                c
                for c in connections
                if c.secret == secret
                and (c.client_pubkey is None or c.client_pubkey == client_pubkey)
            ),
            None,
        )
        if conn is None:
            result, error = None, "invalid secret"
        else:
            await bind_connection_client(conn.id, client_pubkey)
            if conn.is_local:
                await ensure_relay_allows(conn.relay_id, client_pubkey)
            logger.info(
                f"nsecbunker: nip46 client {client_pubkey[:12]}... connected "
                f"to key {signer_key.id[:8]}... (conn {conn.id})"
            )
            result, error = "ack", None
        return await build_response_event(
            signer_priv,
            signer_key.pubkey_hex,
            client_pubkey,
            _resp(req_id, result, error),
        )

    # Every other method requires an already-bound connection.
    conn = next(
        (c for c in connections if c.client_pubkey == client_pubkey and c.active),
        None,
    )
    if conn is None:
        return await build_response_event(
            signer_priv, signer_key.pubkey_hex, client_pubkey,
            _resp(req_id, None, "not connected"),
        )

    result, error = await _dispatch(conn, signer_key, method, params)
    await touch_connection(conn.id)
    if conn.pending_connect:
        # The client is talking to us, so it received the connect ack already.
        await clear_pending_connect(conn.id)
    return await build_response_event(
        signer_priv,
        signer_key.pubkey_hex,
        client_pubkey,
        _resp(req_id, result, error),
    )


async def build_connect_ack(
    signer_privkey_hex: str,
    signer_pubkey_hex: str,
    client_pubkey_hex: str,
    secret: str,
) -> dict:
    """Proactive connect acknowledgement for the nostrconnect:// flow — the
    signer initiates, echoing the client's secret as the result so the client
    can validate it (NIP-46)."""
    return await build_response_event(
        signer_privkey_hex,
        signer_pubkey_hex,
        client_pubkey_hex,
        {"id": _secrets.token_hex(8), "result": secret},
    )


def _resp(req_id: str, result: str | None, error: str | None) -> dict:
    out: dict = {"id": req_id, "result": result or ""}
    if error:
        out["error"] = error
    return out
