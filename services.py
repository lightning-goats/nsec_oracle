import time

from loguru import logger
from pynostr.event import Event

from .crud import (
    create_rate_limited_signing_log,
    create_signing_log,
    get_decrypted_private_key,
    get_key,
    get_keys,
    get_permissions,
)

try:
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
        nip04_decrypt as _nip04_dec,
    )
    from nostr_sdk import (
        nip04_encrypt as _nip04_enc,
    )
    from nostr_sdk import (
        nip44_decrypt as _nip44_dec,
    )
    from nostr_sdk import (
        nip44_encrypt as _nip44_enc,
    )

    _HAS_NOSTR_SDK = True
except ImportError:
    _HAS_NOSTR_SDK = False


async def sign_event(
    wallet_id: str,
    extension_id: str,
    unsigned_event: dict,
    key_id: str | None = None,
) -> dict:
    """
    Sign a Nostr event using the oracle.

    Args:
        wallet_id: LNBits wallet ID
        extension_id: Machine name of the calling extension
        unsigned_event: Dict with kind, tags, content (pubkey optional)
        key_id: Specific key ID to use. Defaults to the newest permitted key.

    Returns:
        Complete signed event dict with id and sig fields added.

    Raises:
        PermissionError: Extension lacks permission for this event kind.
        LookupError: No key configured for this wallet.
    """
    kind = unsigned_event.get("kind", 1)
    permissions = await get_permissions(wallet_id)

    # Resolve an explicit key, or the newest key with matching permission.
    if key_id:
        key = await get_key(key_id)
        if not key or key.wallet != wallet_id:
            raise LookupError(f"Key {key_id} not found for wallet")
        perm = next(
            (
                candidate
                for candidate in permissions
                if candidate.key_id == key.id
                and candidate.extension_id == extension_id
                and candidate.kind == kind
            ),
            None,
        )
    else:
        keys = await get_keys(wallet_id)
        if not keys:
            raise LookupError("No keys configured for this wallet")
        match = next(
            (
                (candidate_key, candidate_perm)
                for candidate_key in keys
                for candidate_perm in permissions
                if candidate_perm.key_id == candidate_key.id
                and candidate_perm.extension_id == extension_id
                and candidate_perm.kind == kind
            ),
            None,
        )
        if match:
            key, perm = match
        else:
            key, perm = keys[0], None

    if not perm:
        raise PermissionError(
            f"Extension '{extension_id}' lacks permission for key {key.id} "
            f"and kind {kind}"
        )

    rate_count = perm.rate_limit_count
    rate_seconds = perm.rate_limit_seconds
    invalid_rate_limit = (rate_count is None) != (rate_seconds is None)
    if rate_count is not None and rate_seconds is not None:
        invalid_rate_limit = (
            invalid_rate_limit or rate_count <= 0 or rate_seconds <= 0
        )
    if invalid_rate_limit:
        raise PermissionError("Invalid rate limit configuration")

    # Decrypt the key and sign the requested event.
    private_key_hex = await get_decrypted_private_key(key.id)
    # Default created_at explicitly rather than relying on the Nostr library to
    # coerce a missing/None timestamp — older pynostr releases (the extension
    # supports >=0.6.2) would otherwise serialize an invalid null created_at.
    created_at = unsigned_event.get("created_at") or int(time.time())
    event = Event(
        kind=kind,
        tags=unsigned_event.get("tags", []),
        content=unsigned_event.get("content", ""),
        pubkey=key.pubkey_hex,
        created_at=created_at,
    )
    event.sign(private_key_hex)
    signed = event.to_dict()
    event_id = signed.get("id", "")

    # Limited permissions reserve and log a slot in one database transaction.
    if rate_count is not None:
        logged = await create_rate_limited_signing_log(
            perm.id,
            key.id,
            extension_id,
            kind,
            event_id,
            rate_count,
            rate_seconds,
        )
        if not logged:
            raise PermissionError(
                f"Rate limit exceeded: {rate_count} per {rate_seconds}s"
            )
    else:
        await create_signing_log(key.id, extension_id, kind, event_id)
    logger.info(
        f"nsec_oracle: signed kind:{kind} for {extension_id} "
        f"(key {key.id[:8]}..., event {event_id[:12]}...)"
    )

    return signed


async def get_wallet_pubkey(
    wallet_id: str, key_id: str | None = None
) -> str | None:
    """Get a wallet's public key hex."""
    if key_id:
        key = await get_key(key_id)
        if key and key.wallet == wallet_id:
            return key.pubkey_hex
        return None
    keys = await get_keys(wallet_id)
    if keys:
        return keys[0].pubkey_hex
    return None


async def _get_owned_key(wallet_id: str, key_id: str):
    key = await get_key(key_id)
    if not key or key.wallet != wallet_id:
        raise LookupError(f"Key {key_id} not found for wallet")
    return key


async def nip04_encrypt(
    wallet_id: str, key_id: str, recipient_pubkey: str, plaintext: str
) -> str:
    if not _HAS_NOSTR_SDK:
        raise RuntimeError("nostr_sdk is not installed")
    key = await _get_owned_key(wallet_id, key_id)
    private_key_hex = await get_decrypted_private_key(key.id)
    sk = NsSK.parse(private_key_hex)
    pk = NsPK.parse(recipient_pubkey)
    result = _nip04_enc(sk, pk, plaintext)
    logger.info(
        f"nsec_oracle: nip04_encrypt for key {key.id[:8]}..."
    )
    return result


async def nip04_decrypt(
    wallet_id: str, key_id: str, sender_pubkey: str, ciphertext: str
) -> str:
    if not _HAS_NOSTR_SDK:
        raise RuntimeError("nostr_sdk is not installed")
    key = await _get_owned_key(wallet_id, key_id)
    private_key_hex = await get_decrypted_private_key(key.id)
    sk = NsSK.parse(private_key_hex)
    pk = NsPK.parse(sender_pubkey)
    result = _nip04_dec(sk, pk, ciphertext)
    logger.info(
        f"nsec_oracle: nip04_decrypt for key {key.id[:8]}..."
    )
    return result


async def nip44_encrypt(
    wallet_id: str, key_id: str, recipient_pubkey: str, plaintext: str
) -> str:
    if not _HAS_NOSTR_SDK:
        raise RuntimeError("nostr_sdk is not installed")
    key = await _get_owned_key(wallet_id, key_id)
    private_key_hex = await get_decrypted_private_key(key.id)
    sk = NsSK.parse(private_key_hex)
    pk = NsPK.parse(recipient_pubkey)
    result = _nip44_enc(sk, pk, plaintext, Nip44Version.V2)
    logger.info(
        f"nsec_oracle: nip44_encrypt for key {key.id[:8]}..."
    )
    return result


async def nip44_decrypt(
    wallet_id: str, key_id: str, sender_pubkey: str, payload: str
) -> str:
    if not _HAS_NOSTR_SDK:
        raise RuntimeError("nostr_sdk is not installed")
    key = await _get_owned_key(wallet_id, key_id)
    private_key_hex = await get_decrypted_private_key(key.id)
    sk = NsSK.parse(private_key_hex)
    pk = NsPK.parse(sender_pubkey)
    result = _nip44_dec(sk, pk, payload)
    logger.info(
        f"nsec_oracle: nip44_decrypt for key {key.id[:8]}..."
    )
    return result
