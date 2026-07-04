from http import HTTPStatus

from fastapi import APIRouter, Depends, HTTPException
from loguru import logger
from pynostr.key import PrivateKey
from starlette.concurrency import run_in_threadpool

from lnbits.core.models import WalletTypeInfo
from lnbits.decorators import require_admin_key, require_invoice_key

from .crud import (
    count_signing_logs,
    create_key,
    create_permission,
    delete_key,
    delete_permission,
    delete_permissions_for_key,
    get_decrypted_private_key,
    get_key,
    get_keys,
    get_permission,
    get_permissions,
    get_signing_logs,
    update_key,
    update_permission,
)
from .discovery import discover_signing_requirements
from .helpers import parse_nostr_private_key
from .models import (
    BunkerKey,
    BunkerPermission,
    CreateKeyData,
    CreatePermissionData,
    Nip04DecryptData,
    Nip04EncryptData,
    Nip44DecryptData,
    Nip44EncryptData,
    PublicBunkerKey,
    QuickSetupData,
    SignEventData,
    UpdateKeyData,
    UpdatePermissionData,
)
from .services import (
    get_wallet_pubkey,
    nip04_decrypt,
    nip04_encrypt,
    nip44_decrypt,
    nip44_encrypt,
    sign_event,
)

nsecbunker_api_router = APIRouter()


def _public_key(key: BunkerKey) -> PublicBunkerKey:
    return PublicBunkerKey.from_bunker_key(key)


async def _require_owned_key(wallet_id: str, key_id: str) -> BunkerKey:
    key = await get_key(key_id)
    if not key or key.wallet != wallet_id:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Key not found."
        )
    return key


# --- Keys ---


@nsecbunker_api_router.post(
    "/api/v1/keys", status_code=HTTPStatus.CREATED
)
async def api_create_key(
    data: CreateKeyData,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> PublicBunkerKey:
    try:
        parse_nostr_private_key(data.private_key)
    except Exception as exc:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Invalid Nostr private key.",
        ) from exc

    key = await create_key(wallet.wallet.id, data)
    return _public_key(key)


@nsecbunker_api_router.get("/api/v1/keys")
async def api_get_keys(
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> list[PublicBunkerKey]:
    keys = await get_keys(wallet.wallet.id)
    return [_public_key(key) for key in keys]


@nsecbunker_api_router.delete(
    "/api/v1/keys/{key_id}", status_code=HTTPStatus.OK
)
async def api_delete_key(
    key_id: str,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> None:
    key = await get_key(key_id)
    if not key:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Key not found."
        )
    if key.wallet != wallet.wallet.id:
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN, detail="Not your key."
        )
    # Cascade: delete permissions first, then the key
    await delete_permissions_for_key(key_id)
    await delete_key(key_id)


# --- Keys: Generate ---


@nsecbunker_api_router.post(
    "/api/v1/keys/generate", status_code=HTTPStatus.CREATED
)
async def api_generate_key(
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> PublicBunkerKey:
    private_key = PrivateKey()
    data = CreateKeyData(private_key=private_key.hex())
    key = await create_key(wallet.wallet.id, data)
    return _public_key(key)


@nsecbunker_api_router.put(
    "/api/v1/keys/{key_id}", status_code=HTTPStatus.OK
)
async def api_update_key(
    key_id: str,
    data: UpdateKeyData,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> PublicBunkerKey:
    key = await get_key(key_id)
    if not key:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Key not found."
        )
    if key.wallet != wallet.wallet.id:
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN, detail="Not your key."
        )
    updated = await update_key(key_id, data)
    return _public_key(updated)


@nsecbunker_api_router.get(
    "/api/v1/keys/{key_id}/export", status_code=HTTPStatus.OK
)
async def api_export_key(
    key_id: str,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> dict:
    key = await get_key(key_id)
    if not key:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Key not found."
        )
    if key.wallet != wallet.wallet.id:
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN, detail="Not your key."
        )
    private_key_hex = await get_decrypted_private_key(key_id)
    # Exporting the raw private key is the single most sensitive operation in
    # the vault — always leave an audit trail.
    logger.warning(
        f"nsecbunker: private key EXPORTED for key {key_id[:8]}... "
        f"(wallet {wallet.wallet.id[:8]}..., pubkey {key.pubkey_hex[:12]}...)"
    )
    pk = PrivateKey(bytes.fromhex(private_key_hex))
    return {"private_key_hex": private_key_hex, "nsec": pk.nsec}


# --- Permissions ---


@nsecbunker_api_router.post(
    "/api/v1/permissions", status_code=HTTPStatus.CREATED
)
async def api_create_permission(
    data: CreatePermissionData,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> BunkerPermission:
    try:
        return await create_permission(wallet.wallet.id, data)
    except LookupError as exc:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail=str(exc)
        ) from exc


@nsecbunker_api_router.get("/api/v1/permissions")
async def api_get_permissions(
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> list[BunkerPermission]:
    return await get_permissions(wallet.wallet.id)


@nsecbunker_api_router.put(
    "/api/v1/permissions/{perm_id}", status_code=HTTPStatus.OK
)
async def api_update_permission(
    perm_id: str,
    data: UpdatePermissionData,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> BunkerPermission:
    perm = await get_permission(perm_id)
    if not perm:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Permission not found."
        )
    if perm.wallet != wallet.wallet.id:
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN, detail="Not your permission."
        )
    return await update_permission(perm_id, data)


@nsecbunker_api_router.delete(
    "/api/v1/permissions/{perm_id}", status_code=HTTPStatus.OK
)
async def api_delete_permission(
    perm_id: str,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> None:
    perm = await get_permission(perm_id)
    if not perm:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Permission not found."
        )
    if perm.wallet != wallet.wallet.id:
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN, detail="Not your permission."
        )
    await delete_permission(perm_id)


# --- Discovery & Quick Setup ---


@nsecbunker_api_router.get("/api/v1/discover")
async def api_discover(
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> list[dict]:
    # Runs blocking filesystem I/O (scans every extension's config.json) — keep
    # it off the event loop.
    discovered = await run_in_threadpool(discover_signing_requirements)
    existing = await get_permissions(wallet.wallet.id)
    keys = await get_keys(wallet.wallet.id)
    default_key_id = keys[0].id if keys else None

    granted_set = {
        (p.extension_id, p.kind)
        for p in existing
        if p.key_id == default_key_id
    }

    result = []
    for ext in discovered:
        reqs = []
        for req in ext.requirements:
            reqs.append({
                "kind": req.kind,
                "kind_label": req.kind_label,
                "description": req.description,
                "required": req.required,
                "recommended_rate_limit": (
                    req.recommended_rate_limit.dict()
                    if req.recommended_rate_limit
                    else None
                ),
                "already_granted": (ext.extension_id, req.kind) in granted_set,
            })
        result.append({
            "extension_id": ext.extension_id,
            "extension_name": ext.extension_name,
            "requirements": reqs,
        })
    return result


@nsecbunker_api_router.post(
    "/api/v1/quick-setup", status_code=HTTPStatus.CREATED
)
async def api_quick_setup(
    data: QuickSetupData,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> list[BunkerPermission]:
    await _require_owned_key(wallet.wallet.id, data.key_id)

    discovered = await run_in_threadpool(discover_signing_requirements)
    ext_info = next(
        (e for e in discovered if e.extension_id == data.extension_id), None
    )
    if not ext_info:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"No signing requirements found for '{data.extension_id}'.",
        )

    existing = await get_permissions(wallet.wallet.id)
    granted_set = {
        (p.extension_id, p.kind) for p in existing if p.key_id == data.key_id
    }

    created: list[BunkerPermission] = []
    for req in ext_info.requirements:
        if (data.extension_id, req.kind) in granted_set:
            continue

        rate_count = None
        rate_seconds = None
        if data.use_recommended_limits and req.recommended_rate_limit:
            rate_count = req.recommended_rate_limit.count
            rate_seconds = req.recommended_rate_limit.seconds

        perm_data = CreatePermissionData(
            extension_id=data.extension_id,
            key_id=data.key_id,
            kind=req.kind,
            rate_limit_count=rate_count,
            rate_limit_seconds=rate_seconds,
        )
        perm = await create_permission(wallet.wallet.id, perm_data)
        created.append(perm)

    return created


# --- Public Key ---


@nsecbunker_api_router.get("/api/v1/pubkey")
async def api_get_pubkey(
    key_id: str | None = None,
    wallet: WalletTypeInfo = Depends(require_invoice_key),
) -> dict:
    pubkey = await get_wallet_pubkey(wallet.wallet.id, key_id)
    if not pubkey:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="No key found for this wallet.",
        )
    return {"pubkey_hex": pubkey}


# --- NIP-04 ---


@nsecbunker_api_router.post("/api/v1/nip04/encrypt")
async def api_nip04_encrypt(
    data: Nip04EncryptData,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> dict:
    try:
        result = await nip04_encrypt(
            wallet.wallet.id, data.key_id, data.pubkey, data.plaintext
        )
        return {"ciphertext": result}
    except LookupError as exc:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail=str(exc)
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=HTTPStatus.SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc
    except Exception as exc:
        logger.error(f"nsecbunker: nip04_encrypt failed: {exc}")
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="Encryption failed.",
        ) from exc


@nsecbunker_api_router.post("/api/v1/nip04/decrypt")
async def api_nip04_decrypt(
    data: Nip04DecryptData,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> dict:
    try:
        result = await nip04_decrypt(
            wallet.wallet.id, data.key_id, data.pubkey, data.ciphertext
        )
        return {"plaintext": result}
    except LookupError as exc:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail=str(exc)
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=HTTPStatus.SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc
    except Exception as exc:
        logger.error(f"nsecbunker: nip04_decrypt failed: {exc}")
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="Decryption failed.",
        ) from exc


# --- NIP-44 ---


@nsecbunker_api_router.post("/api/v1/nip44/encrypt")
async def api_nip44_encrypt(
    data: Nip44EncryptData,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> dict:
    try:
        result = await nip44_encrypt(
            wallet.wallet.id, data.key_id, data.pubkey, data.plaintext
        )
        return {"payload": result}
    except LookupError as exc:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail=str(exc)
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=HTTPStatus.SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc
    except Exception as exc:
        logger.error(f"nsecbunker: nip44_encrypt failed: {exc}")
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="Encryption failed.",
        ) from exc


@nsecbunker_api_router.post("/api/v1/nip44/decrypt")
async def api_nip44_decrypt(
    data: Nip44DecryptData,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> dict:
    try:
        result = await nip44_decrypt(
            wallet.wallet.id, data.key_id, data.pubkey, data.payload
        )
        return {"plaintext": result}
    except LookupError as exc:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail=str(exc)
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=HTTPStatus.SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc
    except Exception as exc:
        logger.error(f"nsecbunker: nip44_decrypt failed: {exc}")
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="Decryption failed.",
        ) from exc


# --- Sign ---


@nsecbunker_api_router.post("/api/v1/sign")
async def api_sign_event(
    data: SignEventData,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> dict:
    try:
        signed = await sign_event(
            wallet_id=wallet.wallet.id,
            extension_id=data.extension_id,
            unsigned_event=data.event,
            key_id=data.key_id,
        )
        return {"event": signed}
    except LookupError as exc:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=str(exc),
        ) from exc
    except PermissionError as exc:
        detail = str(exc)
        if "Rate limit" in detail:
            raise HTTPException(
                status_code=HTTPStatus.TOO_MANY_REQUESTS,
                detail=detail,
            ) from exc
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN,
            detail=detail,
        ) from exc
    except Exception as exc:
        logger.error(f"nsecbunker: sign_event failed: {exc}")
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="Signing failed.",
        ) from exc


# --- Signing Log ---


@nsecbunker_api_router.get("/api/v1/log")
async def api_get_logs(
    offset: int = 0,
    limit: int = 50,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> dict:
    logs = await get_signing_logs(wallet.wallet.id, limit=limit, offset=offset)
    total = await count_signing_logs(wallet.wallet.id)
    return {"data": logs, "total": total}
