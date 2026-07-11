import re
from datetime import datetime

from pydantic import BaseModel, root_validator

# Signing logs are pruned after this many days (see tasks.py). A rate-limit
# window longer than the retention would be silently loosened as rows age out,
# so windows are capped below it. tasks.py imports this constant to stay in sync.
LOG_RETENTION_DAYS = 30
MAX_RATE_LIMIT_SECONDS = LOG_RETENTION_DAYS * 86400

# Extension machine names: letters, digits and _.- only. Bounds the value that
# is written to logs and the signing_log table (prevents log/DB injection).
_EXTENSION_ID_RE = re.compile(r"[a-zA-Z0-9_.\-]{1,64}")

# Nostr event kind is a uint16 per NIP-01.
_MAX_KIND = 65535


def _validate_extension_id(value: object) -> str:
    if not isinstance(value, str) or not _EXTENSION_ID_RE.fullmatch(value):
        raise ValueError(
            "extension_id must be 1-64 characters of letters, digits, '_', '.', '-'"
        )
    return value


def _coerce_kind(value: object) -> int:
    """Coerce a Nostr event kind to a bounded, non-negative integer.

    Rejects booleans, non-integral floats and non-numeric strings so a
    malformed kind fails loudly instead of silently missing its permission
    match (or truncating, e.g. 1.9 -> 1) inside the signer.
    """
    if isinstance(value, bool):
        raise ValueError("event kind must be an integer")
    if isinstance(value, int):
        kind = value
    elif isinstance(value, float) and value.is_integer():
        kind = int(value)
    elif isinstance(value, str) and re.fullmatch(r"\d{1,7}", value.strip()):
        kind = int(value.strip())
    else:
        raise ValueError("event kind must be an integer")
    if not 0 <= kind <= _MAX_KIND:
        raise ValueError(f"event kind must be between 0 and {_MAX_KIND}")
    return kind


def _validate_rate_limit_pair(values: dict, require_update: bool = False) -> dict:
    count_set = "rate_limit_count" in values
    seconds_set = "rate_limit_seconds" in values

    if require_update and not count_set and not seconds_set:
        raise ValueError("Rate limit update must include both fields")
    if count_set != seconds_set:
        raise ValueError("Rate limit count and seconds must be provided together")

    count = values.get("rate_limit_count")
    seconds = values.get("rate_limit_seconds")
    if count is None and seconds is None:
        return values
    if count is None or seconds is None or count <= 0 or seconds <= 0:
        raise ValueError("Rate limit count and seconds must be positive integers")
    if seconds > MAX_RATE_LIMIT_SECONDS:
        raise ValueError(
            f"Rate limit window must not exceed {MAX_RATE_LIMIT_SECONDS} seconds "
            f"({LOG_RETENTION_DAYS} days)"
        )
    return values



class OracleKey(BaseModel):
    class Config:
        extra = "ignore"

    id: str
    wallet: str
    pubkey_hex: str
    encrypted_nsec: str
    label: str | None = None
    created_at: datetime


class PublicOracleKey(BaseModel):
    id: str
    wallet: str
    pubkey_hex: str
    label: str | None = None
    created_at: datetime
    stored: bool

    @classmethod
    def from_oracle_key(cls, key: OracleKey) -> "PublicOracleKey":
        return cls(
            id=key.id,
            wallet=key.wallet,
            pubkey_hex=key.pubkey_hex,
            label=key.label,
            created_at=key.created_at,
            stored=bool(key.encrypted_nsec),
        )


class OraclePermission(BaseModel):
    class Config:
        extra = "ignore"

    id: str
    wallet: str
    extension_id: str
    key_id: str
    kind: int
    rate_limit_count: int | None = None
    rate_limit_seconds: int | None = None
    created_at: datetime


class SigningLog(BaseModel):
    class Config:
        extra = "ignore"

    id: str
    key_id: str
    extension_id: str
    kind: int
    event_id: str
    created_at: datetime


class CreateKeyData(BaseModel):
    private_key: str
    label: str | None = None


class CreatePermissionData(BaseModel):
    extension_id: str
    key_id: str
    kind: int
    rate_limit_count: int | None = None
    rate_limit_seconds: int | None = None

    @root_validator(pre=True, allow_reuse=True)
    def validate_fields(cls, values):
        if values.get("extension_id") is not None:
            values["extension_id"] = _validate_extension_id(values["extension_id"])
        if values.get("kind") is not None:
            values["kind"] = _coerce_kind(values["kind"])
        return _validate_rate_limit_pair(values)


class UpdatePermissionData(BaseModel):
    rate_limit_count: int | None = None
    rate_limit_seconds: int | None = None

    @root_validator(pre=True, allow_reuse=True)
    def validate_rate_limit(cls, values):
        return _validate_rate_limit_pair(values, require_update=True)


class QuickSetupData(BaseModel):
    extension_id: str
    key_id: str
    use_recommended_limits: bool = True

    @root_validator(pre=True, allow_reuse=True)
    def validate_extension(cls, values):
        if values.get("extension_id") is not None:
            values["extension_id"] = _validate_extension_id(values["extension_id"])
        return values


class SignEventData(BaseModel):
    extension_id: str
    event: dict
    key_id: str | None = None

    @root_validator(pre=True, allow_reuse=True)
    def validate_event(cls, values):
        if values.get("extension_id") is not None:
            values["extension_id"] = _validate_extension_id(values["extension_id"])
        event = values.get("event")
        if event is not None:
            if not isinstance(event, dict):
                raise ValueError("event must be an object")
            if event.get("kind") is not None:
                event["kind"] = _coerce_kind(event["kind"])
            tags = event.get("tags")
            if tags is not None and not isinstance(tags, list):
                raise ValueError("event.tags must be a list")
            created_at = event.get("created_at")
            if created_at is not None:
                if (
                    isinstance(created_at, bool)
                    or not isinstance(created_at, (int, float))
                    or (isinstance(created_at, float) and not created_at.is_integer())
                ):
                    raise ValueError("event.created_at must be an integer")
                event["created_at"] = int(created_at)
        return values


class UpdateKeyData(BaseModel):
    label: str | None = None


class Nip04EncryptData(BaseModel):
    key_id: str
    pubkey: str
    plaintext: str


class Nip04DecryptData(BaseModel):
    key_id: str
    pubkey: str
    ciphertext: str


class Nip44EncryptData(BaseModel):
    key_id: str
    pubkey: str
    plaintext: str


class Nip44DecryptData(BaseModel):
    key_id: str
    pubkey: str
    payload: str
