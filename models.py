from datetime import datetime

from pydantic import BaseModel, root_validator


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
    return values



class BunkerKey(BaseModel):
    class Config:
        extra = "ignore"

    id: str
    wallet: str
    pubkey_hex: str
    encrypted_nsec: str
    label: str | None = None
    created_at: datetime


class PublicBunkerKey(BaseModel):
    id: str
    wallet: str
    pubkey_hex: str
    label: str | None = None
    created_at: datetime
    stored: bool

    @classmethod
    def from_bunker_key(cls, key: BunkerKey) -> "PublicBunkerKey":
        return cls(
            id=key.id,
            wallet=key.wallet,
            pubkey_hex=key.pubkey_hex,
            label=key.label,
            created_at=key.created_at,
            stored=bool(key.encrypted_nsec),
        )


class BunkerPermission(BaseModel):
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
    def validate_rate_limit(cls, values):
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


class SignEventData(BaseModel):
    extension_id: str
    event: dict
    key_id: str | None = None


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


# --- NIP-46 (Nostr Connect / remote signing) ---


class BunkerConnection(BaseModel):
    class Config:
        extra = "ignore"

    id: str
    wallet: str
    key_id: str
    # Exactly one of relay_id (local nostrrelay) / relay_url (remote) is set.
    relay_id: str | None = None
    relay_url: str | None = None
    secret: str
    client_pubkey: str | None = None
    label: str | None = None
    allow_encryption: bool = False
    active: bool = True
    pending_connect: bool = False
    created_at: datetime
    last_used_at: datetime | None = None

    @property
    def is_local(self) -> bool:
        return bool(self.relay_id)


class CreateConnectionData(BaseModel):
    key_id: str
    # Provide relay_id for a local relay, or relay_url for a remote one.
    relay_id: str | None = None
    relay_url: str | None = None
    label: str | None = None
    allow_encryption: bool = False

    @root_validator(pre=True, allow_reuse=True)
    def validate_relay(cls, values):
        if bool(values.get("relay_id")) == bool(values.get("relay_url")):
            raise ValueError("Provide exactly one of relay_id or relay_url")
        return values


class CreateNostrConnectData(BaseModel):
    """Client-initiated (nostrconnect://) pairing."""

    key_id: str
    uri: str
    label: str | None = None
    allow_encryption: bool = False


class UpdateConnectionData(BaseModel):
    label: str | None = None
    allow_encryption: bool | None = None
    active: bool | None = None
