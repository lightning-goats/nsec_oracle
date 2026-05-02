from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class BunkerKey(BaseModel):
    class Config:
        extra = "ignore"

    id: str
    wallet: str
    pubkey_hex: str
    encrypted_nsec: str
    label: Optional[str] = None
    created_at: datetime


class PublicBunkerKey(BaseModel):
    id: str
    wallet: str
    pubkey_hex: str
    label: Optional[str] = None
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
    rate_limit_count: Optional[int] = None
    rate_limit_seconds: Optional[int] = None
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
    label: Optional[str] = None


class CreatePermissionData(BaseModel):
    extension_id: str
    key_id: str
    kind: int
    rate_limit_count: Optional[int] = None
    rate_limit_seconds: Optional[int] = None


class UpdatePermissionData(BaseModel):
    rate_limit_count: Optional[int] = None
    rate_limit_seconds: Optional[int] = None


class QuickSetupData(BaseModel):
    extension_id: str
    key_id: str
    use_recommended_limits: bool = True


class SignEventData(BaseModel):
    extension_id: str
    event: dict


class UpdateKeyData(BaseModel):
    label: Optional[str] = None


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
