import asyncio
import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace


def _load_services_module():
    package_name = "nsec_oracle_testpkg"
    module_name = f"{package_name}.services"
    services_path = Path(__file__).resolve().parents[1] / "services.py"

    package = types.ModuleType(package_name)
    package.__path__ = []  # type: ignore[attr-defined]
    sys.modules[package_name] = package

    logger = SimpleNamespace(info=lambda *a, **k: None)
    loguru = types.ModuleType("loguru")
    loguru.logger = logger
    sys.modules["loguru"] = loguru

    class DummyEvent:
        def __init__(self, *, kind, tags, content, pubkey, created_at=None):
            self.kind = kind
            self.tags = tags
            self.content = content
            self.pubkey = pubkey
            self.created_at = created_at
            self.signed_with = None

        def sign(self, private_key_hex):
            self.signed_with = private_key_hex

        def to_dict(self):
            return {
                "kind": self.kind,
                "tags": self.tags,
                "content": self.content,
                "pubkey": self.pubkey,
                "created_at": self.created_at,
                "sig": "dummy-sig",
                "id": "dummy-event-id",
            }

    pynostr = types.ModuleType("pynostr")
    pynostr_event = types.ModuleType("pynostr.event")
    pynostr_event.Event = DummyEvent
    pynostr.event = pynostr_event  # type: ignore[attr-defined]
    sys.modules["pynostr"] = pynostr
    sys.modules["pynostr.event"] = pynostr_event

    crud = types.ModuleType(f"{package_name}.crud")

    async def get_keys(wallet_id):
        return [
            SimpleNamespace(id="key-a", wallet=wallet_id, pubkey_hex="pubkey-a"),
            SimpleNamespace(id="key-b", wallet=wallet_id, pubkey_hex="pubkey-b"),
        ]

    async def get_key(key_id):
        mapping = {
            "key-a": SimpleNamespace(
                id="key-a", wallet="wallet-1", pubkey_hex="pubkey-a"
            ),
            "key-b": SimpleNamespace(
                id="key-b", wallet="wallet-1", pubkey_hex="pubkey-b"
            ),
        }
        return mapping.get(key_id)

    async def get_permissions(wallet_id):
        return [
            SimpleNamespace(
                id="permission-a",
                key_id="key-a",
                extension_id="cyberherd_messaging",
                kind=1,
                rate_limit_count=None,
                rate_limit_seconds=None,
            ),
            SimpleNamespace(
                id="permission-b",
                key_id="key-b",
                extension_id="cyberherd_messaging",
                kind=1,
                rate_limit_count=None,
                rate_limit_seconds=None,
            ),
        ]

    async def get_decrypted_private_key(key_id):
        return f"secret-for-{key_id}"

    async def create_signing_log(key_id, extension_id, kind, event_id):
        create_signing_log.calls.append((key_id, extension_id, kind, event_id))

    create_signing_log.calls = []

    async def create_rate_limited_signing_log(
        permission_id,
        key_id,
        extension_id,
        kind,
        event_id,
        rate_limit_count,
        rate_limit_seconds,
    ):
        create_rate_limited_signing_log.calls.append(
            (
                permission_id,
                key_id,
                extension_id,
                kind,
                event_id,
                rate_limit_count,
                rate_limit_seconds,
            )
        )
        return create_rate_limited_signing_log.allowed

    create_rate_limited_signing_log.calls = []
    create_rate_limited_signing_log.allowed = True

    crud.create_rate_limited_signing_log = create_rate_limited_signing_log
    crud.create_signing_log = create_signing_log
    crud.get_decrypted_private_key = get_decrypted_private_key
    crud.get_key = get_key
    crud.get_keys = get_keys
    crud.get_permissions = get_permissions
    sys.modules[f"{package_name}.crud"] = crud

    spec = importlib.util.spec_from_file_location(module_name, services_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module, create_signing_log, create_rate_limited_signing_log


def test_sign_event_uses_requested_key_when_that_key_has_permission():
    services, create_signing_log, _ = _load_services_module()

    signed = asyncio.run(
        services.sign_event(
            wallet_id="wallet-1",
            extension_id="cyberherd_messaging",
            unsigned_event={"kind": 1, "tags": [], "content": "hello"},
            key_id="key-a",
        )
    )

    assert signed["pubkey"] == "pubkey-a"
    assert create_signing_log.calls == [
        ("key-a", "cyberherd_messaging", 1, "dummy-event-id")
    ]


def test_sign_event_preserves_requested_created_at():
    services, _, _ = _load_services_module()

    signed = asyncio.run(
        services.sign_event(
            wallet_id="wallet-1",
            extension_id="cyberherd_messaging",
            unsigned_event={
                "kind": 1,
                "tags": [],
                "content": "hello",
                "created_at": 1234567890,
            },
            key_id="key-a",
        )
    )

    assert signed["created_at"] == 1234567890


def test_sign_event_uses_atomic_rate_limit_reservation():
    services, create_signing_log, create_rate_limited_log = _load_services_module()

    async def get_permissions(wallet_id):
        return [
            SimpleNamespace(
                id="permission-1",
                key_id="key-a",
                extension_id="cyberherd_messaging",
                kind=1,
                rate_limit_count=10,
                rate_limit_seconds=60,
            )
        ]

    services.get_permissions = get_permissions

    asyncio.run(
        services.sign_event(
            wallet_id="wallet-1",
            extension_id="cyberherd_messaging",
            unsigned_event={"kind": 1, "tags": [], "content": "hello"},
            key_id="key-a",
        )
    )

    assert create_signing_log.calls == []
    assert create_rate_limited_log.calls == [
        (
            "permission-1",
            "key-a",
            "cyberherd_messaging",
            1,
            "dummy-event-id",
            10,
            60,
        )
    ]


def test_sign_event_rejects_exhausted_atomic_rate_limit():
    services, _, create_rate_limited_log = _load_services_module()

    async def get_permissions(wallet_id):
        return [
            SimpleNamespace(
                id="permission-1",
                key_id="key-a",
                extension_id="cyberherd_messaging",
                kind=1,
                rate_limit_count=1,
                rate_limit_seconds=60,
            )
        ]

    services.get_permissions = get_permissions
    create_rate_limited_log.allowed = False

    async def sign():
        return await services.sign_event(
            wallet_id="wallet-1",
            extension_id="cyberherd_messaging",
            unsigned_event={"kind": 1, "tags": [], "content": "hello"},
            key_id="key-a",
        )

    try:
        asyncio.run(sign())
    except PermissionError as exc:
        assert "Rate limit exceeded" in str(exc)
    else:
        raise AssertionError("Expected the exhausted rate limit to reject signing")


def test_sign_event_rejects_invalid_legacy_rate_limit_configuration():
    services, create_signing_log, create_rate_limited_log = _load_services_module()

    async def get_permissions(wallet_id):
        return [
            SimpleNamespace(
                id="permission-1",
                key_id="key-a",
                extension_id="cyberherd_messaging",
                kind=1,
                rate_limit_count=10,
                rate_limit_seconds=None,
            )
        ]

    services.get_permissions = get_permissions

    async def sign():
        return await services.sign_event(
            wallet_id="wallet-1",
            extension_id="cyberherd_messaging",
            unsigned_event={"kind": 1, "tags": [], "content": "hello"},
            key_id="key-a",
        )

    try:
        asyncio.run(sign())
    except PermissionError as exc:
        assert "Invalid rate limit configuration" in str(exc)
    else:
        raise AssertionError("Expected invalid legacy limits to fail closed")

    assert create_signing_log.calls == []
    assert create_rate_limited_log.calls == []


def test_sign_event_defaults_to_newest_key_with_matching_permission():
    services, create_signing_log, _ = _load_services_module()

    async def get_permissions(wallet_id):
        return [
            SimpleNamespace(
                id="permission-b",
                key_id="key-b",
                extension_id="cyberherd_messaging",
                kind=1,
                rate_limit_count=None,
                rate_limit_seconds=None,
            )
        ]

    services.get_permissions = get_permissions

    signed = asyncio.run(
        services.sign_event(
            wallet_id="wallet-1",
            extension_id="cyberherd_messaging",
            unsigned_event={"kind": 1, "tags": [], "content": "hello"},
        )
    )

    assert signed["pubkey"] == "pubkey-b"
    assert create_signing_log.calls == [
        ("key-b", "cyberherd_messaging", 1, "dummy-event-id")
    ]
