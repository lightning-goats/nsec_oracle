import asyncio
import importlib.util
import inspect
import sys
import types
from pathlib import Path
from types import SimpleNamespace


def _load_views_api_module():
    package_name = "nsec_oracle_api_testpkg"
    base_path = Path(__file__).resolve().parents[1]

    package = types.ModuleType(package_name)
    package.__path__ = []  # type: ignore[attr-defined]
    sys.modules[package_name] = package

    lnbits = types.ModuleType("lnbits")
    lnbits_core = types.ModuleType("lnbits.core")
    lnbits_core_models = types.ModuleType("lnbits.core.models")
    lnbits_core_models.WalletTypeInfo = SimpleNamespace
    lnbits_decorators = types.ModuleType("lnbits.decorators")

    def require_admin_key():
        return None

    def require_invoice_key():
        return None

    lnbits_decorators.require_admin_key = require_admin_key
    lnbits_decorators.require_invoice_key = require_invoice_key
    sys.modules["lnbits"] = lnbits
    sys.modules["lnbits.core"] = lnbits_core
    sys.modules["lnbits.core.models"] = lnbits_core_models
    sys.modules["lnbits.decorators"] = lnbits_decorators

    loguru = types.ModuleType("loguru")
    loguru.logger = SimpleNamespace(error=lambda *a, **k: None)
    sys.modules["loguru"] = loguru

    pynostr = types.ModuleType("pynostr")
    pynostr_key = types.ModuleType("pynostr.key")

    class PrivateKey:
        def __init__(self, *args, **kwargs):
            self.nsec = "nsec1dummy"

        def hex(self):
            return "00" * 32

    pynostr_key.PrivateKey = PrivateKey
    pynostr.key = pynostr_key  # type: ignore[attr-defined]
    sys.modules["pynostr"] = pynostr
    sys.modules["pynostr.key"] = pynostr_key

    crud = types.ModuleType(f"{package_name}.crud")

    async def async_none(*args, **kwargs):
        return None

    async def async_list(*args, **kwargs):
        return []

    for name in (
        "count_signing_logs",
        "create_key",
        "create_permission",
        "delete_key",
        "delete_permission",
        "delete_permissions_for_key",
        "get_decrypted_private_key",
        "get_key",
        "get_permission",
        "update_key",
        "update_permission",
    ):
        setattr(crud, name, async_none)
    crud.get_keys = async_list
    crud.get_permissions = async_list
    crud.get_signing_logs = async_list
    sys.modules[f"{package_name}.crud"] = crud

    discovery = types.ModuleType(f"{package_name}.discovery")
    discovery.discover_signing_requirements = lambda: []
    sys.modules[f"{package_name}.discovery"] = discovery

    helpers = types.ModuleType(f"{package_name}.helpers")
    helpers.parse_nostr_private_key = lambda key: key
    sys.modules[f"{package_name}.helpers"] = helpers

    models_spec = importlib.util.spec_from_file_location(
        f"{package_name}.models", base_path / "models.py"
    )
    models = importlib.util.module_from_spec(models_spec)
    assert models_spec is not None and models_spec.loader is not None
    sys.modules[f"{package_name}.models"] = models
    models_spec.loader.exec_module(models)

    services = types.ModuleType(f"{package_name}.services")
    for name in (
        "get_wallet_pubkey",
        "nip04_decrypt",
        "nip04_encrypt",
        "nip44_decrypt",
        "nip44_encrypt",
        "sign_event",
    ):
        setattr(services, name, async_none)
    sys.modules[f"{package_name}.services"] = services

    views_spec = importlib.util.spec_from_file_location(
        f"{package_name}.views_api", base_path / "views_api.py"
    )
    views_api = importlib.util.module_from_spec(views_spec)
    assert views_spec is not None and views_spec.loader is not None
    sys.modules[f"{package_name}.views_api"] = views_api
    views_spec.loader.exec_module(views_api)
    return views_api, require_admin_key


def _wallet_dependency(endpoint):
    return inspect.signature(endpoint).parameters["wallet"].default.dependency


def test_high_impact_rest_operations_require_admin_key():
    views_api, require_admin_key = _load_views_api_module()

    assert _wallet_dependency(views_api.api_sign_event) is require_admin_key
    assert _wallet_dependency(views_api.api_nip04_encrypt) is require_admin_key
    assert _wallet_dependency(views_api.api_nip04_decrypt) is require_admin_key
    assert _wallet_dependency(views_api.api_nip44_encrypt) is require_admin_key
    assert _wallet_dependency(views_api.api_nip44_decrypt) is require_admin_key


def test_sign_endpoint_forwards_requested_key_id():
    views_api, _ = _load_views_api_module()
    calls = []

    async def sign_event(**kwargs):
        calls.append(kwargs)
        return {"id": "event-id"}

    views_api.sign_event = sign_event
    data = views_api.SignEventData(
        extension_id="consumer",
        key_id="key-2",
        event={"kind": 1},
    )
    wallet = SimpleNamespace(wallet=SimpleNamespace(id="wallet-1"))

    asyncio.run(views_api.api_sign_event(data=data, wallet=wallet))

    assert calls == [
        {
            "wallet_id": "wallet-1",
            "extension_id": "consumer",
            "unsigned_event": {"kind": 1},
            "key_id": "key-2",
        }
    ]


def test_discovery_checks_permissions_for_default_key():
    views_api, _ = _load_views_api_module()

    async def get_keys(wallet_id):
        return [
            SimpleNamespace(id="new-key"),
            SimpleNamespace(id="old-key"),
        ]

    async def get_permissions(wallet_id):
        return [
            SimpleNamespace(
                extension_id="consumer",
                key_id="old-key",
                kind=1,
            )
        ]

    views_api.get_keys = get_keys
    views_api.get_permissions = get_permissions
    views_api.discover_signing_requirements = lambda: [
        SimpleNamespace(
            extension_id="consumer",
            extension_name="Consumer",
            requirements=[
                SimpleNamespace(
                    kind=1,
                    kind_label="Text Note",
                    description="Publish notes",
                    required=True,
                    recommended_rate_limit=None,
                )
            ],
        )
    ]
    wallet = SimpleNamespace(wallet=SimpleNamespace(id="wallet-1"))

    discovered = asyncio.run(views_api.api_discover(wallet=wallet))

    assert discovered[0]["requirements"][0]["already_granted"] is False
