import asyncio
import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace


def _load_crud_module():
    package_name = "nsec_oracle_crud_testpkg"
    base_path = Path(__file__).resolve().parents[1]

    package = types.ModuleType(package_name)
    package.__path__ = []  # type: ignore[attr-defined]
    sys.modules[package_name] = package

    lnbits = types.ModuleType("lnbits")
    lnbits_db = types.ModuleType("lnbits.db")
    lnbits_helpers = types.ModuleType("lnbits.helpers")

    class Database:
        def __init__(self, name):
            self.name = name
            self.inserts = []

        async def insert(self, table_name, model):
            self.inserts.append((table_name, model))

    lnbits_db.Database = Database
    lnbits_helpers.decrypt_internal_message = lambda value: value
    lnbits_helpers.encrypt_internal_message = lambda value: f"encrypted:{value}"
    lnbits_helpers.urlsafe_short_hash = lambda: "id-1"
    sys.modules["lnbits"] = lnbits
    sys.modules["lnbits.db"] = lnbits_db
    sys.modules["lnbits.helpers"] = lnbits_helpers

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

    crud_spec = importlib.util.spec_from_file_location(
        f"{package_name}.crud", base_path / "crud.py"
    )
    crud = importlib.util.module_from_spec(crud_spec)
    assert crud_spec is not None and crud_spec.loader is not None
    sys.modules[f"{package_name}.crud"] = crud
    crud_spec.loader.exec_module(crud)
    return crud, models


def test_create_permission_rejects_key_from_another_wallet():
    crud, models = _load_crud_module()

    async def get_key(key_id):
        return SimpleNamespace(id=key_id, wallet="wallet-2")

    crud.get_key = get_key

    try:
        asyncio.run(
            crud.create_permission(
                "wallet-1",
                models.CreatePermissionData(
                    extension_id="cyberherd_messaging",
                    key_id="key-1",
                    kind=1,
                ),
            )
        )
    except LookupError as exc:
        assert "not found for wallet" in str(exc)
    else:
        raise AssertionError("create_permission accepted a foreign key")
