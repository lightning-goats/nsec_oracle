import importlib.util
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError


def _load_models_module():
    models_path = Path(__file__).resolve().parents[1] / "models.py"
    spec = importlib.util.spec_from_file_location(
        "nsec_oracle_models_under_test", models_path
    )
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_oracle_key_dict_keeps_database_secret_fields():
    models = _load_models_module()

    key = models.OracleKey(
        id="key-1",
        wallet="wallet-1",
        pubkey_hex="pubkey-1",
        encrypted_nsec="encrypted",
        created_at=datetime.now(timezone.utc),
    )

    payload = key.dict()

    assert payload["encrypted_nsec"] == "encrypted"
    assert "stored" not in payload


def test_public_oracle_key_strips_secret_and_reports_storage_state():
    models = _load_models_module()

    key = models.OracleKey(
        id="key-1",
        wallet="wallet-1",
        pubkey_hex="pubkey-1",
        encrypted_nsec="encrypted",
        created_at=datetime.now(timezone.utc),
    )

    payload = models.PublicOracleKey.from_oracle_key(key).dict()

    assert payload["stored"] is True
    assert "encrypted_nsec" not in payload


def test_sign_event_data_preserves_optional_key_id():
    models = _load_models_module()

    payload = models.SignEventData(
        extension_id="consumer",
        key_id="key-2",
        event={"kind": 1},
    ).dict()

    assert payload["key_id"] == "key-2"


@pytest.mark.parametrize(
    ("model_name", "payload"),
    [
        (
            "CreatePermissionData",
            {
                "extension_id": "consumer",
                "key_id": "key-1",
                "kind": 1,
                "rate_limit_count": 0,
                "rate_limit_seconds": 60,
            },
        ),
        (
            "CreatePermissionData",
            {
                "extension_id": "consumer",
                "key_id": "key-1",
                "kind": 1,
                "rate_limit_count": 10,
            },
        ),
        (
            "UpdatePermissionData",
            {"rate_limit_count": -1, "rate_limit_seconds": 60},
        ),
        (
            "UpdatePermissionData",
            {"rate_limit_seconds": 60},
        ),
    ],
)
def test_permission_rate_limits_require_positive_complete_pairs(model_name, payload):
    models = _load_models_module()

    with pytest.raises(ValidationError):
        getattr(models, model_name)(**payload)


def test_permission_rate_limits_allow_unlimited_or_positive_pairs():
    models = _load_models_module()

    unlimited = models.CreatePermissionData(
        extension_id="consumer",
        key_id="key-1",
        kind=1,
    )
    limited = models.UpdatePermissionData(
        rate_limit_count=10,
        rate_limit_seconds=60,
    )
    cleared = models.UpdatePermissionData(
        rate_limit_count=None,
        rate_limit_seconds=None,
    )

    assert unlimited.rate_limit_count is None
    assert limited.rate_limit_seconds == 60
    assert cleared.rate_limit_count is None
