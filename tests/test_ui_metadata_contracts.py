import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_kind_zero_keeps_sensitive_warning_and_description():
    source = (ROOT / "static/js/index.js").read_text()

    assert "if (this.permForm.kind === null)" in source
    assert "if (!this.permForm.kind)" not in source


def test_extension_metadata_references_tracked_assets():
    config = json.loads((ROOT / "config.json").read_text())

    assert config["tile"] == "/nsecbunker/static/image/nsecbunker.png"
    assert (ROOT / "static/image/nsecbunker.png").is_file()
    assert config["description_md"].endswith(
        "/lightning-goats/nsecbunker/main/description.md"
    )
    assert (ROOT / "description.md").is_file()
