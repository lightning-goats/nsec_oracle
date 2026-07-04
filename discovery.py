import json
from pathlib import Path

from loguru import logger
from pydantic import BaseModel

from lnbits.settings import settings


class RecommendedRateLimit(BaseModel):
    count: int
    seconds: int


class SigningRequirement(BaseModel):
    kind: int
    kind_label: str
    description: str
    required: bool = False
    recommended_rate_limit: RecommendedRateLimit | None = None


class ExtensionSigningInfo(BaseModel):
    extension_id: str
    extension_name: str
    requirements: list[SigningRequirement]


def discover_signing_requirements() -> list[ExtensionSigningInfo]:
    extensions_dir = Path(settings.lnbits_extensions_path, "extensions")
    if not extensions_dir.is_dir():
        logger.warning(f"nsec_oracle: extensions directory not found: {extensions_dir}")
        return []

    results: list[ExtensionSigningInfo] = []

    for entry in sorted(extensions_dir.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name == "nsec_oracle":
            continue

        config_path = entry / "config.json"
        if not config_path.is_file():
            continue

        try:
            with open(config_path) as f:
                config = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug(f"nsec_oracle: skipping {entry.name}/config.json: {exc}")
            continue

        nostr_signing = config.get("nostr_signing")
        if not nostr_signing or not isinstance(nostr_signing, list):
            continue

        try:
            requirements = [SigningRequirement(**item) for item in nostr_signing]
        except Exception as exc:
            logger.warning(
                f"nsec_oracle: invalid nostr_signing in {entry.name}: {exc}"
            )
            continue

        results.append(
            ExtensionSigningInfo(
                extension_id=entry.name,
                extension_name=config.get("name", entry.name),
                requirements=requirements,
            )
        )

    return results
