"""Global settings management for kseal.

Manages the settings.yaml file in ~/.local/share/kseal/ which tracks:
- downloaded_versions: List of all downloaded kubeseal versions
- kubeseal_version_default: The default version to use (empty = use highest)
"""

from pathlib import Path
from typing import Any

from packaging.version import Version
from pydantic import BaseModel

from .yaml_utils import yaml

SETTINGS_DIR = Path.home() / ".local" / "share" / "kseal"
SETTINGS_FILE = SETTINGS_DIR / "settings.yaml"


class Settings(BaseModel):
    """Global kseal settings."""

    downloaded_versions: list[str] = []
    kubeseal_version_default: str = ""


def load_settings() -> Settings:
    """Load global settings from settings.yaml."""
    if not SETTINGS_FILE.exists():
        return Settings()

    with open(SETTINGS_FILE) as f:
        data: dict[str, Any] = yaml.load(f) or {}

    return Settings(**data)


def save_settings(settings: Settings) -> None:
    """Save global settings to settings.yaml."""
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        yaml.dump(settings.model_dump(), f)


def _sort_versions(versions: list[str]) -> list[str]:
    """Sort versions in descending order (highest first)."""
    return sorted(versions, key=Version, reverse=True)


def add_downloaded_version(version: str) -> None:
    """Add a version to the downloaded list."""
    settings = load_settings()
    if version not in settings.downloaded_versions:
        versions = settings.downloaded_versions + [version]
        settings.downloaded_versions = _sort_versions(versions)
        save_settings(settings)


def get_downloaded_versions() -> list[str]:
    """Get list of downloaded versions (sorted highest first)."""
    settings = load_settings()
    return _sort_versions(settings.downloaded_versions)


def get_default_version() -> str | None:
    """Get the default version (explicit or highest downloaded).

    Returns:
        The default version string, or None if no versions available.
    """
    settings = load_settings()

    # Explicit default takes priority
    if settings.kubeseal_version_default:
        return settings.kubeseal_version_default

    # Fall back to highest downloaded version
    if settings.downloaded_versions:
        return _sort_versions(settings.downloaded_versions)[0]

    return None


def set_default_version(version: str) -> None:
    """Set the global default version."""
    settings = load_settings()
    settings.kubeseal_version_default = version
    save_settings(settings)


def clear_default_version() -> None:
    """Clear the global default version (use highest downloaded)."""
    settings = load_settings()
    settings.kubeseal_version_default = ""
    save_settings(settings)
