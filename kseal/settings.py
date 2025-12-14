"""Global settings management for kseal.

Manages the settings.yaml file in ~/.local/share/kseal/ which tracks:
- downloaded_versions: List of all downloaded kubeseal versions
- kubeseal_version_default: The default version to use (empty = use highest)
"""

from pathlib import Path

from packaging.version import Version
from ruamel.yaml import YAML

SETTINGS_DIR = Path.home() / ".local" / "share" / "kseal"
SETTINGS_FILE = SETTINGS_DIR / "settings.yaml"


def _default_settings() -> dict:
    """Return default settings structure."""
    return {
        "downloaded_versions": [],
        "kubeseal_version_default": "",
    }


def load_settings() -> dict:
    """Load global settings from settings.yaml."""
    if not SETTINGS_FILE.exists():
        return _default_settings()

    yaml = YAML()
    with open(SETTINGS_FILE) as f:
        data = yaml.load(f)

    if data is None:
        return _default_settings()

    # Ensure all keys exist
    defaults = _default_settings()
    for key in defaults:
        if key not in data:
            data[key] = defaults[key]

    return data


def save_settings(settings: dict) -> None:
    """Save global settings to settings.yaml."""
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    yaml = YAML()
    yaml.default_flow_style = False
    with open(SETTINGS_FILE, "w") as f:
        yaml.dump(settings, f)


def _sort_versions(versions: list[str]) -> list[str]:
    """Sort versions in descending order (highest first)."""
    return sorted(versions, key=Version, reverse=True)


def add_downloaded_version(version: str) -> None:
    """Add a version to the downloaded list."""
    settings = load_settings()
    if version not in settings["downloaded_versions"]:
        settings["downloaded_versions"].append(version)
        settings["downloaded_versions"] = _sort_versions(settings["downloaded_versions"])
        save_settings(settings)


def get_downloaded_versions() -> list[str]:
    """Get list of downloaded versions (sorted highest first)."""
    settings = load_settings()
    return _sort_versions(settings["downloaded_versions"])


def get_default_version() -> str | None:
    """Get the default version (explicit or highest downloaded).

    Returns:
        The default version string, or None if no versions available.
    """
    settings = load_settings()

    # Explicit default takes priority
    if settings["kubeseal_version_default"]:
        return settings["kubeseal_version_default"]

    # Fall back to highest downloaded version
    versions = settings["downloaded_versions"]
    if versions:
        return _sort_versions(versions)[0]

    return None


def set_default_version(version: str) -> None:
    """Set the global default version."""
    settings = load_settings()
    settings["kubeseal_version_default"] = version
    save_settings(settings)


def clear_default_version() -> None:
    """Clear the global default version (use highest downloaded)."""
    settings = load_settings()
    settings["kubeseal_version_default"] = ""
    save_settings(settings)
