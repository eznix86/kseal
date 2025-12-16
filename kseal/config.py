"""Configuration management via config file and environment variables.

Priority order (highest to lowest):
1. Environment variables
2. .kseal-config.yaml in current directory
3. Default values
"""

import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from .yaml_utils import yaml

CONFIG_FILE_NAME = ".kseal-config.yaml"


class Config(BaseModel):
    """Project configuration for kseal."""

    version: str = ""  # Empty means use global default or highest downloaded
    controller_name: str = "sealed-secrets"
    controller_namespace: str = "sealed-secrets"
    unsealed_dir: Path = Path(".unsealed")


_config_cache: dict[str, Any] | None = None


def _load_config_file() -> dict[str, Any]:
    """Load configuration from .kseal-config.yaml if it exists."""
    global _config_cache

    if _config_cache is not None:
        return _config_cache

    config_path = Path.cwd() / CONFIG_FILE_NAME
    if not config_path.exists():
        _config_cache = {}
        return _config_cache

    with open(config_path) as f:
        loaded: dict[str, Any] = yaml.load(f) or {}
        _config_cache = loaded

    return _config_cache


def clear_config_cache() -> None:
    """Clear the config cache (useful for testing or after init)."""
    global _config_cache
    _config_cache = None


def get_config() -> Config:
    """Get the full configuration with priority: env > file > default."""
    file_config = _load_config_file()
    defaults = Config()

    return Config(
        version=os.environ.get("KSEAL_VERSION") or file_config.get("version", defaults.version),
        controller_name=os.environ.get("KSEAL_CONTROLLER_NAME")
        or file_config.get("controller_name", defaults.controller_name),
        controller_namespace=os.environ.get("KSEAL_CONTROLLER_NAMESPACE")
        or file_config.get("controller_namespace", defaults.controller_namespace),
        unsealed_dir=Path(
            os.environ.get("KSEAL_UNSEALED_DIR")
            or file_config.get("unsealed_dir", str(defaults.unsealed_dir))
        ),
    )


def get_version() -> str:
    """Get the kubeseal version."""
    return get_config().version


def get_controller_name() -> str:
    """Get the sealed-secrets controller name."""
    return get_config().controller_name


def get_controller_namespace() -> str:
    """Get the sealed-secrets controller namespace."""
    return get_config().controller_namespace


def get_unsealed_dir() -> Path:
    """Get the default directory for unsealed secrets."""
    return get_config().unsealed_dir


def create_config_file(overwrite: bool = False) -> Path:
    """Create a .kseal-config.yaml file with default values.

    Fetches the latest kubeseal version from GitHub to write a specific version
    rather than "latest" keyword.

    Args:
        overwrite: If True, overwrite existing config file.

    Returns:
        Path to the created config file.

    Raises:
        FileExistsError: If config file exists and overwrite is False.
    """
    from .github import get_latest_version

    config_path = Path.cwd() / CONFIG_FILE_NAME

    if config_path.exists() and not overwrite:
        raise FileExistsError(f"Config file already exists: {config_path}")

    # Fetch actual latest version from GitHub
    version = get_latest_version()
    defaults = Config()

    config_content = {
        "version": version,
        "controller_name": defaults.controller_name,
        "controller_namespace": defaults.controller_namespace,
        "unsealed_dir": str(defaults.unsealed_dir),
    }

    with open(config_path, "w") as f:
        yaml.dump(config_content, f)

    clear_config_cache()

    return config_path
