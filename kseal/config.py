"""Configuration management via config file and environment variables.

Priority order (highest to lowest):
1. Environment variables
2. .kseal-config.yaml in current directory
3. Default values
"""

import os
from pathlib import Path

from ruamel.yaml import YAML

CONFIG_FILE_NAME = ".kseal-config.yaml"

DEFAULTS = {
    "version": "",  # Empty means use global default or highest downloaded
    "controller_name": "sealed-secrets",
    "controller_namespace": "sealed-secrets",
    "unsealed_dir": ".unsealed",
}

_config_cache: dict | None = None


def _load_config_file() -> dict:
    """Load configuration from .kseal-config.yaml if it exists."""
    global _config_cache

    if _config_cache is not None:
        return _config_cache

    config_path = Path.cwd() / CONFIG_FILE_NAME
    if not config_path.exists():
        _config_cache = {}
        return _config_cache

    yaml = YAML()
    with open(config_path) as f:
        _config_cache = yaml.load(f) or {}

    return _config_cache


def clear_config_cache() -> None:
    """Clear the config cache (useful for testing or after init)."""
    global _config_cache
    _config_cache = None


def get_config_value(key: str, env_var: str) -> str:
    """Get a config value with priority: env > file > default."""
    env_value = os.environ.get(env_var)
    if env_value:
        return env_value

    file_config = _load_config_file()
    if key in file_config:
        return str(file_config[key])

    return DEFAULTS[key]


def get_version() -> str:
    """Get the kubeseal version."""
    return get_config_value("version", "KSEAL_VERSION")


def get_controller_name() -> str:
    """Get the sealed-secrets controller name."""
    return get_config_value("controller_name", "KSEAL_CONTROLLER_NAME")


def get_controller_namespace() -> str:
    """Get the sealed-secrets controller namespace."""
    return get_config_value("controller_namespace", "KSEAL_CONTROLLER_NAMESPACE")


def get_unsealed_dir() -> Path:
    """Get the default directory for unsealed secrets."""
    return Path(get_config_value("unsealed_dir", "KSEAL_UNSEALED_DIR"))


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
    # Import here to avoid circular import
    from .binary import get_latest_version

    config_path = Path.cwd() / CONFIG_FILE_NAME

    if config_path.exists() and not overwrite:
        raise FileExistsError(f"Config file already exists: {config_path}")

    yaml = YAML()
    yaml.default_flow_style = False

    # Fetch actual latest version from GitHub
    version = get_latest_version()

    config_content = {
        "version": version,
        "controller_name": DEFAULTS["controller_name"],
        "controller_namespace": DEFAULTS["controller_namespace"],
        "unsealed_dir": DEFAULTS["unsealed_dir"],
    }

    with open(config_path, "w") as f:
        yaml.dump(config_content, f)

    clear_config_cache()

    return config_path
