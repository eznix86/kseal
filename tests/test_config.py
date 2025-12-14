"""Tests for configuration loading and priority."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from kseal.config import (
    CONFIG_FILE_NAME,
    clear_config_cache,
    get_controller_name,
    get_controller_namespace,
    get_unsealed_dir,
    get_version,
)


@pytest.fixture(autouse=True)
def reset_cache():
    """Clear config cache before and after each test."""
    clear_config_cache()
    yield
    clear_config_cache()


class TestConfigPriority:
    """Test that config values follow priority: env var > file > default."""

    def test_returns_default_when_no_env_or_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        result = get_controller_name()

        assert result == "sealed-secrets"

    def test_file_takes_priority_over_default(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        (tmp_path / CONFIG_FILE_NAME).write_text("controller_name: file-controller")

        result = get_controller_name()

        assert result == "file-controller"

    def test_env_takes_priority_over_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        (tmp_path / CONFIG_FILE_NAME).write_text("controller_name: file-controller")

        with patch.dict(os.environ, {"KSEAL_CONTROLLER_NAME": "env-controller"}):
            result = get_controller_name()

        assert result == "env-controller"


class TestConfigValues:
    """Test that all config values can be loaded from file."""

    def test_version(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        (tmp_path / CONFIG_FILE_NAME).write_text("version: 0.26.0")

        assert get_version() == "0.26.0"

    def test_controller_name(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        (tmp_path / CONFIG_FILE_NAME).write_text("controller_name: my-controller")

        assert get_controller_name() == "my-controller"

    def test_controller_namespace(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        (tmp_path / CONFIG_FILE_NAME).write_text("controller_namespace: kube-system")

        assert get_controller_namespace() == "kube-system"

    def test_unsealed_dir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        (tmp_path / CONFIG_FILE_NAME).write_text("unsealed_dir: custom-unsealed")

        result = get_unsealed_dir()

        assert isinstance(result, Path)
        assert str(result) == "custom-unsealed"


class TestConfigDefaults:
    """Test default values when no config exists."""

    def test_version_default(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        assert get_version() == ""  # Empty means use global default or highest downloaded

    def test_controller_name_default(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        assert get_controller_name() == "sealed-secrets"

    def test_controller_namespace_default(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        assert get_controller_namespace() == "sealed-secrets"

    def test_unsealed_dir_default(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        result = get_unsealed_dir()

        assert isinstance(result, Path)
        assert str(result) == ".unsealed"
