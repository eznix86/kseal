"""Tests for global settings management."""

import pytest

from kseal.settings import (
    add_downloaded_version,
    clear_default_version,
    get_default_version,
    get_downloaded_versions,
    load_settings,
    save_settings,
    set_default_version,
)


@pytest.fixture
def isolated_settings(tmp_path, monkeypatch):
    """Isolate settings to a temp directory by patching the module constants."""
    import kseal.settings as settings_module

    settings_dir = tmp_path / "kseal"
    settings_file = settings_dir / "settings.yaml"
    monkeypatch.setattr(settings_module, "SETTINGS_DIR", settings_dir)
    monkeypatch.setattr(settings_module, "SETTINGS_FILE", settings_file)
    return settings_dir, settings_file


class TestLoadSettings:
    """Test loading settings from file."""

    def test_returns_defaults_when_file_not_exists(self, isolated_settings):
        settings_dir, settings_file = isolated_settings

        result = load_settings()

        assert result == {
            "downloaded_versions": [],
            "kubeseal_version_default": "",
        }

    def test_loads_existing_settings(self, isolated_settings):
        settings_dir, settings_file = isolated_settings
        settings_dir.mkdir(parents=True, exist_ok=True)
        settings_file.write_text(
            "downloaded_versions:\n  - 0.25.0\n  - 0.24.0\nkubeseal_version_default: 0.25.0\n"
        )

        result = load_settings()

        assert result["downloaded_versions"] == ["0.25.0", "0.24.0"]
        assert result["kubeseal_version_default"] == "0.25.0"

    def test_adds_missing_keys(self, isolated_settings):
        settings_dir, settings_file = isolated_settings
        settings_dir.mkdir(parents=True, exist_ok=True)
        settings_file.write_text("downloaded_versions:\n  - 0.25.0\n")

        result = load_settings()

        assert result["downloaded_versions"] == ["0.25.0"]
        assert result["kubeseal_version_default"] == ""

    def test_handles_empty_file(self, isolated_settings):
        settings_dir, settings_file = isolated_settings
        settings_dir.mkdir(parents=True, exist_ok=True)
        settings_file.write_text("")

        result = load_settings()

        assert result == {
            "downloaded_versions": [],
            "kubeseal_version_default": "",
        }


class TestSaveSettings:
    """Test saving settings to file."""

    def test_creates_directory_if_not_exists(self, isolated_settings):
        settings_dir, settings_file = isolated_settings

        save_settings({"downloaded_versions": ["0.25.0"], "kubeseal_version_default": ""})

        assert settings_dir.exists()
        assert settings_file.exists()

    def test_saves_settings_correctly(self, isolated_settings):
        settings_dir, settings_file = isolated_settings

        save_settings({
            "downloaded_versions": ["0.25.0", "0.24.0"],
            "kubeseal_version_default": "0.25.0",
        })

        content = settings_file.read_text()
        assert "0.25.0" in content
        assert "0.24.0" in content


class TestAddDownloadedVersion:
    """Test adding downloaded versions."""

    def test_adds_new_version(self, isolated_settings):
        add_downloaded_version("0.25.0")

        versions = get_downloaded_versions()
        assert "0.25.0" in versions

    def test_does_not_duplicate_version(self, isolated_settings):
        add_downloaded_version("0.25.0")
        add_downloaded_version("0.25.0")

        versions = get_downloaded_versions()
        assert versions.count("0.25.0") == 1

    def test_sorts_versions_descending(self, isolated_settings):
        add_downloaded_version("0.24.0")
        add_downloaded_version("0.25.0")
        add_downloaded_version("0.23.5")

        versions = get_downloaded_versions()
        assert versions == ["0.25.0", "0.24.0", "0.23.5"]


class TestGetDownloadedVersions:
    """Test getting list of downloaded versions."""

    def test_returns_empty_list_when_none(self, isolated_settings):
        versions = get_downloaded_versions()

        assert versions == []

    def test_returns_sorted_versions(self, isolated_settings):
        settings_dir, settings_file = isolated_settings
        settings_dir.mkdir(parents=True, exist_ok=True)
        settings_file.write_text(
            "downloaded_versions:\n  - 0.24.0\n  - 0.25.0\n  - 0.23.0\n"
            "kubeseal_version_default: ''\n"
        )

        versions = get_downloaded_versions()

        assert versions == ["0.25.0", "0.24.0", "0.23.0"]


class TestGetDefaultVersion:
    """Test getting default version."""

    def test_returns_none_when_no_versions(self, isolated_settings):
        result = get_default_version()

        assert result is None

    def test_returns_explicit_default(self, isolated_settings):
        settings_dir, settings_file = isolated_settings
        settings_dir.mkdir(parents=True, exist_ok=True)
        settings_file.write_text(
            "downloaded_versions:\n  - 0.25.0\n  - 0.24.0\nkubeseal_version_default: 0.24.0\n"
        )

        result = get_default_version()

        assert result == "0.24.0"

    def test_returns_highest_downloaded_when_no_explicit_default(self, isolated_settings):
        settings_dir, settings_file = isolated_settings
        settings_dir.mkdir(parents=True, exist_ok=True)
        settings_file.write_text(
            "downloaded_versions:\n  - 0.24.0\n  - 0.25.0\nkubeseal_version_default: ''\n"
        )

        result = get_default_version()

        assert result == "0.25.0"


class TestSetDefaultVersion:
    """Test setting default version."""

    def test_sets_default_version(self, isolated_settings):
        set_default_version("0.25.0")

        settings = load_settings()
        assert settings["kubeseal_version_default"] == "0.25.0"

    def test_overwrites_existing_default(self, isolated_settings):
        set_default_version("0.24.0")
        set_default_version("0.25.0")

        settings = load_settings()
        assert settings["kubeseal_version_default"] == "0.25.0"


class TestClearDefaultVersion:
    """Test clearing default version."""

    def test_clears_default_version(self, isolated_settings):
        set_default_version("0.25.0")

        clear_default_version()

        settings = load_settings()
        assert settings["kubeseal_version_default"] == ""

    def test_clears_when_no_default_set(self, isolated_settings):
        clear_default_version()

        settings = load_settings()
        assert settings["kubeseal_version_default"] == ""
