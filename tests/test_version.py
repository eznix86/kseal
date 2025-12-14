"""Tests for the version command group."""

from unittest.mock import patch

from click.testing import CliRunner

from kseal.cli import main


class TestVersionList:
    """Test kseal version list command."""

    def test_shows_no_versions_message(self, tmp_path, monkeypatch):
        import kseal.settings as settings_module

        settings_dir = tmp_path / "kseal"
        settings_file = settings_dir / "settings.yaml"
        monkeypatch.setattr(settings_module, "SETTINGS_DIR", settings_dir)
        monkeypatch.setattr(settings_module, "SETTINGS_FILE", settings_file)

        runner = CliRunner()
        result = runner.invoke(main, ["version", "list"])

        assert result.exit_code == 0
        assert "No kubeseal versions downloaded" in result.output

    def test_lists_downloaded_versions(self, tmp_path, monkeypatch):
        import kseal.settings as settings_module

        settings_dir = tmp_path / "kseal"
        settings_file = settings_dir / "settings.yaml"
        monkeypatch.setattr(settings_module, "SETTINGS_DIR", settings_dir)
        monkeypatch.setattr(settings_module, "SETTINGS_FILE", settings_file)

        settings_dir.mkdir(parents=True, exist_ok=True)
        settings_file.write_text(
            "downloaded_versions:\n  - 0.25.0\n  - 0.24.0\nkubeseal_version_default: ''\n"
        )

        runner = CliRunner()
        result = runner.invoke(main, ["version", "list"])

        assert result.exit_code == 0
        assert "0.25.0" in result.output
        assert "0.24.0" in result.output

    def test_marks_default_version(self, tmp_path, monkeypatch):
        import kseal.settings as settings_module

        settings_dir = tmp_path / "kseal"
        settings_file = settings_dir / "settings.yaml"
        monkeypatch.setattr(settings_module, "SETTINGS_DIR", settings_dir)
        monkeypatch.setattr(settings_module, "SETTINGS_FILE", settings_file)

        settings_dir.mkdir(parents=True, exist_ok=True)
        settings_file.write_text(
            "downloaded_versions:\n  - 0.25.0\n  - 0.24.0\nkubeseal_version_default: 0.24.0\n"
        )

        runner = CliRunner()
        result = runner.invoke(main, ["version", "list"])

        assert result.exit_code == 0
        assert "default" in result.output


class TestVersionUpdate:
    """Test kseal version update command."""

    def test_downloads_latest_version(self, tmp_path, monkeypatch):
        import kseal.settings as settings_module

        settings_dir = tmp_path / "kseal"
        settings_file = settings_dir / "settings.yaml"
        monkeypatch.setattr(settings_module, "SETTINGS_DIR", settings_dir)
        monkeypatch.setattr(settings_module, "SETTINGS_FILE", settings_file)

        with (
            patch("kseal.cli.get_latest_version", return_value="0.33.1"),
            patch("kseal.cli.get_default_binary_path") as mock_path,
            patch("kseal.cli.download_kubeseal") as mock_download,
        ):
            mock_path.return_value.exists.return_value = False

            runner = CliRunner()
            runner.invoke(main, ["version", "update"])

            mock_download.assert_called_once()

    def test_skips_download_when_already_exists(self, tmp_path, monkeypatch):
        import kseal.settings as settings_module

        settings_dir = tmp_path / "kseal"
        settings_file = settings_dir / "settings.yaml"
        monkeypatch.setattr(settings_module, "SETTINGS_DIR", settings_dir)
        monkeypatch.setattr(settings_module, "SETTINGS_FILE", settings_file)

        with (
            patch("kseal.cli.get_latest_version", return_value="0.33.1"),
            patch("kseal.cli.get_default_binary_path") as mock_path,
            patch("kseal.cli.download_kubeseal") as mock_download,
        ):
            mock_path.return_value.exists.return_value = True

            runner = CliRunner()
            result = runner.invoke(main, ["version", "update"])

            assert result.exit_code == 0
            assert "Already up to date" in result.output
            mock_download.assert_not_called()


class TestVersionSet:
    """Test kseal version set command."""

    def test_sets_specific_version(self, tmp_path, monkeypatch):
        import kseal.settings as settings_module

        settings_dir = tmp_path / "kseal"
        settings_file = settings_dir / "settings.yaml"
        monkeypatch.setattr(settings_module, "SETTINGS_DIR", settings_dir)
        monkeypatch.setattr(settings_module, "SETTINGS_FILE", settings_file)

        runner = CliRunner()
        result = runner.invoke(main, ["version", "set", "0.25.0"])

        assert result.exit_code == 0
        assert "0.25.0" in result.output

        settings = settings_module.load_settings()
        assert settings["kubeseal_version_default"] == "0.25.0"

    def test_clears_default_version(self, tmp_path, monkeypatch):
        import kseal.settings as settings_module

        settings_dir = tmp_path / "kseal"
        settings_file = settings_dir / "settings.yaml"
        monkeypatch.setattr(settings_module, "SETTINGS_DIR", settings_dir)
        monkeypatch.setattr(settings_module, "SETTINGS_FILE", settings_file)

        # Set a version first
        settings_dir.mkdir(parents=True, exist_ok=True)
        settings_file.write_text(
            "downloaded_versions: []\nkubeseal_version_default: 0.25.0\n"
        )

        runner = CliRunner()
        result = runner.invoke(main, ["version", "set", "--clear"])

        assert result.exit_code == 0
        assert "Cleared default" in result.output

        settings = settings_module.load_settings()
        assert settings["kubeseal_version_default"] == ""

    def test_requires_version_or_clear(self, tmp_path, monkeypatch):
        import kseal.settings as settings_module

        settings_dir = tmp_path / "kseal"
        settings_file = settings_dir / "settings.yaml"
        monkeypatch.setattr(settings_module, "SETTINGS_DIR", settings_dir)
        monkeypatch.setattr(settings_module, "SETTINGS_FILE", settings_file)

        runner = CliRunner()
        result = runner.invoke(main, ["version", "set"])

        assert result.exit_code == 2
        assert "Provide a version or use --clear" in result.output


class TestVersionHelp:
    """Test version command group help."""

    def test_shows_version_subcommands(self):
        runner = CliRunner()
        result = runner.invoke(main, ["version", "--help"])

        assert result.exit_code == 0
        assert "list" in result.output
        assert "update" in result.output
        assert "set" in result.output
