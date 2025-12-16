"""Tests for the init feature - initializing configuration."""

from unittest.mock import patch

from click.testing import CliRunner

from kseal.cli import main
from kseal.config import CONFIG_FILE_NAME, clear_config_cache


class TestInit:
    def test_creates_config_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        clear_config_cache()

        with patch("kseal.github.get_latest_version", return_value="0.27.0"):
            runner = CliRunner()
            result = runner.invoke(main, ["init"])

        assert result.exit_code == 0
        assert "Created" in result.output
        assert (tmp_path / CONFIG_FILE_NAME).exists()

    def test_config_file_has_expected_keys(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        clear_config_cache()

        with patch("kseal.github.get_latest_version", return_value="0.27.0"):
            runner = CliRunner()
            runner.invoke(main, ["init"])

        content = (tmp_path / CONFIG_FILE_NAME).read_text()
        assert "version" in content
        assert "0.27.0" in content
        assert "controller_name" in content
        assert "controller_namespace" in content
        assert "unsealed_dir" in content

    def test_fails_when_config_exists(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        clear_config_cache()

        (tmp_path / CONFIG_FILE_NAME).write_text("existing: config")

        runner = CliRunner()
        result = runner.invoke(main, ["init"])

        assert result.exit_code == 1
        assert "already exists" in result.output

    def test_force_overwrites_existing_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        clear_config_cache()

        (tmp_path / CONFIG_FILE_NAME).write_text("old: config")

        with patch("kseal.github.get_latest_version", return_value="0.27.0"):
            runner = CliRunner()
            result = runner.invoke(main, ["init", "--force"])

        assert result.exit_code == 0
        assert "Created" in result.output

        content = (tmp_path / CONFIG_FILE_NAME).read_text()
        assert "old:" not in content
        assert "version" in content


class TestMainHelp:
    def test_shows_available_commands(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])

        assert result.exit_code == 0
        assert "cat" in result.output
        assert "encrypt" in result.output
        assert "export" in result.output
        assert "init" in result.output
        assert "version" in result.output

    def test_shows_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])

        assert result.exit_code == 0
