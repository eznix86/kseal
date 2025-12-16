"""Tests for kubeseal binary management."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from kseal.binary import (
    get_binary_version,
    get_default_binary_dir,
    get_default_binary_path,
)


class TestGetDefaultBinaryDir:
    def test_returns_kseal_dir_in_home(self):
        result = get_default_binary_dir()

        assert result == Path.home() / ".local" / "share" / "kseal"


class TestGetDefaultBinaryPath:
    def test_includes_version_in_filename(self):
        result = get_default_binary_path("0.25.0")

        assert result == Path.home() / ".local" / "share" / "kseal" / "kubeseal-0.25.0"

    def test_different_versions_have_different_paths(self):
        path_a = get_default_binary_path("0.24.0")
        path_b = get_default_binary_path("0.25.0")

        assert path_a != path_b
        assert "kubeseal-0.24.0" in str(path_a)
        assert "kubeseal-0.25.0" in str(path_b)


class TestGetBinaryVersion:
    def test_parses_version_from_output(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "kubeseal version: 0.25.0"

        with patch("kseal.binary.subprocess.run", return_value=mock_result) as mock_run:
            result = get_binary_version(Path("/usr/bin/kubeseal"))

        assert result == "0.25.0"
        mock_run.assert_called_once()

    def test_parses_version_with_extra_whitespace(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "  kubeseal version: 0.33.1  \n"

        with patch("kseal.binary.subprocess.run", return_value=mock_result):
            result = get_binary_version(Path("/usr/bin/kubeseal"))

        assert result == "0.33.1"

    def test_returns_none_on_nonzero_exit(self):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("kseal.binary.subprocess.run", return_value=mock_result):
            result = get_binary_version(Path("/usr/bin/kubeseal"))

        assert result is None

    def test_returns_none_on_missing_version_string(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "some other output"

        with patch("kseal.binary.subprocess.run", return_value=mock_result):
            result = get_binary_version(Path("/usr/bin/kubeseal"))

        assert result is None

    def test_returns_none_on_exception(self):
        with patch("kseal.binary.subprocess.run", side_effect=Exception("error")):
            result = get_binary_version(Path("/usr/bin/kubeseal"))

        assert result is None

    def test_returns_none_on_timeout(self):
        import subprocess

        with patch("kseal.binary.subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 10)):
            result = get_binary_version(Path("/usr/bin/kubeseal"))

        assert result is None


class TestEnsureKubeseal:
    @patch("kseal.binary.get_version")
    @patch("kseal.binary.get_binary_version")
    @patch("kseal.binary.find_kubeseal_in_path")
    @patch("kseal.binary.download_kubeseal")
    def test_uses_existing_versioned_binary(
        self,
        mock_download,
        mock_find_system,
        mock_get_bin_ver,
        mock_get_version,
        tmp_path,
    ):
        from kseal.binary import ensure_kubeseal

        mock_get_version.return_value = "0.25.0"

        versioned_binary = tmp_path / ".local" / "share" / "kseal" / "kubeseal-0.25.0"
        versioned_binary.parent.mkdir(parents=True)
        versioned_binary.touch()

        mock_get_bin_ver.return_value = "0.25.0"

        with patch("kseal.binary.get_default_binary_path", return_value=versioned_binary):
            result = ensure_kubeseal()

        assert result == versioned_binary
        mock_download.assert_not_called()

    @patch("kseal.binary.get_version")
    @patch("kseal.binary.get_binary_version")
    @patch("kseal.binary.find_kubeseal_in_path")
    @patch("kseal.binary.download_kubeseal")
    def test_uses_system_path_when_version_matches(
        self,
        mock_download,
        mock_find_system,
        mock_get_bin_ver,
        mock_get_version,
        tmp_path,
    ):
        from kseal.binary import ensure_kubeseal

        mock_get_version.return_value = "0.25.0"

        # Default path doesn't exist
        default_path = tmp_path / "default" / "kubeseal-0.25.0"

        # System kubeseal exists with matching version
        system_kubeseal = tmp_path / "system" / "kubeseal"
        system_kubeseal.parent.mkdir(parents=True)
        system_kubeseal.touch()
        mock_find_system.return_value = system_kubeseal
        mock_get_bin_ver.return_value = "0.25.0"

        with patch("kseal.binary.get_default_binary_path", return_value=default_path):
            result = ensure_kubeseal()

        assert result == system_kubeseal
        mock_download.assert_not_called()

    @patch("kseal.binary.get_version")
    @patch("kseal.binary.get_binary_version")
    @patch("kseal.binary.find_kubeseal_in_path")
    @patch("kseal.binary.download_kubeseal")
    def test_downloads_when_system_version_differs(
        self,
        mock_download,
        mock_find_system,
        mock_get_bin_ver,
        mock_get_version,
        tmp_path,
    ):
        from kseal.binary import ensure_kubeseal

        mock_get_version.return_value = "0.25.0"

        # Default path doesn't exist
        default_path = tmp_path / "default" / "kubeseal-0.25.0"

        # System kubeseal exists but wrong version
        system_kubeseal = tmp_path / "system" / "kubeseal"
        system_kubeseal.parent.mkdir(parents=True)
        system_kubeseal.touch()
        mock_find_system.return_value = system_kubeseal
        mock_get_bin_ver.return_value = "0.24.0"  # Different version

        with patch("kseal.binary.get_default_binary_path", return_value=default_path):
            result = ensure_kubeseal()

        assert result == default_path
        mock_download.assert_called_once_with("0.25.0", default_path)

    @patch("kseal.binary.get_version")
    @patch("kseal.binary.get_binary_version")
    @patch("kseal.binary.find_kubeseal_in_path")
    @patch("kseal.binary.download_kubeseal")
    def test_downloads_when_no_binary_found(
        self,
        mock_download,
        mock_find_system,
        mock_get_bin_ver,
        mock_get_version,
        tmp_path,
    ):
        from kseal.binary import ensure_kubeseal

        mock_get_version.return_value = "0.25.0"
        mock_find_system.return_value = None

        default_path = tmp_path / "default" / "kubeseal-0.25.0"

        with patch("kseal.binary.get_default_binary_path", return_value=default_path):
            result = ensure_kubeseal()

        assert result == default_path
        mock_download.assert_called_once_with("0.25.0", default_path)
