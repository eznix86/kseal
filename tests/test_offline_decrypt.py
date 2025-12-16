"""Tests for offline decrypt commands."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from kseal.cli import decrypt_offline_all, decrypt_offline_single
from kseal.decrypt import get_private_key_paths
from kseal.exceptions import KsealError
from kseal.secrets import decrypt_secret
from tests.fakes import FakeFileSystem


class TestGetPrivateKeyPaths:
    """Tests for get_private_key_paths function."""

    def test_returns_all_key_files(self):
        """Test returns all .key files from directory."""
        fs = FakeFileSystem(
            files={
                ".kseal-keys/key1.key": "key1-content",
                ".kseal-keys/key2.key": "key2-content",
            }
        )
        fs.directories.add(".kseal-keys")

        paths = get_private_key_paths(Path(".kseal-keys"), ".*", fs)

        assert len(paths) == 2
        assert all(p.suffix == ".key" for p in paths)

    def test_filters_by_regex(self):
        """Test filters key files by regex pattern."""
        fs = FakeFileSystem(
            files={
                ".kseal-keys/key-2024-01.key": "key1",
                ".kseal-keys/key-2025-01.key": "key2",
                ".kseal-keys/key-2025-02.key": "key3",
            }
        )
        fs.directories.add(".kseal-keys")

        paths = get_private_key_paths(Path(".kseal-keys"), "2025", fs)

        assert len(paths) == 2

    def test_raises_when_directory_not_found(self):
        """Test raises error when keys directory doesn't exist."""
        fs = FakeFileSystem()

        with pytest.raises(KsealError, match="Keys directory not found"):
            get_private_key_paths(Path(".kseal-keys"), ".*", fs)

    def test_raises_when_no_keys_match(self):
        """Test raises error when no keys match pattern."""
        fs = FakeFileSystem(
            files={
                ".kseal-keys/key-old.key": "key1",
            }
        )
        fs.directories.add(".kseal-keys")

        with pytest.raises(KsealError, match="No keys found"):
            get_private_key_paths(Path(".kseal-keys"), "2025", fs)


class TestDecryptOfflineSingle:
    """Tests for decrypt_offline_single function."""

    def test_reads_from_file_path(self):
        """Test reads sealed secret from file path."""
        sealed_yaml = """apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: test-secret
  namespace: default
spec:
  encryptedData:
    key: encrypted_value
"""
        fs = FakeFileSystem(files={"sealed.yaml": sealed_yaml})
        kubeseal = MagicMock()
        kubeseal.decrypt.return_value = "decrypted yaml"

        result = decrypt_offline_single(Path("sealed.yaml"), [Path("key.pem")], fs, kubeseal)

        assert result == "decrypted yaml"
        kubeseal.decrypt.assert_called_once_with(sealed_yaml, [Path("key.pem")])

    def test_reads_from_stdin(self):
        """Test reads sealed secret from stdin content."""
        stdin_content = "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret"
        fs = FakeFileSystem()
        kubeseal = MagicMock()
        kubeseal.decrypt.return_value = "decrypted yaml"

        result = decrypt_offline_single(
            None, [Path("key.pem")], fs, kubeseal, stdin_content=stdin_content
        )

        assert result == "decrypted yaml"
        kubeseal.decrypt.assert_called_once_with(stdin_content, [Path("key.pem")])

    def test_raises_when_no_input(self):
        """Test raises error when no input provided."""
        fs = FakeFileSystem()
        kubeseal = MagicMock()

        with pytest.raises(KsealError, match="No input provided"):
            decrypt_offline_single(None, [Path("key.pem")], fs, kubeseal, stdin_content=None)


class TestDecryptOfflineAll:
    """Tests for decrypt_offline_all function."""

    def test_decrypts_multiple_files(self):
        """Test decrypts all sealed secret files."""
        sealed_yaml = """apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: test
  namespace: default
spec:
  encryptedData:
    key: value
"""
        fs = FakeFileSystem(
            files={
                "secrets/a.yaml": sealed_yaml,
                "secrets/b.yaml": sealed_yaml,
            }
        )
        kubeseal = MagicMock()
        kubeseal.decrypt.return_value = "decrypted"

        results, errors = decrypt_offline_all(
            Path("."), [Path("key.pem")], fs, kubeseal, show_progress=False
        )

        assert len(results) == 2
        assert len(errors) == 0

    def test_returns_empty_when_no_secrets_found(self):
        """Test returns empty lists when no sealed secrets found."""
        fs = FakeFileSystem(files={"config.yaml": "kind: ConfigMap"})
        kubeseal = MagicMock()

        results, errors = decrypt_offline_all(
            Path("."), [Path("key.pem")], fs, kubeseal, show_progress=False
        )

        assert results == []
        assert errors == []
        kubeseal.decrypt.assert_not_called()

    def test_collects_errors_and_continues(self):
        """Test collects errors but continues processing."""
        sealed_yaml_a = """apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: test-a
  namespace: default
spec:
  encryptedData:
    key: value
"""
        sealed_yaml_b = """apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: test-b
  namespace: default
spec:
  encryptedData:
    key: value
"""
        fs = FakeFileSystem(
            files={
                "a.yaml": sealed_yaml_a,
                "b.yaml": sealed_yaml_b,
            }
        )
        call_count = [0]

        def mock_decrypt(content, keys):
            call_count[0] += 1
            if call_count[0] == 1:
                raise KsealError("Decryption failed")
            return "decrypted"

        kubeseal = MagicMock()
        kubeseal.decrypt.side_effect = mock_decrypt

        results, errors = decrypt_offline_all(
            Path("."), [Path("key.pem")], fs, kubeseal, show_progress=False
        )

        # One succeeds, one fails
        assert len(results) == 1
        assert len(errors) == 1
        assert "Decryption failed" in errors[0]

    def test_preserve_other_docs_with_in_place(self):
        """Test preserves non-SealedSecret docs when preserve_other_docs=True."""
        multi_doc_yaml = """apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
data:
  key: value
---
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: my-secret
  namespace: default
spec:
  encryptedData:
    password: encrypted
"""
        fs = FakeFileSystem(files={"multi.yaml": multi_doc_yaml})
        kubeseal = MagicMock()
        # Return decrypted secret YAML
        kubeseal.decrypt.return_value = """apiVersion: v1
kind: Secret
metadata:
  name: my-secret
  namespace: default
stringData:
  password: decrypted-value
"""

        results, errors = decrypt_offline_all(
            Path("."),
            [Path("key.pem")],
            fs,
            kubeseal,
            show_progress=False,
            preserve_other_docs=True,
        )

        assert len(results) == 1
        assert len(errors) == 0
        # Check that ConfigMap is preserved
        decrypted_content = results[0][1]
        assert "kind: ConfigMap" in decrypted_content
        assert "kind: Secret" in decrypted_content
        assert "my-config" in decrypted_content


class TestDecryptSecret:
    """Tests for decrypt_secret function."""

    def test_preserves_configmap_before_sealed_secret(self):
        """Test preserves ConfigMap that appears before SealedSecret."""
        multi_doc = """apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  setting: value
---
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: app-secret
  namespace: default
spec:
  encryptedData:
    api_key: encrypted
"""
        kubeseal = MagicMock()
        kubeseal.decrypt.return_value = """apiVersion: v1
kind: Secret
metadata:
  name: app-secret
  namespace: default
stringData:
  api_key: my-api-key
"""

        result = decrypt_secret(multi_doc, kubeseal, [Path("key.pem")])

        assert "kind: ConfigMap" in result
        assert "kind: Secret" in result
        assert "app-config" in result
        assert "app-secret" in result

    def test_preserves_configmap_after_sealed_secret(self):
        """Test preserves ConfigMap that appears after SealedSecret."""
        multi_doc = """apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: app-secret
  namespace: default
spec:
  encryptedData:
    api_key: encrypted
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  setting: value
"""
        kubeseal = MagicMock()
        kubeseal.decrypt.return_value = """apiVersion: v1
kind: Secret
metadata:
  name: app-secret
  namespace: default
stringData:
  api_key: my-api-key
"""

        result = decrypt_secret(multi_doc, kubeseal, [Path("key.pem")])

        assert "kind: ConfigMap" in result
        assert "kind: Secret" in result

    def test_decrypts_multiple_sealed_secrets(self):
        """Test decrypts multiple SealedSecrets in same file."""
        multi_doc = """apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: secret-a
  namespace: default
spec:
  encryptedData:
    key: encrypted-a
---
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: secret-b
  namespace: default
spec:
  encryptedData:
    key: encrypted-b
"""
        call_count = [0]

        def mock_decrypt(content, keys):
            call_count[0] += 1
            name = "secret-a" if call_count[0] == 1 else "secret-b"
            return f"""apiVersion: v1
kind: Secret
metadata:
  name: {name}
  namespace: default
stringData:
  key: decrypted-{name}
"""

        kubeseal = MagicMock()
        kubeseal.decrypt.side_effect = mock_decrypt

        result = decrypt_secret(multi_doc, kubeseal, [Path("key.pem")])

        assert result.count("kind: Secret") == 2
        assert "secret-a" in result
        assert "secret-b" in result
        assert kubeseal.decrypt.call_count == 2

    def test_raises_when_no_sealed_secret(self):
        """Test raises error when no SealedSecret in content."""
        config_only = """apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
data:
  key: value
"""
        kubeseal = MagicMock()

        with pytest.raises(KsealError, match="No SealedSecret found"):
            decrypt_secret(config_only, kubeseal, [Path("key.pem")])

    def test_raises_on_empty_content(self):
        """Test raises error on empty content."""
        kubeseal = MagicMock()

        with pytest.raises(KsealError, match="Empty or invalid"):
            decrypt_secret("", kubeseal, [Path("key.pem")])
