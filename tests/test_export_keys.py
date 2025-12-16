"""Tests for export-keys command."""

from datetime import datetime
from pathlib import Path

from kseal.cli import export_sealing_keys
from kseal.services.kubernetes import SealingKey
from tests.fakes import FakeFileSystem, FakeKubernetes


class TestExportSealingKeys:
    """Tests for export_sealing_keys function."""

    def test_exports_single_key(self):
        """Test exporting a single sealing key."""
        key_content = b"-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----\n"
        kubernetes = FakeKubernetes(
            sealing_keys=[
                SealingKey(
                    name="sealed-secrets-key123",
                    tls_key=key_content,
                    created_at=datetime(2025, 1, 1),
                )
            ]
        )
        fs = FakeFileSystem()

        count = export_sealing_keys(Path(".kseal-keys"), kubernetes, fs)

        assert count == 1
        assert ".kseal-keys/sealed-secrets-key123.key" in fs.files
        assert fs.files[".kseal-keys/sealed-secrets-key123.key"] == key_content.decode()

    def test_exports_multiple_keys(self):
        """Test exporting multiple sealing keys."""
        key1 = b"-----BEGIN RSA PRIVATE KEY-----\nkey1\n-----END RSA PRIVATE KEY-----\n"
        key2 = b"-----BEGIN RSA PRIVATE KEY-----\nkey2\n-----END RSA PRIVATE KEY-----\n"
        kubernetes = FakeKubernetes(
            sealing_keys=[
                SealingKey(name="key-abc", tls_key=key1, created_at=datetime(2025, 1, 1)),
                SealingKey(name="key-xyz", tls_key=key2, created_at=datetime(2025, 1, 2)),
            ]
        )
        fs = FakeFileSystem()

        count = export_sealing_keys(Path("backup"), kubernetes, fs)

        assert count == 2
        assert "backup/key-abc.key" in fs.files
        assert "backup/key-xyz.key" in fs.files

    def test_returns_zero_when_no_keys(self):
        """Test returns 0 when no sealing keys found."""
        kubernetes = FakeKubernetes(sealing_keys=[])
        fs = FakeFileSystem()

        count = export_sealing_keys(Path(".kseal-keys"), kubernetes, fs)

        assert count == 0
        assert len(fs.files) == 0

    def test_creates_output_directory(self):
        """Test creates the output directory."""
        key_content = b"-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----\n"
        kubernetes = FakeKubernetes(
            sealing_keys=[
                SealingKey(name="key", tls_key=key_content, created_at=datetime(2025, 1, 1))
            ]
        )
        fs = FakeFileSystem()

        export_sealing_keys(Path("deep/nested/path"), kubernetes, fs)

        assert "deep/nested/path" in fs.directories

    def test_uses_custom_namespace(self):
        """Test uses custom namespace for fetching keys."""
        kubernetes = FakeKubernetes(sealing_keys=[])
        fs = FakeFileSystem()

        export_sealing_keys(Path(".kseal-keys"), kubernetes, fs, namespace="kube-system")

        assert kubernetes.get_sealing_keys_calls == ["kube-system"]

    def test_default_namespace_is_sealed_secrets(self):
        """Test default namespace is sealed-secrets."""
        kubernetes = FakeKubernetes(sealing_keys=[])
        fs = FakeFileSystem()

        export_sealing_keys(Path(".kseal-keys"), kubernetes, fs)

        assert kubernetes.get_sealing_keys_calls == ["sealed-secrets"]
