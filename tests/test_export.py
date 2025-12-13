"""Tests for the export feature - exporting decrypted secrets to files."""

import base64
from pathlib import Path

import pytest

from kseal.cli import export_all, export_all_from_cluster, export_single
from kseal.exceptions import KsealError
from tests.fakes import FakeFileSystem, FakeKubernetes


class TestExportSingle:
    def test_exports_to_default_location(self, tmp_path, monkeypatch):
        # Still need tmp_path/monkeypatch for get_unsealed_dir() which reads config
        monkeypatch.chdir(tmp_path)
        from kseal.config import clear_config_cache

        clear_config_cache()

        fs = FakeFileSystem(
            files={
                "secrets/app.yaml": """\
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: app-secret
  namespace: production
"""
            }
        )

        kubernetes = FakeKubernetes(
            secrets={
                ("app-secret", "production"): {
                    "name": "app-secret",
                    "namespace": "production",
                    "data": {"api-key": base64.b64encode(b"secret-key").decode()},
                    "labels": None,
                    "annotations": None,
                }
            }
        )

        output_path = export_single(Path("secrets/app.yaml"), kubernetes, fs=fs)

        assert ".unsealed" in str(output_path)
        content = fs.files[str(output_path)]
        assert "secret-key" in content
        assert "kind: Secret" in content

    def test_exports_to_custom_output(self):
        fs = FakeFileSystem(
            files={
                "sealed.yaml": """\
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: test
  namespace: default
"""
            }
        )

        kubernetes = FakeKubernetes(
            secrets={
                ("test", "default"): {
                    "name": "test",
                    "namespace": "default",
                    "data": {"key": base64.b64encode(b"value").decode()},
                    "labels": None,
                    "annotations": None,
                }
            }
        )

        output_file = Path("custom/output.yaml")
        result = export_single(Path("sealed.yaml"), kubernetes, output_file, fs)

        assert result == output_file
        assert "custom/output.yaml" in fs.files
        assert "value" in fs.files["custom/output.yaml"]

    def test_raises_when_not_sealed_secret(self):
        fs = FakeFileSystem(
            files={
                "config.yaml": """\
apiVersion: v1
kind: ConfigMap
metadata:
  name: test
"""
            }
        )

        kubernetes = FakeKubernetes()

        with pytest.raises(KsealError) as exc_info:
            export_single(Path("config.yaml"), kubernetes, fs=fs)

        assert "not a SealedSecret" in str(exc_info.value)

    def test_raises_when_secret_not_found(self):
        fs = FakeFileSystem(
            files={
                "sealed.yaml": """\
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: missing
  namespace: default
"""
            }
        )

        kubernetes = FakeKubernetes(secrets={})

        with pytest.raises(KsealError) as exc_info:
            export_single(Path("sealed.yaml"), kubernetes, fs=fs)

        assert "not found" in str(exc_info.value)


class TestExportAll:
    def test_exports_all_sealed_secrets(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from kseal.config import clear_config_cache

        clear_config_cache()

        fs = FakeFileSystem(
            files={
                "secret1.yaml": """\
kind: SealedSecret
metadata:
  name: secret1
  namespace: default
""",
                "secret2.yaml": """\
kind: SealedSecret
metadata:
  name: secret2
  namespace: default
""",
                "config.yaml": """\
kind: ConfigMap
metadata:
  name: config
""",
            }
        )

        kubernetes = FakeKubernetes(
            secrets={
                ("secret1", "default"): {
                    "name": "secret1",
                    "namespace": "default",
                    "data": {"key": base64.b64encode(b"value1").decode()},
                    "labels": None,
                    "annotations": None,
                },
                ("secret2", "default"): {
                    "name": "secret2",
                    "namespace": "default",
                    "data": {"key": base64.b64encode(b"value2").decode()},
                    "labels": None,
                    "annotations": None,
                },
            }
        )

        exported_count, errors = export_all(kubernetes, fs, show_progress=False)

        assert exported_count == 2
        assert errors == []

    def test_returns_zero_when_no_secrets_found(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from kseal.config import clear_config_cache

        clear_config_cache()

        fs = FakeFileSystem(
            files={
                "config.yaml": """\
kind: ConfigMap
metadata:
  name: config
"""
            }
        )

        kubernetes = FakeKubernetes()

        exported_count, errors = export_all(kubernetes, fs, show_progress=False)

        assert exported_count == 0
        assert errors == []

    def test_collects_errors_and_continues(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from kseal.config import clear_config_cache

        clear_config_cache()

        fs = FakeFileSystem(
            files={
                "bad.yaml": """\
kind: SealedSecret
metadata:
  name: missing-secret
  namespace: default
""",
                "good.yaml": """\
kind: SealedSecret
metadata:
  name: good-secret
  namespace: default
""",
            }
        )

        kubernetes = FakeKubernetes(
            secrets={
                ("good-secret", "default"): {
                    "name": "good-secret",
                    "namespace": "default",
                    "data": {"key": base64.b64encode(b"value").decode()},
                    "labels": None,
                    "annotations": None,
                },
            }
        )

        exported_count, errors = export_all(kubernetes, fs, show_progress=False)

        assert exported_count == 1
        assert len(errors) == 1
        assert "missing-secret" in errors[0]

    def test_searches_recursively(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from kseal.config import clear_config_cache

        clear_config_cache()

        fs = FakeFileSystem(
            files={
                "root.yaml": """\
kind: SealedSecret
metadata:
  name: root-secret
  namespace: default
""",
                "k8s/secrets/deep.yaml": """\
kind: SealedSecret
metadata:
  name: deep-secret
  namespace: default
""",
            }
        )

        kubernetes = FakeKubernetes(
            secrets={
                ("root-secret", "default"): {
                    "name": "root-secret",
                    "namespace": "default",
                    "data": {},
                    "labels": None,
                    "annotations": None,
                },
                ("deep-secret", "default"): {
                    "name": "deep-secret",
                    "namespace": "default",
                    "data": {},
                    "labels": None,
                    "annotations": None,
                },
            }
        )

        exported_count, errors = export_all(kubernetes, fs, show_progress=False)

        assert exported_count == 2
        assert errors == []


class TestExportAllFromCluster:
    def test_exports_secrets_from_cluster(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from kseal.config import clear_config_cache

        clear_config_cache()

        fs = FakeFileSystem()

        kubernetes = FakeKubernetes(
            cluster_secrets=[
                {
                    "name": "app-secret",
                    "namespace": "production",
                    "data": {"api-key": base64.b64encode(b"secret-key").decode()},
                    "labels": None,
                    "annotations": None,
                },
                {
                    "name": "db-secret",
                    "namespace": "production",
                    "data": {"password": base64.b64encode(b"dbpass").decode()},
                    "labels": None,
                    "annotations": None,
                },
            ]
        )

        exported_count, errors = export_all_from_cluster(
            kubernetes, fs, show_progress=False
        )

        assert exported_count == 2
        assert errors == []
        assert kubernetes.list_calls == 1

        # Check files are created with namespace/name.yaml structure
        assert ".unsealed/production/app-secret.yaml" in fs.files
        assert ".unsealed/production/db-secret.yaml" in fs.files
        assert "secret-key" in fs.files[".unsealed/production/app-secret.yaml"]
        assert "dbpass" in fs.files[".unsealed/production/db-secret.yaml"]

    def test_returns_zero_when_no_secrets_in_cluster(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from kseal.config import clear_config_cache

        clear_config_cache()

        fs = FakeFileSystem()
        kubernetes = FakeKubernetes(cluster_secrets=[])

        exported_count, errors = export_all_from_cluster(
            kubernetes, fs, show_progress=False
        )

        assert exported_count == 0
        assert errors == []

    def test_exports_secrets_from_multiple_namespaces(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from kseal.config import clear_config_cache

        clear_config_cache()

        fs = FakeFileSystem()

        kubernetes = FakeKubernetes(
            cluster_secrets=[
                {
                    "name": "secret1",
                    "namespace": "namespace-a",
                    "data": {"key": base64.b64encode(b"value1").decode()},
                    "labels": None,
                    "annotations": None,
                },
                {
                    "name": "secret2",
                    "namespace": "namespace-b",
                    "data": {"key": base64.b64encode(b"value2").decode()},
                    "labels": None,
                    "annotations": None,
                },
            ]
        )

        exported_count, errors = export_all_from_cluster(
            kubernetes, fs, show_progress=False
        )

        assert exported_count == 2

        assert ".unsealed/namespace-a/secret1.yaml" in fs.files
        assert ".unsealed/namespace-b/secret2.yaml" in fs.files
