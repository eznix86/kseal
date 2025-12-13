"""Tests for the cat feature - viewing decrypted secrets."""

import base64
from pathlib import Path

import pytest

from kseal.cli import cat_secret
from kseal.exceptions import KsealError
from tests.fakes import FakeFileSystem, FakeKubernetes


class TestCatSecret:
    def test_outputs_decrypted_secret(self, capsys):
        fs = FakeFileSystem(
            files={
                "sealed.yaml": """\
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: my-secret
  namespace: production
"""
            }
        )

        kubernetes = FakeKubernetes(
            secrets={
                ("my-secret", "production"): {
                    "name": "my-secret",
                    "namespace": "production",
                    "data": {"password": base64.b64encode(b"secret-value").decode()},
                    "labels": None,
                    "annotations": None,
                }
            }
        )

        cat_secret(Path("sealed.yaml"), kubernetes, fs, color=False)

        output = capsys.readouterr().out
        assert "secret-value" in output
        assert "kind: Secret" in output

    def test_outputs_multiple_keys(self, capsys):
        fs = FakeFileSystem(
            files={
                "sealed.yaml": """\
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: db-creds
  namespace: default
"""
            }
        )

        kubernetes = FakeKubernetes(
            secrets={
                ("db-creds", "default"): {
                    "name": "db-creds",
                    "namespace": "default",
                    "data": {
                        "username": base64.b64encode(b"admin").decode(),
                        "password": base64.b64encode(b"hunter2").decode(),
                    },
                    "labels": None,
                    "annotations": None,
                }
            }
        )

        cat_secret(Path("sealed.yaml"), kubernetes, fs, color=False)

        output = capsys.readouterr().out
        assert "admin" in output
        assert "hunter2" in output

    def test_raises_when_file_not_sealed_secret(self):
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
            cat_secret(Path("config.yaml"), kubernetes, fs)

        assert "not a SealedSecret" in str(exc_info.value)

    def test_raises_when_secret_not_in_cluster(self):
        fs = FakeFileSystem(
            files={
                "sealed.yaml": """\
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: missing-secret
  namespace: default
"""
            }
        )

        kubernetes = FakeKubernetes(secrets={})

        with pytest.raises(KsealError) as exc_info:
            cat_secret(Path("sealed.yaml"), kubernetes, fs)

        assert "not found" in str(exc_info.value)

    def test_uses_default_namespace(self, capsys):
        fs = FakeFileSystem(
            files={
                "sealed.yaml": """\
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: my-secret
"""
            }
        )

        kubernetes = FakeKubernetes(
            secrets={
                ("my-secret", "default"): {
                    "name": "my-secret",
                    "namespace": "default",
                    "data": {"key": base64.b64encode(b"value").decode()},
                    "labels": None,
                    "annotations": None,
                }
            }
        )

        cat_secret(Path("sealed.yaml"), kubernetes, fs, color=False)

        output = capsys.readouterr().out
        assert "value" in output
